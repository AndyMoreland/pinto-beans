
#include <stdio.h>
#include <string.h>
#include "filesys/inode.h"
#include "threads/synch.h"
#include "hash.h"
#include "threads/malloc.h"
#include "cache.h"

enum cache_flags
  {
    USED = 0x1,
    ACCESSED = 0x2,
    DIRTY = 0x4,
    INIT = 0x8,
    READING_DISK = 0x16,
  }; 

struct cache_entry
  {
    enum block_type type;
    block_sector_t sector;

    enum cache_flags flags;   
    int retain_cnt;
    int release_cnt;
    struct lock entry_lock;
    struct condition finished;
    struct hash_elem elem;
    uint8_t data[BLOCK_SECTOR_SIZE];
  };

static struct hash cache_hash;
static struct cache_entry *cache_entries;
static int cache_size;
static int cache_clock_cursor; static struct lock cache_lock;

static unsigned cache_hash_hash_func (const struct hash_elem *, void *);
static bool cache_hash_less_func (const struct hash_elem *,
                                  const struct hash_elem *, void *);

static void cache_do_flush (struct cache_entry *);
static void cache_do_evict (struct cache_entry *, enum block_type, block_sector_t);
static void cache_do_disk_read (struct cache_entry *);
static struct cache_entry *cache_find_available (void);
static struct cache_entry *cache_lookup (enum block_type type, 
                                         block_sector_t sector, bool create);
static struct cache_entry *cache_retain (enum block_type type, block_sector_t sector);

void 
cache_init (int size)
{
  cache_entries = calloc (sizeof (struct cache_entry), size);
  if (!cache_entries)
    PANIC ("could not allocate disk cache of size %d", size);
  
  int i;
  for (i = 0; i < size; ++i)
    {
      lock_init (&cache_entries[i].entry_lock);
      cond_init (&cache_entries[i].finished);
    }

  cache_size = size;
  cache_clock_cursor = 0;

  lock_init (&cache_lock);
  if (!hash_init (&cache_hash, cache_hash_hash_func, cache_hash_less_func, NULL))
    PANIC ("could not create cache hash table");
}

void 
cache_read (enum block_type type, block_sector_t sector, void *dst)
{
  struct cache_entry *entry = cache_retain (type, sector);
  if (!entry) // no cache slot available
    {
      printf ("warning: no disk cache available: reading (%d, %d)\n",
              (int) type, (int) sector);
      block_read (block_get_role (type), sector, dst);
    }
  else
    {
      lock_acquire (&entry->entry_lock);
      memcpy (dst, entry->data, BLOCK_SECTOR_SIZE);
      ++entry->release_cnt;
      lock_release (&entry->entry_lock);
    }
}

void 
cache_write (enum block_type type, block_sector_t sector, const void *src)
{
  struct cache_entry *entry = cache_retain (type, sector);
  if (!entry) // no cache slot available
    {
      printf ("warning: no disk cache available: write (%d, %d)\n",
              (int) type, (int) sector);
      block_write (block_get_role (type), sector, src);
    }
  else
    {
      lock_acquire (&entry->entry_lock);
      memcpy (entry->data, src, BLOCK_SECTOR_SIZE);
      ++entry->release_cnt;
      lock_release (&entry->entry_lock);
    }
}

static unsigned 
cache_hash_hash_func (const struct hash_elem *e, void *aux UNUSED)
{
  struct cache_entry *entry = hash_entry (e, struct cache_entry, elem);
  struct {
    enum block_type type;
    block_sector_t sector;
  } id = { .type = entry->type, .sector = entry->sector };
  return hash_bytes (&id, sizeof (id));
}

static bool 
cache_hash_less_func (const struct hash_elem *ae,
                      const struct hash_elem *be, void *aux UNUSED)
{
  struct cache_entry *a = hash_entry (ae, struct cache_entry, elem);
  struct cache_entry *b = hash_entry (be, struct cache_entry, elem);
  
  if (a->type != b->type)
    return a->type < b->type;
  else
    return a->sector < b->sector;
}

static struct cache_entry *
cache_lookup (enum block_type type, block_sector_t sector, bool create)
{
  struct cache_entry entry_dummy;
  entry_dummy.type = type;
  entry_dummy.sector = sector;

  struct hash_elem *elem = hash_find (&cache_hash, &entry_dummy.elem);
  if (elem)
    return hash_entry (elem, struct cache_entry, elem);
  else if (!create)
    return NULL; 

  struct cache_entry *entry = cache_find_available ();
  if (entry)
    {
      cache_do_evict (entry, type, sector);
      entry->flags |= INIT;
    }
  return entry;
}

static void 
advance_clock_cursor (void)
{
  ++cache_clock_cursor;
  if (cache_clock_cursor == cache_size)
    cache_clock_cursor = 0;
}

static bool 
cache_should_evict (struct cache_entry *entry)
{
  if (!lock_try_acquire (&entry->entry_lock))
    return false;

  if (!(entry->flags & USED))
    return true;
  else if (entry->flags & ACCESSED)
    entry->flags ^= ACCESSED;
  else if (entry->retain_cnt == entry->release_cnt) 
    return true;

  lock_release (&entry->entry_lock);
  return false;
}

static struct cache_entry*
cache_find_available (void)
{
  int passes = 0;
  struct cache_entry *available = NULL;
  int clock_start = cache_clock_cursor;

  while (!available && passes < 2)
    {
      struct cache_entry *candidate = &cache_entries[cache_clock_cursor]; 
      advance_clock_cursor ();
      if (cache_should_evict (candidate))
        available = candidate;

      if (cache_clock_cursor == clock_start)
        ++passes;
    }

  return available;
}

static struct cache_entry * 
cache_retain (enum block_type type, block_sector_t sector)
{
  lock_acquire (&cache_lock);
  struct cache_entry *entry = cache_lookup (type, sector, true);
  if (!entry)
    {
      lock_release (&cache_lock);
      return NULL;
    }
  ++entry->retain_cnt;
  entry->flags |= ACCESSED;
  lock_release (&cache_lock);

  lock_acquire (&entry->entry_lock);
  if (entry->flags & INIT)
    {
      entry->flags ^= INIT; 
      cache_do_disk_read (entry);
    }
  else 
    {
      while (entry->flags & READING_DISK)
        cond_wait (&entry->finished, &entry->entry_lock);
    }
  lock_release (&entry->entry_lock);
  return entry;
}

/* Performs a disk read for the given cache entry, updating its
 * cache contents to match its disk sector. It is assumed that the 
 * entry_lock is held by current thread.
 */
static void
cache_do_disk_read (struct cache_entry *entry)
{
  ASSERT (lock_held_by_current_thread (&entry->entry_lock));

  entry->flags |= READING_DISK;
  lock_release (&entry->entry_lock);
  block_read (block_get_role (entry->type), entry->sector, entry->data);
  lock_acquire (&entry->entry_lock);
  entry->flags ^= READING_DISK;
  cond_broadcast (&entry->finished, &entry->entry_lock);
}

static void 
cache_do_flush (struct cache_entry *entry)
{
  ASSERT (lock_held_by_current_thread (&entry->entry_lock));

  if ((entry->flags & USED) && (entry->flags & DIRTY))
    {
      block_write (block_get_role (entry->type), entry->sector, entry->data);
      entry->flags ^= DIRTY;
    }
}

static void 
cache_do_evict (struct cache_entry *entry, 
                enum block_type new_type, block_sector_t new_sector)
{
  ASSERT (lock_held_by_current_thread (&cache_lock));
  ASSERT (lock_held_by_current_thread (&entry->entry_lock));

  if (entry->flags & USED)
    {
      hash_delete (&cache_hash, &entry->elem);
      lock_release (&cache_lock);
      cache_do_flush (entry);
      lock_acquire (&cache_lock); 
    }
  else
    entry->flags |= USED;

  entry->type = new_type;
  entry->sector = new_sector;
  entry->retain_cnt = entry->release_cnt = 0;
  hash_insert (&cache_hash, &entry->elem); 
}

