
#include <stdio.h>
#include <string.h>
#include "filesys/inode.h"
#include "threads/synch.h"
#include "hash.h"
#include "threads/malloc.h"
#include "cache.h"
#include "filesys.h"
#include "threads/thread.h"

#define CACHE_MAX_READAHEAD 16
#define CACHE_NUM_READAHEAD_THREADS 4

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
static int cache_clock_cursor; 
static struct lock cache_lock;

static block_sector_t rahead_queue[CACHE_MAX_READAHEAD];
static unsigned rahead_start, rahead_size;
static struct lock rahead_lock;
static struct condition rahead_available;

static unsigned cache_hash_hash_func (const struct hash_elem *, void *);
static bool cache_hash_less_func (const struct hash_elem *,
                                  const struct hash_elem *, void *);

static void cache_do_flush (struct cache_entry *);
static void cache_do_evict (struct cache_entry *, block_sector_t);
static void cache_do_disk_read (struct cache_entry *);
static struct cache_entry *cache_find_available (void);
static struct cache_entry *cache_lookup (block_sector_t sector, bool create);
static struct cache_entry *cache_retain (block_sector_t sector);

static void rahead_thread_func (void *aux UNUSED);

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
  rahead_start = rahead_size = 0;
  lock_init (&rahead_lock);
  cond_init (&rahead_available);
  if (!hash_init (&cache_hash, cache_hash_hash_func, cache_hash_less_func, NULL))
    PANIC ("could not create cache hash table");

  for (i = 0; i < CACHE_NUM_READAHEAD_THREADS; ++i)
    {
      char tname[16];
      snprintf (tname, sizeof (tname), "rahead-%d", i);
      thread_create (tname, PRI_DEFAULT, rahead_thread_func, NULL);
    }
}

void 
cache_read (block_sector_t sector, void *dst)
{
  struct cache_entry *entry = cache_retain (sector);
  if (!entry) // no cache slot available
    {
      printf ("warning: no disk cache available: reading %u\n", sector);
      block_read (fs_device, sector, dst);
    }
  else
    {
      memcpy (dst, entry->data, BLOCK_SECTOR_SIZE);
      lock_acquire (&entry->entry_lock);
      ++entry->release_cnt;
      lock_release (&entry->entry_lock);
    }
}

void 
cache_write (block_sector_t sector, const void *src)
{
  struct cache_entry *entry = cache_retain (sector);
  if (!entry) // no cache slot available
    {
      printf ("warning: no disk cache available: write %u\n", sector);
      block_write (fs_device, sector, src);
    }
  else
    {
      memcpy (entry->data, src, BLOCK_SECTOR_SIZE);
      lock_acquire (&entry->entry_lock);
      ++entry->release_cnt;
      entry->flags |= DIRTY;
      lock_release (&entry->entry_lock);
    }
}

static block_sector_t* 
rahead_entry (unsigned i)
{
  return rahead_queue + ((rahead_start + i) % CACHE_MAX_READAHEAD);
}

static bool 
rahead_find (unsigned sector)
{
  unsigned i;
  for (i = 0; i < rahead_size; ++i)
    {
      if (*rahead_entry (i) == sector)
        return true;
    }
  return false;
}

static bool
cache_find (block_sector_t sector)
{
  struct cache_entry entry_dummy;
  entry_dummy.sector = sector;

  return hash_find (&cache_hash, &entry_dummy.elem) != NULL;
}

void 
cache_readahead (block_sector_t sector)
{
  lock_acquire (&cache_lock);
  if (!rahead_find (sector)
      && !cache_find (sector) 
      && rahead_size < CACHE_MAX_READAHEAD)
    {
      *rahead_entry (rahead_size++) = sector;
      cond_signal (&rahead_available, &cache_lock);
    }
    
  lock_release (&cache_lock);
}

void *
cache_begin (block_sector_t sector)
{
  struct cache_entry *entry = cache_retain (sector);
  return entry? entry->data : NULL;
}

#define cache_entry(dat) ((struct cache_entry *) \
        ((uint8_t *)dat - offsetof (struct cache_entry, data)))

void 
cache_end (void *cache_block, bool dirty)
{
  struct cache_entry *entry = cache_entry (cache_block);
  lock_acquire (&entry->entry_lock);
  ++entry->release_cnt;
  if (dirty)
    entry->flags |= DIRTY;
  lock_release (&entry->entry_lock);
}

void 
cache_flush_all (void)
{
  lock_acquire (&cache_lock);
  int i;
  for (i = 0; i < cache_size; ++i)
    {
      struct cache_entry *entry = &cache_entries[i];
      lock_acquire (&entry->entry_lock);
      cache_do_flush (entry);
      lock_release (&entry->entry_lock);
    }
  lock_release (&cache_lock);
}

static unsigned 
cache_hash_hash_func (const struct hash_elem *e, void *aux UNUSED)
{
  struct cache_entry *entry = hash_entry (e, struct cache_entry, elem);
  return hash_int ((int)entry->sector);
}

static bool 
cache_hash_less_func (const struct hash_elem *ae,
                      const struct hash_elem *be, void *aux UNUSED)
{
  struct cache_entry *a = hash_entry (ae, struct cache_entry, elem);
  struct cache_entry *b = hash_entry (be, struct cache_entry, elem);
  
  return a->sector < b->sector;
}

static struct cache_entry *
cache_lookup (block_sector_t sector, bool create)
{
  struct cache_entry entry_dummy;
  entry_dummy.sector = sector;

  struct hash_elem *elem = hash_find (&cache_hash, &entry_dummy.elem);
  struct cache_entry *entry;
  if (elem)
    {
      entry = hash_entry (elem, struct cache_entry, elem);
      lock_acquire (&entry->entry_lock);
    }
  else if (!create)
    return NULL; 
  else
    entry = cache_find_available ();

  if (entry)
    {
      cache_do_evict (entry, sector);
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
  if (lock_held_by_current_thread (&entry->entry_lock) 
      || !lock_try_acquire (&entry->entry_lock))
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
cache_retain (block_sector_t sector)
{
  lock_acquire (&cache_lock);
  struct cache_entry *entry = cache_lookup (sector, true);
  if (!entry)
    {
      lock_release (&cache_lock);
      return NULL;
    }
  ++entry->retain_cnt;
  entry->flags |= ACCESSED;
  lock_release (&cache_lock);

  // we already hold entry's lock through cache_lookup
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
  block_read (fs_device, entry->sector, entry->data);
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
      block_write (fs_device, entry->sector, entry->data);
      entry->flags ^= DIRTY;
    }
}

static void 
cache_do_evict (struct cache_entry *entry, block_sector_t new_sector)
{
  ASSERT (lock_held_by_current_thread (&cache_lock));
  ASSERT (lock_held_by_current_thread (&entry->entry_lock));
  ASSERT (entry->retain_cnt == entry->release_cnt);

  if (entry->flags & USED)
    {
      hash_delete (&cache_hash, &entry->elem);
      lock_release (&cache_lock);
      cache_do_flush (entry);
      lock_acquire (&cache_lock); 
    }
  else
    entry->flags |= USED;

  entry->sector = new_sector;
  entry->retain_cnt = entry->release_cnt = 0;
  hash_insert (&cache_hash, &entry->elem); 
}

/* readahead / writebehind implementation */

static block_sector_t 
rahead_pop (void)
{
  block_sector_t s = *rahead_entry (0);
  ++rahead_start;
  --rahead_size;
  return s;
}

static void
rahead_thread_func (void *aux UNUSED)
{
  while (true)
    {
      lock_acquire (&cache_lock);
      while (!rahead_size)
        cond_wait (&rahead_available, &cache_lock);
      block_sector_t sector = rahead_pop ();
      struct cache_entry *entry = cache_lookup (sector, true);
      lock_release (&cache_lock);
      if (!entry)
        continue;

      if (entry->flags & INIT)
        {
          entry->flags ^= INIT; 
          cache_do_disk_read (entry);
        }
      lock_release (&entry->entry_lock);
    }
}
