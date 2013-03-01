
#include <threads/vaddr.h> 
#include <threads/thread.h>
#include <threads/synch.h>
#include "page.h"
#include "frame.h"

/* API: 
 * look up vaddr and get information about it
 * create a page at an addr (called to load an executable or extend stack)
 * reinstate page @ an addr (might be part of looking up a vaddr)
 */
enum page_type
  {
    SWAP,
    SWAP_ZERO_INIT,
    MMAP_WRITE_ON_EVICT,
    MMAP_READ_ONLY
  };

struct aux_pt_entry
{
  struct hash_elem elem;
  struct list_elem thread_pages_elem;
  void *user_addr; /* key */
  uint32_t *pd;
  /* Store swap slot or the file/offset to read from */
  /* Might want an ENUM to track which mode this page is -- for instance,
     if it is an mmapped file or if it is just swapped out. */
  enum page_type type;
  frame_id frame;

  union {
    struct mmap_info {
      size_t offset;
      struct mmap_descriptor *md;
    };
    swap_descriptor swap_info;
  };
};

static struct hash aux_pt;
static struct lock aux_pt_lock;

static struct aux_pt_entry *page_create_entry (void *vaddr, uint32_t *pd);
static struct aux_pt_entry *page_lookup_entry (void *user_vaddr);
static bool page_destroy_entry (struct aux_pt_entry *entry);
static bool page_is_resident (struct aux_pt_entry *entry);
static void page_setup (struct aux_pt_entry *entry);

void 
page_init (void)
{
  hash_init (&aux_pt, hash_address, page_less, NULL);
  lock_init (&aux_pt_lock);
}

void
page_create_page (void *vaddr, bool zeroed, bool writable) 
{
  struct aux_pt_entry *entry = page_create_entry (vaddr, thread_current ()->pd);
  ASSERT (entry);
  entry->frame = FRAME_INVALID;
  entry->type = SWAP;
}

void
page_free_page (void *vaddr)
{
  struct aux_pt_entry *entry = page_lookup_entry (vaddr);

  if (entry->frame != FRAME_INVALID) 
    {
      frame_pin (entry->frame);
      if (page_is_resident (entry))
        frame_clear_frame (entry->frame);
      else if (page->type == SWAP)
        {
          swap_clear (entry->swap_info);
        }
      else
        {
          // FIXME: mmap cleanup
        }
    }
  lock_acquire (&aux_pt_lock);
  hash_delete (&aux_pt, &entry->hash_elem);
  lock_release (&aux_pt_lock);
  pagedir_clear_page (entry->pd, entry->user_addr);
  // FIXME: remove from thread's page list
}

void
page_in (void *vaddr) 
{
  ASSERT (!page_is_resident (page_lookup_entry (user_vaddr)));
  page_in_and_pin (vaddr);
  page_unpin (vaddr);
}

void 
page_out (void *vaddr)
{
  struct aux_pt_entry *entry = page_lookup_entry (vaddr);
  ASSERT (entry->frame != FRAME_INVALID && page_is_resident (entry));

  pagedir_clear_page (entry->pd, entry->user_addr);
  if (entry->type == SWAP) 
    {
      // FIXME: locking - page trying to be swapped out already, etc  
      void *frame_addr = frame_get_kernel_addr (entry->frame);
      entry->swap_info = swap_write (frame_addr, PGSIZE);
    } 
  else 
    { // mmap
      // FIXME: memmap page out
    }
}

void page_in_and_pin (void *user_vaddr)
{
  struct aux_pt_entry *entry = page_lookup_entry (vaddr);

  if (entry->frame != FRAME_INVALID)
    {
      frame_pin (entry->frame);
      if (page_is_resident (entry))
        return;
      frame_unpin (entry->frame);
    }
  frame_id new_frame = frame_get_frame_pinned (entry->user_addr, entry->pd);
  page_setup (new_frame);
  entry->frame = new_frame;
}

void page_unpin (void *user_vaddr)
{
  struct aux_pt_entry *entry = page_lookup_entry (vaddr);
  ASSERT (entry->frame != FRAME_INVALID);
  frame_unpin (entry->frame);
}

static void 
page_setup (struct aux_pt_entry *entry)
{
  // FIXME: do this
  void *frame_addr = frame_get_kernel_addr (entry->frame);
  memset (frame_addr, 0, PG_SIZE);
}

static hash_address (const struct hash_elem *e, void *aux UNUSED)
{
  return hash_bytes (pg_no (hash_entry (e->elem, aux_pt_entry, elem)->user_addr), sizeof(void *));
}

static page_less (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
  if (a->pd != b->pd)
    return a->pd < b->pd;
  else
    return pg_no (a->user_addr) < pg_no (b->user_addr);
}


static void page_setup (struct aux_pt_entry *entry);

static struct aux_pt_entry *
page_create_entry (void *vaddr, uint32_t *pd)
{
  struct aux_pt_entry *record = malloc(sizeof (struct aux_pt_entry));
  if (record)
    {
      record->pd = pd;
      record->user_addr = vaddr;
      lock_acquire (&aux_pt_lock);
      hash_insert (&aux_pt, record->elem); 
      lock_release (&aux_pt_lock);
      // FIXME: register page with thread for cleanup
    }
  return record;
}

/* Returns true if succeeded in registering a page. */
bool 
page_register_page (void *user_vaddr, page_type page_mode) 
{
  void *frame = frame_get_frame_at (user_vaddr);

  if (frame != NULL)
    {
      if (page_record_page (frame, page_mode))
        {
          /* Successfully allocated frame table entry */
          
        }
      else
        return frame;
    }
  else
    {
      /* No eviction policy yet. */
      panic ();
    }
}

/* Right now just returns our internal struct. Might want to clean this interface. */
struct aux_pt_entry
page_lookup_entry (void *user_vaddr)
{
  struct aux_pt_entry query = { .user_addr = user_vaddr, .pd = thread_current ()->pd };
  
  struct hash_elem *result = hash_find(&aux_pt, &query->elem);
  if (result != NULL)
    return hash_entry (&result->elem, aux_pt_entry, elem);
  else
    PANIC ("no page found under 0x%x", vaddr); 
}

static bool 
page_is_resident (struct aux_pt_entry *entry)
{
  return pagedir_get_page (entry->pd, entry->user_addr) != NULL;
}

static bool 
page_destroy_entry (struct aux_pt_entry *entry)
{
  ASSERT (entry);
  if (entry->is_loaded) 
    {
      // TOOD: clean up frame
    }
  else if (entry->is
}

