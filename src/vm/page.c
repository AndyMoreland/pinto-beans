
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
  bool is_loaded;

  union {
    void *frame_addr;
    struct mmap_info {
      size_t offset;
      struct mmap_descriptor *md;
    };
    struct swapd swap_info;
  };
};

static struct hash aux_pt;
static struct lock aux_pt_lock;

static struct aux_pt_entry *page_create_entry (void *vaddr, uint32_t *pd);
static struct aux_pt_entry *page_lookup_entry (void *user_vaddr, uint32_t *pd);
static bool page_destroy_entry (struct aux_pt_entry *entry);

bool 
page_create_page (void *vaddr, bool zeroed, bool writable) 
{
  struct aux_pt_entry *entry = page_create_entry (vaddr, thread_current ()->pd);
  ASSERT (entry);
  void *frame = frame_get_frame (vaddr, entry->pd);
  ASSERT (frame);
  if (!pagedir_set_page (entry->pd, vaddr, frame, writable))
    return false;

  entry->is_loaded = true;
  entry->type = SWAP;
  return true;
}

void
page_free_page (void *vaddr)
{
  struct aux_pt_entry *entry = page_lookup_entry (vaddr, thread_current ()->pd);

  lock_acquire (&aux_pt_lock);
  hash_delete (&aux_pt, &entry->hash_elem);
  lock_release (&aux_pt_lock);

  if (entry->is_loaded) {
    frame_clear_frame (entry->frame_addr);
  } else if (entry->type == SWAP) {
    swap_clear (entry->swap_info);
  } else {
     // FIXME: memmap cleanup
  }
  pagedir_clear_page (entry->pd, entry->user_addr);
  free (vaddr);
}

void
page_in (void *vaddr) 
{
  struct aux_pt_entry *entry = page_lookup_entry (vaddr, thread_current ()->pd);
  if (entry->is_loaded)
    PANIC ("attempt to page in an active page");

  void *frame;
  if (entry->type == SWAP) {
    frame = frame_create_frame (entry->user_addr, entry->pd);
    swap_read (frame, entry->swap_info, PG_SIZE);
  } else { // mmap
    // FIXME: mmap page in
  }

  entry->frame_addr = frame;
  entry->is_loaded = false;
}

void 
page_out (void *vaddr)
{
  struct aux_pt_entry *entry = page_lookup_entry (vaddr, thread_current ()->pd);
  if (!entry->is_loaded)
    PANIC ("attempt to page out an inactive page");

  void *frame = entry->frame_addr;
  if (entry->type == SWAP) {
    // FIXME: locking - page trying to be swapped out already, etc  
    entry->swap_info = swap_write (frame, PGSIZE);
  } else { // mmap
    // FIXME: memmap page out
  }
  frame_clear_frame (frame);
  entry->is_loaded = false;
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

page_init (void)
{
  hash_init (&aux_pt, hash_address, page_less, NULL);
  lock_init (&aux_pt_lock);
}

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
      record->is_loaded = false;
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
page_lookup_entry (void *user_vaddr, uint32_t *pd)
{
  struct aux_pt_entry query = { .user_addr = user_vaddr, .pd = pd };
  
  struct hash_elem *result = hash_find(&aux_pt, &query->elem);
  if (result != NULL)
    return hash_entry (&result->elem, aux_pt_entry, elem);
  else
    PANIC ("no page found under 0x%x", vaddr); 
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

bool
page_reload_page (void *user_vaddr)
{
  uint32_t pd = current_thread ()->pd;

  if (page_lookup (page buser_vaddr))
    {
      /* then we need to proceed according to the page's swap strategy. */
      
    }
}
