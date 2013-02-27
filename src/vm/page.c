
#include "page.h"
#include "threads/vaddr.h" 
#include "threads/thread.h"
#include "threads/synch.h"

/* API: 
 * look up vaddr and get information about it
 * create a page at an addr (called to load an executable or extend stack)
 * reinstate page @ an addr (might be part of looking up a vaddr)
 */
enum page_type
  {
    SWAP,
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
  struct frame_table_entry *frame_entry;

  union {
    struct mmap_info {
      size_t offset;
      struct mmap_descriptor *md;
    };
    struct swap_info {
      // FIXME: swap info 
      
    }
  }
};

bool 
page_create_at (void *vaddr, bool zeroed, bool writable) 
{
  uintptr_t page_no = pg_no (vaddr);
  struct aux_pt_entry *entry = page_create_entry (vaddr, thread_current ()->pd);
  void *frame = frame_get_frame (vaddr, entry->pd);
  return pagedir_set_page (entry->pd, vaddr, frame, writable);
}

bool 
page_free_page (void *vaddr)
{
  struct hash_elem elem;
  struct aux_pt_entry *entry = 
}

bool 
page_in (void *vaddr) 
{

}

bool 
page_out (void *vaddr)
{
}


static struct hash aux_pt;
static struct lock aux_pt_lock;

static hash_address (const struct hash_elem *e, void *aux UNUSED)
{
  return hash_bytes (pg_no (hash_entry (e->elem, aux_pt_entry, elem)->user_addr), sizeof(void *));
}

static page_less (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
  if (a->pd != b->bd)
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
page_lookup_page (void *user_vaddr)
{
  uint32_t pd = current_thread ()->pd;
  struct aux_pt_entry query = { .user_addr = user_vaddr, .pd = pd };
  
  struct hash_elem *result = hash_find(&aux_pt, &query->elem);

  if (result != NULL)
    return hash_entry (&result->elem, aux_pt_entry, elem);
  else
    return NULL;
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
