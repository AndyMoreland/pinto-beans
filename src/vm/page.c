
#include <threads/vaddr.h> 
#include <threads/thread.h>
#include <threads/synch.h>
#include <hash.h>
#include <userprog/pagedir.h>
#include <threads/vaddr.h>
#include <threads/malloc.h>
#include <string.h>
#include "page.h"
#include "frame.h"
#include "swap.h"
#include <stdio.h>

/* API: 
 * look up vaddr and get information about it
 * create a page at an addr (called to load an executable or extend stack)
 * reinstate page @ an addr (might be part of looking up a vaddr)
 */
enum page_type
  {
    SWAP,
    SWAP_ZERO_INIT,
    MMAP
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
  bool writable;
  frame_id frame;

  union {
    struct {
      size_t offset;
      struct mmap_descriptor *md;
    } mmap_info;
    swap_descriptor swap_info;
  };
};

static struct hash aux_pt;
static struct lock aux_pt_lock;

static unsigned hash_address (const struct hash_elem *e, void *aux);
static bool page_less (const struct hash_elem *a, const struct hash_elem *b, void *aux);
static struct aux_pt_entry *page_create_entry (void *vaddr, uint32_t *pd);
static struct aux_pt_entry *page_lookup_current (void *user_vaddr);
static struct aux_pt_entry *page_lookup_entry (void *user_vaddr, uint32_t *pd);
static bool page_is_resident (struct aux_pt_entry *entry);
static void page_setup_contents (struct aux_pt_entry *entry, frame_id new_frame);

void *
FIXME_page_get_kernel_addr (void *vaddr)
{
  struct aux_pt_entry *entry = page_lookup_current (vaddr);
  if (!entry || entry->frame == FRAME_INVALID || !page_is_resident (entry))
    return NULL;
  
  return frame_get_kernel_addr (entry->frame);
}

void 
page_init (void)
{
  hash_init (&aux_pt, hash_address, page_less, NULL);
  lock_init (&aux_pt_lock);
}

bool 
page_create_swap_page (void *vaddr, bool zeroed, bool writable) 
{
  struct aux_pt_entry *entry = page_create_entry (vaddr, thread_current ()->pagedir);
  if (!entry)
    return false;

  entry->frame = FRAME_INVALID;
  entry->type = zeroed? SWAP_ZERO_INIT : SWAP;
  entry->writable = true;
  return true;
}

bool 
page_create_mmap_pages (const char *filename, void *vaddr, bool writable)
{
  // FIXME: todo
}

void
page_free_page (void *vaddr)
{
  struct aux_pt_entry *entry = page_lookup_current (vaddr);

  if (entry->frame != FRAME_INVALID) 
    {
      frame_pin (entry->frame);
      if (page_is_resident (entry))
        frame_release_frame (entry->frame);
      else if (entry->type == SWAP)
        {
          swap_clear (entry->swap_info);
        }
      else
        {
          // FIXME: mmap cleanup
        }
    }
  lock_acquire (&aux_pt_lock);
  hash_delete (&aux_pt, &entry->elem);
  lock_release (&aux_pt_lock);
  pagedir_clear_page (entry->pd, entry->user_addr);
  // FIXME: remove from thread's page list
}

bool
page_in (void *vaddr) 
{
  struct aux_pt_entry *entry = page_lookup_current (vaddr);
  if (entry)
    {
      ASSERT (!page_is_resident (entry));
    }

  if (!page_in_and_pin (vaddr))
    return false;

  page_unpin (vaddr);
  return true;
}

/* Pages out the given page. It is assumed that this page is already
 * pinned externally. 
 */
void 
page_out (void *vaddr, uint32_t *pd)
{
  struct aux_pt_entry *entry = page_lookup_entry (vaddr, pd);
  ASSERT (entry->frame != FRAME_INVALID);

  if (!page_is_resident (entry)) {
    frame_unpin (entry->frame);
    return;
  }

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

bool page_in_and_pin (void *user_vaddr)
{
  struct aux_pt_entry *entry = page_lookup_current (user_vaddr);
  if (!entry)
    return false;

  if (entry->frame != FRAME_INVALID)
    {
      frame_pin (entry->frame);
      if (page_is_resident (entry))
        return true;
      frame_unpin (entry->frame);
    }
  frame_id new_frame = frame_get_frame_pinned (entry->user_addr, entry->pd);
  ASSERT (new_frame != FRAME_INVALID && frame_get_kernel_addr (new_frame));
  page_setup_contents (entry, new_frame);
  entry->frame = new_frame;
  if (!pagedir_set_page (entry->pd, entry->user_addr, frame_get_kernel_addr (new_frame), entry->writable))
    PANIC ("could not update pagedir; out of kernel memory?");
  return true;
}

void page_unpin (void *user_vaddr)
{
  struct aux_pt_entry *entry = page_lookup_current (user_vaddr);
  ASSERT (entry->frame != FRAME_INVALID);
  frame_unpin (entry->frame);
}

static void 
page_setup_contents (struct aux_pt_entry *entry, frame_id new_frame)
{
  // FIXME: do this
  void *frame_addr = frame_get_kernel_addr (new_frame);
  bool first_load = (entry->frame == FRAME_INVALID);
  switch (entry->type) 
  {
  case SWAP:
    if (!first_load)
      {
        size_t bytes = swap_read (frame_addr, entry->swap_info, PGSIZE);
        if (bytes != PGSIZE)
          PANIC ("only read %d bytes from frame into 0x%p", (int) bytes, new_frame);
      }
    break;
  case SWAP_ZERO_INIT:
    if (first_load)
      memset (frame_addr, 0, PGSIZE);
    break; 
  case MMAP:
    // FIXME: setup mmap shenanigans 
    break;
  default:
    PANIC ("unrecognized page type %d", entry->type);
  }
}

static unsigned 
hash_address (const struct hash_elem *e, void *aux UNUSED)
{
  return hash_int (pg_no (hash_entry (e, struct aux_pt_entry, elem)->user_addr));
}

static bool 
page_less (const struct hash_elem *ae, const struct hash_elem *be, void *aux UNUSED)
{
  struct aux_pt_entry *a = hash_entry (ae, struct aux_pt_entry, elem);
  struct aux_pt_entry *b = hash_entry (be, struct aux_pt_entry, elem);

  if (a->pd != b->pd)
    return a->pd < b->pd;
  else
    return pg_no (a->user_addr) < pg_no (b->user_addr);
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
      hash_insert (&aux_pt, &record->elem); 
      lock_release (&aux_pt_lock);
      // FIXME: register page with thread for cleanup
    }
  return record;
}

struct aux_pt_entry *
page_lookup_entry (void *user_vaddr, uint32_t *pd)
{
  struct aux_pt_entry query = { .user_addr = user_vaddr, .pd = pd };
  
  struct hash_elem *result = hash_find(&aux_pt, &query.elem);
  if (result != NULL)
    return hash_entry (result, struct aux_pt_entry, elem);
  else
    return NULL;
}

/* Right now just returns our internal struct. Might want to clean this interface. */
struct aux_pt_entry *
page_lookup_current (void *user_vaddr)
{
  return page_lookup_entry (user_vaddr, thread_current ()->pagedir);
}

static bool 
page_is_resident (struct aux_pt_entry *entry)
{
  return pagedir_get_page (entry->pd, entry->user_addr) != NULL;
}


