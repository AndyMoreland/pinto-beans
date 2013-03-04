
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

/* This enum represents the possible eviction strategies
   for a page. */
enum page_type
  {
    SWAP,
    SWAP_LAZY,
    MMAP
  };

/* This struct stores all of the information that we keep
   in the aux page table about a page */
struct aux_pt_entry
{
  struct hash_elem elem; /* Hash table element */
  struct list_elem thread_pages_elem; /* For a thread's page list */
  void *user_addr; /* User VADDR used as hash key */
  uint32_t *pd;    /* User pagedir */

  enum page_type type; /* Eviction strategy */
  bool writable;       /* If the page if read-only */
  frame_id frame;      /* Casted pointer to the 
                          frame_table_entry for the
                          frame of the page */

  union { /* Either the info needed for mmap or swap */
    struct {
      size_t offset; /* How far into the file we are */
      size_t len; /* How much of the file to read */
      struct file *fd; /* Which file we're reading from */
    } mmap_info;

    swap_descriptor swap_info; /* Casted ID of the first swap sector */
  };
};

static struct hash aux_pt; /* The aux page table */
static struct lock aux_pt_lock; /* Lock for the aux page table -- 
                                   acquired before all operations on it. */

static unsigned hash_address (const struct hash_elem *e, void *aux);
static bool page_less (const struct hash_elem *a, 
                       const struct hash_elem *b, void *aux);
static struct aux_pt_entry *page_create_entry (void *vaddr);
static struct aux_pt_entry *page_lookup_current (void *user_vaddr);
static struct aux_pt_entry *page_lookup_entry (void *user_vaddr, uint32_t *pd);
static bool page_is_resident (struct aux_pt_entry *entry);
static void page_setup_contents (struct aux_pt_entry *entry, frame_id new_frame);

/* Initialize lock and page table */
void 
page_init (void)
{
  hash_init (&aux_pt, hash_address, page_less, NULL);
  lock_init (&aux_pt_lock);
}

/* Constructor for creating a new aux_pt_entry with a swap eviction strat.
   Lazily paged in.
   False if unable to malloc. */

bool 
page_create_swap_page (void *vaddr, bool zeroed, bool writable) 
{
  struct aux_pt_entry *entry = page_create_entry (vaddr);
  if (!entry)
    return false;
  
  if (zeroed)
    {
      entry->type = SWAP_LAZY;
      entry->mmap_info.fd = NULL;
    }
  else
    entry->type = SWAP;
  entry->writable = writable;
  return true;
}

/* Constructor for an aux_pt_entry with an mmap strat. 
   Lazily paged in.
   False if unable to malloc or open file. */
bool 
page_create_mmap_page (struct file *fd, off_t offset, off_t len,
                       void *vaddr, bool writable, bool swap)
{
  struct aux_pt_entry *entry = page_create_entry (vaddr);
  if (!entry)
    return false;
 
  entry->type = swap? SWAP_LAZY : MMAP;
  entry->writable = writable;
  entry->mmap_info.fd = file_reopen (fd);
  entry->mmap_info.offset = offset;
  entry->mmap_info.len = len;
  if (entry->mmap_info == NULL)
    {
      free (entry);
      return false;
    }
  return true;
}

/* Write out the mmapped page to its file if it is dirty */
static void
page_possibly_write_mmap (struct aux_pt_entry *entry)
{
  if (entry->type == MMAP && entry->writable && 
      pagedir_is_dirty (entry->pd, entry->user_addr))
    {
      void *kaddr = frame_get_kernel_addr (entry->frame);
      lock_acquire (&fs_lock);
      file_write_at (entry->mmap_info.fd, kaddr, 
        entry->mmap_info.len,  entry->mmap_info.offset);
      lock_release (&fs_lock);
    }
}

/* Perform the necessary housekeeping in order to free a page.
   Will handle cleaning up its mmap file or swap space.
   If it is resident, the frame will be freed. 
   Takes the list_elem from a thread's page_list. */
void
page_free_page (struct list_elem *elem)
{
  struct aux_pt_entry *entry = list_entry (elem, struct aux_pt_entry, thread_pages_elem);

  list_remove (elem);
  lock_acquire (&aux_pt_lock);
  hash_delete (&aux_pt, &entry->elem);
  lock_release (&aux_pt_lock);
  bool pinned = false;

  if (entry->frame != FRAME_INVALID) 
    {
      frame_pin (entry->frame);
      if (page_is_resident (entry))
        {
          page_possibly_write_mmap (entry);
          frame_release_frame (entry->frame);
        }
      else
        {
          pinned = true;
          if (entry->type == SWAP)
            swap_clear (entry->swap_info);
        }
    }

  if (entry->type == MMAP || (entry->type == SWAP_LAZY && entry->mmap_info.fd)) 
    {
      lock_acquire (&fs_lock);
      file_close (entry->mmap_info.fd);
      lock_release (&fs_lock);
    }

  if(pinned)
    frame_unpin (entry->frame);

  free (entry);
}

/* Frees `count` pages starting at start_vaddr
   using page_free_page. Properly skips already freed pages. 
   Returns true if no pages were skipped, false otherwise. */

bool 
page_free_range (void *start_vaddr, unsigned count)
{
  int8_t *start = start_vaddr;
  int i;
  for (i = (int) count - 1; i >= 0; --i)
    {
      void *vaddr = start + i * PGSIZE;
      struct aux_pt_entry *entry = page_lookup_current (vaddr);
      if (!entry)
        return false;
      page_free_page (&entry->thread_pages_elem);
    }
  return true;
}

/* Returns true if the page exists in the aux_pt, false otherwise */
bool 
page_exists (void *vaddr, uint32_t *pd)
{
  return page_lookup_entry (vaddr, pd) != NULL;
}

/* Returns true if the page specified by (vaddr, pd) is marked as
   writable in the aux pt */
bool
page_writable (void *vaddr, uint32_t *pd)
{
  return page_lookup_entry (vaddr, pd)->writable;
}

/* Attempts to page in the page located at `vaddr` for the 
   current thread. 
   It is incorrect to page_in a resident page.
   The page is not pinned.
   Returns false if it cannot page_in_and_pin it, true otherwise. */
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
   pinned externally. This operation will not release the pin on
   the corresponding page. 
   The eviction strategy is chosen according to `page_type`
   It is incorrect to page_out a non-resident page. */
void 
page_out (void *vaddr, uint32_t *pd)
{
  struct aux_pt_entry *entry = page_lookup_entry (vaddr, pd);
  ASSERT (entry->frame != FRAME_INVALID);

  if (!page_is_resident (entry)) {
    PANIC ("attempt to page out non-resident page");
    frame_unpin (entry->frame);
    return;
  }
  
  pagedir_clear_page (entry->pd, entry->user_addr);
  if (entry->type == SWAP)
    {
      void *frame_addr = frame_get_kernel_addr (entry->frame);
      entry->swap_info = swap_write (frame_addr, PGSIZE);
    } 
  else 
    { // mmap
      page_possibly_write_mmap (entry);
    }
}

/* Pages in the page specified by user_vaddr and the current thread's
   pd. The page will be pinned at the point of return.
   If the page does not exist in the aux_pt then false is returned.
*/
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

/* Release the pin on a page specified by user_vaddr in the current 
   thread. */
void page_unpin (void *user_vaddr)
{
  struct aux_pt_entry *entry = page_lookup_current (user_vaddr);
  ASSERT (entry->frame != FRAME_INVALID);
  frame_unpin (entry->frame);
}

/* Helper function for loading an mmap'd page from its backing file.
   Entry corresponds to the page's aux_pt entry and frame_addr is a
   kernel virtual address to load the data into. */
static void 
page_in_mmap (struct aux_pt_entry *entry, void *frame_addr)
{
  lock_acquire (&fs_lock);
  off_t bytes = file_read_at (entry->mmap_info.fd, frame_addr,
    entry->mmap_info.len, entry->mmap_info.offset);
  lock_release (&fs_lock);
  memset ((int8_t *)frame_addr + bytes, 0, PGSIZE - bytes);
}

/* Given an aux_pt entry and a frame_id, load `entry` into `new_frame`
   according to its eviction strategy. */
static void 
page_setup_contents (struct aux_pt_entry *entry, frame_id new_frame)
{
  void *frame_addr = frame_get_kernel_addr (new_frame);
  bool first_load = (entry->frame == FRAME_INVALID);
  if (entry->type == SWAP_LAZY)
    {
      if (!entry->mmap_info.fd)
        memset (frame_addr, 0, PGSIZE);
      else
        {
          page_in_mmap (entry, frame_addr);
          lock_acquire (&fs_lock);
          file_close (entry->mmap_info.fd);
          lock_release (&fs_lock);
        }

      entry->type = SWAP;
    }

  else 
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
      case MMAP:
        page_in_mmap (entry, frame_addr);
        break;
      default:
        PANIC ("unrecognized page type %d", entry->type);
      }
}

/* Hash function for the aux_pt hash table.
   Hashes the page_no of the given hash_elem's user_addr. */
static unsigned 
hash_address (const struct hash_elem *e, void *aux UNUSED)
{
  return hash_int (pg_no (hash_entry (e, struct aux_pt_entry, elem)->user_addr));
}

/* Less function for the aux_pt hash table.
   Compares lexicographically on (pd, uvaddr) */
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

/* Constructor for an aux_pt_entry for user `vaddr` in the
   current thread. NULL is returned if the vaddr's page already
   has an entry or if malloc fails. */

static struct aux_pt_entry *
page_create_entry (void *vaddr)
{
  if (page_lookup_current (vaddr))
    return NULL;

  struct aux_pt_entry *record = malloc(sizeof (struct aux_pt_entry));
  if (record)
    {
      record->pd = thread_current ()->pagedir;
      record->user_addr = vaddr;
      lock_acquire (&aux_pt_lock);
      hash_insert (&aux_pt, &record->elem); 
      lock_release (&aux_pt_lock);
      list_push_front (&thread_current ()->pages_list, &record->thread_pages_elem);
      record->frame = FRAME_INVALID;
    }
  return record;
}

/* Look up the aux_pt_entry for `user_vaddr` and `pd`.
   Null if the address is not found in our aux_pt. */
struct aux_pt_entry *
page_lookup_entry (void *user_vaddr, uint32_t *pd)
{
  struct aux_pt_entry query = { .user_addr = user_vaddr, .pd = pd };
  
  lock_acquire (&aux_pt_lock);
  struct hash_elem *result = hash_find(&aux_pt, &query.elem);
  lock_release (&aux_pt_lock);
  if (result != NULL)
    return hash_entry (result, struct aux_pt_entry, elem);
  else
    return NULL;
}

/* Like page_lookup_entry except it assumes the pd of the current thread. */
struct aux_pt_entry *
page_lookup_current (void *user_vaddr)
{
  return page_lookup_entry (user_vaddr, thread_current ()->pagedir);
}

/* Returns true if the MMU's pagetable has the PTE_P bit set to 1 
   for the user_addr, pd combo in `entry`. */
static bool 
page_is_resident (struct aux_pt_entry *entry)
{
  return pagedir_get_page (entry->pd, entry->user_addr) != NULL;
}

