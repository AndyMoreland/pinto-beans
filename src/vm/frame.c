/* Need to be able to get an address of a frame that we can write to.
   Should evict a frame if it needs to.
   Need to know what "evicting" means.
   If the page was read only then eviction just means doing nothing.
   Otherwise we need to write it back to its file or to swap.
*/

/* In order to work we need to store our kernel address.
   We also need to store our user address for our evcition. */

#include <debug.h>
#include <list.h>
#include <threads/synch.h>
#include <threads/palloc.h>
#include <threads/malloc.h>
#include <userprog/pagedir.h>
#include <stdio.h>
#include "frame.h"
#include "page.h"

struct frame_table_entry
  {
    void *frame_addr;
    void *user_addr;
    uint32_t *pd;
    struct lock pin_lock;
    struct list_elem elem;
  };

static struct frame_table_entry *clock_hand;
static struct list frame_table;
static struct lock frame_table_lock;
static struct list free_list;

static struct frame_table_entry *frame_entry (frame_id id);
static struct frame_table_entry *frame_create_entry (void *vaddr, uint32_t *pd, void *frame);
static void advance_clock_hand (void);
static struct frame_table_entry *clock_evict (void);

void frame_unpin (frame_id frame);

void frame_init (size_t num_user_pages UNUSED)
{
  clock_hand = NULL;
  list_init (&frame_table);
  list_init (&free_list);
  lock_init (&frame_table_lock);
}

void frame_pin (frame_id frame);
void frame_unpin (frame_id frame);
void frame_release_frame (frame_id frame);

frame_id
frame_get_frame_pinned (void *user_vaddr, uint32_t *pd)
{
  struct frame_table_entry *entry;
  void *frame = palloc_get_page (PAL_USER);
  if (frame) {
    entry = frame_create_entry (user_vaddr, pd, frame);
    if (!clock_hand)
      clock_hand = entry;
  } else {
    // try to swap
    entry = clock_evict ();
    if (!entry)
      PANIC ("no available pages");
    entry->user_addr = user_vaddr;
    entry->pd = pd;
  }

  return entry;
}

void *
frame_get_kernel_addr (frame_id frame) 
{
  if (frame == FRAME_INVALID)
    return NULL;
  return frame_entry (frame)->frame_addr;
}

void 
frame_pin (frame_id frame)
{
  lock_acquire (&frame_entry (frame)->pin_lock);
}

void 
frame_unpin (frame_id frame)
{
  lock_release (&frame_entry (frame)->pin_lock);
}

void
frame_release_frame (frame_id frame)
{
  ASSERT (frame);
  struct frame_table_entry *entry = frame_entry (frame);
  lock_acquire (&frame_table_lock);
  if (clock_hand == entry)
    {
      advance_clock_hand ();
      // if we didn't move, list will be empty after free
      if (clock_hand == entry)
        clock_hand = NULL;
    }
  list_remove (&entry->elem);
  pagedir_clear_page (entry->pd, entry->user_addr);
  list_push_front (&free_list, &entry->elem);
  lock_release (&entry->pin_lock);
  lock_release (&frame_table_lock);
}

static struct frame_table_entry *
frame_entry (frame_id id)
{
  return (struct frame_table_entry *)id;
}

static struct frame_table_entry *
frame_create_entry (void *vaddr, uint32_t *pd, void *frame)
{
  struct frame_table_entry *entry = malloc (sizeof (struct frame_table_entry));
  entry->frame_addr = frame;
  entry->user_addr = vaddr;
  entry->pd = pd;
  lock_init (&entry->pin_lock);
  lock_acquire (&entry->pin_lock);

  lock_acquire (&frame_table_lock);
  list_push_back (&frame_table, &entry->elem);
  lock_release (&frame_table_lock);
  
  // don't release pin; responsible for releasing externally
  return entry;
}

static bool
frame_try_evict (struct frame_table_entry *entry)
{
  if (!lock_try_acquire (&entry->pin_lock))
    return false;
  else if (!pagedir_is_accessed (entry->pd, entry->user_addr))
    {
      page_out (entry->user_addr, entry->pd);
      return true;
    }
  else 
    {
      pagedir_set_accessed (entry->pd, entry->user_addr, false);
      lock_release (&entry->pin_lock);
      return false;
    }
}

static struct frame_table_entry * 
clock_evict (void)
{
  lock_acquire (&frame_table_lock);
  struct frame_table_entry *entry;
  if (!list_empty (&free_list))
    {
      entry = list_entry (list_begin (&free_list), struct frame_table_entry, elem);
      lock_acquire (&entry->pin_lock);
      list_remove (&entry->elem);
      list_push_back (&frame_table, &entry->elem);
    }
  else if (!clock_hand)   
    entry = NULL;
  else
    {
      struct frame_table_entry *start = clock_hand;
      int loop_attempts = 0;
      while (!frame_try_evict (clock_hand))
        {
          advance_clock_hand ();
          if (clock_hand == start)
            {
              ++loop_attempts;
              if (loop_attempts == 2)
                {
                  lock_release (&frame_table_lock);
                  return NULL;
                }
            }
        }
      entry = clock_hand;
      advance_clock_hand ();
    }

  lock_release (&frame_table_lock);
  return entry;
}

static void 
advance_clock_hand (void)
{
  if (list_empty (&frame_table))
    clock_hand = NULL;
  else 
    {
      clock_hand = list_entry (list_next (&clock_hand->elem),
        struct frame_table_entry, elem);
        
      if (&clock_hand->elem == list_end (&frame_table))
        clock_hand = list_entry (list_begin (&frame_table),
          struct frame_table_entry, elem);
    }
}
