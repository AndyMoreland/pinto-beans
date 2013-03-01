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
#include "frame.h"

struct frame_table_entry
{
  void *frame_addr;
  void *user_addr;
  uint32_t *pd;
  struct lock pin_lock;
  struct list_elem frame_table_elem;
}

static frame_table_entry *clock_hand;
static struct list frame_table;
static struct lock frame_table_lock;

static frame_table_entry *frame_entry (frame_id id);
static frame_table_entry *frame_create_entry (void *vaddr, uint32_t *pd, void *frame);
static void advance_clock_hand (void);

void frame_unpin (frame_id frame);

void frame_init (size_t num_user_pages) 
{
  max_frames = num_user_pages;
  clock_hand = NULL;
  list_init (&frame_table);
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
  } else {
    // try to swap

    if (!frame) 
      PANIC ("no available pages");
  }

  return entry;
}

void *
frame_get_kernel_addr (frame_id frame) 
{
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
  frame_table_entry *entry = frame_entry (frame);
  lock_acquire (&frame_table_lock);
  if (clock_hand == entry)
    {
      advance_clock_hand ();
      // if we didn't move, list will be empty after free
      if (clock_hand == entry)
        clock_hand = NULL;
    }
  list_remove (&entry->frame_table_elem);
  palloc_free_page (entry->frame_addr);
  free (entry);
}

static frame_table_entry *
frame_entry (frame_id id)
{
  return (frame_table_entry *)id;
}

static frame_table_entry *
frame_create_entry (void *vaddr, uint32_t *pd, void *frame)
{
  struct frame_table_entry *entry = malloc (sizeof (struct frame_table_entry));
  entry->frame_addr = frame;
  entry->user_vaddr = vaddr;
  entry->pd = pd;
  lock_init (&entry->pin_lock);
  lock_acquire (&entry->pin_lock);

  lock_acquire (&frame_table_lock);
  list_push_back (&frame_table, &entry->frame_table_elem);
  lock_release (&frame_table_lock);
  
  // don't release pin; responsible for releasing externally
  return entry;
}

