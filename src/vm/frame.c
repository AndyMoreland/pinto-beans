#include <debug.h>
#include <list.h>
#include <threads/synch.h>
#include <threads/palloc.h>
#include <threads/malloc.h>
#include <userprog/pagedir.h>
#include <stdio.h>
#include "frame.h"
#include "page.h"

/* Data that we store about each physical frame. */
struct frame_table_entry
  {
    void *frame_addr; /* Kernel virtual address of frame. */
    void *user_addr;  /* User vaddr of page stored in frame. */
    uint32_t *pd;     /* User pd for page stored in frame. */
    struct lock pin_lock; /* Pin lock which is a monitor 
                             for resident page & this frame. */
    struct list_elem elem; /* elem for the frame table or free list. */
    bool is_dying;        /* If we are in the process of freeing this frame. */
  };

/* Pointer to the "clock hand" position in the frame_table list. */
static struct frame_table_entry *clock_hand;
/* Allocated frames are stored in this list. */
static struct list frame_table;
/* Freed frames are stored in this list. */
static struct list free_list;
/* Protects the frame_table and the free_list */
static struct lock frame_table_lock;

static struct frame_table_entry *frame_entry (frame_id id);
static struct frame_table_entry *frame_create_entry (void *vaddr, uint32_t *pd, void *frame);
static void advance_clock_hand (void);
static struct frame_table_entry *clock_evict (void);

void frame_unpin (frame_id frame);

/* Initialize lists and locks. */
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

/* External API. Finds a frame for the page at (user_vaddr, pd).
   Returns a casted pointer to the frame_table entry for the frame. 
   Panics if it is unable to find space anywhere. */
frame_id
frame_get_frame_pinned (void *user_vaddr, uint32_t *pd)
{
  struct frame_table_entry *entry;
  void *frame = palloc_get_page (PAL_USER);
  if (frame) {
    entry = frame_create_entry (user_vaddr, pd, frame);
    lock_acquire (&frame_table_lock);
    // Make sure that the clock hand always points somewhere
    // if there is something in the allocated list.
    if (!clock_hand)
      clock_hand = entry;
    lock_release (&frame_table_lock);
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

/* Given a frame_id it returns the kernel addr of 
   the physical frame. */
void *
frame_get_kernel_addr (frame_id frame) 
{
  if (frame == FRAME_INVALID)
    return NULL;
  return frame_entry (frame)->frame_addr;
}

/* Pin the frame. */
void 
frame_pin (frame_id frame)
{
  lock_acquire (&frame_entry (frame)->pin_lock);
}   

/* Unpin the frame. */
void 
frame_unpin (frame_id frame)
{
  lock_release (&frame_entry (frame)->pin_lock);
}

/* Called when a page is being cleaned up. This
   puts the frame in the free list. It is assumed that
   the frame is pinned externally. */
void
frame_release_frame (frame_id frame)
{
  ASSERT (frame);
  struct frame_table_entry *entry = frame_entry (frame);
  entry->is_dying = true;
  // We have to unpin here in order to avoid deadlock.
  // We usually acquire frame_table_lock and then pin_lock
  // If we don't unpin then we'd have a potential for a bad interleaving.
  frame_unpin (frame);
  lock_acquire (&frame_table_lock);
  entry->is_dying = false;
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
  lock_release (&frame_table_lock);
}

/* Given a frame_id we return the associated frame_table_entry. 
   This method is used in order to permit more layers of indirection
   if desired. */
static struct frame_table_entry *
frame_entry (frame_id id)
{
  return (struct frame_table_entry *)id;
}

/* Constructor for a frame_table_entry for `uvaddr`, `pd` and a 
   kernel vaddr `frame`. 
   The frame is returned pinned. */
static struct frame_table_entry *
frame_create_entry (void *vaddr, uint32_t *pd, void *frame)
{
  struct frame_table_entry *entry = malloc (sizeof (struct frame_table_entry));
  entry->frame_addr = frame;
  entry->user_addr = vaddr;
  entry->pd = pd;
  entry->is_dying = false;
  lock_init (&entry->pin_lock);
  lock_acquire (&entry->pin_lock);
  lock_acquire (&frame_table_lock);
  list_push_back (&frame_table, &entry->elem);
  lock_release (&frame_table_lock);
  
  // don't release pin; responsible for releasing externally
  return entry;
}

/* Attempts to acquire the pin lock on `entry`. If it succeeds it will
   check the dirty bit on the resident page. If that is 0, it will evict
   the page and return "true". Else, false. */
static bool
frame_try_evict (struct frame_table_entry *entry)
{
  if (!lock_try_acquire (&entry->pin_lock))
    return false;
  else if (!entry->is_dying && !pagedir_is_accessed (entry->pd, entry->user_addr))
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

/* Run our clock eviction algorithm on frame_table list.
   Iterates until we find somethign to free. 
   Returns NULL if we loop around twice and nothing is evicted. */
static struct frame_table_entry * 
clock_evict (void)
{
  lock_acquire (&frame_table_lock);
  struct frame_table_entry *entry;
  // If we find something in the free list we can just return that.
  if (!list_empty (&free_list))
    {
      entry = list_entry (list_begin (&free_list), struct frame_table_entry, elem);
      lock_acquire (&entry->pin_lock);
      list_remove (&entry->elem);
      list_push_back (&frame_table, &entry->elem);
    }
  else if (!clock_hand)
    // something has gone terribly wrong -- there is nothing in the free list,
    // there is nothing to palloc and there is nothing in the frame_table.
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

/* Advance the clock hand. Assumes that the frame table is externally locked. */
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
