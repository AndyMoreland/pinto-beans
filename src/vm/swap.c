
#include <devices/block.h>
#include <bitmap.h>
#include <debug.h>
#include <threads/synch.h>
#include "swap.h"
/* FIXME: remove these */
#include <stdio.h>
#include <threads/thread.h>

#define SWAP_FULL ((block_sector_t)-1)
#define NO_SWAP SWAP_FULL

static struct block *swap_get_device (void);
static block_sector_t swap_get_available_sectors (size_t count);
static size_t swap_num_sectors (size_t frame_size);

static struct bitmap *swap_used_slots;
static struct lock swap_used_slots_lock;

void
swap_init (void)
{
  swap_used_slots = bitmap_create (block_size (swap_get_device ()));
  lock_init (&swap_used_slots_lock);
  if (!swap_used_slots)
    PANIC ("unable to create swap_used_slots");
  bitmap_set_all (swap_used_slots, false);
}

swap_descriptor
swap_write (const void *frame_start, size_t frame_size)
{
  size_t num_sectors = swap_num_sectors (frame_size);
  size_t swap_start = swap_get_available_sectors (SWAP_MAX_SECTORS);

  if (swap_start == SWAP_FULL)  
    PANIC ("no available swap slots");

  size_t s;
  for (s = 0; s < num_sectors; ++s)
    {
      block_write (swap_get_device (), swap_start + s, (char *)frame_start + s * BLOCK_SECTOR_SIZE);
    }

  return (swap_descriptor) swap_start;
}

/* Reads a page worth of swap sectors starting at sd into frame_start.
   Also marks these sectors as free. */
size_t
swap_read (void *frame_start, swap_descriptor sd, size_t bufsize)
{
  size_t num_sectors = swap_num_sectors (bufsize);
  block_sector_t swap_start = sd;

  ASSERT (num_sectors == SWAP_MAX_SECTORS);
  lock_acquire (&swap_used_slots_lock);
  ASSERT (bitmap_all (swap_used_slots, swap_start, num_sectors));
  lock_release (&swap_used_slots_lock);

  char *cursor = (char *)frame_start;

  size_t s;
  for (s = 0; s < num_sectors; ++s)
    {
      block_read (swap_get_device (), swap_start + s, cursor);
      cursor += BLOCK_SECTOR_SIZE;
    }

  lock_acquire (&swap_used_slots_lock);
  bitmap_set_multiple (swap_used_slots, swap_start, num_sectors, false);
  lock_release (&swap_used_slots_lock);

  return cursor - (char *)frame_start;
}

void 
swap_clear (swap_descriptor sd)
{
  lock_acquire (&swap_used_slots_lock);
  ASSERT (bitmap_all (swap_used_slots, sd, SWAP_MAX_SECTORS));
  bitmap_set_multiple (swap_used_slots, sd, SWAP_MAX_SECTORS, false);
  lock_release (&swap_used_slots_lock);
}

static size_t
swap_num_sectors (size_t frame_size)
{
  ASSERT (frame_size % BLOCK_SECTOR_SIZE == 0);
  size_t count = frame_size / BLOCK_SECTOR_SIZE;
  ASSERT (count <= SWAP_MAX_SECTORS);
  return count;
}

static struct block*
swap_get_device (void)
{
  return block_get_role (BLOCK_SWAP);
}

static block_sector_t 
swap_get_available_sectors (size_t count)
{
  // look for 1 consecutive 'false' starting at 0
  lock_acquire (&swap_used_slots_lock);
  size_t free = bitmap_scan_and_flip (swap_used_slots, 0, count, false);
  lock_release (&swap_used_slots_lock);
  return free != BITMAP_ERROR? free : SWAP_FULL;
}

