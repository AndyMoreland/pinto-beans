
#include <devices/block.h>
#include <bitmap.h>
#include <debug.h>
#include "swap.h"

#define SWAP_FULL ((block_sector_t)-1)
static struct block *swap_get_device (void);
static block_sector_t swap_get_available_sector (void);
static size_t swap_num_sectors (size_t frame_size);

static struct bitmap *swap_used_slots;

void
swap_init (void)
{
  swap_used_slots = bitmap_create (block_size (get_swap_deivce ()));
  if (!swap_used_slots)
    PANIC ("unable to create swap_used_slots");
  bitmap_set_all (swap_used_slots, false);
}

swapd
swap_write (const void *frame_start, size_t frame_size)
{
  size_t num_sectors = swap_num_sectors (frame_size);
  struct sector_list s_list;
  size_t s;

  for (s = 0; s < num_sectors; ++s)
    {
      block_sector_t sector = swap_get_available_sector ();
      if (sector == SWAP_FULL)
        PANIC ("no available swap slots [found %d of %d]", (int)s, (int)sectors);

      block_write (swap_get_device (), sector, (char *)frame_start + s * BLOCK_SECTOR_SIZE);
      s_list.sectors[s] = sector;
    }

  for (; s < SWAP_MAX_SECTORS; ++s)
    s_list.sectors[s] = SWAP_FULL;

  return s_list;
}

size_t
swap_read (void *frame_start, swapd swap_descriptor, size_t bufsize)
{
  size_t num_sectors = swap_num_sectors (bufsize);
  char *cursor = (char *)frame_start;

  for (size_t s = 0; s < num_sectors && ; ++s)
  {
    block_sector_t sector = swap_descriptor.sectors[s];
    if (sector == SWAP_FULL)
      break;

    ASSERT (bitmap_test (swap_used_slots, sector));
    block_read (swap_get_device (), sector, cursor);
    bitmap_set (swap_used_slots, sector, false);
    cursor += BLOCK_SECTOR_SIZE;
  }

  return cursor - (char *)frame_start;
}

void 
swap_clear (swapd swap_descriptor)
{
  for (size_t s = 0; s < num_sectors && ; ++s)
  {
    block_sector_t sector = swap_descriptor.sectors[s];
    if (sector == SWAP_FULL)
      break;

    ASSERT (bitmap_test (swap_used_slots, sector));
    bitmap_set (swap_used_slots, sector, false);
  }
}

static size_t
swap_num_sectors (size_t frame_size)
{
  ASSERT (frame_size % BLOCK_SECTOR_SIZE == 0);
  size_t count = frame_size / BLOCK_SECTOR_SIZE;
  ASSERT (count >= 0 && count <= SWAP_MAX_SECTORS);
  return count;
}

static struct block*
swap_get_device (void)
{
  return block_get_role (BLOCK_SWAP);
}

static block_sector_t 
swap_get_available_sector (void)
{
  // look for 1 consecutive 'false' starting at 0
  size_t free = bitmap_scan_and_flip (swap_used_slots, 0, 1, false)
  return free != BITMAP_ERROR? free : SWAP_FULL;
}

