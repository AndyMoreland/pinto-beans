#ifndef SWAP_H_
#define SWAP_H_

#include <inttypes.h>
#include <devices/block.h>

#define SWAP_MAX_SECTORS 8
typedef block_sector_t swap_descriptor;

void swap_init (void);
swap_descriptor swap_write (const void *frame_start, size_t frame_size);
size_t swap_read (void *frame_start, swap_descriptor sd, size_t frame_size);
void swap_clear (swap_descriptor sd);

#endif

