#ifndef SWAP_H_
#define SWAP_H_

#include <inttypes.h>

#define SWAP_MAX_SECTORS 8
struct sector_list 
  {
    uint16_t sectors[SWAP_MAX_SECTORS];
  };
 
typedef struct sector_list swapd;

void swap_init (void);
swapd swap_write (const void *frame_start, size_t frame_size);
size_t swap_read (void *frame_start, swapd swap_descriptor, size_t frame_size);
void swap_clear (swapd swap_descriptor);

#endif

