
#ifndef FRAME_H_
#define FRAME_H_

#include <inttypes.h>

#define FRAME_INVALID NULL
typedef void *frame_id;

void frame_init (size_t num_user_pages);
frame_id frame_get_frame_pinned (void *user_vaddr, uint32_t *pd);
void *frame_get_kernel_addr (frame_id frame);
void frame_pin (frame_id frame);
void frame_unpin (frame_id frame);
void frame_release_frame (frame_id frame);

#endif
