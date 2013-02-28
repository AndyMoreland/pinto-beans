
#ifndef FRAME_H_
#define FRAME_H_

struct frame_reference {
  void *user_vaddr;
  uint32_t *user_pagedir;
};

void frame_init (void);
void *frame_create_frame (void *user_vaddr, uint32_t *pd);
void frame_clear_frame (void *frame_addr);

#endif
