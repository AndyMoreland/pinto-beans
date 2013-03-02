
#ifndef PAGE_H_
#define PAGE_H_

#include <inttypes.h>

void *FIXME_page_get_kernel_addr (void *vaddr);

void page_init (void);
bool page_create_page (void *vaddr, bool zeroed, bool writable);
void page_free_page (void *vaddr);
bool page_in (void *vaddr);
void page_out (void *vaddr);
bool page_in_and_pin (void *user_vaddr);
void page_unpin (void *user_vaddr);

#endif
