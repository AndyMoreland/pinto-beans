
#ifndef PAGE_H_
#define PAGE_H_

#include <filesys/file.h>
#include <inttypes.h>

void *FIXME_page_get_kernel_addr (void *vaddr);

void page_init (void);
bool page_create_swap_page (void *vaddr, bool zeroed, bool writable);
void page_free_page (struct list_elem *elem);
uint32_t page_create_mmap_pages (struct file *fd, void *vaddr, bool writable);
bool page_munmap_pages (uint32_t mmapid);
bool page_exists (void *vaddr, uint32_t *pd);
bool page_writable (void *vaddr, uint32_t *pd);
bool page_in (void *vaddr);
void page_out (void *vaddr, uint32_t *pd);
bool page_in_and_pin (void *user_vaddr);
void page_unpin (void *user_vaddr);

#endif
