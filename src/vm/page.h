
#ifndef PAGE_H_
#define PAGE_H_

#include <filesys/file.h>
#include <inttypes.h>

void page_init (void);
bool page_create_swap_page (void *vaddr, bool zeroed, bool writable);
void page_free_page (struct list_elem *elem);
bool page_create_mmap_page (struct file *fd, off_t offset, off_t len,
                            void *vaddr, bool writable, bool swap);
bool page_free_range (void *start_vaddr, unsigned count);
bool page_exists (void *vaddr, uint32_t *pd);
bool page_in (void *vaddr);
void page_out (void *vaddr, uint32_t *pd);
bool page_in_and_pin (void *user_vaddr);
void page_unpin (void *user_vaddr);

#endif
