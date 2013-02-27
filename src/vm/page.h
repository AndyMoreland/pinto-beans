
#ifndef PAGE_H_
#define PAGE_H_

bool page_create_at (void *vaddr, bool zeroed, bool writable);
bool page_free_page (void *vaddr);
bool page_in (void *vaddr);
bool page_out (void *vaddr);

#endif
