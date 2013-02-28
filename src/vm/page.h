
#ifndef PAGE_H_
#define PAGE_H_

bool page_create_page (void *vaddr, bool zeroed, bool writable);
void page_free_page (void *vaddr);
void page_in (void *vaddr);
void page_out (void *vaddr);

#endif
