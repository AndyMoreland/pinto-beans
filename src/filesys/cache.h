
#ifndef CACHE_H_
#define CACHE_H_

void cache_init (int size);
void cache_read (enum block_type, block_sector_t, void *);
void cache_write (enum block_type, block_sector_t, const void *);

#endif
