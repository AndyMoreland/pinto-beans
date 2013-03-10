
#ifndef CACHE_H_
#define CACHE_H_

void cache_init (int size);
void cache_read (block_sector_t, void *);
void cache_write (block_sector_t, const void *);
void cache_readahead (block_sector_t);

void *cache_begin (block_sector_t);
void cache_end (void *cache_block, bool dirty);

void cache_flush_all (void);

#endif
