#ifndef FILESYS_CACHE_H
#define FILESYS_CACHE_H

#include "devices/block.h"
void cache_init(void);
void cache_clear(void);
void cache_write(block_sector_t, int, void *, int);
void cache_read(block_sector_t, int, void *, int);
void cache_set_zero(block_sector_t);

#endif