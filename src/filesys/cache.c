#include "filesys/cache.h"
#include "filesys/filesys.h"
#include "devices/block.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include <string.h>
#include <stdlib.h>
#include <debug.h>
#define CACHE_COUNT 64

static char cache_buffer[CACHE_COUNT * BLOCK_SECTOR_SIZE];
static const uint32_t CACHE_P = 0x1;
static const uint32_t CACHE_D = 0x2;
static const uint32_t CACHE_A = 0x4;
static const uint32_t CACHE_PIN = 0x8;
struct cache_node {
    uint32_t flag;
    block_sector_t sector_idx;
    void *buf;
};

struct lock cache_lock;
struct cache_node cache_info[CACHE_COUNT];

static uint32_t fetch_pos(void);
static void evict_sector(struct cache_node *);
static struct cache_node* find_sector(block_sector_t);

static void evict_sector(struct cache_node *info_node) {
    if (info_node->flag & CACHE_P) {
        if (info_node->flag & CACHE_D) {
            block_write(fs_device, info_node->sector_idx, info_node->buf);
        }
    }

    info_node->flag = 0;
    info_node->sector_idx = 0;
}

// must be called with cache lock
static uint32_t fetch_pos() {
    static uint32_t pos = 0;
    while (true) {
        uint32_t f = cache_info[pos].flag;
        if ((!(f & CACHE_P)) ||
         ((!(f & CACHE_A)) && (!(f & CACHE_PIN))) ) {
            evict_sector(&cache_info[pos]);
            uint32_t res = pos;
            pos = (pos + 1) & (CACHE_COUNT - 1);
            return res;
        }
        if (f & CACHE_A)
            cache_info[pos].flag ^= CACHE_A;
        pos = (pos + 1) & (CACHE_COUNT - 1);
    }
}

static struct cache_node* find_sector(block_sector_t sector_idx) {
    for (int i = 0 ; i < CACHE_COUNT ; ++i) {
        if ((cache_info[i].flag & CACHE_P) && cache_info[i].sector_idx == sector_idx) {
            return &cache_info[i]; 
        }
    }
    uint32_t t = fetch_pos();
    cache_info[t].flag = CACHE_P;
    cache_info[t].sector_idx = sector_idx;
    block_read(fs_device, sector_idx, cache_info[t].buf);
    return &cache_info[t];
}

void cache_init() {
    lock_init(&cache_lock);
    for (int i = 0 ; i < CACHE_COUNT ; ++i) {
        cache_info[i].flag = 0;
        cache_info[i].sector_idx = 0;
        cache_info[i].buf = cache_buffer + i * BLOCK_SECTOR_SIZE;
    }
}

void cache_clear() {
    lock_acquire(&cache_lock);
    for (int i = 0 ; i < CACHE_COUNT ; ++i) {
        evict_sector(&cache_info[i]);
    }
    lock_release(&cache_lock);
}

void cache_write(block_sector_t sector_idx, int sector_ofs, void *buffer, int size) {
    ASSERT(sector_ofs + size <= BLOCK_SECTOR_SIZE);

    lock_acquire(&cache_lock);
    struct cache_node *cn = find_sector(sector_idx);
    cn->flag |= CACHE_PIN;
    lock_release(&cache_lock);
    cn->flag |= CACHE_A | CACHE_D;
    memcpy(cn->buf + sector_ofs, buffer, size);
    cn->flag ^= CACHE_PIN;
    if (sector_idx + 1 < block_size(fs_device)) {
        lock_acquire(&cache_lock);
        cn = find_sector(sector_idx + 1); // fetch next sector
        lock_release(&cache_lock);
    }

}
void cache_read(block_sector_t sector_idx, int sector_ofs, void * buffer, int size) {
    ASSERT(sector_ofs + size <= BLOCK_SECTOR_SIZE);
    lock_acquire(&cache_lock);
    struct cache_node *cn = find_sector(sector_idx);
    cn->flag |= CACHE_PIN;
    lock_release(&cache_lock);
    cn->flag |= CACHE_A;
    memcpy(buffer, cn->buf + sector_ofs, size);
    cn->flag ^= CACHE_PIN;
    if (sector_idx + 1 < block_size(fs_device)) {
        lock_acquire(&cache_lock);
        cn = find_sector(sector_idx + 1); // fetch next sector
        lock_release(&cache_lock);
    }
}

void cache_set_zero(block_sector_t sector_idx) {
    static char zero[BLOCK_SECTOR_SIZE];
    cache_write(sector_idx, 0, zero, BLOCK_SECTOR_SIZE);
}