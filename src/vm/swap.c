
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "vm/swap.h"
#include "devices/block.h"
#include <bitmap.h>

static struct block *swap_block;
static struct bitmap *slot_bitmap;
static uint32_t sector_for_page;
static struct semaphore slot_sema;
static struct lock slot_lock;

void swap_slot_init() {
    swap_block = block_get_role(BLOCK_SWAP);
    
    slot_bitmap = bitmap_create(block_size(swap_block));
    lock_init(&slot_lock);
    sector_for_page = PGSIZE / BLOCK_SECTOR_SIZE;
    sema_init(&slot_sema, block_size(swap_block) / sector_for_page);
    printf("set block size for %d pages\n", block_size(swap_block) / sector_for_page);
}
uint32_t save_page_to_block(void *vaddr) {
    sema_down(&slot_sema);
    lock_acquire(&slot_lock);
    size_t idx = bitmap_scan_and_flip (slot_bitmap, 0, sector_for_page, 0);
    size_t i = 0;
    if (idx == BITMAP_ERROR) {
        
        lock_release(&slot_lock);
        sema_up(&slot_sema);
        return -1;
    }
    for (i = 0 ; i < sector_for_page ; ++i) {
        block_write(swap_block, idx + i, vaddr + i * BLOCK_SECTOR_SIZE);
    }
    lock_release(&slot_lock);
    return idx;
}
void copy_page_from_block(void *vaddr, uint32_t sector_start) {
    size_t i = 0;
    ASSERT(bitmap_test(slot_bitmap, sector_start));
    lock_acquire(&slot_lock);
    
    bitmap_set_multiple(slot_bitmap, sector_start, sector_for_page, 0);
    for (i = 0 ; i < sector_for_page ; ++i) {
        block_read(swap_block, sector_start + i, vaddr + i * BLOCK_SECTOR_SIZE);
    }
    lock_release(&slot_lock);
    sema_up(&slot_sema);
}

void clear_page_in_block(uint32_t sector_start) {
    lock_acquire(&slot_lock);
    bitmap_set_multiple(slot_bitmap, sector_start, sector_for_page, 0);
    lock_release(&slot_lock);
    sema_up(&slot_sema);
}