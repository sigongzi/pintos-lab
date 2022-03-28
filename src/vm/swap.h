#ifndef SWAP_SLOT
#define SWAP_SLOT


#include <stdint.h>
#include <stdbool.h>

void swap_slot_init(void);
uint32_t save_page_to_block(void *); /* return sector number */
void copy_page_from_block(void *, uint32_t);
void clear_page_in_block(uint32_t);

#endif