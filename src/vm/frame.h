#ifndef FRAME_TABLE
#define FRAME_TABLE

#include <hash.h>
#include <debug.h>
#include <stdint.h>
#include "threads/thread.h"


struct frame_page {
    struct hash_elem hash_elem;
    uintptr_t addr;
    struct thread* t;
    void *vaddr;
};

void frame_init(void);
void *frame_get_page(void *);
void *frame_save_page(uint32_t *);
unsigned
page_hash (const struct hash_elem *p_, void *aux UNUSED);
bool
page_less (const struct hash_elem *a_, const struct hash_elem *b_,
           void *aux UNUSED);
struct frame_page *
frame_page_lookup (const uintptr_t addr);
void frame_add_page(void *uaddr, uintptr_t kaddr);
void frame_remove(void *addr);
void frame_remove_elem(struct hash_elem *hash_elem);
void frame_add_elem(struct hash_elem *hash_elem);
#endif
