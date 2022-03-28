#ifndef PAGE_MANAGEMENT
#define PAGE_MANAGEMENT

#include <stdbool.h>
#include <stdint.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

#define SECTOR_SHIFT 9
/* do not use 0x40 used by swap function */
#define PAGE_FILE 0x20
#define PAGE_SWAP 0x10
#define PAGE_LOAD 0x8
#define REAL_WRITE 0x400
#define FLAG_MASK 0x7
#define STACK_ESP 0x200
#define STACK_MAX_GAP 0x1000000
void page_init(void);
bool install_lazy_page(void *, void *,bool ,bool);
bool check_valid(void *, struct intr_frame*);
void clear_content(uint32_t *);
void swap_to_disk(struct thread *,uint32_t *, void *);
void load_from_slot(uint32_t *, void *);
void load_from_file(uint32_t *, void *, void *);
bool is_vm_range_unused(void *, void *);
void map_vm_range(void *, void *, int32_t);

extern struct lock frame_hash_lock;
#endif