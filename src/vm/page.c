#include "vm/swap.h"
#include "vm/frame.h" 
#include "vm/page.h"
#include "userprog/pagedir.h"
#include "userprog/exception.h"
#include "userprog/process.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/pte.h"
#include "threads/vaddr.h"
#include "threads/interrupt.h"
static void *zero_page;
static void make_pte_slot(uint32_t *, uint32_t);
static void make_pte_memory(uint32_t *, uintptr_t);
static void make_pte_file(uint32_t *, int32_t);
static void *get_memory_addr(uint32_t *);
static uint32_t get_slot_idx(uint32_t *);
static int get_mapid(uint32_t *);
static struct lock page_lock;

static void make_pte_slot(uint32_t *pte, uint32_t sector_start) {
    *pte = (*pte) & (FLAG_MASK ^ PTE_P);
    *pte = (*pte) | PAGE_LOAD;
    *pte = (*pte) | PAGE_SWAP;
    *pte = (*pte) | (sector_start << SECTOR_SHIFT);
}

static void make_pte_memory(uint32_t *pte, uintptr_t addr) {
    *pte = (*pte) | addr;
}

static void make_pte_file(uint32_t *pte, int32_t mapid) {
    *pte = (*pte) & (FLAG_MASK ^ PTE_P);
    *pte = (*pte) | PAGE_LOAD;
    *pte = (*pte) | PAGE_FILE;
    *pte = (*pte) | (mapid << SECTOR_SHIFT);
}
static void *get_memory_addr(uint32_t *pte) {
    return ptov((*pte) & (~(PGSIZE - 1)));
}

static uint32_t get_slot_idx(uint32_t *pte) {
    return ((*pte) >> SECTOR_SHIFT) & SECTOR_MASK;
}

static int get_mapid(uint32_t *pte) {
    return ((*pte) >> SECTOR_SHIFT) & SECTOR_MASK;
}

void page_init() {
    swap_slot_init();
    frame_init();
    
    zero_page = palloc_get_page(PAL_ZERO | PAL_ASSERT);
    lock_init(&page_lock);

}

bool install_lazy_page(void *kaddr, void *uaddr, bool writable, bool zero) {
    struct thread *t = thread_current();

    uint32_t *pte = lookup_page(t->pagedir, uaddr, 1);
    *pte = PTE_U;
    if (zero) {
        if (writable) *pte |= REAL_WRITE;
        *pte = (*pte) | (vtop(zero_page) & (~(PGSIZE - 1)));
        *pte = (*pte) | PTE_P;
        return true;    
    }
    ASSERT(!(vtop(kaddr) & (PGSIZE - 1)));

    

    uint32_t sector_start = save_page_to_block(kaddr);

    if (sector_start == -1) return false;

    if (writable) *pte = (*pte) | PTE_W;
    
    make_pte_slot(pte, sector_start);
    return true;
}

bool check_valid(void *addr, struct intr_frame *f) {
    lock_acquire(&page_lock);
    struct thread *t = thread_current();
    uint32_t *pte;
    void *kpage;
    void *alloc_addr = pg_round_down(addr);
    lock_acquire(&t->pgtbl_lock);
    pte = lookup_page(t->pagedir, alloc_addr, 0);
    lock_release(&t->pgtbl_lock);

    bool not_present = (f->error_code & PF_P) == 0;
    //printf("page fault for %x for thread %s with id %d\n", addr, t->name, t->tid);
    //printf("user command: %x\n", (uint32_t)f->eip);
    if ((uint32_t)f->eip < (uint32_t)PHYS_BASE) {
        if (f->esp < t->sp_top) {
            if ((t->sp_top - f->esp) > STACK_MAX_GAP) {
                lock_release(&page_lock);
                return false;
            }
        }
        
        t->sp_top = f->esp;
        if ((uint32_t)t->sp_top < (uint32_t)t->old_top) {
            t->old_top = t->sp_top;
        }
    }

    if ((uint32_t)addr >= (uint32_t)t->old_top && 
        (uint32_t)addr < (uint32_t)(t->sp_top - STACK_ESP)) {
            lock_release(&page_lock);
            return false;
    }
    if (pte == NULL || (not_present && (!((*pte) & PAGE_LOAD))) ) {
        if ((uint32_t)addr >= (uint32_t)(t->sp_top - STACK_ESP)) {
            pte = lookup_page(t->pagedir, alloc_addr, 1);
            *pte = PTE_U | PTE_W | PTE_P;
            kpage = frame_get_page(alloc_addr);
            make_pte_memory(pte, vtop(kpage));
            //t->sp_top = alloc_addr;
            lock_release(&page_lock);
            return true;
        } 
        return false;
    }

    if ((*pte) & PTE_P) {
        kpage = get_memory_addr(pte);
        /* allocate a page for writing for all zero page */
        if (kpage == zero_page) {
            ASSERT(f->error_code & PF_W);
            if ((*pte) & REAL_WRITE) {
                *pte ^= REAL_WRITE;
                *pte |= PTE_W;
            }
            *pte = (*pte) & FLAG_MASK;
            kpage = frame_get_page(alloc_addr);
            make_pte_memory(pte, vtop(kpage));
            lock_release(&page_lock);
            return true;
        }
        lock_release(&page_lock);
        return false;
    }
    
    if((*pte) & PAGE_SWAP) {
        
        kpage = frame_get_page(alloc_addr);
        //printf("page fault for %x for thread %s with id %d in load from %d sector \n", 
        //    addr, t->name, t->tid, get_slot_idx(pte));
        load_from_slot(pte, kpage);
    }
    else if((*pte) & PAGE_FILE) {
        kpage = frame_get_page(alloc_addr);
        load_from_file(pte, alloc_addr, kpage);
    }
    lock_release(&page_lock);
    return true;
}
void clear_content(uint32_t *pte) {
    if ((*pte) & PTE_P) {
        void *kaddr = get_memory_addr(pte);
        if(kaddr != zero_page)
            frame_remove(kaddr);
    }
    else if((*pte) & PAGE_LOAD){
        /* delete mmap in process.c*/
        uint32_t sector_start = get_slot_idx(pte);
        clear_page_in_block(sector_start);
    }
}
void swap_to_disk(struct thread *t, uint32_t *pagedir, void *vaddr) {
    uint32_t *pte = lookup_page(pagedir, vaddr, 0);
    void *kaddr = get_memory_addr(pte);
    ASSERT((*pte) & PTE_P);
    int32_t mapid = process_in_mmap(vaddr);
    if (mapid != -1) {
        // printf("user mmap?\n");
        process_unload_mmap(t, mapid, vaddr, kaddr);
        
        make_pte_file(pte, mapid);
    }
    else {
        uint32_t sector_start = save_page_to_block(kaddr);
        ASSERT(sector_start != -1);
        make_pte_slot(pte, sector_start);
    }
}

void load_from_slot(uint32_t *pte, void *addr) {
    uint32_t sector_start = get_slot_idx(pte);
    copy_page_from_block(addr, sector_start);
    *pte = ((*pte) & FLAG_MASK) | PTE_P;
    make_pte_memory(pte, vtop(addr));
}

void load_from_file(uint32_t *pte, void *vaddr, void *addr) {
    // printf("load file?\n");
    int32_t mapid = get_mapid(pte);
    process_load_mmap(mapid, vaddr, addr);
    *pte = ((*pte) & FLAG_MASK) | PTE_P;
    make_pte_memory(pte, vtop(addr));
}


bool is_vm_range_unused(void *st, void *ed) {
    void *addr;
    struct thread *t = thread_current();
    bool res = true;
    lock_acquire(&t->pgtbl_lock);
    for (addr = st; addr < ed ; addr += PGSIZE) {
        uint32_t *pte = lookup_page(t->pagedir, addr, 0);
        if (pte != NULL) {
            if ((*pte) & PTE_P) {
                res = false;
                break;
            }
            else if((*pte) & PAGE_LOAD){
                res = false;
                break;
            }
        }
    }
    lock_release(&t->pgtbl_lock);
    return res;
}

void map_vm_range(void *st, void *ed, int32_t mapid) {
    void *addr;
    struct thread *t = thread_current();
    lock_acquire(&t->pgtbl_lock);
    for (addr = st; addr < ed ; addr += PGSIZE) {
        uint32_t *pte = lookup_page(t->pagedir, addr, 1);
        *pte = PTE_U | PTE_W;
        make_pte_file(pte, mapid);
    }
    lock_release(&t->pgtbl_lock);
}