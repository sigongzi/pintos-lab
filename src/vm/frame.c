#include "vm/frame.h"
#include "vm/page.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/pte.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include <string.h>
#include <hash.h>


static struct hash frames;

struct lock frame_hash_lock;


/* Returns the page containing the given virtual address,
   or a null pointer if no such page exists. */
struct frame_page *
frame_page_lookup (const uintptr_t addr)
{
  struct frame_page p;
  struct hash_elem *e;

  p.addr = addr;
  e = hash_find (&frames, &p.hash_elem);
  return e != NULL ? hash_entry (e, struct frame_page, hash_elem) : NULL;
}

/* Returns a hash value for page p. */
unsigned
page_hash (const struct hash_elem *p_, void *aux UNUSED)
{
  const struct frame_page *p = hash_entry (p_, struct frame_page, hash_elem);
  return hash_bytes (&p->addr, sizeof p->addr);
}

/* Returns true if page a precedes page b. */
bool
page_less (const struct hash_elem *a_, const struct hash_elem *b_,
           void *aux UNUSED)
{
  const struct frame_page *a = hash_entry (a_, struct frame_page, hash_elem);
  const struct frame_page *b = hash_entry (b_, struct frame_page, hash_elem);

  return a->addr < b->addr;
}




void frame_init() {
    hash_init (&frames, page_hash, page_less, NULL);
    lock_init (&frame_hash_lock);
    
}

void *frame_get_page(void *uaddr) {
    void* kpage = palloc_get_page(PAL_USER | PAL_ZERO);
    lock_acquire(&frame_hash_lock);
    if (kpage != NULL) {
        frame_add_page(uaddr, vtop(kpage));
        lock_release(&frame_hash_lock);
        return kpage;
    }

    struct hash_iterator i;

    
    while(1) {
        bool find_page = 0;
        hash_first (&i, &frames);
        while (hash_next (&i))
        {
            struct frame_page *fp = hash_entry (hash_cur (&i), struct frame_page, hash_elem);
            uint32_t *pte;
            lock_acquire(&fp->t->pgtbl_lock);
            if (fp->t->pagedir == NULL) {
                printf("%s %x\n", fp->t->name, &fp->t->pagedir);
            }
            ASSERT((uint32_t)fp->vaddr <= (uint32_t)PHYS_BASE)
            pte = lookup_page(fp->t->pagedir, fp->vaddr, 0);
            
            ASSERT(pte != NULL);

            if ((*pte) & PTE_D) {
                if (!((*pte) & PTE_A)) {
                    find_page = 1;
                    swap_to_disk(fp->t, fp->t->pagedir, fp->vaddr);
                    lock_release(&fp->t->pgtbl_lock); 
                    fp->t = thread_current();
                    fp->vaddr = uaddr;
                    kpage = ptov(fp->addr);
                    memset(kpage, 0, PGSIZE);
                    break;    
                }
                *pte ^= PTE_A;
            }
            lock_release(&fp->t->pgtbl_lock); 
        }
        if (find_page) {
            break;
        }
    }
    lock_release(&frame_hash_lock);
    return kpage;
}

void frame_remove_elem(struct hash_elem *hash_elem) {
    hash_delete(&frames, hash_elem);
}
void frame_add_elem(struct hash_elem *hash_elem) {
    hash_insert(&frames, hash_elem);
}
void frame_remove(void *addr) {
    uintptr_t kaddr = vtop(addr);
    struct frame_page *fp = frame_page_lookup(kaddr);
    hash_delete(&frames, &fp->hash_elem);
    palloc_free_page(addr);
    free(fp);
}

void frame_add_page(void *uaddr, uintptr_t kaddr) {
    struct frame_page *fp = malloc(sizeof(struct frame_page));
    fp->addr = kaddr;
    fp->t = thread_current();
    fp->vaddr = uaddr;
    //fp->pte = lookup_page(fp->t->pagedir, uaddr, 0);
    hash_insert(&frames, &fp->hash_elem);
}