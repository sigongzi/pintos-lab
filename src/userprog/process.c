#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <list.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/directory.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "threads/pte.h"
#include "vm/page.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);
static bool cut_argument(struct argument_bearer *arg);
static bool load_argument_to_stack
(struct argument_bearer *arg, void **esp);
static struct thread* find_child_thread(tid_t tid);
static void close_fd(file_descriptor *fd);
static file_descriptor* find_fd(int fd);
static void remove_mmap(mmap_descriptor* md);
static mmap_descriptor* find_mmap(struct thread *t, int mapid);


/*
  The raw characters line is loaded in buf element in the structure
  Calculate the argc and argv for each argument
*/

static bool cut_argument(struct argument_bearer *arg) {
  char *save_ptr = arg->buf;
  arg->argc = 0;
  while((*save_ptr) != '\0') {
    if (arg->argc == MAX_USERARG_CNT) return false;
    arg->argv[arg->argc++] = strtok_r(NULL, " ", &save_ptr);
  }
  return true;
}

/*
  Move the argument to user stack
*/
static bool load_argument_to_stack
(struct argument_bearer *arg, void **esp) {
  int i;

  void *tmp_esp = *esp;
  for(i = arg->argc - 1; i >= 0 ; --i) {
    uint32_t len = strlen(arg->argv[i]) + 1;
    tmp_esp -= len;
    memcpy((char *)tmp_esp, arg->argv[i], len);
    arg->argv[i] = (char *)tmp_esp;
  }
  /* word alignment for 32 bit */
  tmp_esp = (void *)ROUND_DOWN((uint32_t) tmp_esp, ALIGN_WORD);
  /* push a null pointer behind the last element in argv */
  tmp_esp -= ALIGN_WORD;
  *(uint32_t *)tmp_esp = 0;
  /* push argv array */
  for(i = arg->argc - 1; i >= 0 ; --i) {
    tmp_esp -= ALIGN_WORD;
    *(uint32_t *)tmp_esp = (uint32_t) arg->argv[i];
  }

  /* push argv */
  void *save_argv = tmp_esp;
  tmp_esp -= ALIGN_WORD;
  *(uint32_t *)tmp_esp = (uint32_t) save_argv;
  
  /* push argc */
  tmp_esp -= ALIGN_WORD;
  *(uint32_t *)tmp_esp = arg->argc;

  /* place for a fake return address */
  tmp_esp -= ALIGN_WORD;
  *(uint32_t *)tmp_esp = 0;


  *esp = tmp_esp;
  return true;
}
/*
  helper function in process.c
  find child thread by tid 
*/
static struct thread * find_child_thread(tid_t tid) {
  struct thread *cur = thread_current();
  struct thread *ch = NULL;
  struct list_elem *e;
  for (e = list_begin (&cur->child_list); e != list_end (&cur->child_list);
       e = list_next (e)) {
         ch = list_entry(e, struct thread, as_child);
         if(ch->tid == tid) {
            break;
         }
       }
  return ch;
}
/*
  helper function in process.c
  delete file_descriptor structure
*/
static void close_fd(file_descriptor *fd) {
  if(fd == NULL) return;
  file_close(fd->f);
  list_remove(&fd->elem);
  free(fd);
}
/*
  helper function in process.c
  find file_descriptor structure
*/
static file_descriptor* find_fd(int fd) {
  file_descriptor *fd_save = NULL;
  struct thread *cur = thread_current();
  struct list_elem *e;
  for (e = list_begin(&cur->file_list) ; e != list_end(&cur->file_list); 
    e = list_next(e)) {
      file_descriptor *fd_ano = list_entry(e, file_descriptor, elem);
      if (fd_ano->fd == fd) {
        fd_save = fd_ano;
        break;
      }
    } 
  return fd_save;
}
/*
  helper function in process.c
  remove mmap_descriptor structure
*/
static void remove_mmap(mmap_descriptor* md) {
  struct thread *t = thread_current();
  void *addr;
  uint32_t *pte;
  lock_acquire(&frame_hash_lock);
  lock_acquire(&t->pgtbl_lock);
  for (addr = md->start ; addr < pg_round_up(md->end) ; addr += PGSIZE) {
    pte = lookup_page(t->pagedir, addr, 0);
    ASSERT(pte != NULL);
    if (((*pte) & PTE_P) && ((*pte) & PTE_D)) {
      process_unload_mmap(thread_current(), md->mapid, addr, addr);
    }
    if ((*pte) & PTE_P) {
      clear_content(pte);
    }
    *pte = 0;
  }
  lock_release(&t->pgtbl_lock);
  lock_release(&frame_hash_lock);
  file_close(md->f);
  list_remove(&md->elem);
  free(md);
}
/*
  helper function in process.c
  find mmap_descriptor structure
*/
static mmap_descriptor* find_mmap(struct thread *t, int mapid) {
  mmap_descriptor *mmap_save = NULL;
  struct list_elem *e;
  for (e = list_begin(&t->mmap_list) ; e != list_end(&t->mmap_list); 
    e = list_next(e)) {
      mmap_descriptor *mmap_ano = list_entry(e, mmap_descriptor, elem);
      if (mmap_ano->mapid == mapid) {
        mmap_save = mmap_ano;
        break;
      }
    } 
  return mmap_save;
}
/*
  interface for syscall.c
  For OPEN syscall to add file descriptor in process
*/
int process_add_file(struct file *f) {
  file_descriptor *fd_save = calloc(1, sizeof(file_descriptor));
  struct list_elem *e;
  struct thread *cur = thread_current();
  if (fd_save == NULL) return -1;
  int alloc_fd = 2;
  fd_save->f = f;
  for (e = list_begin(&cur->file_list); e != list_end(&cur->file_list);
    e = list_next(e)) {
      file_descriptor *fd_ano = list_entry(e, file_descriptor, elem);
      if(fd_ano->fd == alloc_fd) ++alloc_fd;
      else {
        break;
      }
    }
  fd_save->fd = alloc_fd;
  list_insert(e, &fd_save->elem);
  return alloc_fd;
}

/*
  interface for syscall.c
  For WRITE syscall to find file structure in process
*/

struct file* process_find_file(int fd) {
  file_descriptor *fd_save = find_fd(fd);
  if (fd_save == NULL) return NULL;
  return fd_save->f;
}
/*
  interface for syscall.c
  For CLOSE syscall to close file descriptor with specific fd
*/

bool process_close_file(int fd) {
  file_descriptor *fd_save = find_fd(fd);
  if(fd_save == NULL) return 0;
  close_fd(fd_save);
  return 1;
}

/*
  interface for syscall.c
  For EXIT syscall to clear all file record and release memory resource
*/
void
process_clear_file() {
  struct list_elem *e;
  struct thread *cur = thread_current();
  for (e = list_begin(&cur->file_list); e != list_end(&cur->file_list);
    ) {
      file_descriptor *fd_ano = list_entry(e, file_descriptor, elem);
      e = list_next(e);
      close_fd(fd_ano);
    }
  if(cur->load_file) {
    file_allow_write(cur->load_file);
    file_close(cur->load_file);
  }
  if(cur->dir) {
    dir_close(cur->dir);
  }
}
/*
  interface for syscall.c
*/

int process_add_mmap(struct file *f, void *st, void *ed) {
  mmap_descriptor *mmap_save = calloc(1, sizeof(mmap_descriptor));
  if (mmap_save == NULL) {
    return -1;
  }
  mmap_save->start = st;
  mmap_save->end = ed;
  mmap_save->f = f;
  int alloc_mapid = 2;

  struct list_elem *e;
  struct thread *cur = thread_current();
  for (e = list_begin(&cur->mmap_list); e != list_end(&cur->mmap_list);
    e = list_next(e)) {
      mmap_descriptor *mmap_ano = list_entry(e, mmap_descriptor, elem);
      if(mmap_ano->mapid == alloc_mapid) ++alloc_mapid;
      else {
        break;
      }
    }
  mmap_save->mapid = alloc_mapid;
  list_insert(e, &mmap_save->elem);
  return alloc_mapid;
}


/*
  interface for syscall.c
*/
void process_remove_mmap(mapid_t mapid) {
  mmap_descriptor *md = find_mmap(thread_current(), mapid);
  if (md == NULL) return;
  remove_mmap(md);
}


/*
  interface for syscall.c
*/

void process_clear_mmap() {
  struct list_elem *e;
  struct thread *cur = thread_current();
  for (e = list_begin(&cur->mmap_list); e != list_end(&cur->mmap_list);
    ) {
      mmap_descriptor *mmap_ano = list_entry(e, mmap_descriptor, elem);
      e = list_next(e);
      remove_mmap(mmap_ano);
    }
}
/*
  interface for page.c
*/

int process_in_mmap(void *vaddr) {
  struct list_elem *e;
  struct thread *cur = thread_current();
  for (e = list_begin(&cur->mmap_list); e != list_end(&cur->mmap_list);
    e = list_next(e)) {
      mmap_descriptor *mmap_ano = list_entry(e, mmap_descriptor, elem);
      if ((uint32_t)vaddr >= (uint32_t)mmap_ano->start && (uint32_t)vaddr <= (uint32_t)mmap_ano->end) {
        return mmap_ano->mapid;
      }
    }
  return -1;
}
/*
  interface for page.c
*/
void process_load_mmap(mapid_t mapid, void *vaddr, void *target) {
  mmap_descriptor *mmap_save = find_mmap(thread_current(), mapid);
  off_t offset = vaddr - mmap_save->start;
  uint32_t load_byte 
    = (mmap_save->end - vaddr + 1) < PGSIZE ? (mmap_save->end - vaddr + 1) : PGSIZE;
  uint32_t zero_byte = PGSIZE - load_byte;
  lock_acquire(&file_lock);
  file_read_at(mmap_save->f, target, load_byte, offset);
  lock_release(&file_lock);
  if (zero_byte) {
    memset(target + load_byte, 0, zero_byte);
  }
}

/*
  interface for page.c
*/
void process_unload_mmap(struct thread *t, mapid_t mapid, void *vaddr, void *src) {
  mmap_descriptor *mmap_save = find_mmap(t, mapid);
  off_t offset = vaddr - mmap_save->start;
  uint32_t load_byte 
    = (mmap_save->end - vaddr + 1) < PGSIZE ? (mmap_save->end - vaddr + 1) : PGSIZE;
  lock_acquire(&file_lock);
  file_write_at(mmap_save->f, src, load_byte, offset);
  lock_release(&file_lock);
}

/** Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  struct argument_bearer *fn_copy;
  struct thread *cur = thread_current();
  struct thread *ch = NULL;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  
  strlcpy (fn_copy->buf, file_name, ARGSIZE);

  if(!cut_argument(fn_copy)) {
    // check for failure, even unnecessary
    palloc_free_page(fn_copy);
    return TID_ERROR;
  }

  /* the child process needs to know its father */
  fn_copy->parent = cur;

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (fn_copy->argv[0], PRI_DEFAULT, start_process, fn_copy);
  if (tid == TID_ERROR)
    palloc_free_page (fn_copy);
  sema_down(&cur->wait_child_load);
  ch = find_child_thread(tid);
  if(ch == NULL) {
    tid = TID_ERROR;
  } else if(ch->exit_status == -LOAD_FAIL){
    list_remove(&ch->as_child);
    ch->parent = NULL;
    tid = TID_ERROR;
    sema_up(&ch->end_process);
  }
  return tid;
}

/** A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  struct argument_bearer *arg = file_name_;
  char *file_name = arg->argv[0];
  struct intr_frame if_;
  struct thread *cur = thread_current();
  bool success;

  /* init process in thread structure */
  cur->exit_status = 0;
  list_init(&cur->child_list);
  list_init(&cur->file_list);
  list_init(&cur->mmap_list);
  lock_init(&cur->pgtbl_lock);
  cur->sp_top = cur->old_top = PHYS_BASE;
  cur->parent = arg->parent;
  cur->dir = NULL;
  list_insert(list_begin(&cur->parent->child_list), &cur->as_child);
  sema_init(&cur->wait_child_load, 0);
  sema_init(&cur->end_process, 0);
  sema_init(&cur->parent_sema, 1);

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (file_name, &if_.eip, &if_.esp);
  /* If load argument to user stack failed, quit */
  if (success) {
    success = load_argument_to_stack(arg, &if_.esp);
  }
  /* If load failed, quit. */
  /* allocated a page to structure arg in process_execute */
  palloc_free_page (arg); 
  if (!success) {
    cur->exit_status = -LOAD_FAIL;
    /* clear file (may open in load() function) with the lock hold by parent process */
    process_clear_file();
    /* unlink the parent(in parent process_execute() before it exits) */
    sema_up(&cur->parent->wait_child_load);
    sema_down(&cur->end_process);
    thread_exit ();
  }
  /* notice parent process we have finished the load */ 

  cur->dir = dir_open_root();
  sema_up(&cur->parent->wait_child_load);
  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/** Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid) 
{
  if(child_tid == -1) return -1;
  struct thread* ch = find_child_thread(child_tid);
  int status;
  if (ch == NULL) return -1;

  sema_down(&ch->end_process);
  status = ch->exit_status;
  list_remove(&ch->as_child);

  palloc_free_page(ch);
  
  return status;
}

/** Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;
  /** decrease the reference for the current directory */
  
  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      lock_acquire(&frame_hash_lock);
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
      lock_release(&frame_hash_lock);
    }
  sema_down(&cur->parent_sema);
  struct list_elem *e;
  for (e = list_begin(&cur->child_list) ; e != list_end(&cur->child_list);
    e = list_next(e)) {
      struct thread *ch = list_entry(e, struct thread, as_child);
      sema_down(&ch->parent_sema);
      if(ch->status == THREAD_DYING) {
        sema_up(&ch->parent_sema);
        palloc_free_page(ch);
      }
      else {
        ch->parent = NULL;
        sema_up(&ch->parent_sema);
      }
    }
  sema_up(&cur->parent_sema);
  sema_up(&cur->end_process);
}

/** Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/** We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/** ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/** For use with ELF types in printf(). */
#define PE32Wx PRIx32   /**< Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /**< Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /**< Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /**< Print Elf32_Half in hexadecimal. */

/** Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/** Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/** Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /**< Ignore. */
#define PT_LOAD    1            /**< Loadable segment. */
#define PT_DYNAMIC 2            /**< Dynamic linking info. */
#define PT_INTERP  3            /**< Name of dynamic loader. */
#define PT_NOTE    4            /**< Auxiliary info. */
#define PT_SHLIB   5            /**< Reserved. */
#define PT_PHDR    6            /**< Program header table. */
#define PT_STACK   0x6474e551   /**< Stack segment. */

/** Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /**< Executable. */
#define PF_W 2          /**< Writable. */
#define PF_R 4          /**< Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/** Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Open executable file. */
  file = filesys_open (file_name);
  t->load_file = file;
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }
  file_deny_write(file);
  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  return success;
}

/** load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/** Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/** Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;
      uint32_t flags = PAL_USER;

      #ifdef VM
      flags = 0;
      #endif
      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (flags);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      #ifndef VM
      if (!install_page (upage, kpage, writable)) 
        {
          palloc_free_page (kpage);
          return false; 
        }
      #else

      
      if (!install_lazy_page(kpage, upage, writable, page_zero_bytes == PGSIZE) ) {
        return false;
      }

      palloc_free_page(kpage);
      #endif
      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/** Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  
  bool success = false;

#ifndef VM
  uint8_t *kpage;
  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE;
      else
        palloc_free_page (kpage);
    }
#else

  *esp = PHYS_BASE;
  success = true;
  
#endif  
  return success;
}

/** Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
