#include "userprog/syscall.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <debug.h>
#include <console.h>
#include "threads/vaddr.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "filesys/filesys.h"
#include "vm/page.h"
#include "devices/shutdown.h"
#include "devices/input.h"

static void syscall_handler (struct intr_frame *);

static uint32_t sys_halt(void);
static uint32_t sys_exit(void);
static uint32_t sys_exec(void);
static uint32_t sys_wait(void);
static uint32_t sys_create(void);
static uint32_t sys_remove(void);
static uint32_t sys_open(void);
static uint32_t sys_filesize(void);
static uint32_t sys_read(void);
static uint32_t sys_write(void);
static uint32_t sys_seek(void);
static uint32_t sys_tell(void);
static uint32_t sys_close(void);
static uint32_t sys_mmap(void);
static uint32_t sys_munmap(void);
static uint32_t sys_chdir(void);
static uint32_t sys_mkdir(void);
static uint32_t sys_readdir(void);
static uint32_t sys_isdir(void);
static uint32_t sys_inumber(void);


static int
get_user (const uint8_t *uaddr);
static bool
put_user (uint8_t *udst, uint8_t byte);
static bool get_word(uint8_t *uaddr, uint32_t *arg);
static bool get_arg(int ord, uint32_t *arg);
static bool getnbuf(char *uaddr, char *buf, size_t n);
static bool
check_string(char *uaddr);
static inline uint32_t Min(uint32_t a, uint32_t b) {
  return a < b ? a : b;
}
static const uint32_t BUFSIZE = 128;
static const uint32_t FILENAME_LENGTH = 15; 



static void *user_stack;


struct lock file_lock;
 
static uint32_t (*syscalls[])(void) = {
  /* system call for lab 2 */
  [SYS_HALT] = sys_halt,
  [SYS_EXIT] = sys_exit,
  [SYS_EXEC] = sys_exec,
  [SYS_WAIT] = sys_wait,
  [SYS_CREATE] = sys_create,
  [SYS_REMOVE] = sys_remove,
  [SYS_OPEN] = sys_open,
  [SYS_FILESIZE] = sys_filesize,
  [SYS_READ] = sys_read,
  [SYS_WRITE] = sys_write,
  [SYS_SEEK] = sys_seek,
  [SYS_TELL] = sys_tell,
  [SYS_CLOSE] = sys_close,
  /* system call for lab3 */
  [SYS_MMAP] = sys_mmap,
  [SYS_MUNMAP] = sys_munmap,
  [SYS_CHDIR] = sys_chdir,
  [SYS_MKDIR] = sys_mkdir,
  [SYS_READDIR] = sys_readdir,
  [SYS_ISDIR] = sys_isdir,
  [SYS_INUMBER] = sys_inumber,
};

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int
get_user (const uint8_t *uaddr)
{
  if((uint32_t)uaddr >= (uint32_t)PHYS_BASE) return -1;
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));
  return result;
}

/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte)
{
  if((uint32_t)udst >= (uint32_t) PHYS_BASE) return 0;
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
       : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}

/*
  get 4 bytes a word from user address uaddr
*/
static bool
get_word(uint8_t *uaddr, uint32_t *arg) {
  uint32_t res = 0;
  int tmp = 0;
  int i = 0;
  for (i = 3 ; i >= 0 ; --i) {
    tmp = get_user(uaddr + i);
    if (tmp == -1) return false;
    res = res << 8 | (tmp & 0xff);
  }
  *arg = res;
  return true;
}

/*
  get the ord th argument
  the start address of the argument is user_stack + ord * 4
*/
static bool
get_arg(int ord, uint32_t *arg) {
  if (!get_word(thread_current()->sp_top + ord * 4, arg)) return false;
  return true;
}

/*
  get content from user address for exact n bytes
  return false due to invalid memory visit
*/
static bool
getnbuf(char *uaddr, char *buf, size_t n) {
  size_t i;
  int tmp;
  for(i = 0 ; i < n ; ++i) {
    if ((tmp = get_user((uint8_t *)uaddr)) == -1) {
      return false;
    }
    *buf = (tmp & 0xff);
    ++buf;
    ++uaddr;
  }

  return true;
}
/*
  put content to user address for exact n bytes
  return false due to invalid memory visit
*/
static bool
putnbuf(char *uaddr, char *buf, size_t n) {
  size_t i;
  for(i = 0 ; i < n ; ++i) {
    if(!put_user((uint8_t *)uaddr, *buf)) return false;
    uaddr++;
    buf++;
  }
  return true;
}

/*
  get a string from user address
  return -1 when visit invlaid memory
  of return the length of string
  cut the string when its length greater than n
*/
static bool
check_string(char *uaddr) {
  size_t i = 0;
  int tmp;
  while(true) {
    if((tmp = get_user((uint8_t *)uaddr)) == -1) {
      return false;
    }
    if ((char)tmp == '\0') return true;
    ++uaddr;
  }

  return false;
}

void exit_print(int status) {
  struct thread *cur = thread_current();
  
  lock_acquire(&file_lock);
  process_clear_file();
  lock_release(&file_lock);
  process_clear_mmap();
  printf ("%s: exit(%d)\n", cur->name, status);
  cur->exit_status = status;
  thread_exit();
}

void
syscall_init (void) 
{
  lock_init(&file_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  // printf ("system call!\n");
  uint32_t syscall_num;
  if (!get_word(f->esp, &syscall_num)) {
    exit_print(-1);
    return;
  }

  if (syscall_num < NELEM(syscalls) && syscalls[syscall_num]) {
    user_stack = f->esp;
    thread_current()->sp_top = f->esp;
    f->eax = syscalls[syscall_num]();
  } else {
    printf("unknown sys call %x\n", syscall_num);
    f->eax = -1;
  }
}


static uint32_t sys_halt() {
  shutdown_power_off ();
  NOT_REACHED();
  return 0;
}

static uint32_t sys_exit() {
  uint32_t status;
  if (!get_arg(1, &status)) {
    exit_print(-1);
  }
  exit_print(status);
  
  NOT_REACHED();
  return 0;
}

static uint32_t sys_exec() {
  uint32_t addr;
  if (!get_arg(1, &addr)) {
    exit_print(-1);
  }
  char *s = (char *)addr;
  if (!check_string(s)) exit_print(-1);
  lock_acquire(&file_lock);
  tid_t res = process_execute(s);
  lock_release(&file_lock);
  return res;
}

static uint32_t sys_wait() {
  uint32_t tid;
  if (!get_arg(1, &tid)) exit_print(-1);
  return process_wait(tid);
}

static uint32_t sys_create() {
  uint32_t addr, init_size;
  bool res;
  if (!get_arg(1, &addr) || !get_arg(2, &init_size)) exit_print(-1);
  if (!check_string((char *)addr)) exit_print(-1);
  lock_acquire(&file_lock);
  res = filesys_create((char *)addr, init_size);
  lock_release(&file_lock);
  return res;
}

static uint32_t sys_remove() {
  uint32_t addr;
  bool res;
  if(!get_arg(1, &addr)) exit_print(-1);
  if (!check_string((char *)addr)) exit_print(-1);
  lock_acquire(&file_lock);
  res = filesys_remove((char *)addr);
  lock_release(&file_lock);
  return res;
}

static uint32_t sys_open() {
  uint32_t addr;
  struct file *f;
  if (!get_arg(1, &addr)) exit_print(-1);
  if(!check_string((char *)addr)) exit_print(-1);
  lock_acquire(&file_lock);
  f = filesys_open((char *)addr);
  lock_release(&file_lock);

  if(f == NULL) return -1;
  return process_add_file(f);
}

static uint32_t sys_filesize() {
  uint32_t fd;
  uint32_t len;
  if (!get_arg(1, &fd)) exit_print(-1);
  struct file *f = process_find_file(fd);
  if(f == NULL) return -1;
  lock_acquire(&file_lock);
  len = file_length(f);
  lock_release(&file_lock);
  return len;
}

static uint32_t sys_read() {
  uint32_t fd, addr, n;
  uint32_t i;
  char *s;
  char buf[BUFSIZE];
  struct file *f;
  bool res_for_bad_memory = 0;
  if (!get_arg(1, &fd) || !get_arg(2, &addr) || !get_arg(3, &n)) exit_print(-1);
  s = (char *)addr;
  if (fd == 1) return -1;
  if (fd == 0) {
    for (i = 0 ; i < n ; ++i) {
      if(!put_user((uint8_t *)s, input_getc())) {
        res_for_bad_memory = 1;
        break;
      }
      ++s;
    }
  }
  else {
    
    f = process_find_file(fd);
    if (f == NULL || file_isdir(f)) n = -1;
    else {
      
      lock_acquire(&file_lock);
      if (f->pos > file_length(f)) n = -1;
      else {
        uint32_t rd = 0, tmp, ad;
        while (rd < n) {
          tmp = Min(n - rd, BUFSIZE);
          
          
          ad = file_read(f, buf, tmp);
          if (!putnbuf(s, buf, ad)) {
            res_for_bad_memory = 1;
            break;
          }
          s += ad;
          rd += ad;
          if (!ad || ad < tmp) break;
        }
        n = rd;
      }
      lock_release(&file_lock);
      
    }
  }
  if (res_for_bad_memory) {
    exit_print(-1);
  }
  return n;
}

static uint32_t sys_write() {
  uint32_t fd, addr, n;
  char *s;
  char buf[BUFSIZE];
  struct file *f;
  bool res_for_bad_memory = 0;
  if (!get_arg(1, &fd) || !get_arg(2, &addr) || !get_arg(3, &n)) exit_print(-1);

  s = (char *)addr;
  if (fd == 0) return 0;
  if (fd == 1) {
    uint32_t wt = 0, tmp;
    while(wt < n) {
      tmp = Min(n - wt, BUFSIZE);
      
      if (!getnbuf(s, buf, tmp)) {
        res_for_bad_memory = 1;
        break;
      }
      putbuf(buf, tmp);
      
      
      wt += tmp;
      s += tmp;
    }
  }
  else {
    f = process_find_file(fd);
    if(f == NULL) {
      n = 0;
    }
    else if(file_isdir(f)) {
      //printf("file is a directory");
      n = -1;
    }
    else {
      lock_acquire(&file_lock);
      uint32_t wt = 0, tmp, ad;
      while(wt < n) {
        tmp = Min(n - wt, BUFSIZE);
        if (!getnbuf(s, buf, tmp)) {
          res_for_bad_memory = 1;
          break;
        }
        ad = file_write(f, buf, tmp);
        
        s += ad;
        wt += ad;
        if(ad < tmp) break;
      }
      n = wt;
      lock_release(&file_lock);
    }
  }
  if(res_for_bad_memory) {
    exit_print(-1);
  }
  return n;
}

static uint32_t sys_seek() {
  uint32_t fd;
  uint32_t pos;
  if (!get_arg(1, &fd) || !get_arg(2, &pos)) exit_print(-1);
  struct file *f = process_find_file(fd);
  if(f == NULL) return -1;
  lock_acquire(&file_lock);
  file_seek(f, pos);
  lock_release(&file_lock);
  return 0;
}

static uint32_t sys_tell() {
  uint32_t fd;
  uint32_t res;
  if (!get_arg(1, &fd)) exit_print(-1);
  struct file *f = process_find_file(fd);
  if(f == NULL) return -1;
  lock_acquire(&file_lock);
  res = file_tell(f);
  lock_release(&file_lock);
  return res;
}

static uint32_t sys_close() {
  uint32_t fd;
  bool res;
  if (!get_arg(1, &fd)) exit_print(-1);
  lock_acquire(&file_lock);
  res = process_close_file(fd);
  lock_release(&file_lock);
  if (!res) return -1;
  return 0;
}

static uint32_t sys_mmap() {
  uint32_t fd;
  uint32_t addr;
  struct file *f;
  void *st, *ed;
  int mapid;
  if(!get_arg(1, &fd) || !get_arg(2, &addr)) exit_print(-1);

  if (fd <= 1) return -1;
  if (addr == 0 || (addr & PGMASK)) return -1;

  f = process_find_file(fd);
  if (f == NULL) return -1;

  st = (void *)addr;
  ed = (void *)(addr + file_length(f) - 1);

  if (!is_vm_range_unused(st, pg_round_up(ed))) return -1;

  lock_acquire(&file_lock);
  f = file_reopen(f);
  lock_release(&file_lock);

  if(f == NULL) return -1;

  mapid = process_add_mmap(f, st, ed);
  if (mapid != -1) {
    map_vm_range(st, ed, mapid);
  }
  return mapid;
}

static uint32_t sys_munmap() {
  uint32_t mapid;
  if (!get_arg(1, &mapid)) exit_print(-1);

  process_remove_mmap(mapid);

  return 0;
}

static uint32_t sys_chdir() {
  uint32_t addr;
  if (!get_arg(1, &addr)) exit_print(-1);
  if (!check_string((char *)addr)) exit_print(-1);
  bool success = 0;
  lock_acquire(&file_lock);
  success = filesys_chdir((char *)addr);
  lock_release(&file_lock);
  return success;
}

static uint32_t sys_mkdir() {
  uint32_t addr;
  if (!get_arg(1, &addr)) exit_print(-1);
  if (!check_string((char *)addr)) exit_print(-1);
  bool success = 0;
  lock_acquire(&file_lock);
  success = filesys_mkdir((char *)addr);
  lock_release(&file_lock);
  return success;
}

static uint32_t sys_readdir() {
  uint32_t fd;
  uint32_t addr;
  char file_name[FILENAME_LENGTH];
  if(!get_arg(1, &fd) || !get_arg(2, &addr)) exit_print(-1);
  struct file *f = process_find_file(fd);
  if (f == NULL) return -1;
  bool success = 0;
  memset(file_name, 0, sizeof(file_name));
  lock_acquire(&file_lock);
  success = file_readdir(f, file_name);
  lock_release(&file_lock);
  if(!putnbuf((char *)addr, file_name, strlen(file_name) + 1)) exit_print(-1);
  return success;
}

static uint32_t sys_isdir() {
  uint32_t fd;
  if(!get_arg(1, &fd)) exit_print(-1);
  struct file *f = process_find_file(fd);
  if (f == NULL) return -1;
  uint32_t res;
  lock_acquire(&file_lock);
  res = file_isdir(f);
  lock_release(&file_lock);
  return res;
}

static uint32_t sys_inumber() {
  uint32_t fd;
  if(!get_arg(1, &fd)) exit_print(-1);
  struct file *f = process_find_file(fd);
  if(f == NULL) return -1;
  uint32_t res;
  lock_acquire(&file_lock);
  res = file_inumber(f);
  lock_release(&file_lock);
  return res;
}