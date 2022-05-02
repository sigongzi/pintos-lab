#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/file.h"

#define ARGSIZE 128
#define MAX_USERARG_CNT (ARGSIZE >> 1)
#define ALIGN_WORD 4
#define KERNEL_KILL 1
#define LOAD_FAIL 2

typedef int mapid_t;
extern struct lock file_lock;

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
int process_add_file(struct file *);
int process_add_mmap(struct file *, void *, void *);
int process_in_mmap(void *);
void process_remove_mmap(mapid_t);
struct file* process_find_file(int);

void process_load_mmap(mapid_t mapid, void *vaddr, void *target);
void process_unload_mmap(struct thread *t, mapid_t mapid, void *vaddr, void *src);

bool process_close_file(int);
void process_clear_file(void);
void process_clear_mmap(void);
struct argument_bearer{
    char buf[ARGSIZE];
    uint32_t argc;
    char *argv[MAX_USERARG_CNT];
    struct thread *parent;
};

typedef struct {
    int fd; /* file descriptor for process */
    struct file *f; /* file pointer in file system */
    struct list_elem elem; /* element in file_list per process */
}file_descriptor;



typedef struct {
    mapid_t mapid; /* file descriptor for process */
    struct file *f; /* file pointer in file system */
    struct list_elem elem; /* element in file_list per process */
    void *start, *end; /* virtual address range */
}mmap_descriptor;

#endif /**< userprog/process.h */
