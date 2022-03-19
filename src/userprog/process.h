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

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
int process_add_file(struct file *f);
struct file* process_find_file(int fd);
bool process_close_file(int fd);
void process_clear(void);
struct argument_bearer{
    char buf[ARGSIZE];
    uint32_t argc;
    char *argv[MAX_USERARG_CNT];
    struct thread *parent;
};

typedef struct {
    int fd;
    struct file *f;
    struct list_elem elem;
}file_descriptor;

#endif /**< userprog/process.h */
