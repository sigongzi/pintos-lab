#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#define NELEM(x) (sizeof(x)/sizeof((x)[0]))
void syscall_init (void);
void exit_print(int status);

#endif /**< userprog/syscall.h */
