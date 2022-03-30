#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include "threads/synch.h"
#include "threads/fpreal.h"
#include "filesys/file.h"

/** States in a thread's life cycle. */
enum thread_status
{
   THREAD_RUNNING, /**< Running thread. */
   THREAD_READY,   /**< Not running but ready to run. */
   THREAD_BLOCKED, /**< Waiting for an event to trigger. */
   THREAD_DYING    /**< About to be destroyed. */
};

/** Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t)-1) /**< Error value for tid_t. */

/** Thread priorities. */
#define PRI_MIN 0      /**< Lowest priority. */
#define PRI_DEFAULT 31 /**< Default priority. */
#define PRI_MAX 63     /**< Highest priority. */
#define NESTED_MAX 8

/** A kernel thread or user process.

   Each thread structure is stored in its own 4 kB page.  The
   thread structure itself sits at the very bottom of the page
   (at offset 0).  The rest of the page is reserved for the
   thread's kernel stack, which grows downward from the top of
   the page (at offset 4 kB).  Here's an illustration:

        4 kB +---------------------------------+
             |          kernel stack           |
             |                |                |
             |                |                |
             |                V                |
             |         grows downward          |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             +---------------------------------+
             |              magic              |
             |                :                |
             |                :                |
             |               name              |
             |              status             |
        0 kB +---------------------------------+

   The upshot of this is twofold:

      1. First, `struct thread' must not be allowed to grow too
         big.  If it does, then there will not be enough room for
         the kernel stack.  Our base `struct thread' is only a
         few bytes in size.  It probably should stay well under 1
         kB.

      2. Second, kernel stacks must not be allowed to grow too
         large.  If a stack overflows, it will corrupt the thread
         state.  Thus, kernel functions should not allocate large
         structures or arrays as non-static local variables.  Use
         dynamic allocation with malloc() or palloc_get_page()
         instead.

   The first symptom of either of these problems will probably be
   an assertion failure in thread_current(), which checks that
   the `magic' member of the running thread's `struct thread' is
   set to THREAD_MAGIC.  Stack overflow will normally change this
   value, triggering the assertion. */
/** The `elem' member has a dual purpose.  It can be an element in
   the run queue (thread.c), or it can be an element in a
   semaphore wait list (synch.c).  It can be used these two ways
   only because they are mutually exclusive: only a thread in the
   ready state is on the run queue, whereas only a thread in the
   blocked state is on a semaphore wait list. */
struct thread
{
   /* Owned by thread.c. */
   tid_t tid;                 /**< Thread identifier. */
   enum thread_status status; /**< Thread state. */
   char name[16];             /**< Name (for debugging purposes). */
   uint8_t *stack;            /**< Saved stack pointer. */
   int priority;              /**< Priority. */
   int donation_state;        /**<record whether current priority is donated, 1 is donated, 0 is not*/
   int origin_priority;       /**< original priority of one thread, 
                                    changed only in thread_set_priority and initialization*/
   struct lock *wait_lock; /**< a thread only waits one lock at a time*/

   int64_t wakeup_time; /**< wake up time */
   struct list donation_list; /**< a list for donation_elem */
   struct list_elem donation_elem; /**< record the threads waiting this thread's lock */
   struct list_elem allelem; /**< List element for all threads list. */

   /* Shared between thread.c and synch.c. */
   struct list_elem elem; /**< List element. */

   /*MLFQ variable*/
   int niceness; /*Niceness between [-20,20]*/
   fpreal_t recent_cpu;

#ifdef USERPROG
   /* Owned by userprog/process.c. */
   uint32_t *pagedir; /**< Page directory. */
   int exit_status; /*save exit status for WAIT function to read */
   struct semaphore wait_child_load; /* wait child load finish in EXEC function*/
   struct semaphore end_process; /* wait child end in WAIT function or 
    in EXEC function changing child parent pointer to NULL before child thread exits */
   struct semaphore parent_sema; /* changing parent pointer in child thread when exits */
   struct list child_list; /* link all the child thread in a list*/
   struct list file_list; /* link all the file pointer in a list */
   struct list_elem as_child; /* be linked as an element in child_list */
   struct thread *parent; /* record parent, if parent is NULL, it can delete itself. 
   Or it must be recycled when its parent exits*/
   struct file *load_file; /* the file loaded. It denies to be written before the process ends */
   void *sp_top;
#endif

   /* Owned by thread.c. */
   unsigned magic; /**< Detects stack overflow. */
};

/** If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

void thread_init(void);
void thread_start(void);

void thread_tick(void);
void thread_print_stats(void);

typedef void thread_func(void *aux);
tid_t thread_create(const char *name, int priority, thread_func *, void *);

void thread_block(void);
void thread_unblock(struct thread *);

struct thread *thread_current(void);
tid_t thread_tid(void);
const char *thread_name(void);

void thread_exit(void) NO_RETURN;
void thread_yield(void);
void thread_secondly_update(void);

/** Performs some operation on thread t, given auxiliary data AUX. */
typedef void thread_action_func(struct thread *t, void *aux);
void thread_foreach(thread_action_func *, void *);

int thread_get_priority(void);
void thread_set_priority(int);

int thread_get_nice(void);
void thread_set_nice(int);
int thread_get_recent_cpu(void);
int thread_get_load_avg(void);
bool priority_higher(const struct list_elem *a, const struct list_elem *b, void *aux UNUSED);
bool wakeup_earlier(const struct list_elem *a, const struct list_elem *b, void *aux UNUSED);
bool priority_higher_donation(const struct list_elem *a, const struct list_elem *b, void *aux UNUSED);

void thread_insert_sleep(struct thread *t);
void thread_wakeup(int64_t ticks);
void thread_insert_ready(struct thread *t);
void thread_acquire_donation(struct thread *dest, struct thread *src, int level);
void thread_release_donation(struct lock *lock);

void adjust_elem(struct thread *t);

#endif /**< threads/thread.h */
