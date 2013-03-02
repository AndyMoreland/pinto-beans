#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/switch.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "devices/timer.h"

#ifdef USERPROG
#include "userprog/process.h"
#endif

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

#define MLFQS_PRI_RECOMPUTE_TICKS 4 

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_lists[PRI_COUNT];


/* List of all processes.  Processes are added to this list
   when they are first scheduled and removed when they exit. */
static struct list all_list;

/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Stack frame for kernel_thread(). */
struct kernel_thread_frame 
  {
    void *eip;                  /* Return address. */
    thread_func *function;      /* Function to call. */
    void *aux;                  /* Auxiliary data for function. */
  };

/* Statistics. */
static long long idle_ticks;    /* # of timer ticks spent idle. */
static long long kernel_ticks;  /* # of timer ticks in kernel threads. */
static long long user_ticks;    /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4            /* # of timer ticks to give each thread. */
static unsigned thread_ticks;   /* # of timer ticks since last yield. */

/* Scheduling statistics. */
static fixed_point load_average;

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

/* A coarse lock that protects the FS from concurrent access. */
extern struct lock fs_lock;

static void kernel_thread (thread_func *, void *aux);

static void idle (void *aux UNUSED);
static struct thread *running_thread (void);
static struct thread *next_thread_to_run (void);
static struct thread *find_next_thread_to_run (void);
static void init_thread (struct thread *, const char *name, int priority, int nice, fixed_point recent_cpu);
static bool is_thread (struct thread *) UNUSED;
static void *alloc_frame (struct thread *, size_t size);
static void schedule (void);
void thread_schedule_tail (struct thread *prev);
static tid_t allocate_tid (void);
static void thread_mlfqs_update_load_average (void);
static void thread_mlfqs_update_priority (struct thread *t, void *aux);
static void thread_mlfqs_update_recent_cpu (struct thread *t, void *aux);
static void thread_possibly_yield (void);

/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void
thread_init (void) 
{
  ASSERT (intr_get_level () == INTR_OFF);

  lock_init (&tid_lock);

  /* Initialize the ready queues */
  int i;
  for (i = 0; i < PRI_COUNT; i++)
    list_init (&ready_lists[i]);
  list_init (&all_list);
  load_average = fixed_point_create (LOAD_AVERAGE_DEFAULT);
  lock_init (&fs_lock);

  /* Set up a thread structure for the running thread. */
  initial_thread = running_thread ();
  init_thread (initial_thread, "main", PRI_DEFAULT, NICE_DEFAULT, RECENT_CPU_DEFAULT);
  initial_thread->status = THREAD_RUNNING;
  initial_thread->tid = allocate_tid ();
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void
thread_start (void) 
{
  /* Create the idle thread. */
  struct semaphore idle_started;
  sema_init (&idle_started, 0);
  thread_create ("idle", PRI_MIN, idle, &idle_started);

  /* Start preemptive thread scheduling. */
  intr_enable ();

  /* Wait for the idle thread to initialize idle_thread. */
  sema_down (&idle_started);
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void
thread_tick (void) 
{
  struct thread *t = thread_current ();

  /* Update statistics. */
  if (t == idle_thread)
    idle_ticks++;
#ifdef USERPROG
  else if (t->pagedir != NULL)
    user_ticks++;
#endif
  else
    kernel_ticks++;

  if (thread_mlfqs)
    {
      enum intr_level old_level = intr_disable();
      if (t != idle_thread)
        t->recent_cpu = fixed_point_add_int (t->recent_cpu, 1);
      if (timer_ticks () % TIMER_FREQ == 0)
        {
          thread_mlfqs_update_load_average ();
          thread_foreach (thread_mlfqs_update_recent_cpu, NULL);
        }
      if (timer_ticks () % MLFQS_PRI_RECOMPUTE_TICKS == 0)
        { 
          thread_foreach (thread_mlfqs_update_priority, NULL);
          /* If we recaculate priorities on a tick which is not a
             time slice boundary, then we still want to preempt
             if we have raised another thread's priority over our
             current thread. */
          if (find_next_thread_to_run ()->priority > t->priority)
            intr_yield_on_return ();
        }


      intr_set_level (old_level);
    }
  

  /* Enforce preemption. */
  if (++thread_ticks >= TIME_SLICE)
    intr_yield_on_return ();
}

/* Prints thread statistics. */
void
thread_print_stats (void) 
{
  printf ("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
          idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */
tid_t
thread_create (const char *name, int priority,
               thread_func *function, void *aux) 
{
  struct thread *t;
  struct kernel_thread_frame *kf;
  struct switch_entry_frame *ef;
  struct switch_threads_frame *sf;
  tid_t tid;

  ASSERT (function != NULL);

  /* Allocate thread. */
  t = palloc_get_page (PAL_ZERO);
  if (t == NULL)
    return TID_ERROR;

  /* Initialize thread. */
  init_thread (t, name, priority, thread_current ()->nice, thread_current ()->recent_cpu);
  tid = t->tid = allocate_tid ();

  /* Stack frame for kernel_thread(). */
  kf = alloc_frame (t, sizeof *kf);
  kf->eip = NULL;
  kf->function = function;
  kf->aux = aux;

  /* Stack frame for switch_entry(). */
  ef = alloc_frame (t, sizeof *ef);
  ef->eip = (void (*) (void)) kernel_thread;

  /* Stack frame for switch_threads(). */
  sf = alloc_frame (t, sizeof *sf);
  sf->eip = switch_entry;
  sf->ebp = 0;

  /* Add to run queue. */
  thread_unblock (t);
  thread_possibly_yield();

  return tid;
}

void thread_donate_priority_to_thread (struct thread *a, struct thread *b) 
{
  if (thread_mlfqs)
    return;

  struct thread *cursor;
  /* This `gnarly` for loop just iterates up the tree structure
     for priority donation discussed in the ascii art of DESIGNDOC */
  for (cursor = b; cursor != NULL && a->priority > cursor->priority; 
       cursor = cursor->blocked_lock? cursor->blocked_lock->holder : NULL) {
    thread_change_priority (cursor, a->priority);
  }
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void
thread_block (void) 
{
  ASSERT (!intr_context ());
  ASSERT (intr_get_level () == INTR_OFF);

  thread_current ()->status = THREAD_BLOCKED;
  schedule ();
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
void
thread_unblock (struct thread *t) 
{
  ASSERT (is_thread (t));
  ASSERT (t->status == THREAD_BLOCKED);

  enum intr_level old_level = intr_disable ();
  list_push_back (&ready_lists[t->priority], &t->elem);
  t->status = THREAD_READY;
  intr_set_level (old_level);
}

/* Returns the name of the running thread. */
const char *
thread_name (void) 
{
  return thread_current ()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current (void) 
{
  struct thread *t = running_thread ();
  
  /* Make sure T is really a thread.
     If either of these assertions fire, then your thread may
     have overflowed its stack.  Each thread has less than 4 kB
     of stack, so a few big automatic arrays or moderate
     recursion can cause stack overflow. */
  ASSERT (is_thread (t));
  ASSERT (t->status == THREAD_RUNNING);

  return t;
}

/* Returns the running thread's tid. */
tid_t
thread_tid (void) 
{
  return thread_current ()->tid;
}

/* Stores the exit_code of the process, if necessary.
   Prints a message about the exit of the thread.
   Exits the thread. */
void
thread_exit_with_message (int exit_code) 
{
  printf ("%s: exit(%d)\n", thread_current ()->name, exit_code);
#ifdef USERPROG
  process_set_return_val (exit_code);
#endif
  thread_exit ();
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void
thread_exit (void) 
{
  ASSERT (!intr_context ());

#ifdef USERPROG
  process_exit ();
#endif

  /* Remove thread from all threads list, set our status to dying,
     and schedule another process.  That process will destroy us
     when it calls thread_schedule_tail(). */
  intr_disable ();
  list_remove (&thread_current()->allelem);
  thread_current ()->status = THREAD_DYING;
  schedule ();
  NOT_REACHED ();
}

static void
thread_possibly_yield (void)
{
  if (thread_current ()->priority < find_next_thread_to_run ()->priority)
    thread_yield ();
}
/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
void
thread_yield (void) 
{
  struct thread *cur = thread_current ();
  enum intr_level old_level;
  
  ASSERT (!intr_context ());

  old_level = intr_disable ();
  if (cur != idle_thread) 
    list_push_back (&ready_lists[cur->priority], &cur->elem);
  cur->status = THREAD_READY;
  schedule ();
  intr_set_level (old_level);
}

/* Invoke function 'func' on all threads, passing along 'aux'.
   This function must be called with interrupts off. */
void
thread_foreach (thread_action_func *func, void *aux)
{
  struct list_elem *e;

  ASSERT (intr_get_level () == INTR_OFF);

  for (e = list_begin (&all_list); e != list_end (&all_list);
       e = list_next (e))
    {
      struct thread *t = list_entry (e, struct thread, allelem);
      func (t, aux);
    }
}

/* Update the effective priority of the specified thread
   and ensure that the thread is placed in the correct
   ready queue if necessary. 
   Does not update the native priority of the thread. */
void
thread_change_priority (struct thread *t, int new_priority)
{
  ASSERT (intr_get_level () == INTR_OFF);

  t->priority = new_priority;
  if (t->status == THREAD_READY) {
    list_remove (&t->elem);
    list_push_back (&ready_lists[new_priority], &t->elem);
  }
}

/* Computes the thread's donated priority by iterating
   over the locks that it holds and finding the highest
   priority thread waiting on any of its locks */
int
thread_compute_donated_priority (struct thread *t)
{
  int max_priority = -1;
  struct list_elem *cursor;
  for (cursor = list_begin (&t->locks);
       cursor != list_end (&t->locks);
       cursor = list_next (cursor)) 
    {
      struct lock *heldLock = list_entry (cursor, struct lock, elem);
      struct thread *max_waiter = sema_highest_waiter (&heldLock->semaphore);
    
      if (max_waiter != NULL && max_waiter->priority > max_priority)
        max_priority = max_waiter->priority;
    
    }
  return max_priority;
}

/* Sets the thread's actual priority to the max of
   its native and donated priority. */
void 
thread_update_actual_priority (struct thread *t)
{
  int donated = thread_compute_donated_priority (t);
  if (t->native_priority > donated)
    t->priority = t->native_priority;
  else
    t->priority = donated;
}

/* Computes the MLFQS priority for a given thread and returns it */
static int 
thread_mlfqs_compute_priority (struct thread *t)
{
  fixed_point new_priority = fixed_point_subtract (
    fixed_point_create (PRI_MAX),
    fixed_point_add_int (fixed_point_divide_int (t->recent_cpu, 4), t->nice * 2));
 
  int new_priority_int = fixed_point_truncate (new_priority);
  if (new_priority_int < PRI_MIN) 
    new_priority_int = PRI_MIN;
  else if (new_priority_int > PRI_MAX)
    new_priority_int = PRI_MAX;

  return new_priority_int;
}

/* Computes and updates the recent CPU for a given thread */
static void
thread_mlfqs_update_recent_cpu (struct thread *t, void *aux UNUSED)
{
  if (t == idle_thread)
    return;

  fixed_point penalty_ratio = fixed_point_divide(
    fixed_point_multiply_int (load_average, 2),
    fixed_point_add_int (fixed_point_multiply_int (load_average, 2), 1));

  t->recent_cpu = fixed_point_add_int (
    fixed_point_multiply (penalty_ratio, t->recent_cpu), 
    t->nice);
}

/* Computes and updates the priority of the given thread.
   Makes sure to fix ready lists if necessary. */
static void
thread_mlfqs_update_priority (struct thread *t, void *aux UNUSED)
{
  if (t != idle_thread)
    thread_change_priority (t, thread_mlfqs_compute_priority (t));
}

/* Sets the current RUNNING thread's priority to NEW_PRIORITY. 
   May yield. */
void
thread_set_priority (int new_priority) 
{
  ASSERT(new_priority <= PRI_MAX);
  ASSERT(new_priority >= PRI_MIN);
  enum intr_level old_level = intr_disable ();  
  struct thread *current = thread_current ();
  current->native_priority = new_priority;
  thread_update_actual_priority (current);
  
  thread_possibly_yield (); 
  
  intr_set_level (old_level);
}

/* Computes the count of ready (or currently running non-idle) threads. */
static int
thread_get_ready_thread_count (void) {
  int i;
  int ready_threads = 0;
  for (i = 0; i < PRI_COUNT; i++)
    ready_threads += list_size (&ready_lists[i]);

  if (thread_current () != idle_thread)
    ++ready_threads;
  
  return ready_threads;
}

/* Computes and updates the globala system load average */
static void
thread_mlfqs_update_load_average (void) {
  int ready_thread_count = thread_get_ready_thread_count ();

  fixed_point new_load_avg = fixed_point_divide_int (
    fixed_point_add_int (fixed_point_multiply_int (load_average, 59), ready_thread_count),
    60);

  load_average = new_load_avg;
}

/* Returns the current thread's priority. */
int
thread_get_priority (void) 
{
  return thread_current ()->priority;
}

/* Sets the current thread's nice value to NICE. */
void
thread_set_nice (int nice) 
{
  ASSERT(nice <= NICE_MAX);
  ASSERT(nice >= NICE_MIN);
  enum intr_level old_level = intr_disable ();
  
  thread_current ()->nice = nice;
  thread_set_priority (thread_mlfqs_compute_priority (thread_current ()));

  intr_set_level (old_level);
}

/* Returns the current thread's nice value. */
int
thread_get_nice (void) 
{
  return thread_current ()->nice;
}

/* Returns 100 times the system load average. */
int
thread_get_load_avg (void) 
{
  return fixed_point_round (fixed_point_multiply_int (load_average, 100));
}

/* Returns 100 times the current thread's recent_cpu value. */
int
thread_get_recent_cpu (void) 
{
  return fixed_point_round (fixed_point_multiply_int (thread_current ()->recent_cpu, 100));
}

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle (void *idle_started_ UNUSED) 
{
  struct semaphore *idle_started = idle_started_;
  idle_thread = thread_current ();
  sema_up (idle_started);

  for (;;) 
    {
      /* Let someone else run. */
      intr_disable ();
      thread_block ();

      /* Re-enable interrupts and wait for the next one.

         The `sti' instruction disables interrupts until the
         completion of the next instruction, so these two
         instructions are executed atomically.  This atomicity is
         important; otherwise, an interrupt could be handled
         between re-enabling interrupts and waiting for the next
         one to occur, wasting as much as one clock tick worth of
         time.

         See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
         7.11.1 "HLT Instruction". */
      asm volatile ("sti; hlt" : : : "memory");
    }
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread (thread_func *function, void *aux) 
{
  ASSERT (function != NULL);

  intr_enable ();       /* The scheduler runs with interrupts off. */
  function (aux);       /* Execute the thread function. */
  thread_exit ();       /* If function() returns, kill the thread. */
}

/* Returns the running thread. */
struct thread *
running_thread (void) 
{
  uint32_t *esp;

  /* Copy the CPU's stack pointer into `esp', and then round that
     down to the start of a page.  Because `struct thread' is
     always at the beginning of a page and the stack pointer is
     somewhere in the middle, this locates the curent thread. */
  asm ("mov %%esp, %0" : "=g" (esp));
  return pg_round_down (esp);
}

/* Returns true if T appears to point to a valid thread. */
static bool
is_thread (struct thread *t)
{
  return t != NULL && t->magic == THREAD_MAGIC;
}

/* Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread (struct thread *t, const char *name, int priority, int nice, fixed_point recent_cpu)
{
  enum intr_level old_level;

  ASSERT (t != NULL);
  ASSERT (PRI_MIN <= priority && priority <= PRI_MAX);
  ASSERT (name != NULL);
  
  memset (t, 0, sizeof *t);
  t->status = THREAD_BLOCKED;
  strlcpy (t->name, name, sizeof t->name);
  t->stack = (uint8_t *) t + PGSIZE;
  if(thread_mlfqs)
    priority = PRI_DEFAULT;
  t->priority = priority;
  t->native_priority = priority;
  t->nice = nice;
  t->recent_cpu = recent_cpu;
  list_init (&t->locks);

#ifdef USERPROG
  list_init (&t->file_descriptors);
  list_init (&t->child_processes);
#endif
  list_init (&t->pages_list);

  t->magic = THREAD_MAGIC;

  old_level = intr_disable ();
  list_push_back (&all_list, &t->allelem);
  intr_set_level (old_level);
}

/* Allocates a SIZE-byte frame at the top of thread T's stack and
   returns a pointer to the frame's base. */
static void *
alloc_frame (struct thread *t, size_t size) 
{
  /* Stack data is always allocated in word-size units. */
  ASSERT (is_thread (t));
  ASSERT (size % sizeof (uint32_t) == 0);

  t->stack -= size;
  return t->stack;
}

/* Iterates over the ready lists looking for the highest priority thread.
   Returns the highest priority runnable thread or the idle thread. */
static struct thread *
find_next_thread_to_run (void) 
{
  
  int i;
  for (i = PRI_MAX; i >= 0; i--)
    if (!list_empty (&ready_lists[i]))
      return list_entry (list_begin (&ready_lists[i]), struct thread, elem);

  return idle_thread;
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *
next_thread_to_run (void) 
{
  struct thread *next = find_next_thread_to_run ();
  if (next != idle_thread) {
    list_remove (&next->elem);
  }
  return next;
}

/* Completes a thread switch by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.  This function is normally invoked by
   thread_schedule() as its final action before returning, but
   the first time a thread is scheduled it is called by
   switch_entry() (see switch.S).

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function.

   After this function and its caller returns, the thread switch
   is complete. */
void
thread_schedule_tail (struct thread *prev)
{
  struct thread *cur = running_thread ();
  
  ASSERT (intr_get_level () == INTR_OFF);

  /* Mark us as running. */
  cur->status = THREAD_RUNNING;

  /* Start new time slice. */
  thread_ticks = 0;

#ifdef USERPROG
  /* Activate the new address space. */
  process_activate ();
#endif

  /* If the thread we switched from is dying, destroy its struct
     thread.  This must happen late so that thread_exit() doesn't
     pull out the rug under itself.  (We don't free
     initial_thread because its memory was not obtained via
     palloc().) */
  if (prev != NULL && prev->status == THREAD_DYING && prev != initial_thread) 
    {
      ASSERT (prev != cur);
      palloc_free_page (prev);
    }
}

/* Schedules a new process.  At entry, interrupts must be off and
   the running process's state must have been changed from
   running to some other state.  This function finds another
   thread to run and switches to it.

   It's not safe to call printf() until thread_schedule_tail()
   has completed. */
static void
schedule (void) 
{
  struct thread *cur = running_thread ();
  struct thread *next = next_thread_to_run ();
  struct thread *prev = NULL;

  ASSERT (intr_get_level () == INTR_OFF);
  ASSERT (cur->status != THREAD_RUNNING);
  ASSERT (is_thread (next));

  if (cur != next)
    prev = switch_threads (cur, next);
  thread_schedule_tail (prev);
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid (void) 
{
  static tid_t next_tid = 1;
  tid_t tid;

  lock_acquire (&tid_lock);
  tid = next_tid++;
  lock_release (&tid_lock);

  return tid;
}

/* Offset of `stack' member within `struct thread'.
   Used by switch.S, which can't figure it out on its own. */
uint32_t thread_stack_ofs = offsetof (struct thread, stack);
