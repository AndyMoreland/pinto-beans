
#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "threads/interrupt.h"

/* Return value for failed syscalls. */
#define SYSCALL_ERROR_EXIT_CODE -1

/* Stack growth tolerances */
#define STACK_BOTTOM 0xbf800000
#define STACK_GROWTH_TOLERANCE 32

void syscall_init (void);
void syscall_cleanup_process_data (void);

#endif /* userprog/syscall.h */
