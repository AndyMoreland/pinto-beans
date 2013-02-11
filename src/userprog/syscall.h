
#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "threads/interrupt.h"

#define SYSCALL_ERROR_EXIT_CODE -1

void syscall_init (void);
void syscall_cleanup_process_data (void);

#endif /* userprog/syscall.h */
