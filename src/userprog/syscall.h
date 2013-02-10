
#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "threads/interrupt.h"

#define SYSCALL_ERROR_EXIT_CODE 1

void syscall_init (void);
void syscall_halt (struct intr_frame *f);
void syscall_exit (struct intr_frame *f);
void syscall_exec (struct intr_frame *f);
void syscall_wait (struct intr_frame *f);
void syscall_create (struct intr_frame *f);
void syscall_remove (struct intr_frame *f);
void syscall_open (struct intr_frame *f);
void syscall_filesize (struct intr_frame *f);
void syscall_read (struct intr_frame *f);
void syscall_write (struct intr_frame *f);
void syscall_seek (struct intr_frame *f);
void syscall_tell (struct intr_frame *f);
void syscall_close (struct intr_frame *f);

#endif /* userprog/syscall.h */
