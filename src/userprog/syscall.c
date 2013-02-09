#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  printf ("[syscall_handler] system call!\n");
  printf ("[syscall_handler] we think the number is: %d", *(int *)(f->esp));
  thread_exit ();
}


int 
write (int fd, const void *buffer, unsigned size)
{
  printf("woo\n");
  return;
}
