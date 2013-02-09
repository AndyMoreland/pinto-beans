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

static void *
syscall_pointer_to_arg(struct intr_frame *f, int arg_number) {
  return (void *)((char *)f->esp + sizeof (char *) * arg_number);
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  printf ("[syscall_handler] system call!\n");
  printf ("[syscall_handler] we think the number is: %d\n", *(int *)(f->esp));
  // FIXME: need to validate ESP and interrupt number
  int interrupt_number = *(int *)(syscall_pointer_to_arg(f, 0));
  switch (interrupt_number) 
    {
    case SYS_WRITE:
      printf ("[syscall] Attempting to execute 'write'\n");
      // FIXME: need to validate the second pointer and ensure that pointer + size doesn't leave
      // user memory
      write (*(int *)syscall_pointer_to_arg (f, 1), *(void **)syscall_pointer_to_arg (f, 2),  
             *(size_t *)syscall_pointer_to_arg (f, 3)); 
      break;
      
    case SYS_EXIT:
      printf ("[syscall] Attempting to exit with code: %d\n", *(int *) syscall_pointer_to_arg (f, 1));
      // FIXME: record number here.
      thread_exit ();
      break;
    }
}


int 
write (int fd, const void *buffer, unsigned size)
{
  printf ("[syscall] Attemping to write\n");
  if(fd == STDOUT_FILENO)
    {
      // FIXME: suggested that we might want to break larger buffers
      putbuf(buffer, size);
    }
  else
    {
      // FIXME: Do file shit
    }
    
  
  return 0;
}
