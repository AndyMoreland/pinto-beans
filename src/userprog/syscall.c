#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/* Verifies that the given pointer points to valid memory */
static bool
syscall_verify_pointer (void *vaddr) 
{
  struct thread *t = thread_current ();

  /* Check if vaddr is within user address space
     and belongs to a mapped page. */
  return (is_user_vaddr (vaddr) 
          && pagedir_get_page (t->pagedir, pg_round_down (vaddr)) != NULL);
}

/* Verifies that the given pointer offset by `offset` points to a valid
   address */
static bool
syscall_verify_pointer_offset (void *vaddr, size_t offset)
{
  return syscall_verify_pointer ((char *) vaddr + offset);
}

/* Returns the arg_number'th argument. arg_number = 0 returns int number. */
static bool
syscall_pointer_to_arg(struct intr_frame *f, int arg_number, void **buffer)
{
  void *pointer = (void *)((char *)f->esp + sizeof (char *) * arg_number);
  *buffer = pointer;
  return syscall_verify_pointer (pointer)
    && syscall_verify_pointer_offset (pointer, sizeof (void *));
}

static void
syscall_handler (struct intr_frame *f) 
{
  int *interrupt_number;
  if(!syscall_pointer_to_arg(f, 0, (void **) &interrupt_number))
    thread_exit_with_message (SYSCALL_ERROR_EXIT_CODE);

  switch (*interrupt_number) 
    {
    case SYS_HALT:
      syscall_halt (f);
      break;

    case SYS_EXIT:
      syscall_exit (f);
      break;

    case SYS_EXEC:
      syscall_exec (f);
      break;

    case SYS_WAIT:
      syscall_wait (f);
      break;

    case SYS_CREATE:
      syscall_create (f);
      break;

    case SYS_REMOVE:
      syscall_remove (f);
      break;

    case SYS_OPEN:
      syscall_open (f);
      break;

    case SYS_FILESIZE:
      syscall_filesize (f);
      break;

    case SYS_READ:
      syscall_read (f);
      break;

    case SYS_WRITE:
      syscall_write (f);
      break;

    case SYS_SEEK:
      syscall_seek (f);
      break;

    case SYS_TELL:
      syscall_tell (f);
      break;

    case SYS_CLOSE:
      syscall_close (f);
      break;
    }
}


void
syscall_write (struct intr_frame *f)
{
  // FIXME: include return value
  int *fd;
  void **buffer;
  unsigned *size;
  
  if(!syscall_pointer_to_arg(f, 1, (void **) &fd)
     || !syscall_pointer_to_arg(f, 2, (void **) &buffer)
     || !syscall_pointer_to_arg(f, 3, (void **) &size)
     || !syscall_verify_pointer_offset(*buffer, *size))
    thread_exit_with_message (SYSCALL_ERROR_EXIT_CODE);

  if(*fd == STDOUT_FILENO)
    {
      // FIXME: suggested that we might want to break larger buffers
      putbuf(*buffer, *size);
    }
  else
    {
      // FIXME: Do file shit
    }
    
  
  return 0;
}

void 
syscall_exit (struct intr_frame *f)
{
  int *exit_number;

  if(!syscall_pointer_to_arg(f, 1, (void **) &exit_number))
    thread_exit_with_message (SYSCALL_ERROR_EXIT_CODE);

  thread_exit_with_message (*exit_number);
}
