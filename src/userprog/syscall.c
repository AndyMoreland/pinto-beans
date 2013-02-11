#include <stdio.h>
#include <syscall-nr.h>
#include "userprog/syscall.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/malloc.h"
#include "devices/input.h"
#include "threads/synch.h"

#define FIRST_FD_ID 2
#define FILE_FAILURE -1

static void syscall_handler (struct intr_frame *);
static void syscall_halt (struct intr_frame *f);
static void syscall_exit (struct intr_frame *f);
static void syscall_exec (struct intr_frame *f);
static void syscall_wait (struct intr_frame *f);
static void syscall_create (struct intr_frame *f);
static void syscall_remove (struct intr_frame *f);
static void syscall_open (struct intr_frame *f);
static void syscall_filesize (struct intr_frame *f);
static void syscall_read (struct intr_frame *f);
static void syscall_write (struct intr_frame *f);
static void syscall_seek (struct intr_frame *f);
static void syscall_tell (struct intr_frame *f);
static void syscall_close (struct intr_frame *f);
static void syscall_do_close (int fd_id);
static void syscall_exit_and_cleanup (int code);

struct file_descriptor {
  struct list_elem elem;
  struct file *f;
  int fd_id;
};

/* Return a new FD ID for the current thread. Starts at FIRST_FD_ID.  */
static int
syscall_get_new_fd_id (void)
{
  struct thread *t = thread_current ();

  t->highest_fd_id++;

  if (t->highest_fd_id < 2)
    t->highest_fd_id = 2;
  
  return t->highest_fd_id;
}

/* Get the file descriptor associated with fd_id in the current thread.
   Returns NULL if none found. */
static struct file_descriptor *
syscall_get_fd (int fd_id) 
{
  struct thread *t = thread_current ();
  struct list_elem *e;

  for (e = list_begin (&t->file_descriptors);
       e != list_end (&t->file_descriptors);
       e = list_next (e))
    {
      struct file_descriptor *fd = list_entry (e, struct file_descriptor, elem);
      if (fd->fd_id == fd_id)
        return fd;
    }

  return NULL;
}

/* Get the file associated with the fd_id.
   Returns NULL if none found. */
static struct file *
syscall_get_file (int fd_id) 
{
  struct file_descriptor *fd = syscall_get_fd (fd_id);
  return fd->f;
}

/* Creates and returns an FD for `name`.
   Opens file.
   Inserts into thread's file list.
   NULL if open failed. */
static struct file_descriptor *
syscall_create_fd_for_file (char *name) {
  struct file *file = filesys_open(name);
  struct file_descriptor *fd = NULL;
  struct thread *t = thread_current ();

  if (file != NULL)
    {
      fd = calloc (1, sizeof (struct file_descriptor));
      fd->fd_id = syscall_get_new_fd_id ();
      fd->f = file;
      list_push_back (&t->file_descriptors, &fd->elem);
    }

  return fd;
}

void
syscall_exit_and_cleanup (int code) 
{
  struct thread *t = thread_current ();
  struct list_elem *e;

  for (e = list_begin (&t->file_descriptors);
       e != list_end (&t->file_descriptors);
       e = list_next (e))
    {
      struct file_descriptor *fd = list_entry (e, struct file_descriptor, elem);
      syscall_do_close(fd->fd_id);
    }

  thread_exit_with_message (code);
}

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

static void
syscall_create (struct intr_frame *f)
{
  char **file;
  unsigned *initial_size;

  if (!syscall_pointer_to_arg (f, 1, (void **) &file)
     || !syscall_pointer_to_arg (f, 2, (void **) &initial_size))
    syscall_exit_and_cleanup (SYSCALL_ERROR_EXIT_CODE);
  
  lock_acquire (&fs_lock);
  f->eax = filesys_create (*file, *initial_size);
  lock_release (&fs_lock);
}

static void
syscall_open (struct intr_frame *f) {
  char **name;
  struct file_descriptor *fd = NULL;

  if (!syscall_pointer_to_arg (f, 1, (void **) &name))
    syscall_exit_and_cleanup (SYSCALL_ERROR_EXIT_CODE);
  
  lock_acquire (&fs_lock);
  if(*name != NULL)
    fd = syscall_create_fd_for_file (*name);
  lock_release (&fs_lock);
  
  if (fd != NULL)
    f->eax = fd->fd_id;
  else
    f->eax = FILE_FAILURE;
}

static void
syscall_do_close (int fd_id)
{
  struct file_descriptor *fd = syscall_get_fd (fd_id);
  
  if (fd != NULL)
    {
      lock_acquire (&fs_lock);
      file_close (fd->f);
      free(fd);
      lock_release (&fs_lock);
    }
}

static void
syscall_close (struct intr_frame *f)
{
  int *fd_id;

  if (!syscall_pointer_to_arg (f, 1, (void **) &fd_id))
    syscall_exit_and_cleanup (SYSCALL_ERROR_EXIT_CODE);

  lock_acquire (&fs_lock);
  syscall_do_close(*fd_id);
  lock_release (&fs_lock);
}

static void
syscall_remove (struct intr_frame *f)
{
  char **name;

  if (!syscall_pointer_to_arg (f, 1, (void **) &name))
    syscall_exit_and_cleanup (SYSCALL_ERROR_EXIT_CODE);

  if (*name != NULL)
    {
      lock_acquire (&fs_lock);
      if (filesys_remove(*name))
        f->eax = true;
      else
        f->eax = false;
      lock_release (&fs_lock);
    }
}

static void
syscall_filesize (struct intr_frame *f)
{
  int *fd_id;

  if (!syscall_pointer_to_arg (f, 1, (void **) &fd_id))
    syscall_exit_and_cleanup (SYSCALL_ERROR_EXIT_CODE);

  struct file_descriptor *fd = syscall_get_fd (*fd_id);

  lock_acquire (&fs_lock);
  if (fd != NULL)
    f->eax = file_length (fd->f);
  else
    f->eax = FILE_FAILURE;
  lock_release (&fs_lock);
}

static void
syscall_write (struct intr_frame *f)
{
  int *fd_id;
  void **buffer;
  unsigned *size;
  
  if (!syscall_pointer_to_arg (f, 1, (void **) &fd_id)
     || !syscall_pointer_to_arg (f, 2, (void **) &buffer)
     || !syscall_pointer_to_arg (f, 3, (void **) &size)
     || !syscall_verify_pointer_offset (*buffer, *size))
    thread_exit_with_message (SYSCALL_ERROR_EXIT_CODE);

  if (*fd_id == STDOUT_FILENO)
    {
      putbuf(*buffer, *size);
      f->eax = *size;
    }
  else
    {
      struct file_descriptor *fd = syscall_get_fd (*fd_id);

      lock_acquire (&fs_lock);
      if (fd != NULL)
        f->eax = file_write (fd->f, *buffer, *size);
      else
        f->eax = FILE_FAILURE;
      lock_release (&fs_lock);
    }
}

static void
syscall_read (struct intr_frame *f)
{
  int *fd_id;
  void **buffer;
  unsigned *size;
  
  if (!syscall_pointer_to_arg (f, 1, (void **) &fd_id)
     || !syscall_pointer_to_arg (f, 2, (void **) &buffer)
     || !syscall_pointer_to_arg (f, 3, (void **) &size)
     || !syscall_verify_pointer_offset (*buffer, *size))
    syscall_exit_and_cleanup (SYSCALL_ERROR_EXIT_CODE);

  if (*fd_id == STDIN_FILENO)
    {
      unsigned bytes_read = 0;

      while (bytes_read < *size)
        (*(uint8_t **)buffer)[bytes_read++] = input_getc ();

      f->eax = bytes_read;
    }
  else
    {
      struct file_descriptor *fd = syscall_get_fd (*fd_id);

      lock_acquire (&fs_lock);
      if (fd != NULL)
        f->eax = file_read (fd->f, *buffer, *size);
      else
        f->eax = FILE_FAILURE;
      lock_release (&fs_lock);
    }
}

static void
syscall_seek (struct intr_frame *f)
{
  int *fd_id;
  int *position;

  if (!syscall_pointer_to_arg (f, 1, (void **) &fd_id)
      || !syscall_pointer_to_arg (f, 2, (void **) &position))
    syscall_exit_and_cleanup (SYSCALL_ERROR_EXIT_CODE);

  struct file_descriptor *fd = syscall_get_fd (*fd_id);

  lock_acquire (&fs_lock);
  if (fd != NULL)
    file_seek (fd->f, *position);
  lock_release (&fs_lock);
}

static void
syscall_tell (struct intr_frame *f)
{
  int *fd_id;

  if (!syscall_pointer_to_arg (f, 1, (void **) &fd_id))
    syscall_exit_and_cleanup (SYSCALL_ERROR_EXIT_CODE);

  struct file_descriptor *fd = syscall_get_fd (*fd_id);
  
  lock_acquire (&fs_lock);
  if (fd != NULL)
    f->eax = file_tell (fd->f);
  lock_release (&fs_lock);

  f->eax = FILE_FAILURE;
}

static void 
syscall_exit (struct intr_frame *f)
{
  int *exit_number;

  if (!syscall_pointer_to_arg (f, 1, (void **) &exit_number))
    syscall_exit_and_cleanup (SYSCALL_ERROR_EXIT_CODE);

  syscall_exit_and_cleanup (*exit_number);
}

static void
syscall_halt (struct intr_frame *f)
{
}

static void
syscall_exec (struct intr_frame *f)
{
}

static void
syscall_wait (struct intr_frame *f)
{
}
