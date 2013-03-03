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
#include "userprog/process.h"
#include "devices/shutdown.h"
#include "vm/page.h"

#define FIRST_FD_ID 2
#define FILE_FAILURE -1
#define STACK_BOTTOM 0xbff00000
#define STACK_GROWTH_TOLERANCE 64

static void syscall_handler (struct intr_frame *);
static void syscall_halt (struct intr_frame *f, struct list *pin_list);
static void syscall_exit (struct intr_frame *f, struct list *pin_list);
static void syscall_exec (struct intr_frame *f, struct list *pin_list);
static void syscall_wait (struct intr_frame *f, struct list *pin_list);
static void syscall_create (struct intr_frame *f, struct list *pin_list);
static void syscall_remove (struct intr_frame *f, struct list *pin_list);
static void syscall_open (struct intr_frame *f, struct list *pin_list);
static void syscall_filesize (struct intr_frame *f, struct list *pin_list);
static void syscall_read (struct intr_frame *f, struct list *pin_list);
static void syscall_write (struct intr_frame *f, struct list *pin_list);
static void syscall_seek (struct intr_frame *f, struct list *pin_list);
static void syscall_tell (struct intr_frame *f, struct list *pin_list);
static void syscall_close (struct intr_frame *f, struct list *pin_list);
static void syscall_do_close (int fd_id);

static bool syscall_verify_pointer (void *vaddr, struct list *pin_list, void *esp);
static bool syscall_verify_pointer_offset (void *vaddr, size_t offset, struct list *pin_list, 
                                           void *esp);

static bool syscall_ensure_valid_page (void *uaddr, struct list *pin_list, void *esp);
static void syscall_cleanup_pins_and_exit (int message, struct list *pin_list);

struct file_descriptor {
  struct list_elem elem;
  struct file *f;
  int fd_id;
};

struct pinned_page {
  void *uaddr;
  struct list_elem elem;
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
      if (fd != NULL)
        {
          fd->fd_id = syscall_get_new_fd_id ();
          fd->f = file;
          list_push_back (&t->file_descriptors, &fd->elem);
        }
    }

  return fd;
}

/* Iterates over the current thread's file descriptors and
   frees each of them after closing their files. */
void
syscall_cleanup_process_data (void)
{
  struct thread *t = thread_current ();
  struct list_elem *e;

  for (e = list_begin (&t->file_descriptors);
       e != list_end (&t->file_descriptors);
       e = list_begin (&t->file_descriptors))
    {
      struct file_descriptor *fd = list_entry (e, struct file_descriptor, elem);
      syscall_do_close(fd->fd_id);
    }

  lock_acquire (&fs_lock);
  file_close (t->executable);
  lock_release (&fs_lock);
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static bool
syscall_verify_buffer_writable (void *vaddr, size_t length)
{
  // printf ("Verifying writable\n");
  struct thread *t = thread_current ();
  // printf ("1\n");
  bool result = page_writable (vaddr, t->pagedir)
    && page_writable (vaddr + length, t->pagedir);
  // printf ("yo. 2\n");

  size_t offset_tmp;
  for (offset_tmp = PGSIZE; offset_tmp < length; offset_tmp += PGSIZE)
    result = result && page_writable ((char *) vaddr + offset_tmp, t->pagedir);

  // printf ("3\n");

  return result;
}

/* Verifies that vaddr is within user memory and also mapped to a page */
static bool
syscall_verify_address (void *vaddr, struct list *pin_list, void *esp)
{
  return is_user_vaddr (vaddr)
    && syscall_ensure_valid_page (pg_round_down (vaddr), pin_list, esp);
}

/* Verifies that the given pointer points to valid memory.
   Checks the address and 4 bytes after the address. */
static bool
syscall_verify_pointer (void *vaddr, struct list *pin_list, void *esp) 
{
  /* Check if vaddr is within user address space
     and belongs to a mapped page. */
  return syscall_verify_address (vaddr, pin_list, esp) 
    && syscall_verify_pointer_offset (vaddr, sizeof (void *), pin_list, esp);
}

/* Verifies that the given pointer offset by `offset` points to a valid
   address. 
   Iterates over all pages that are spanned by the offset and makes sure they
   are mapped. */
static bool
syscall_verify_pointer_offset (void *vaddr, size_t offset, struct list *pin_list, void *esp)
{
  bool result = syscall_verify_address (vaddr, pin_list, esp);
  size_t offset_tmp;
  for (offset_tmp = PGSIZE; offset_tmp < offset; offset_tmp += PGSIZE)
    result = result && syscall_verify_address ((char *) vaddr + offset_tmp, pin_list, esp);
  return result && syscall_verify_address ((char *) vaddr + offset, pin_list, esp);
}

/* Makes *buffer point to the arg_number'th arg.
   arg_number = 0 returns interrupt number.
   Verifies that the pointer is valid. */
static bool
syscall_pointer_to_arg (struct intr_frame *f, int arg_number, void **buffer, 
                        struct list *pin_list)
{
  void *pointer = (void *)((char *)f->esp + sizeof (char *) * arg_number);
  *buffer = pointer;
  return syscall_verify_pointer (pointer, pin_list, f->esp);
}

/* Iterates over the characters in the given string buffer.
   Ensures that all bytes are mapped (intelligently) and 
   in user memory. */
static bool
syscall_verify_string (char *str, struct list *pin_list, void *esp)
{
  struct thread *t = thread_current ();

  char *cursor = str;
  void *cur_page = pagedir_get_page (t->pagedir, pg_round_down (cursor));
  void *previous_page_start = pg_round_down (cursor);
  bool valid = is_user_vaddr (cursor) && cur_page != NULL;
  
  syscall_ensure_valid_page (pg_round_down (cursor), pin_list, esp);

  while (valid && *cursor != '\0')
    {
      cursor++;
      if ((void *) cursor - previous_page_start >= PGSIZE)
        {
          cur_page = pagedir_get_page (t->pagedir, pg_round_down (cursor));
          
          previous_page_start = cursor;
          syscall_ensure_valid_page (pg_round_down (cursor), pin_list, esp);
        }
      valid = valid && is_user_vaddr (cursor) && cur_page != NULL;
    }

  return valid;
}

static bool
syscall_potentially_grow_stack (void *uaddr, void *esp)
{
  if ((((int64_t) esp - (int64_t) uaddr <= (int64_t) STACK_GROWTH_TOLERANCE)
       || (uaddr >= esp))
      && (STACK_BOTTOM < uaddr))
    {
      page_create_swap_page (pg_round_down (uaddr), true, true);
      // printf ("Grew the stack!\n");
      return true;
    }
  return false;
}

static bool
syscall_ensure_valid_page (void *uaddr, struct list *pin_list, void *esp)
{
  // printf ("Ensuring [%p] is valid for esp: [%p]\n", uaddr, esp);
  struct list_elem *e;
  /* Check to see if we have already pinned this address' page */
  for (e = list_begin (pin_list); e != list_end (pin_list);
       e = list_next (e))
    {
      struct pinned_page *cursor = list_entry (e, struct pinned_page, elem);
      if (cursor->uaddr == pg_round_down(uaddr))
        return true;
    }

  // printf ("Trying to page in\n");
  /* If we successfully page it in then track it */
  if (page_in_and_pin (pg_round_down (uaddr)))
    {
      struct pinned_page *pp = malloc (sizeof (struct pinned_page));
      pp->uaddr = pg_round_down (uaddr);
      list_push_front (pin_list, &pp->elem);
      // printf ("Successfully paged in!\n");
      return true;
    } 
  else
    {
      /* Try to grow the stack to include this, and then pin it */
      if (syscall_potentially_grow_stack (uaddr, esp))
        return syscall_ensure_valid_page (uaddr, pin_list, esp);
      
      /* Give up */
      return false;
    }
}

static void
syscall_cleanup_pins (struct list *pin_list)
{
  while (!list_empty (pin_list))
    {
      struct pinned_page *pp = list_entry (list_pop_front (pin_list), struct pinned_page, elem);
      page_unpin (pg_round_down (pp->uaddr));
      free (pp);
    }
}

static void
syscall_cleanup_pins_and_exit (int message, struct list *pin_list)
{
  syscall_cleanup_pins (pin_list);
  thread_exit_with_message (message);
}

static void
syscall_handler (struct intr_frame *f) 
{
  struct list pin_list;
  list_init (&pin_list);

  int *interrupt_number;
  if (!syscall_pointer_to_arg (f, 0, (void **) &interrupt_number, &pin_list))
    syscall_cleanup_pins_and_exit (SYSCALL_ERROR_EXIT_CODE, &pin_list);

  switch (*interrupt_number) 
    {
    case SYS_HALT:
      syscall_halt (f, &pin_list);
      break;

    case SYS_EXIT:
      syscall_exit (f, &pin_list);
      break;

    case SYS_EXEC:
      syscall_exec (f, &pin_list);
      break;

    case SYS_WAIT:
      syscall_wait (f, &pin_list);
      break;

    case SYS_CREATE:
      syscall_create (f, &pin_list);
      break;

    case SYS_REMOVE:
      syscall_remove (f, &pin_list);
      break;

    case SYS_OPEN:
      syscall_open (f, &pin_list);
      break;

    case SYS_FILESIZE:
      syscall_filesize (f, &pin_list);
      break;

    case SYS_READ:
      syscall_read (f, &pin_list);
      break;

    case SYS_WRITE:
      syscall_write (f, &pin_list);
      break;

    case SYS_SEEK:
      syscall_seek (f, &pin_list);
      break;

    case SYS_TELL:
      syscall_tell (f, &pin_list);
      break;

    case SYS_CLOSE:
      syscall_close (f, &pin_list);
      break;
    default:
      syscall_cleanup_pins_and_exit (SYSCALL_ERROR_EXIT_CODE, &pin_list);
      break;
    }

  syscall_cleanup_pins (&pin_list);
}

/* Below are syscalls.
   They do what they sound like.
   They are all wrappers around logic implemented
   elsewhere. They perform verification and retrieval of
   their arguments and then pass them on. 
   If they fail they return FILE_FAILURE, or
   whatever what they delegate to returns. */

static void
syscall_create (struct intr_frame *f, struct list *pin_list)
{
  char **file;
  unsigned *initial_size;

  if (!syscall_pointer_to_arg (f, 1, (void **) &file, pin_list)
      || !syscall_verify_string (*file, pin_list, f->esp)
      || !syscall_pointer_to_arg (f, 2, (void **) &initial_size, pin_list))
    syscall_cleanup_pins_and_exit (SYSCALL_ERROR_EXIT_CODE, pin_list);
  
  lock_acquire (&fs_lock);
  f->eax = filesys_create (*file, *initial_size);
  lock_release (&fs_lock);
}

static void
syscall_open (struct intr_frame *f, struct list *pin_list) {
  char **name;
  struct file_descriptor *fd = NULL;

  if (!syscall_pointer_to_arg (f, 1, (void **) &name, pin_list)
      || !syscall_verify_string (*name, pin_list, f->esp))
    syscall_cleanup_pins_and_exit (SYSCALL_ERROR_EXIT_CODE, pin_list);
  
  lock_acquire (&fs_lock);
  if (*name != NULL)
    fd = syscall_create_fd_for_file (*name);
  lock_release (&fs_lock);

  if (fd != NULL)
    f->eax = fd->fd_id;
  else
    f->eax = FILE_FAILURE;
}

void
syscall_do_close (int fd_id)
{
  struct file_descriptor *fd = syscall_get_fd (fd_id);
  
  if (fd != NULL)
    {
      lock_acquire (&fs_lock);
      list_remove (&fd->elem);
      file_close (fd->f);
      free (fd);
      lock_release (&fs_lock);
    }
}

static void
syscall_close (struct intr_frame *f, struct list *pin_list)
{
  int *fd_id;

  if (!syscall_pointer_to_arg (f, 1, (void **) &fd_id, pin_list))
    syscall_cleanup_pins_and_exit (SYSCALL_ERROR_EXIT_CODE, pin_list);

  syscall_do_close (*fd_id);
}

static void
syscall_remove (struct intr_frame *f, struct list *pin_list)
{
  char **name;
  if (!syscall_pointer_to_arg (f, 1, (void **) &name, pin_list)
      || !syscall_verify_string (*name, pin_list, f->esp))
    syscall_cleanup_pins_and_exit (SYSCALL_ERROR_EXIT_CODE, pin_list);

  if (*name != NULL)
    {
      lock_acquire (&fs_lock);
      f->eax = filesys_remove(*name);
      lock_release (&fs_lock);
    }
}

static void
syscall_filesize (struct intr_frame *f, struct list *pin_list)
{
  int *fd_id;

  if (!syscall_pointer_to_arg (f, 1, (void **) &fd_id, pin_list))
    syscall_cleanup_pins_and_exit (SYSCALL_ERROR_EXIT_CODE, pin_list);

  struct file_descriptor *fd = syscall_get_fd (*fd_id);

  lock_acquire (&fs_lock);
  if (fd != NULL)
    f->eax = file_length (fd->f);
  else
    f->eax = FILE_FAILURE;
  lock_release (&fs_lock);
}

static void
syscall_write (struct intr_frame *f, struct list *pin_list)
{
  int *fd_id;
  void **buffer;
  unsigned *size;
  
  if (!syscall_pointer_to_arg (f, 1, (void **) &fd_id, pin_list)
      || !syscall_pointer_to_arg (f, 2, (void **) &buffer, pin_list)
      || !syscall_pointer_to_arg (f, 3, (void **) &size, pin_list)
      || !syscall_verify_pointer_offset (*buffer, *size, pin_list, f->esp))
    syscall_cleanup_pins_and_exit (SYSCALL_ERROR_EXIT_CODE, pin_list);

  if (*fd_id == STDOUT_FILENO)
    {
      putbuf (*buffer, *size);
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
syscall_read (struct intr_frame *f, struct list *pin_list)
{
  int *fd_id;
  void **buffer;
  unsigned *size;
  
  if (!syscall_pointer_to_arg (f, 1, (void **) &fd_id, pin_list)
      || !syscall_pointer_to_arg (f, 2, (void **) &buffer, pin_list)
      || !syscall_pointer_to_arg (f, 3, (void **) &size, pin_list)
      || !syscall_verify_pointer_offset (*buffer, *size, pin_list, f->esp)
      || !syscall_verify_buffer_writable (*buffer, *size))
    syscall_cleanup_pins_and_exit (SYSCALL_ERROR_EXIT_CODE, pin_list);

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
syscall_seek (struct intr_frame *f, struct list *pin_list)
{
  int *fd_id;
  int *position;

  if (!syscall_pointer_to_arg (f, 1, (void **) &fd_id, pin_list)
      || !syscall_pointer_to_arg (f, 2, (void **) &position, pin_list))
    syscall_cleanup_pins_and_exit (SYSCALL_ERROR_EXIT_CODE, pin_list);

  struct file_descriptor *fd = syscall_get_fd (*fd_id);

  lock_acquire (&fs_lock);
  if (fd != NULL)
    file_seek (fd->f, *position);
  lock_release (&fs_lock);
}

static void
syscall_tell (struct intr_frame *f, struct list *pin_list)
{
  int *fd_id;

  if (!syscall_pointer_to_arg (f, 1, (void **) &fd_id, pin_list))
    syscall_cleanup_pins_and_exit (SYSCALL_ERROR_EXIT_CODE, pin_list);

  struct file_descriptor *fd = syscall_get_fd (*fd_id);
  
  lock_acquire (&fs_lock);
  if (fd != NULL)
    f->eax = file_tell (fd->f);
  else
    f->eax = FILE_FAILURE;

  lock_release (&fs_lock);

}

static void 
syscall_exit (struct intr_frame *f, struct list *pin_list)
{
  int *exit_number;

  if (!syscall_pointer_to_arg (f, 1, (void **) &exit_number, pin_list))
    syscall_cleanup_pins_and_exit (SYSCALL_ERROR_EXIT_CODE, pin_list);

  syscall_cleanup_pins_and_exit (*exit_number, pin_list);
}

static void
syscall_halt (struct intr_frame *f UNUSED, struct list *pin_list UNUSED)
{
  shutdown_power_off ();
}

static void
syscall_exec (struct intr_frame *f, struct list *pin_list)
{
  char **cmdline;
  if (!syscall_pointer_to_arg (f, 1, (void **) &cmdline, pin_list)
      || !syscall_verify_string (*cmdline, pin_list, f->esp))
    syscall_cleanup_pins_and_exit (SYSCALL_ERROR_EXIT_CODE, pin_list);

  f->eax = process_execute (*cmdline);
}

static void
syscall_wait (struct intr_frame *f, struct list *pin_list)
{
  int *pid;

  if (!syscall_pointer_to_arg (f, 1, (void **) &pid, pin_list))
    syscall_cleanup_pins_and_exit (SYSCALL_ERROR_EXIT_CODE, pin_list);

  f->eax = process_wait (*pid);
}

