#include <stdio.h>
#include <syscall-nr.h>
#include "userprog/syscall.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/directory.h"
#include "threads/malloc.h"
#include "devices/input.h"
#include "threads/synch.h"
#include "userprog/process.h"
#include "devices/shutdown.h"
#include "user/syscall.h"
#include "filesys/inode.h"

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
static void syscall_chdir (struct intr_frame *f);
static void syscall_mkdir (struct intr_frame *f);
static void syscall_readdir (struct intr_frame *f);
static void syscall_isdir (struct intr_frame *f);
static void syscall_inumber (struct intr_frame *f);
static void syscall_do_close (int fd_id);

static bool syscall_verify_pointer (void *vaddr);
static bool syscall_verify_pointer_offset (void *vaddr, size_t offset);

struct file_descriptor {
  struct list_elem elem;
  struct filedir *filedir; 
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

/* Creates and returns an FD for `name`.
   Opens file.
   Inserts into thread's file list.
   NULL if open failed. */
static struct file_descriptor *
syscall_create_fd_for_file (char *name) {
  struct file_descriptor *fd = NULL;
  struct thread *t = thread_current ();

  struct filedir *handle = filesys_open(name);
      
  if (handle != NULL)
    {
      fd = calloc (1, sizeof (struct file_descriptor));
      if (fd != NULL)
        {
          fd->fd_id = syscall_get_new_fd_id ();
          fd->filedir = handle;
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
  file_close (t->executable);
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/* Verifies that vaddr is within user memory and also mapped to a page */
static bool
syscall_verify_address (void *vaddr)
{
  struct thread *t = thread_current ();
  return is_user_vaddr (vaddr) 
    && pagedir_get_page (t->pagedir, pg_round_down (vaddr)) != NULL;
}

/* Verifies that the given pointer points to valid memory.
   Checks the address and 4 bytes after the address. */
static bool
syscall_verify_pointer (void *vaddr) 
{
  /* Check if vaddr is within user address space
     and belongs to a mapped page. */
  return syscall_verify_address (vaddr) && syscall_verify_pointer_offset (vaddr, sizeof (void *));
}

/* Verifies that the given pointer offset by `offset` points to a valid
   address. 
   Iterates over all pages that are spanned by the offset and makes sure they
   are mapped. */
static bool
syscall_verify_pointer_offset (void *vaddr, size_t offset)
{
  bool result = true;
  size_t offset_tmp;
  for (offset_tmp = PGSIZE; offset_tmp < offset; offset_tmp += PGSIZE)
    result = result && syscall_verify_address ((char *) vaddr + offset_tmp);
  return result && syscall_verify_address ((char *) vaddr + offset);
}

/* Makes *buffer point to the arg_number'th arg.
   arg_number = 0 returns interrupt number.
   Verifies that the pointer is valid. */
static bool
syscall_pointer_to_arg (struct intr_frame *f, int arg_number, void **buffer)
{
  void *pointer = (void *)((char *)f->esp + sizeof (char *) * arg_number);
  *buffer = pointer;
  return syscall_verify_pointer (pointer);
}

/* Iterates over the characters in the given string buffer.
   Ensures that all bytes are mapped (intelligently) and 
   in user memory. */
static bool
syscall_verify_string (char *str)
{
  struct thread *t = thread_current ();

  char *cursor = str;
  void *cur_page = pagedir_get_page (t->pagedir, pg_round_down (cursor));
  void *previous_page_start = pg_round_down (cursor);
  bool valid = is_user_vaddr (cursor) && cur_page != NULL;
  
  while (valid && *cursor != '\0')
    {
      cursor++;
      if ((void *) cursor - previous_page_start >= PGSIZE)
        {
          cur_page = pagedir_get_page (t->pagedir, pg_round_down (cursor));
          previous_page_start = cursor;
        }
      valid = valid && is_user_vaddr (cursor) && cur_page != NULL;
    }

  return valid;
}

static void
syscall_handler (struct intr_frame *f) 
{
  int *interrupt_number;
  if (!syscall_pointer_to_arg (f, 0, (void **) &interrupt_number))
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

    case SYS_CHDIR:
      syscall_chdir (f);
      break;

    case SYS_MKDIR:
      syscall_mkdir (f);
      break;

    case SYS_READDIR:
      syscall_readdir (f);
      break;

    case SYS_ISDIR:
      syscall_isdir (f);
      break;

    case SYS_INUMBER:
      syscall_inumber (f);
      break;

    default:
      thread_exit_with_message (SYSCALL_ERROR_EXIT_CODE);
      break;
    }
}

/* Below are syscalls.
   They do what they sound like.
   They are all wrappers around logic implemented
   elsewhere. They perform verification and retrieval of
   their arguments and then pass them on. 
   If they fail they return FILE_FAILURE, or
   whatever what they delegate to returns. */

static void
syscall_create (struct intr_frame *f)
{
  char **file;
  unsigned *initial_size;

  if (!syscall_pointer_to_arg (f, 1, (void **) &file)
      || !syscall_verify_pointer (*file)
      || !syscall_verify_string (*file)
      || !syscall_pointer_to_arg (f, 2, (void **) &initial_size))
    thread_exit_with_message (SYSCALL_ERROR_EXIT_CODE);
  
  f->eax = filesys_create (*file, *initial_size);
}

static void
syscall_open (struct intr_frame *f) {
  char **name;
  struct file_descriptor *fd = NULL;

  if (!syscall_pointer_to_arg (f, 1, (void **) &name)
      || !syscall_verify_pointer (*name)
      || !syscall_verify_string (*name))
    thread_exit_with_message (SYSCALL_ERROR_EXIT_CODE);
  
  if (*name != NULL)
    fd = syscall_create_fd_for_file (*name);
  
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
      list_remove (&fd->elem);
      if (fd->filedir->mode == FILE_DESCRIPTOR_FILE)
        file_close (fd->filedir->f);
      else
        dir_close (fd->filedir->d);
      free (fd->filedir);
      free (fd);
    }
}

static void
syscall_close (struct intr_frame *f)
{
  int *fd_id;

  if (!syscall_pointer_to_arg (f, 1, (void **) &fd_id))
    thread_exit_with_message (SYSCALL_ERROR_EXIT_CODE);

  syscall_do_close (*fd_id);
}

static void
syscall_remove (struct intr_frame *f)
{
  char **name;
  if (!syscall_pointer_to_arg (f, 1, (void **) &name)
      || !syscall_verify_string (*name))
    thread_exit_with_message (SYSCALL_ERROR_EXIT_CODE);

  if (*name != NULL)
    f->eax = filesys_remove(*name);
}

static void
syscall_filesize (struct intr_frame *f)
{
  int *fd_id;

  if (!syscall_pointer_to_arg (f, 1, (void **) &fd_id))
    thread_exit_with_message (SYSCALL_ERROR_EXIT_CODE);

  struct file_descriptor *fd = syscall_get_fd (*fd_id);

  if (fd != NULL && fd->filedir->mode == FILE_DESCRIPTOR_FILE)
    f->eax = file_length (fd->filedir->f);
  else
    f->eax = FILE_FAILURE;
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
      putbuf (*buffer, *size);
      f->eax = *size;
    }
  else
    {
      struct file_descriptor *fd = syscall_get_fd (*fd_id);

      if (fd != NULL && fd->filedir->mode == FILE_DESCRIPTOR_FILE)
        f->eax = file_write (fd->filedir->f, *buffer, *size);
      else
        f->eax = FILE_FAILURE;
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
    thread_exit_with_message (SYSCALL_ERROR_EXIT_CODE);

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

      if (fd != NULL && fd->filedir->mode == FILE_DESCRIPTOR_FILE)
        f->eax = file_read (fd->filedir->f, *buffer, *size);
      else
        f->eax = FILE_FAILURE;
    }
}

static void
syscall_seek (struct intr_frame *f)
{
  int *fd_id;
  int *position;

  if (!syscall_pointer_to_arg (f, 1, (void **) &fd_id)
      || !syscall_pointer_to_arg (f, 2, (void **) &position))
    thread_exit_with_message (SYSCALL_ERROR_EXIT_CODE);

  struct file_descriptor *fd = syscall_get_fd (*fd_id);

  if (fd != NULL && fd->filedir->mode == FILE_DESCRIPTOR_FILE)
    file_seek (fd->filedir->f, *position);
}

static void
syscall_tell (struct intr_frame *f)
{
  int *fd_id;

  if (!syscall_pointer_to_arg (f, 1, (void **) &fd_id))
    thread_exit_with_message (SYSCALL_ERROR_EXIT_CODE);

  struct file_descriptor *fd = syscall_get_fd (*fd_id);
  
  if (fd != NULL && fd->filedir->mode == FILE_DESCRIPTOR_FILE)
    f->eax = file_tell (fd->filedir->f);
  else
    f->eax = FILE_FAILURE;
}

static void 
syscall_exit (struct intr_frame *f)
{
  int *exit_number;

  if (!syscall_pointer_to_arg (f, 1, (void **) &exit_number))
    thread_exit_with_message (SYSCALL_ERROR_EXIT_CODE);

  thread_exit_with_message (*exit_number);
}

static void
syscall_halt (struct intr_frame *f UNUSED)
{
  shutdown_power_off ();
}

static void
syscall_exec (struct intr_frame *f)
{
  char **cmdline;
  if (!syscall_pointer_to_arg (f, 1, (void **) &cmdline)
      || !syscall_verify_string (*cmdline))
    thread_exit_with_message (SYSCALL_ERROR_EXIT_CODE);

  f->eax = process_execute (*cmdline);
}

static void
syscall_wait (struct intr_frame *f)
{
  int *pid;

  if (!syscall_pointer_to_arg (f, 1, (void **) &pid))
    thread_exit_with_message (SYSCALL_ERROR_EXIT_CODE);

  f->eax = process_wait (*pid);
}

static void
syscall_chdir (struct intr_frame *f)
{
  char **dir;
  struct thread *t = thread_current ();
  if (!syscall_pointer_to_arg (f, 1, (void **) &dir)
      || !syscall_verify_string (*dir))
    thread_exit_with_message (SYSCALL_ERROR_EXIT_CODE);

  lock_acquire (&fs_lock);
  struct dir *new_dir = filesys_open_dir (*dir);
  if (new_dir)
    {
      if (t->working_directory != NULL)
        dir_close (t->working_directory);
      t->working_directory = new_dir;
      f->eax = true;
    }
  else
    f->eax = false;
  lock_release (&fs_lock);
}

static void
syscall_mkdir (struct intr_frame *f)
{
  char **dir;

  if (!syscall_pointer_to_arg (f, 1, (void **) &dir)
      || !syscall_verify_string (*dir))
    thread_exit_with_message (SYSCALL_ERROR_EXIT_CODE);
  
  lock_acquire (&fs_lock);
  f->eax = filesys_mkdir (*dir);
  lock_release (&fs_lock);
}

static void
syscall_readdir (struct intr_frame *f)
{
  int *fd_id;
  char **name;

  if (!syscall_pointer_to_arg (f, 1, (void **) &fd_id)
      || !syscall_pointer_to_arg (f, 2, (void **) &name)
      || !syscall_verify_pointer_offset (*name, READDIR_MAX_LEN + 1))
    thread_exit_with_message (SYSCALL_ERROR_EXIT_CODE);

  struct file_descriptor *fd = syscall_get_fd (*fd_id);  

  if (fd->filedir->mode == FILE_DESCRIPTOR_DIR)
    f->eax = dir_readdir (fd->filedir->d, *name);
  else
    f->eax = FILE_FAILURE;

}

static void
syscall_isdir (struct intr_frame *f)
{
  int *fd_id;
  if (!syscall_pointer_to_arg (f, 1, (void **) &fd_id))
    thread_exit_with_message (SYSCALL_ERROR_EXIT_CODE);

  lock_acquire (&fs_lock);
  struct file_descriptor *fd = syscall_get_fd (*fd_id);  
  lock_release (&fs_lock);
  f->eax = fd->filedir->mode == FILE_DESCRIPTOR_DIR;
}

static void
syscall_inumber (struct intr_frame *f)
{
  int *fd_id;
  
  if (!syscall_pointer_to_arg (f, 1, (void **) &fd_id))
    thread_exit_with_message (SYSCALL_ERROR_EXIT_CODE);

  lock_acquire (&fs_lock);
  struct file_descriptor *fd = syscall_get_fd (*fd_id);  
  
  if (fd->filedir->mode == FILE_DESCRIPTOR_FILE)
    f->eax = inode_get_inumber (file_get_inode (fd->filedir->f));
  else
    f->eax = inode_get_inumber (dir_get_inode (fd->filedir->d));
  lock_release (&fs_lock);
}
