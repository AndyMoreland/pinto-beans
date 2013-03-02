#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "userprog/syscall.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "vm/page.h"
#include "vm/frame.h"

/* Maximum command line arguments. */
#define MAX_ARGS 128

static thread_func start_process NO_RETURN;
static bool load (const char *file_name, int argc, char **argv, 
                  void (**eip) (void), void **esp);
static int parse_words (char *cmdline, char **argv, int max_argc);

/* Struct used for storing process data that needs to 
   live on after the process dies. */
struct pdata {
  struct list_elem elem; // used for storage in list of child processes
  int tid; // id of thread associated with this process
  struct lock monitor; // Monitor variable that guards struct state
  struct semaphore dead_latch; // 0 tickets if thread alive, 1 if dead
  int references; // initialized to 2 -- decremented when parent/child die
  int process_return_val;
};

/* Removes the given tid's pdata from parent's child list */
/* Returns the pdata struct of the child if succesful or NULL */
static struct pdata *
pdata_remove_tid (struct thread *parent, tid_t tid)
{
  if (!parent)
    return NULL;

  struct list_elem *e;
  struct list *children = &parent->child_processes;
  for (e = list_begin (children); e != list_end (children);
       e = list_next (e))
    {
      struct pdata *child = list_entry (e, struct pdata, elem);
      if (child->tid == tid)
        {
          list_remove (e);
          return child;
        }
    }

  return NULL;
}

/* Returns a pointer to the pdata struct for the current thread. */
static struct pdata *
pdata_current (void)
{
  return thread_current ()->pdata;
}

/* Creates a new pdata struct and initializes the members. */
static struct pdata *
pdata_create (void)
{
  struct pdata *p = malloc (sizeof (struct pdata));
  if (!p)
    return NULL;
  memset (p, 0, sizeof (struct pdata));

  lock_init (&p->monitor);
  sema_init (&p->dead_latch, 0);
  p->references = 2;
  return p;
}

/* Decrements the ref count of the given pdata.
   If the ref count drops to 0, frees the struct */
static void 
pdata_release (struct pdata *p)
{
  if (!p) 
    return;

  lock_acquire (&p->monitor);
  p->references--;
  bool should_free = (p->references == 0);
  lock_release (&p->monitor);

  if (should_free) 
    free (p);
}

/* Called when t exits. Iterates over children
   releasing t's reference to them.
   Also decrements t's own pdata block's reference
   count and releases the semaphore */
static void pdata_on_exit (struct thread *t)
{
  struct pdata *p = t->pdata;

  struct list *children = &t->child_processes;
  while (!list_empty (children))
    {
      struct list_elem *e = list_pop_front (children);
      struct pdata *child = list_entry (e, struct pdata, elem);
      pdata_release (child);
    }

  if (p)
    {
      sema_up (&p->dead_latch);
      pdata_release (p);
    }
}

/* Utility struct used for argument passing
   and synchronization with exec syscall */
struct process_init_data {
  char *cmdline;
  struct thread *parent_process;
  struct semaphore sema;
  bool success;
};

/* stroktok_r's over the cmdline. Returns argc and
   updates argv. */
static int
parse_words (char *cmdline, char **argv, int max_argc) {
  char *word;
  char *context;
  int count = 0;

  for (word = strtok_r (cmdline, " ", &context); word && count < max_argc;
       word = strtok_r (NULL, " ", &context)) {
     argv[count++] = word;
  }

  return count;
}

/* Finds the first word of 'src' (all characters before the first
   space or null-terminator) and stores it into 'dst'.

   The result is null-terminated in 'dst'. returns the length of
   the sequence read, not including the null-terminator. */
static int 
parse_first_word (char *dst, const char *src, int buflen)
{
  ASSERT (dst && src);
  ASSERT (buflen > 0);

  int c = 0;
  int maxlen = buflen - 1;
  while (c < maxlen && src[c] && src[c] != ' ')
    {
      dst[c] = src[c];
      ++c;
    }

  dst[c] = 0;
  return c;
}

/* Updates the return value in the current
   threads pdata block. Used in thread.c */
void 
process_set_return_val (int retval)
{
  struct pdata *p = pdata_current ();  
  if (p)
    p->process_return_val = retval;
}

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *cmdline) 
{
  char *cmdline_copy;
  tid_t tid;

  /* We require that a cmdline input be at most the size of a page. */
  if (strlen (cmdline) > PGSIZE)
    return TID_ERROR;

  size_t bufsize = strlen (cmdline) + 1;
  cmdline_copy = malloc (bufsize);
  if (!cmdline_copy)
    return TID_ERROR;
  
  strlcpy (cmdline_copy, cmdline, bufsize);
  
  /* Create a new thread to execute FILE_NAME. */
  char process_name[20];
  parse_first_word (process_name, cmdline, sizeof (process_name));

  struct process_init_data data;
  data.cmdline = cmdline_copy;
  data.parent_process = thread_current ();
  sema_init (&data.sema, 0);

  tid = thread_create (process_name, PRI_DEFAULT, start_process, &data);
  sema_down (&data.sema);
  
  if (tid == TID_ERROR)
    {
      free (data.cmdline);
      return TID_ERROR;
    }
  return data.success? tid : TID_ERROR;
}

static int
process_estimate_stack_size (int strlen, int argc)
{
  int stack_size = strlen; // size of args passed
  stack_size += sizeof (int); // padding (up to 4 bytes)
  stack_size += sizeof (char *); // argv[argc]
  stack_size += argc * sizeof (char *); // argv[0...1]
  stack_size += sizeof (char * *); // &argv
  stack_size += sizeof (int); // argc
  stack_size += sizeof (void *); // return address
  
  return stack_size;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *aux)
{
  struct process_init_data* init_data = (struct process_init_data *)aux;
  char *argv[MAX_ARGS];
  int argc = parse_words (init_data->cmdline, argv, MAX_ARGS);
  char *file_name = argv[0];
  struct intr_frame if_;
  bool success;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (file_name, argc, argv, &if_.eip, &if_.esp);

  free (init_data->cmdline);
  init_data->cmdline = NULL; 

  if (success)
    {
      struct pdata *process_data = pdata_create ();
      if (!process_data)
        success = false;
      else
        {
          process_data->tid = thread_current ()->tid;
          thread_current ()->pdata = (void *)process_data;
          thread_current ()->parent_process = init_data->parent_process;
          list_push_back (&init_data->parent_process->child_processes, &process_data->elem);
        }
    }
        
  init_data->success = success;
  sema_up (&init_data->sema);
  /* If load failed, quit. */

  if (!success) 
    {
      thread_exit ();
    }

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting. */
int
process_wait (tid_t child_tid)
{
  if (1) {
    struct pdata *child = pdata_remove_tid (thread_current (), child_tid);
    if (!child)
      return -1;

    sema_down (&child->dead_latch);
    int retval = child->process_return_val;
    pdata_release (child);
    return retval;
  }

  return -1;
}

/* Free the current process's data, file descriptors and page table. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  /* Close open file descriptors */
  syscall_cleanup_process_data ();
  
  /* Decrement refcount on thread's pdata, release sema */
  pdata_on_exit (cur);
  
  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL)
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      while (!list_empty (&cur->pages_list))
        page_free_page (list_front (&cur->pages_list));
      pagedir_destroy (pd);
    }

}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack_with_args (void **esp, int argc, char *argv[]);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
static bool 
load (const char *file_name, int argc, char **argv,
      void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;
  int strlen_args = 0;

  for (i = 0; i < argc; i++)
    strlen_args += strlen(argv[i]);
  
  int stack_size = process_estimate_stack_size (strlen_args, argc);

  /* We have an overestimate for the stack size required for the
     args passed. If this exceeds a page, bail out! */
  if (stack_size > PGSIZE)
    {
      success = false;
      goto done;
    }
    
  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Open executable file. */
  lock_acquire (&fs_lock);
  file = filesys_open (file_name);
  lock_release (&fs_lock);

  if (file == NULL)
      goto done; 

  t->executable = file;
  /* Read and verify executable header. */
  lock_acquire (&fs_lock);
  file_deny_write (file);
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      goto done; 
    }
  lock_release (&fs_lock);
  
  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      lock_acquire (&fs_lock);
      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);
      lock_release (&fs_lock);

      lock_acquire (&fs_lock);
      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      lock_release (&fs_lock);

      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }
  
  /* Set up stack. */
  if (!setup_stack_with_args (esp, argc, argv))
    goto done;
  
  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  if (lock_held_by_current_thread (&fs_lock))
    lock_release (&fs_lock);

  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);
  
  // printf ("WRITABLE(%p): %d\n", upage, writable);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      bool success;
      if (page_read_bytes)
        success = page_create_mmap_page (file, ofs, 
           page_read_bytes, upage, writable, writable);
      else
        success = page_create_swap_page (upage, true, writable);
        
      if (!success)
        return false;

      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      ofs += PGSIZE;
      upage += PGSIZE;
    }
  return true;
}

/* create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack_with_args (void **esp, int argc, char *argv[])
{
  uint8_t *kpage;
  bool success = false;
  char *string_locations[argc];

//  kpage = frame_get_kernel_addr (frame_get_frame_pinned (((uint8_t *) PHYS_BASE) - PGSIZE, thread_current ()->pagedir));
  kpage = ((uint8_t *) PHYS_BASE) - PGSIZE;
  if (page_create_swap_page (kpage, true, true)) {
    success = true;
  } else {
    kpage = NULL;
  }
//  memset (kpage, 0, PGSIZE);
//  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
//      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success) 
        {
          page_in_and_pin (kpage);
          *esp = PHYS_BASE;
          int i;
          for (i = argc - 1; i >= 0; i--)
            {
              /* Store the arguments on the stack */
              *esp -= strlen (argv[i]) + 1;
              string_locations[i] = *esp;
              memcpy (*esp, argv[i], strlen (argv[i]) + 1);
            }
          /* Alignment padding and argv[argc] = 0 */

          *esp -= (size_t) *esp % 4;
          *esp -= sizeof (char *);
          
          for (i = argc - 1; i >= 0; i--) 
            {
              /* Store pointers to arguments */
              *esp -= sizeof (char *);
              memcpy (*esp, &string_locations[i], sizeof (char *)); 
            }

          /* Store argv pointer */
          void *tmp = *esp;
          *esp -= sizeof (char **);
          memcpy (*esp, &tmp, sizeof (char *));

          /* Store argc */
          *esp -= sizeof (int);
          memcpy (*esp, &argc, sizeof (int));
          
          /* Make space for return address */
          *esp -= sizeof (void *);
          page_unpin (kpage);
        }
      else
        palloc_free_page (kpage);
    }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
