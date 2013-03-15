#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "filesys/cache.h"
#include "threads/malloc.h"

#define DEFAULT_DIR_SIZE 16

/* Partition that contains the file system. */
struct block *fs_device;

static void do_format (void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) 
{
  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");

  inode_init ();
  free_map_init ();

  if (format) 
    do_format ();

  free_map_open ();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void) 
{
  free_map_close ();
  cache_flush_all ();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *path, off_t initial_size) 
{
  block_sector_t inode_sector = 0;
  char *filename = dir_split_filename (path);
  if (!filename)
    return false;

  // printf ("Creating file: [%s]\n", filename);
  struct dir *dir = dir_open_base_dir (path);
  struct dir *containing_dir = dir_lookup_containing_dir (path, dir);
  bool success = (dir != NULL && containing_dir != NULL
                  && free_map_allocate (1, &inode_sector)
                  && inode_create (inode_sector, initial_size, false)
                  && dir_add (containing_dir, filename, inode_sector));

  if (!success && inode_sector != 0) 
    free_map_release (inode_sector, 1);

  if (dir != NULL)
    dir_close (dir);
  
  if (containing_dir != NULL)
    dir_close (containing_dir);

  free (filename);

  return success;
}

struct filedir *
filesys_open (const char *name)
{
  struct filedir *fd = malloc (sizeof (struct filedir));
  fd->f = filesys_open_file (name);

  if (fd->f != NULL)
    {
      fd->mode = FILE_DESCRIPTOR_FILE;
      return fd;
    }
  else
    {
      fd->d = filesys_open_dir (name);
      if (fd->d)
        {
          fd->mode = FILE_DESCRIPTOR_DIR;
          return fd;
        }
      
    }
  free (fd);
  return NULL;
}


/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *
filesys_open_file (const char *path)
{
  struct dir *dir = dir_open_base_dir (path);
  struct inode *inode = NULL;
  
  if (dir != NULL)
    inode = dir_resolve_path (path, dir);
  dir_close (dir);

  if (!inode)
    return NULL;

  if (inode_is_dir (inode))
    {
      inode_close (inode);
      return NULL;
    }
  else
    return file_open (inode);
}

static bool
filesys_path_all_slashes (const char *path)
{
  if (strlen (path) == 0)
    return false;

  const char *cursor;
  for (cursor = path; *cursor != '\0'; cursor++)
    if (*cursor != '/')
      return false;

  return true;
}

/* Opens the dir with the given NAME.
   Returns the new dir if successful or a null pointer
   otherwise.
   Fails if no dir named NAME exists,
   or if an internal memory allocation fails. */
struct dir *
filesys_open_dir (const char *path)
{
  struct dir *dir = dir_open_base_dir (path);
  struct inode *inode = NULL;

  if (filesys_path_all_slashes (path))
    path = "/.";
  
  if (dir != NULL)
    inode = dir_resolve_path (path, dir);
  dir_close (dir);

  if (!inode)
    return NULL;

  if (!inode_is_dir (inode))
    {
      inode_close (inode);
      return NULL;
    }
  else
    return dir_open (inode);
}


/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
//FIXME my freeing here is terrible.
bool
filesys_remove (const char *path) 
{
  char *filename = dir_split_filename (path);
  
  if (filename == NULL)
    return false;

  struct dir *dir = dir_open_base_dir (path);
  if (dir == NULL) {
    free(filename);
    return false;
  }

  struct dir *containing_dir = dir_lookup_containing_dir (path, dir);
  
  if (containing_dir == NULL) {
    free (filename);
    dir_close (dir);
    return false;
  }

  bool success = dir_remove (containing_dir, filename);
  dir_close (dir); 
  dir_close (containing_dir);
  free (filename);

  return success;
}

bool
filesys_mkdir (const char *path)
{
  char *filename = dir_split_filename (path);
  if (filename == NULL)
    return false;

  bool success = true;
  block_sector_t inode_sector = 0;

  struct dir *dir = dir_open_base_dir (path);

  if (dir != NULL)
    {
      struct dir *containing_dir = dir_lookup_containing_dir (path, dir);
      if (containing_dir == NULL)
        {
          dir_close (dir);
          return false;
        }
      success = success && free_map_allocate (1, &inode_sector);
      success = success && dir_create (inode_sector, DEFAULT_DIR_SIZE);
      success = success && dir_init (inode_sector, dir_get_inode (containing_dir));
      success = success && dir_add (containing_dir, filename, inode_sector);
      // printf ("Attempting to add sector [%d] to [%p] and success: [%d]\n", inode_sector, dir_get_inode (containing_dir), success);
      dir_close (containing_dir);
      dir_close (dir);
    }

  if (!success && inode_sector != 0) 
    free_map_release (inode_sector, 1);
  
  free (filename);
  return success;
}


/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR, DEFAULT_DIR_SIZE))
    PANIC ("root directory creation failed");
  struct inode *root_inode = inode_open (ROOT_DIR_SECTOR);
  dir_init (ROOT_DIR_SECTOR, root_inode);
  inode_close (root_inode);
  free_map_close ();
  printf ("done.\n");
}
