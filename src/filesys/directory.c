#include "filesys/directory.h"
#include <stdio.h>
#include <string.h>
#include <list.h>
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"

/* A directory. */
struct dir 
  {
    struct inode *inode;                /* Backing store. */
    off_t pos;                          /* Current position. */
  };

/* A single directory entry. */
struct dir_entry 
  {
    block_sector_t inode_sector;        /* Sector number of header. */
    char name[NAME_MAX + 1];            /* Null terminated file name. */
    bool in_use;                        /* In use or free? */
  };

static bool dir_can_remove_dir (struct inode *dir_inode);

/* Lock DIR. This lock is not exposed outside of
   this file so make sure to unlock it before returning
   to the user. */
static void
dir_lock_dir (struct dir *dir)
{
  inode_acquire_dir_lock (dir->inode);
}

/* Unlock DIR. Must be called before returning from
   any directory entrypoint function that locks DIR. */
static void
dir_unlock_dir (struct dir *dir)
{
  inode_release_dir_lock (dir->inode);
}

/* Returns pointer to heap allocated filename component of PATH.
   Returns NULL if memory allocation fails.
   Caller must free. */
char *
dir_split_filename (const char *path)
{
  ASSERT (path != NULL);

  char *cursor;
  for (cursor = &path[strlen (path)]; cursor > path; cursor--)
      if (*cursor == '/')
          break;

  if (*cursor == '/')
    cursor++;

  char *return_val = malloc (strlen (cursor) + 1);
  if (return_val == NULL)
    return NULL;
  strlcpy (return_val, cursor, strlen (cursor) + 1);

  return return_val;
}

/* Returns inode of file or dir at end of PATH relative to BASE.
   NULL if not found. 
   Caller must free BASE and returned INODE. */
struct inode *
dir_resolve_path (const char *path, struct dir *base)
{
  if (strlen (path) == 0)
    return NULL;

  struct dir *containing_dir = dir_lookup_containing_dir (path, base);

  if (containing_dir == NULL) {
    return NULL;
  }

  dir_lock_dir (containing_dir);

  char *filename = dir_split_filename (path);
  if (filename == NULL)
    {
      dir_close (containing_dir);
      dir_unlock_dir (containing_dir);
      return NULL;
    }
  struct inode *result;
  dir_lookup (containing_dir, filename, &result);
  dir_unlock_dir (containing_dir);
  dir_close (containing_dir);
  free (filename);
  
  return result;
}

/* Given a full pathNAME relative to BASE it will
   return a `struct dir *` pointing to the last dir in the pathname. 
   Caller is responsible for closing BASE and returned dir.
   May return BASE reopened.
   Returns unlocked dir.
*/
struct dir *
dir_lookup_containing_dir (const char *path, struct dir *base)
{
  if (path == NULL)
    return NULL;

  char *context;
  char *word = NULL;
  char *next = NULL;
  // malloced because we don't support stack extension
  char *buffer = malloc (strlen (path) + 1);
  if (!buffer)
    return NULL;
  strlcpy (buffer, path, strlen (path) + 1);

  struct dir *current_dir = base;
  dir_lock_dir (current_dir);
  struct inode *current_inode;

  /* Loop executes once for each WORD in the NAME filepath */
  for (word = strtok_r (buffer, "/", &context), next = strtok_r (NULL, "/", &context); next;
       word = next, next = strtok_r (NULL, "/", &context)) 
    {
      if (dir_lookup (current_dir, word, &current_inode))
        {
          dir_unlock_dir (current_dir);
          if (current_dir != base)
            dir_close (current_dir);

          if (inode_is_dir (current_inode))
            {
              current_dir = dir_open (current_inode);
              dir_lock_dir (current_dir);
              if (current_dir == NULL)
                break;
            }
          else if (strtok_r (NULL, "/", &context) != NULL)
            {
              inode_close (current_inode);
              current_dir = NULL;
              break;
            }
        }
      else 
        {
          dir_unlock_dir (current_dir);

          if (current_dir != base)
            dir_close (current_dir);

          current_dir = NULL;
          break;
        }
    }

  free (buffer);

  if (current_dir != NULL)
    dir_unlock_dir (current_dir);

  if (current_dir == base)
    return dir_reopen (base);
  
  return current_dir;

}

/* Creates a directory with space for ENTRY_CNT entries in the
   given SECTOR.  Returns true if successful, false on failure. */
bool
dir_create (block_sector_t sector, size_t entry_cnt)
{
  return inode_create (sector, entry_cnt * sizeof (struct dir_entry), true);
}

/* Adds the default .. and . directories to the given DIR with parent dir inode PARENT.
   This does not need to lock the directory because presumably only the initializer holds
   a reference to the dir. */
bool
dir_init (block_sector_t sector, struct inode *parent)
{
  struct inode *dir_inode = inode_open (sector);
  struct dir *new = dir_open (dir_inode);

  if (!new || !dir_inode)
    return false;

  dir_add (new, ".", inode_get_inumber (new->inode));
  dir_add (new, "..", inode_get_inumber (parent));
  dir_close (new);

  return true;
}

/* Opens and returns the directory for the given INODE, of which
   it takes ownership.  Returns a null pointer on failure. */
struct dir *
dir_open (struct inode *inode) 
{
  struct dir *dir = calloc (1, sizeof *dir);
  if (inode != NULL && dir != NULL)
    {
      dir->inode = inode;
      dir->pos = 0;
      return dir;
    }
  else
    {
      inode_close (inode);
      free (dir);
      return NULL; 
    }
}

/* Opens the root directory and returns a directory for it.
   Return true if successful, false on failure. */
struct dir *
dir_open_root (void)
{
  return dir_open (inode_open (ROOT_DIR_SECTOR));
}

/* Given a NAME returns the root directory if the NAME begins
   with a '/' or the working directory of the current thread. */
struct dir *
dir_open_base_dir (const char *name)
{
  if ((name != NULL && name[0] == '/') || (thread_current ()->working_directory == NULL))
    return dir_open_root ();

  return dir_reopen (thread_current ()->working_directory);
}

/* Opens and returns a new directory for the same inode as DIR.
   Returns a null pointer on failure. */
struct dir *
dir_reopen (struct dir *dir) 
{
  return dir_open (inode_reopen (dir->inode));
}

/* Destroys DIR and frees associated resources. */
void
dir_close (struct dir *dir) 
{
  if (dir != NULL)
    {
      inode_close (dir->inode);
      free (dir);
    }
}

/* Returns the inode encapsulated by DIR. */
struct inode *
dir_get_inode (struct dir *dir) 
{
  ASSERT (dir != NULL);
  return dir->inode;
}

/* Searches DIR for a file with the given NAME.
   If successful, returns true, sets *EP to the directory entry
   if EP is non-null, and sets *OFSP to the byte offset of the
   directory entry if OFSP is non-null.
   otherwise, returns false and ignores EP and OFSP. */
static bool
lookup (const struct dir *dir, const char *name,
        struct dir_entry *ep, off_t *ofsp) 
{
  struct dir_entry e;
  size_t ofs;
  
  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e)
    {
      if (e.in_use && !strcmp (name, e.name)) 
        {
          if (ep != NULL)
            *ep = e;
          if (ofsp != NULL)
            *ofsp = ofs;
          return true;
        }
    }
  return false;
}

/* Searches DIR for a file with the given NAME
   and returns true if one exists, false otherwise.
   On success, sets *INODE to an inode for the file, otherwise to
   a null pointer.  The caller must close *INODE. */
bool
dir_lookup (const struct dir *dir, const char *name,
            struct inode **inode) 
{
  struct dir_entry e;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  if (lookup (dir, name, &e, NULL))
    *inode = inode_open (e.inode_sector);
  else
    *inode = NULL;

  return *inode != NULL;
}

/* Adds a file named NAME to DIR, which must not already contain a
   file by that name.  The file's inode is in sector
   INODE_SECTOR.
   Returns true if successful, false on failure.
   Fails if NAME is invalid (i.e. too long) or a disk or memory
   error occurs. */
bool
dir_add (struct dir *dir, const char *name, block_sector_t inode_sector)
{
  struct dir_entry e;
  off_t ofs;
  bool success = false;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  /* Check NAME for validity. */
  if (*name == '\0' || strlen (name) > NAME_MAX)
    return false;

  dir_lock_dir (dir);

  /* Check that NAME is not in use. */
  if (lookup (dir, name, NULL, NULL))
    goto done;

  /* Set OFS to offset of free slot.
     If there are no free slots, then it will be set to the
     current end-of-file.
     
     inode_read_at() will only return a short read at end of file.
     Otherwise, we'd need to verify that we didn't get a short
     read due to something intermittent such as low memory. */
  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e) 
    if (!e.in_use)
      break;

  /* Write slot. */
  e.in_use = true;
  strlcpy (e.name, name, sizeof e.name);
  e.inode_sector = inode_sector;
  success = inode_write_at (dir->inode, &e, sizeof e, ofs) == sizeof e;

 done:
  dir_unlock_dir (dir);
  return success;
}

static bool
dir_can_remove_dir (struct inode *dir_inode)
{
  if (inode_get_open_count (dir_inode) > 1)
    return false;

  if (inode_get_inumber (dir_inode) == ROOT_DIR_SECTOR)
    return false;

  char buffer[NAME_MAX + 1];
  
  struct dir *dir = dir_open (inode_reopen (dir_inode));
  int count = 0;
  while (dir_readdir (dir, buffer))
    count++;

  dir_close (dir);
  

  return count == 0;
}

/* Removes any entry for NAME in DIR.
   Returns true if successful, false on failure,
   which occurs only if there is no file with the given NAME. */
bool
dir_remove (struct dir *dir, const char *name) 
{
  struct dir_entry e;
  struct inode *inode = NULL;
  bool success = false;
  off_t ofs;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  dir_lock_dir (dir);
  
  /* Find directory entry. */
  if (!lookup (dir, name, &e, &ofs))
    goto done;

  /* Open inode. */
  inode = inode_open (e.inode_sector);
  if (inode == NULL)
    goto done;

  if (inode_is_dir (inode) && !dir_can_remove_dir (inode))
    goto done;
    

  /* Erase directory entry. */
  e.in_use = false;
  if (inode_write_at (dir->inode, &e, sizeof e, ofs) != sizeof e) 
    goto done;
  
  /* Remove inode. */
  inode_remove (inode);
  success = true;
  
 done:
  inode_close (inode);
  dir_unlock_dir (dir);
  return success;
}

/* Reads the next directory entry in DIR and stores the name in
   NAME.  Returns true if successful, false if the directory
   contains no more entries. */
bool
dir_readdir (struct dir *dir, char name[NAME_MAX + 1])
{
  struct dir_entry e;

  while (inode_read_at (dir->inode, &e, sizeof e, dir->pos) == sizeof e) 
    {
      dir->pos += sizeof e;
      if (e.in_use && strcmp (e.name, "..") && strcmp (e.name, "."))
        {
          strlcpy (name, e.name, NAME_MAX + 1);
          return true;
        } 
    }
  return false;
}
