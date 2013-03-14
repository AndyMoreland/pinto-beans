#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include <stdio.h>
#include "cache.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

#define INODE_NUM_DIRECT 123
#define INODE_NUM_INDIRECT 1
#define INODE_NUM_DBL_INDIRECT 1

#define INDIRECT_CAP 128
#define DBL_INDIRECT_CAP (INDIRECT_CAP * INDIRECT_CAP)
#define LOG_INDIRECT_CAP 7
#define INODE_PTR_INVALID ((block_sector_t)-1)

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    off_t length;                       /* File size in bytes. */
    unsigned magic;                     /* Magic number. */
    struct 
      {
        block_sector_t direct[INODE_NUM_DIRECT];
        block_sector_t indirect[INODE_NUM_INDIRECT];
        block_sector_t dbl_indirect[INODE_NUM_DBL_INDIRECT];
      };
    bool is_dir;                      /* True if inode represents a directory. */
    uint32_t unused[0];               /* Not used. */
  };

struct inode_indirect_disk
  {
    block_sector_t ptrs[INDIRECT_CAP];
  };

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}


/* In-memory inode. */
struct inode 
  {
    struct list_elem elem;              /* Element in inode list. */
    block_sector_t sector;              /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    struct lock dir_lock;               /* If this inode represents a directory
                                           then this prevents concurent access. */
    struct lock extend_lock;
  };

static bool
sector_is_valid (block_sector_t block)
{
  return block != INODE_PTR_INVALID;
}

static block_sector_t 
inode_get_ptr (block_sector_t *block_ptr, bool create)
{
//  ASSERT (create == !sector_is_valid(*block_ptr));
  if (create)
    free_map_allocate (1, block_ptr);
  return *block_ptr;
}

static block_sector_t
inode_indirect_lookup (off_t block, block_sector_t *ptrs, off_t count,
                       int depth, bool create, void *parent)
{
  off_t child_cap = (1 << (depth * LOG_INDIRECT_CAP));
  ASSERT (block < count * child_cap);
  if (!depth)
    {
      block_sector_t retval = inode_get_ptr (ptrs + block, create);
      cache_end (parent, create);
      return retval;
    }
  off_t child_index = block / child_cap;
  off_t child_block_offset = block % child_cap;

  block_sector_t sector; 
  bool created = false;
  if (!child_block_offset && create)
    {
      block_sector_t *ptr = ptrs + child_index; 
      ASSERT (!sector_is_valid (*ptr)); 
      created = free_map_allocate (1, ptr);
      sector = *ptr;
    }
  else
    sector = ptrs[child_index];
  cache_end (parent, created);
  if (!sector_is_valid (sector))
    return sector;

  struct inode_indirect_disk *child = cache_begin (sector);
  if (created)
    memset (child->ptrs, INODE_PTR_INVALID, sizeof (child->ptrs));
  return inode_indirect_lookup (child_block_offset, child->ptrs, 
      INDIRECT_CAP, depth - 1, create, child);
}

static block_sector_t
byte_to_sector (struct inode *inode, off_t pos, bool create)
{
  struct inode_disk *disk = cache_begin (inode->sector);
  off_t block = pos / BLOCK_SECTOR_SIZE;
  if (block < INODE_NUM_DIRECT)
  {
    return inode_indirect_lookup (block, disk->direct, 
                    INODE_NUM_DIRECT, 0, create, disk);
  }

  block -= INODE_NUM_DIRECT;
  if (block < INODE_NUM_INDIRECT * INDIRECT_CAP)
    {
      return inode_indirect_lookup (block, disk->indirect, 
                    INODE_NUM_INDIRECT, 1, create, disk);
    }

  block -= INODE_NUM_INDIRECT * INDIRECT_CAP;
  if (block < INODE_NUM_DBL_INDIRECT * DBL_INDIRECT_CAP)
    {
      return inode_indirect_lookup (block, disk->dbl_indirect, 
                    INODE_NUM_DBL_INDIRECT, 2, create, disk);
    }

  printf ("block too big for disk: %u\n", block);
  cache_end (disk, false);
  return INODE_PTR_INVALID;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
  cache_init (64);
}
static off_t
inode_do_write (struct inode *inode, const void *buffer_, off_t size,
                off_t offset, bool extend);

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length, bool is_dir)
{
  bool success = false;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof (struct inode_disk) == BLOCK_SECTOR_SIZE);

  struct inode *inode = inode_open (sector);
  if (inode->open_cnt > 1)
    {
      printf ("create on open inode: %u\n", sector);
      return false;
    }

  struct inode_disk *disk = cache_begin (sector);
  memset (disk, INODE_PTR_INVALID, sizeof *disk);

  disk->length = 0;
  disk->magic = INODE_MAGIC;
  disk->is_dir = is_dir;
  inode->sector = sector;
  cache_end (disk, true);

  if (length == inode_do_write (inode, NULL, length, 0, true))
    success = true;

  inode_close (inode);
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  lock_init (&inode->dir_lock);
  lock_init (&inode->extend_lock);
  /* FIXME: readahead inode->sector? */
  printf ("Returning inode: %p\n", inode);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

static void 
inode_close_sector (block_sector_t sector, int depth)
{
  if (!sector_is_valid (sector))
    return;
  if (depth > 0)
    {
      struct inode_indirect_disk *block = cache_begin (sector);
      int i;
      for (i = 0; i < INDIRECT_CAP; ++i)
        inode_close_sector (block->ptrs[i], depth - 1);
      cache_end (block, false); 
    }
  
  /* FIXME: any cache invalidation necessary? */
  free_map_release (sector, 1);
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
 
      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
          struct inode_disk *block = cache_begin (inode->sector);
          int i;
          for (i = 0; i < INODE_NUM_DIRECT; ++i)
            inode_close_sector (block->direct[i], 0);
          for (i = 0; i < INODE_NUM_INDIRECT; ++i)
            inode_close_sector (block->indirect[i], 1);
          for (i = 0; i < INODE_NUM_DBL_INDIRECT; ++i)
            inode_close_sector (block->dbl_indirect[i], 2);
          cache_end (block, false);
          free_map_release (inode->sector, 1);
        }

      free (inode); 
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;

  while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset, false);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Read full sector directly into caller's buffer. */
          cache_read (sector_idx, buffer + bytes_read);
        }
      else 
        {
          uint8_t *data = cache_begin (sector_idx);
          // FIXME: what if an exception happens right here? will transaction hang?
          memcpy (buffer + bytes_read, data + sector_ofs, chunk_size);
          cache_end (data, false);
        }
      
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }

  return bytes_read;
}

static off_t
inode_do_write (struct inode *inode, const void *buffer_, off_t size,
                off_t offset, bool extend)
{
//  printf ("inode_do_write: %u\n", inode->sector);
  if (!size)
    return 0;

  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      bool new_block = extend && ((offset % BLOCK_SECTOR_SIZE) == 0);
      block_sector_t sector = byte_to_sector (inode, offset, new_block);
      if (!sector_is_valid (sector))
        return bytes_written;

      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      int left = BLOCK_SECTOR_SIZE - sector_ofs;
      if (!extend)
        {
          off_t inode_left = inode_length (inode) - offset;
          if (inode_left < left)
            left = inode_left;
        } 

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < left ? size : left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE && buffer)
        {
          /* Write full sector directly to disk. */
          cache_write (sector, buffer + bytes_written);
        }
      else 
        {
          uint8_t *data = cache_begin (sector);
          if (buffer)
            memcpy (data + sector_ofs, buffer + bytes_written, chunk_size);
          else
            memset (data + sector_ofs, 0, chunk_size);
          cache_end (data, true);
        }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      if (extend)
        {
          struct inode_disk *disk = cache_begin (inode->sector);
          disk->length = offset;
          cache_end (disk, true);
        }
          
      bytes_written += chunk_size;
    }

  return bytes_written; 
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  if (inode->deny_write_cnt)
    return 0;

  const uint8_t *buffer = buffer_;

  if (offset > inode_length (inode))
    {
      lock_acquire (&inode->extend_lock);
      off_t len = inode_length (inode);
      if (offset > len)
        inode_do_write (inode, NULL, offset - len, len, true);
      lock_release (&inode->extend_lock);
    }
   
  off_t written = 0;
  if (offset + size > inode_length (inode))
    {
      lock_acquire (&inode->extend_lock);
      off_t len = inode_length (inode);
      if (offset + size > len)
        {
          written = inode_do_write (inode, buffer, len - offset, offset, false);
          if (written == len - offset)
            written += inode_do_write (inode, buffer + written, offset + size - len, len, true);
        }
      else
        written = inode_do_write (inode, buffer, size, offset, false);
      lock_release (&inode->extend_lock);
    }
  else
    written = inode_do_write (inode, buffer, size, offset, false);

  return written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  printf (" -- - -- - - - - - --inode deny write called on: %p, sector: %d\n", inode, inode->sector);
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  printf ("inode->deny_write_cnt: %d, inode->open_cnt: %d, inode: %p, sector: %d\n", inode->deny_write_cnt, inode->open_cnt, inode, inode->sector);
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  struct inode_disk *block = cache_begin (inode->sector);
  off_t len = block->length;
  cache_end (block, false);
  return len;
}

/* Returns `true` if INODE represents a directory, `false` otherwise */
bool
inode_is_dir (const struct inode *inode)
{
  struct inode_disk *block = cache_begin (inode->sector);
  bool is_dir = block->is_dir;
  cache_end (block, false);
  return is_dir;
}


