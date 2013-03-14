#ifndef FILESYS_FILESYS_H
#define FILESYS_FILESYS_H

#include <stdbool.h>
#include "filesys/off_t.h"

/* Sectors of system file inodes. */
#define FREE_MAP_SECTOR 0       /* Free map file inode sector. */
#define ROOT_DIR_SECTOR 1       /* Root directory file inode sector. */

/* Block device that contains the file system. */
struct block *fs_device;

void filesys_init (bool format);
void filesys_done (void);
bool filesys_create (const char *name, off_t initial_size);
struct filedir *filesys_open (const char *name);
struct file *filesys_open_file (const char *name);
struct dir *filesys_open_dir (const char *name);
bool filesys_mkdir (const char *path);
bool filesys_remove (const char *name);

enum filedir_type
  {
    FILE_DESCRIPTOR_FILE,
    FILE_DESCRIPTOR_DIR
  };

struct filedir
  {
    union 
      {
        struct file *f;
        struct dir *d;
      };
    enum filedir_type mode;
  };

#endif /* filesys/filesys.h */
