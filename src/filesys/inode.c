#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "filesys/cache.h"

/** Identifies an inode. */
#define INODE_MAGIC 0x494e4f44
#define ALLOC_SECTOR 0x4
#define FIRST_SIZE (BLOCK_SECTOR_SIZE * BLOCK_SECTOR_SIZE / 4)


/** On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    uint32_t sector_cnt;                /**< First data sector. */
    off_t length;                       /**< File size in bytes. */
    unsigned magic;                     /**< Magic number. */
    enum inode_type type;
    uint32_t entry_number;              /** entry_number for directory*/
    block_sector_t sub_idx[123];            /**< single layer linker for sector number>*/
  };

/** Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

/** In-memory inode. */
struct inode 
  {
    struct list_elem elem;              /**< Element in inode list. */
    block_sector_t sector;              /**< Sector number of disk location. */
    int open_cnt;                       /**< Number of openers. */
    bool removed;                       /**< True if deleted, false otherwise. */
    int deny_write_cnt;                 /**< 0: writes ok, >0: deny writes. */
    int read_cnt;
    struct lock read_cnt_lock;
    struct condition write_cond;
    struct lock queue_lock;
    struct lock inode_lock;
    struct lock write_lock;
    struct inode_disk data;             /**< Inode content. */
  };

/** Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector (const struct inode_disk *inode_disk, off_t pos) 
{
  ASSERT (inode_disk != NULL);
  if (pos < inode_disk->length) {
    uint32_t sub_layer, idx;
    block_sector_t res;
    sub_layer = inode_disk->sub_idx[pos / FIRST_SIZE];
    idx = (pos % FIRST_SIZE) / BLOCK_SECTOR_SIZE;

    cache_read(sub_layer, idx * sizeof(block_sector_t), &res, sizeof(block_sector_t));

    return res;
  }
  else
    return -1;
}
/** extend the file length to a new length */
static
bool extend_length(struct inode_disk *inode_disk, uint32_t new_length) {
  
  uint32_t now_length = inode_disk->sector_cnt * BLOCK_SECTOR_SIZE;
  bool success = 1;
  while (now_length < new_length) {
    
    uint32_t sub_layer = now_length / FIRST_SIZE;
    
    uint32_t idx = (now_length % FIRST_SIZE) / BLOCK_SECTOR_SIZE;
  
    if (idx == 0) {
      free_map_allocate(1, &inode_disk->sub_idx[sub_layer]);
    }
    

    block_sector_t start;

    if (!free_map_allocate(ALLOC_SECTOR, &start)) {
      success = 0;
      goto fail;
    }
    for (int i = 0 ; i < ALLOC_SECTOR ; ++i) {
      cache_set_zero(start + i);
    }


    for (int i = 0 ; i < ALLOC_SECTOR ; ++i) {
      block_sector_t tmp = start + i;
      cache_write(inode_disk->sub_idx[sub_layer], (idx + i) * sizeof(block_sector_t), 
        &tmp, sizeof(block_sector_t));    
    }

    inode_disk->sector_cnt += ALLOC_SECTOR;
    now_length += ALLOC_SECTOR * BLOCK_SECTOR_SIZE;  
  }

  inode_disk->length = new_length;
  fail:
  return success;
}

/** List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;
struct lock inodes_list_lock;

/** Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
  lock_init (&inodes_list_lock);
}

/** Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length, enum inode_type type)
{
  struct inode_disk *disk_inode = NULL;
  bool success = false;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
    {
      disk_inode->length = 0;
      disk_inode->magic = INODE_MAGIC;
      disk_inode->type = type;
      //printf("a file with type %d in sector %d", type, sector);
      disk_inode->entry_number = 0;
      extend_length(disk_inode, length);
      cache_write(sector, 0, disk_inode, BLOCK_SECTOR_SIZE);
      free (disk_inode);
      success = 1;
    }
  return success;
}

/** Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  
  struct list_elem *e;
  struct inode *inode;
  lock_acquire(&inodes_list_lock);
  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          
          struct inode *res = inode_reopen (inode);
          
          lock_release(&inodes_list_lock);
          return res;
        }
    }
  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL) {
    lock_release(&inodes_list_lock);
    return NULL;
  }

  /* Initialize. */
  //printf("inode open a file on sector %d\n", sector);
  list_push_front (&open_inodes, &inode->elem);
  
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  inode->read_cnt = 0;
  cond_init(&inode->write_cond);
  lock_init(&inode->read_cnt_lock);
  lock_init(&inode->queue_lock);
  lock_init(&inode->inode_lock);
  lock_init(&inode->write_lock);
  cache_read (inode->sector, 0, &inode->data, BLOCK_SECTOR_SIZE);
  //printf("%d file reference becomes %d\n", sector, inode->open_cnt);
  lock_release(&inodes_list_lock);
  return inode;
}

/** Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  struct inode *res;
  lock_acquire(&inode->inode_lock);
  if (inode->removed) res = NULL;
  else if (inode != NULL) {
    //printf("inode open a file on sector %d\n", inode->sector);
    res = inode;
    inode->open_cnt++;
    //printf("%d file reference becomes %d\n", res->sector, res->open_cnt);
  }
  
  lock_release(&inode->inode_lock);
  return res;
}

/** Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  lock_acquire(&inode->inode_lock);
  block_sector_t res = inode->sector;
  lock_release(&inode->inode_lock);
  return res;
}

/** Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;
  
  /* Release resources if this was the last opener. */
  lock_acquire(&inodes_list_lock);
  lock_acquire(&inode->inode_lock);
  //printf("inode close a file on %d \n", inode->sector);
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      //printf("%d file reference becomes 0\n", inode->sector);
      list_remove (&inode->elem);
      
      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
          
          for (uint32_t i = 0 ; i < inode->data.sector_cnt; i += ALLOC_SECTOR) {
            block_sector_t s = byte_to_sector(&inode->data, i * BLOCK_SECTOR_SIZE);
            free_map_release (s, ALLOC_SECTOR);
          }
          uint32_t upper = (inode->data.sector_cnt * BLOCK_SECTOR_SIZE + FIRST_SIZE - 1)/ FIRST_SIZE;
          for (uint32_t i = 0; i < upper ; ++i)  {
            free_map_release(inode->data.sub_idx[i], 1);
          }

          free_map_release (inode->sector, 1); 
        }
      else {
        cache_write(inode->sector, 0, &inode->data, BLOCK_SECTOR_SIZE);
      }
      lock_release(&inode->inode_lock);
      lock_release(&inodes_list_lock);
      free (inode); 
      return;
    }
  //printf("%d file reference becomes %d\n", inode->sector, inode->open_cnt);
  lock_release(&inode->inode_lock);
  lock_release(&inodes_list_lock);
}

/** Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  lock_acquire(&inode->inode_lock);
  inode->removed = true;
  lock_release(&inode->inode_lock);
}

/** Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{

  //printf("call inode read at\n");
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  if (inode_length(inode) <= offset) return 0;

  lock_acquire(&inode->queue_lock);

  lock_acquire(&inode->read_cnt_lock);
  
  inode->read_cnt++;

  ASSERT(inode->open_cnt >= inode->read_cnt);
  lock_release(&inode->read_cnt_lock);
  lock_release(&inode->queue_lock);

  while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (&inode->data, offset);

      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      cache_read(sector_idx, sector_ofs, buffer + bytes_read, chunk_size);

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }

  lock_acquire(&inode->read_cnt_lock);
  ASSERT(inode->read_cnt > 0);
  inode->read_cnt--;
  if (inode->read_cnt == 0) {
    cond_signal(&inode->write_cond, &inode->read_cnt_lock);
  }
  lock_release(&inode->read_cnt_lock);
  //printf(", at last read with bytes of %d\n", bytes_read);
  return bytes_read;
}

/** Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;

  //printf("call inode write at\n");
  if (inode->deny_write_cnt)
    return 0;

  
  lock_acquire(&inode->queue_lock);
  lock_acquire(&inode->read_cnt_lock);
  while (inode->read_cnt != 0) {
    cond_wait(&inode->write_cond, &inode->read_cnt_lock);
  }
  lock_release(&inode->read_cnt_lock);
  
  if (offset + size > inode->data.length) {
    lock_acquire(&inode->inode_lock);
    if(!extend_length(&inode->data, offset + size)) {
      lock_release(&inode->inode_lock);
      lock_release(&inode->queue_lock);
      return 0;
    }
    lock_release(&inode->inode_lock);
    cache_write(inode->sector, 0, &inode->data, BLOCK_SECTOR_SIZE);
  }
  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (&inode->data, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      cache_write(sector_idx, sector_ofs, (void *)buffer + bytes_written, chunk_size);

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }
  lock_release(&inode->queue_lock);
  return bytes_written;
}

/** Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  lock_acquire(&inode->inode_lock);
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  lock_release(&inode->inode_lock);
  
}

/** Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  
  lock_acquire(&inode->inode_lock);
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
  lock_release(&inode->inode_lock);
}

/** Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  ASSERT(inode != NULL)
  lock_acquire(&inode->inode_lock);
  off_t res = inode->data.length;
  lock_release(&inode->inode_lock);
  return res;
}

enum inode_type inode_get_type(const struct inode *inode) {
  lock_acquire(&inode->inode_lock);
  enum inode_type res = inode->data.type;
  lock_release(&inode->inode_lock);
  return res;
}

void inode_change_entry_number(struct inode *inode, int v) {
  
  lock_acquire(&inode->inode_lock);
  ASSERT(inode->data.type == INODE_DIR);
  inode->data.entry_number += v;
  lock_release(&inode->inode_lock);
}

uint32_t inode_get_entry_number(struct inode *inode) {
  
  lock_acquire(&inode->inode_lock);
  uint32_t res = inode->data.entry_number;
  lock_release(&inode->inode_lock);
  return res;
}

bool inode_is_removed(struct inode *inode) {
  lock_acquire(&inode->inode_lock);
  bool res = !inode->removed;
  lock_release(&inode->inode_lock);
  return res;
}