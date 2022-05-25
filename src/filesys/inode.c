#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
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
void extend_length(struct inode_disk *inode_disk, uint32_t new_length) {
  
  uint32_t now_length = inode_disk->sector_cnt * BLOCK_SECTOR_SIZE;
  while (now_length < new_length) {
    
    uint32_t sub_layer = now_length / FIRST_SIZE;
    
    uint32_t idx = (now_length % FIRST_SIZE) / BLOCK_SECTOR_SIZE;
  
    if (idx == 0) {
      free_map_allocate(1, &inode_disk->sub_idx[sub_layer]);
    }
    

    block_sector_t start;
    free_map_allocate(ALLOC_SECTOR, &start);
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

}

/** List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/** Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
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
  cache_read (inode->sector, 0, &inode->data, BLOCK_SECTOR_SIZE);
  return inode;
}

/** Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/** Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
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
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
 
      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
          
          for (uint32_t i = 0 ; i < inode->data.sector_cnt; i += ALLOC_SECTOR) {
            block_sector_t s = byte_to_sector(&inode->data, i * BLOCK_SECTOR_SIZE);
            free_map_release (s, 4);
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
      free (inode); 
    }
}

/** Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/** Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  if (inode_length(inode) <= offset) return 0;
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


  if (inode->deny_write_cnt)
    return 0;


  if (offset + size > inode->data.length) {
    extend_length(&inode->data, offset + size);
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

  return bytes_written;
}

/** Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/** Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/** Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  return inode->data.length;
}

enum inode_type inode_get_type(const struct inode *inode) {
  return inode->data.type;
}

void inode_change_entry_number(struct inode *inode, int v) {
  ASSERT(inode->data.type == INODE_DIR);
  inode->data.entry_number += v;
}

uint32_t inode_get_entry_number(struct inode *inode) {
  return inode->data.entry_number;
}