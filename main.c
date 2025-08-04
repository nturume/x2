#include <assert.h>
// #include <bits/pthreadtypes.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/cdefs.h>
#include <time.h>
// #include <unistd.h>

#define u8 uint8_t
#define u16 uint16_t
#define u32 uint32_t
#define u64 uint64_t
#define usize size_t

#define isize ssize_t
#define i8 int8_t
#define i16 int16_t
#define i32 int32_t
#define i64 int64_t

#define EXT2_SECRM_FL 0x00000001
#define EXT2_UNRM_FL 0x00000002
#define EXT2_COMPR_FL 0x00000004
#define EXT2_SYNC_FL 0x00000008
#define EXT2_IMMUTABLE_FL 0x00000010
#define EXT2_APPEND_FL 0x00000020
#define EXT2_NODUMP_FL 0x00000040
#define EXT2_NOATIME_FL 0x00000080
#define EXT2_DIRTY_FL 0x00000100
#define EXT2_COMPRBLK_FL 0x00000200
#define EXT2_NOCOMPR_FL 0x00000400
#define EXT2_ECOMPR_FL 0x00000800
#define EXT2_BTREE_FL 0x00001000
#define EXT2_INDEX_FL 0x00001000
#define EXT2_IMAGIC_FL 0x00002000
#define EXT2_RESERVED_FL 0x80000000

#define EXT2_FT_UNKNOWN 0
#define EXT2_FT_REG_FILE 1
#define EXT2_FT_DIR 2
#define EXT2_FT_CHRDEV 3
#define EXT2_FT_BLKDEV 4
#define EXT2_FT_FIFO 5
#define EXT2_FT_SOCK 6
#define EXT2_FT_SYMLINK 7

#define EXT2_S_ISUID 0x0800
#define EXT2_S_ISGID 0x0400
#define EXT2_S_ISVTX 0x0200

#define EXT2_S_IRUSR 0x0100
#define EXT2_S_IWUSR 0x0080
#define EXT2_S_IXUSR 0x0040
#define EXT2_S_IRGRP 0x0020
#define EXT2_S_IWGRP 0x0010
#define EXT2_S_IXGRP 0x0008
#define EXT2_S_IROTH 0x0004
#define EXT2_S_IWOTH 0x0002
#define EXT2_S_IXOTH 0x0001

#define EXT2_S_IFSOCK 0xC000
#define EXT2_S_IFLNK 0xA000
#define EXT2_S_IFREG 0x8000
#define EXT2_S_IFBLK 0x6000
#define EXT2_S_IFDIR 0x4000
#define EXT2_S_IFCHR 0x2000
#define EXT2_S_IFIFO 0x1000

#define BLOCKSIZE 4096

#define X2_OK 0
#define X2_ERR_NO_SPACE -1
#define X2_ERR_NO_ENT -2
#define X2_ERR_SEEK_OUT_OF_BOUNDS -3
#define X2_ERR_ENT_EXISTS -4
#define X2_ERR_DIR_NOT_EMPTY -5
#define X2_ERR_NOT_SYMLINK -6
#define X2_ERR_NOT_DIR -7

struct SuperBlock {
  u32 inodes_count;
  u32 blocks_count;
  u32 r_blocks_count;
  u32 free_blocks_count;
  u32 free_inodes_count;
  u32 first_data_block;
  u32 log_block_size;
  u32 log_frag_size;
  u32 blocks_per_group;
  u32 frags_per_group;
  u32 inodes_per_group;
  u32 mtime;
  u32 wtime;
  u16 mnt_count;
  u16 max_mnt_count;
  u16 magic;
  u16 state;
  u16 errors;
  u16 minor_rev_level;
  u32 lastcheck;
  u32 checkinterval;
  u32 creator_os;
  u32 rev_level;
  u16 def_resuid;
  u16 def_resgid;
  u32 first_ino;
  u16 inode_size;
  u16 block_group_nr;
  u32 feature_compat;
  u32 feature_incompat;
  u32 feature_ro_compat;
  u8 uuid[16];
  char volume_name[16];
  char last_mounted[64];
  u32 algorithm_usage_bitmap;
  u8 prealloc_blocks;
  u8 prealloc_dir_blocks;
  u16 padding1;
  u8 journal_uuid[16];
  u32 journal_inum;
  u32 journal_dev;
  u32 last_orphan;
  u32 hash_seed[4];
  u8 def_hash_version;
  u8 reserved_char_pad;
  u16 reserved_word_pad;
  u32 default_mount_opts;
  u32 first_meta_bg;
  u32 reserved[190];
};

struct Inode {
  u16 mode;
  u16 uid;
  u32 size;
  u32 atime;
  u32 ctime;
  u32 mtime;
  u32 dtime;
  u16 gid;
  u16 links_count;
  u32 blocks;
  u32 flags;
  u32 osd1;
  u32 block[15];
  u32 generation;
  u32 file_acl;
  u32 dir_acl;
  u32 faddr;
  u8 frag;
  u8 fsize;
  u16 pad1;
  u16 uid_high;
  u16 gid_high;
  u32 reserved2;
};

struct DirInodeR {
  usize blockbuf;
  struct Inode *ino;
  usize block;
  usize offt;
  usize block_idx;
  struct DirEnt *prev_ptr; /*->|*/
  struct DirEnt *ent_ptr;  /*->|*/
  usize ent_block;         /*<-|*/
  int done;
};

struct FileInodeRW {
  struct Inode *ino; /*<|*/
  usize inode_idx;   /*|*/
  usize filesz;
  usize block;
  usize offt;
  usize block_idx;
  int done;
};

struct GroupDesc {
  u32 block_bitmap;
  u32 inode_bitmap;
  u32 inode_table;
  u16 free_blocks_count;
  u16 free_inodes_count;
  u16 used_dirs_count;
  u16 pad;
  u32 reserved[3];
};

struct DirEnt {
  u32 inode;
  u16 rec_len;
  u8 name_len;
  u8 file_type;
  u8 *name;
};

struct BlockDev {
  void (*readBlock)(void *ctx, usize pos, u8 *buf);
  void (*writeBlock)(void *ctx, usize pos, const u8 *buf);
  void *ctx;
};

/* glbls */
struct SuperBlock sb;
struct BlockDev *dev;
struct GroupDesc *gdesc;
u8 blockbuf[4][BLOCKSIZE];
u8 namebuf[1][255];
/* glbls */

static usize alignB(u64 addr, usize target) { return addr & ~(target - 1); }
static usize alignF(u64 addr, usize target) {
  return alignB(addr - 1, target) + target;
}

static usize x2blockSize() { return 1024u << sb.log_block_size; }
static usize x2inodesPerBlock() { return x2blockSize() / sb.inode_size; }
static usize x2totalGroups() {
  return ((sb.blocks_count - 1) / sb.blocks_per_group) + 1;
}

static usize inodesPerBlock() { return x2blockSize() / sb.inode_size; }

static void x2readBlocks(usize pos, usize n, u8 *buf) {
  for (usize i = 0; i < n; i++) {
    dev->readBlock(dev, pos + i, buf + (BLOCKSIZE * i));
  }
}

static void x2writeBlocks(usize pos, usize n, u8 *buf) {
  // if (pos == 0)crintf("999999999999999999999999999999999\n");
  for (usize i = 0; i < n; i++) {
    dev->writeBlock(dev, pos + i, buf + (BLOCKSIZE * i));
  }
}

static u32 x2readTimestamp() {
  time_t t;
  time(&t);
  return t;
}

static void x2ReadSuperBlock() {
  x2readBlocks(0, 1, blockbuf[0]);
  sb = *((struct SuperBlock *)(blockbuf[0] + 1024));
}

static void x2writeSuperBlock() {
  x2readBlocks(0, 1, blockbuf[0]);
  *((struct SuperBlock *)(blockbuf[0] + 1024)) = sb;
  x2writeBlocks(0, 1, blockbuf[0]);
}

static void x2ReadBGDescs() {
  usize sz = x2totalGroups() * sizeof(struct GroupDesc);
  x2readBlocks(1, 1, blockbuf[0]);
  memcpy(gdesc, blockbuf[0], sz);
}

static void x2witeBGDescs() {
  usize sz = x2totalGroups() * sizeof(struct GroupDesc);
  x2readBlocks(1, 1, blockbuf[0]);
  memcpy(blockbuf[0], gdesc, sz);
  x2writeBlocks(1, 1, blockbuf[0]);
}

static usize x2getInodeBlockCount(struct Inode *ino) {
  return ino->blocks / (x2blockSize() / 512);
}

/*must be reg file*/
static u64 x2getFileSize(struct Inode *ino) {
  return ((u64)ino->size + (((u64)ino->dir_acl) << 32));
}

static void x2setFileSize(struct Inode *ino, u64 filesz) {
  ino->size = filesz;
  ino->dir_acl = filesz >> 32;
}

struct InodeLoc {
  usize block;
  usize idx;
};

struct InodeLoc x2getInodeLoc(usize inode_idx) {
  inode_idx -= 1; /*??*/
  usize group = (inode_idx) / sb.inodes_per_group;
  usize inode_table = gdesc[group].inode_table;
  usize local_inode_idx = (inode_idx) % sb.inodes_per_group;
  usize target_table_block = local_inode_idx / x2inodesPerBlock();
  return (struct InodeLoc){.block = inode_table + target_table_block,
                           .idx = local_inode_idx % x2inodesPerBlock()};
}

static void x2ReadInode(usize inode_idx, struct Inode *inode) {
  struct InodeLoc loc = x2getInodeLoc(inode_idx);
  x2readBlocks(loc.block, 1, blockbuf[0]);
  *inode = ((struct Inode *)blockbuf[0])[loc.idx];
}

static void x2WriteInode(usize inode_idx, struct Inode *inode) {
  struct InodeLoc loc = x2getInodeLoc(inode_idx);
  x2readBlocks(loc.block, 1, blockbuf[0]);
  ((struct Inode *)blockbuf[0])[loc.idx] = *inode;
  /* TODO write shit*/
  x2writeBlocks(loc.block, 1, blockbuf[0]);
}

static usize x2getFileBlock(struct Inode *inode, usize block_idx) {
  u64 fsize = x2getFileSize(inode);
  usize block;
  if (block_idx < 12) {
    block = inode->block[block_idx];
    return block;
  }
  block_idx -= 12;

  if (block_idx < 1024) {
    x2readBlocks(inode->block[12], 1, blockbuf[1]); /*indirect shit*/
    u32 *indirect = (u32 *)blockbuf[1];
    block = indirect[block_idx];
    return block;
  }

  block_idx -= 1024;

  if (block_idx < 1024 * 1024) {
    x2readBlocks(inode->block[13], 1, blockbuf[1]); /* doubl indirect shit*/
    u32 dindirect = ((u32 *)blockbuf[1])[(block_idx >> 10) & 0x3ff];
    x2readBlocks(dindirect, 1, blockbuf[1]);
    u32 *indirect = (u32 *)blockbuf[1];
    block = indirect[block_idx & 0x3ff];
    return block;
  }

  assert("Unhandled case..." == NULL);
}

/*init*/
static struct DirInodeR x2dirInoInit(struct Inode *ino, usize blockbuf) {
  return (struct DirInodeR){
      .blockbuf = blockbuf,
      .ino = ino,
      .block = x2getFileBlock(ino, 0),
      .offt = 0,
      .block_idx = 0,
      .prev_ptr = NULL, /*->|*/
      .ent_ptr = NULL,  /*->|*/
      .ent_block = 0,   /*<-|*/
      .done = 0,
  };
}

static struct FileInodeRW x2fileInoInit(struct Inode *ino, usize inode_idx) {
  return (struct FileInodeRW){
      .ino = ino,
      .inode_idx = inode_idx,
      .filesz = x2getFileSize(ino),
      .block = x2getFileBlock(ino, 0),
      .offt = 0,
      .block_idx = 0,
      .done = 0,
  };
}

static void x2finoRefresh(struct FileInodeRW *fino) {
  fino->block = x2getFileBlock(fino->ino, fino->block_idx);
  fino->filesz = x2getFileSize(fino->ino);
}

static void x2FileInoNxtBlock(struct FileInodeRW *fino) {
  fino->block_idx += 1;
  fino->block = x2getFileBlock(fino->ino, fino->block_idx);
}

static struct DirEnt x2dirEntInit(u8 *name) {
  return (struct DirEnt){.name = name};
}
/*inits*/

/*must be dir*/
static struct DirEnt *x2ReadNxtDirEnt(struct DirInodeR *dino,
                                      struct DirEnt *dirent) {
  if (dino->done)
    return NULL;
  assert((BLOCKSIZE - dino->offt) >= 12);
  x2readBlocks(dino->block, 1, blockbuf[dino->blockbuf]);
  struct DirEnt *tmp = (struct DirEnt *)(blockbuf[dino->blockbuf] + dino->offt);
  /*--*/
  dino->prev_ptr = dino->offt == 0 ? NULL : dino->ent_ptr;
  dino->ent_ptr = tmp;
  dino->ent_block = dino->block;
  /*--*/
  u8 *dino_name = dirent->name;
  *dirent = *tmp;
  dirent->name = dino_name;
  memcpy(dirent->name, blockbuf[dino->blockbuf] + dino->offt + 8,
         tmp->name_len);
  dirent->name[tmp->name_len] = '\0';
  if ((tmp->rec_len + dino->offt) >= BLOCKSIZE) {
    dino->block_idx += 1;
    dino->block = x2getFileBlock(dino->ino, dino->block_idx);
    dino->offt = 0;
    if (x2getInodeBlockCount(dino->ino) == dino->block_idx)
      dino->done = 1;
  } else {
    dino->offt += tmp->rec_len;
  }
  return dirent;
}

static int x2FileSeekBy(struct FileInodeRW *fino, int forw, usize n) {
  if (forw) {
    if (n > (fino->filesz - fino->offt)) {
      return X2_ERR_SEEK_OUT_OF_BOUNDS;
    }
    fino->offt += n;
  } else {
    if (n > fino->offt) {
      return X2_ERR_SEEK_OUT_OF_BOUNDS;
    }
    fino->offt -= n;
  }
  fino->block_idx = fino->offt / BLOCKSIZE;
  fino->block = x2getFileBlock(fino->ino, fino->block_idx);
  return X2_OK;
}

static int x2FileSeekTo(struct FileInodeRW *fino, usize pos) {
  if (pos > fino->filesz) {
    return X2_ERR_SEEK_OUT_OF_BOUNDS;
  }
  fino->offt = pos;
  fino->block_idx = fino->offt / BLOCKSIZE;
  fino->block = x2getFileBlock(fino->ino, fino->block_idx);
  return X2_OK;
}

static usize x2ReadFileBlock(struct FileInodeRW *fino, u8 *buf, usize len) {
  usize offset = fino->offt % BLOCKSIZE;
  assert((BLOCKSIZE - offset) >= len);
  usize rlen = len;
  usize rem = (fino->filesz - fino->offt);
  if (rlen > rem) {
    rlen = rem;
  }
  x2readBlocks(fino->block, 1, blockbuf[0]);
  memcpy(buf, blockbuf[0] + offset, rlen);
  fino->offt += rlen;
  if (fino->offt % BLOCKSIZE == 0) {
    x2FileInoNxtBlock(fino);
  }
  return rlen;
}

static usize x2readFile(struct FileInodeRW *fino, u8 *buf, usize len) {
  if (len == 0)
    return 0;

  if (len > (fino->filesz - fino->offt)) {
    len = fino->filesz - fino->offt;
  }

  usize remaining_in_block = BLOCKSIZE - (fino->offt % BLOCKSIZE);
  usize total_read = 0;

  if (len <= remaining_in_block) {
    return x2ReadFileBlock(fino, buf, len);
  }

  if (remaining_in_block > 0) {
    assert(x2ReadFileBlock(fino, buf, remaining_in_block) ==
           remaining_in_block);
    total_read = remaining_in_block;
  }

  len -= total_read;
  buf += total_read;

  /*at block boundary*/
  usize full_blocks_to_read = len / BLOCKSIZE;

  for (u32 i = 0; i < full_blocks_to_read; i++) {
    assert(x2ReadFileBlock(fino, buf, BLOCKSIZE) == BLOCKSIZE);
    buf += BLOCKSIZE;
    total_read += BLOCKSIZE;
  }

  usize remaining = len % BLOCKSIZE;
  if (remaining > 0) {
    total_read += x2ReadFileBlock(fino, buf, remaining);
  }

  return total_read;
}

/*upto 32K bits*/
static void x2bitmapBlockSet(u8 *bitmap, usize bitpos) {
  assert(bitpos < BLOCKSIZE * 8);
  usize byte = bitpos / 8;
  usize bit = bitpos % 8;
  /*must be clear*/
  assert((bitmap[byte] & (1u << bit)) == 0);
  bitmap[byte] |= (1u << bit);
}

/*upto 32K bits*/
static u8 x2bitmapBlockGet(u8 *bitmap, usize bitpos) {
  assert(bitpos < BLOCKSIZE * 8);
  usize byte = bitpos / 8;
  usize bit = bitpos % 8;
  return (bitmap[byte] >> bit) & 1;
}

/*upto 32K bits*/
static void x2bitmapBlockClear(u8 *bitmap, usize bitpos) {
  assert(bitpos < BLOCKSIZE * 8);
  usize byte = bitpos / 8;
  usize bit = bitpos % 8;
  /*must be set*/
  assert((bitmap[byte] & (1u << bit)) != 0);
  bitmap[byte] &= ~(1u << bit);
}

static int x2bitmapFirstFree(u8 *bitmap, usize *res) {
  for (u32 i = 0; i < BLOCKSIZE; i++) {
    if (bitmap[i] != 0xff) {
      u8 curbit = bitmap[i];
      u8 j;
      for (j = 0; j < 8; j++) {
        if (!(curbit & 1))
          break;
        curbit >>= 1;
      }
      *res = j + i * 8;
      return X2_OK;
    }
  }
  return X2_ERR_NO_SPACE;
}

static int x2bitmapGetFreeRange(u8 *bitmap, usize n, usize *start) {
  if (x2bitmapFirstFree(bitmap, start) != X2_OK) {
    return X2_ERR_NO_SPACE;
  }
  usize acc = 0;
  for (usize i = 0; i < BLOCKSIZE * 8; i++) {
    if (x2bitmapBlockGet(bitmap, i)) {
      acc = 0;
      *start = i + 1;
    } else {
      acc += 1;
    }
    if (acc == n) {
      return X2_OK;
    }
  }
  return X2_ERR_NO_SPACE;
}

static void x2bitmapSetFreeRange(u8 *bitmap, usize start, usize n) {
  for (usize i = 0; i < n; i++) {
    /* TODO optimize shit*/
    x2bitmapBlockSet(bitmap, start + i);
  }
}

static usize x2blocksHoldingBitmap(usize total_items) {
  return ((total_items - 1) / (8 * BLOCKSIZE)) + 1;
}

static int x2allocGroupBlocks(usize group_idx, usize nblocks, usize *start) {
  assert(group_idx < x2totalGroups());
  x2readBlocks(gdesc[group_idx].block_bitmap, 1, blockbuf[0]);
  if (!x2bitmapGetFreeRange(blockbuf[0], nblocks, start)) {
    x2bitmapSetFreeRange(blockbuf[0], *start, nblocks);
    /* TODO write bitmap*/
    x2writeBlocks(gdesc[group_idx].block_bitmap, 1, blockbuf[0]);

    gdesc[group_idx].free_blocks_count -= 1;
    x2witeBGDescs();

    sb.free_blocks_count -= 1;
    x2writeSuperBlock();

    return X2_OK;
  }
  return X2_ERR_NO_SPACE;
}

struct AllocRes {
  usize group;
  usize start_idx;
};

static int x2allocBlocks(usize nblocks, struct AllocRes *res) {
  for (usize i = 0; i < x2totalGroups(); i++) {
    if (!x2allocGroupBlocks(i, nblocks, &res->start_idx)) {
      res->group = i;
      return X2_OK;
    }
  }
  return X2_ERR_NO_SPACE;
}

static int x2allocBlockX(usize *idx) {
  struct AllocRes ar;
  int res = x2allocBlocks(1, &ar);
  if (res != X2_OK) {
    return res;
  }
  *idx = ar.group * sb.blocks_per_group + ar.start_idx;
  return X2_OK;
}

static int x2allocInode(struct AllocRes *res, u8 is_dir) {
  for (usize i = 0; i < x2totalGroups(); i++) {
    x2readBlocks(gdesc[i].inode_bitmap, 1, blockbuf[0]);
    if (!x2bitmapFirstFree(blockbuf[0], &res->start_idx)) {
      x2bitmapBlockSet(blockbuf[0], res->start_idx);
      x2writeBlocks(gdesc[i].inode_bitmap, 1, blockbuf[0]);
      // x2readBlocks(gdesc[i].inode_bitmap, 1, blockbuf[0]);
      assert(x2bitmapBlockGet(blockbuf[0], res->start_idx));
      res->group = i;
      res->start_idx += 1;
      sb.free_inodes_count -= 1;
      x2writeSuperBlock();
      gdesc[i].free_inodes_count -= 1;
      if (is_dir) {
        gdesc[i].used_dirs_count += 1;
      }
      x2witeBGDescs();
      struct Inode zero = {0};
      x2WriteInode(i * sb.inodes_per_group + res->start_idx, &zero);
      return X2_OK;
    }
  }
  return X2_ERR_NO_SPACE;
}

static int x2allocInodeX(usize *idx, u8 is_dir) {
  struct AllocRes ar;
  int res = x2allocInode(&ar, is_dir);
  if (res != X2_OK) {
    return res;
  }
  *idx = ar.group * sb.inodes_per_group + ar.start_idx;
  return X2_OK;
}

static void x2dealloInodeBit(usize inode_idx, u8 is_dir) {
  inode_idx -= 1;
  usize group = inode_idx / sb.inodes_per_group;
  usize bit = inode_idx % sb.inodes_per_group;
  x2readBlocks(gdesc[group].inode_bitmap, 1, blockbuf[0]);
  x2bitmapBlockClear(blockbuf[0], bit);
  x2writeBlocks(gdesc[group].inode_bitmap, 1, blockbuf[0]);

  gdesc[group].free_inodes_count += 1;
  if (is_dir) {
    gdesc[group].used_dirs_count -= 1;
  }
  x2witeBGDescs();

  sb.free_inodes_count += 1;
  x2writeSuperBlock();
}

struct BlockLoc {
  usize group;
  usize bitmap_idx;
};

struct BlockLoc x2getBlockLoc(usize realblockpos) {
  usize g = realblockpos / sb.blocks_per_group;
  usize b = realblockpos % sb.blocks_per_group;
  return (struct BlockLoc){.group = g, .bitmap_idx = b};
}

static void x2deallocBlock(usize realblockpos) {
  struct BlockLoc bloc = x2getBlockLoc(realblockpos);
  x2readBlocks(gdesc[bloc.group].block_bitmap, 1, blockbuf[0]);
  x2bitmapBlockClear(blockbuf[0], bloc.bitmap_idx);
  /* TODO write block*/
  x2writeBlocks(gdesc[bloc.group].block_bitmap, 1, blockbuf[0]);

  sb.free_blocks_count += 1;
  x2writeSuperBlock();

  gdesc[bloc.group].free_blocks_count += 1;
  x2witeBGDescs();
}

static struct BlockLoc x2getFileBlockLoc(struct Inode *ino, usize block_idx) {
  usize realblockpos = x2getFileBlock(ino, block_idx);
  return x2getBlockLoc(realblockpos);
}

static void x2deallocIndirect(u32 *ptr) {
  while (*ptr) {
    x2deallocBlock(*ptr);
    ptr += 1;
  }
}

static void x2deallocInodeBlocks(struct Inode *ino, usize file_size) {
  usize total_blocks = file_size / BLOCKSIZE;
  for (usize i = 0; i < total_blocks;) {
    usize victim = x2getFileBlock(ino, i);
    if (victim != 0) {
      x2deallocBlock(victim);
      i++;
    }
  }
  /*sparse file not suppohed*/
  if (total_blocks < 13u) {
    return;
  }

  x2deallocBlock(ino->block[12]);

  if (total_blocks < (1024u + 13u)) {
    return;
  }

  /*{*/
  x2readBlocks(ino->block[13], 1, blockbuf[1]);
  u32 *ptr = (void *)blockbuf[1];

  x2deallocIndirect(ptr);

  x2deallocBlock(ino->block[13]);

  if (total_blocks < ((13u + 1024u) + (1024u * 1024u))) {
    return;
  }
  /*}*/

  /*idgaf about large files*/
  assert(0);
}

static void printString(u8 *s, usize len) {
  for (usize i = 0; i < len; i++) {
    printf("%c", s[i]);
  }
}

static int x2addDirEntToBlock(usize block_idx, struct DirEnt *ent) {
  assert(block_idx != 0);
  x2readBlocks(block_idx, 1, blockbuf[1]);
  u16 rec_len = alignF(8 + ent->name_len, 4);
  u8 *ptr = blockbuf[1];
  u8 *endptr = ptr + BLOCKSIZE;
  for (; ptr < endptr;) {
    struct DirEnt *record = (struct DirEnt *)ptr;

    if (ent->name_len == record->name_len &&
        memcmp(ptr + 8, ent->name, ent->name_len) == 0 && record->inode != 0) {
      printString(ptr + 8, 1);
      return X2_ERR_ENT_EXISTS;
    }

    if ((record->inode == 0) && record->rec_len >= rec_len) {
      /* ovewrite shi */
      record->name_len = ent->name_len;
      record->file_type = ent->file_type;
      record->inode = ent->inode;
      memset(ptr + 8, 0, rec_len - 8);
      memcpy(ptr + 8, ent->name, ent->name_len);
      /* TODO write block*/
      x2writeBlocks(block_idx, 1, blockbuf[1]);
      return X2_OK;
    }

    u16 actual_rec_len = alignF(8 + record->name_len, 4);
    u16 gap = record->rec_len - actual_rec_len;

    if (gap >= rec_len) {
      /* gap found */
      ptr += actual_rec_len;
      memset(ptr, 0, rec_len);
      struct DirEnt *new_rec = (struct DirEnt *)ptr;
      ptr += 8;
      *new_rec = *ent;
      memcpy(ptr, ent->name, ent->name_len);
      usize old = record->rec_len;
      new_rec->rec_len = record->rec_len - actual_rec_len; /* update new */
      record->rec_len = actual_rec_len;                    /* update old */
      /* TODO write block */
      x2writeBlocks(block_idx, 1, blockbuf[1]);
      return X2_OK;
    }
    ptr += record->rec_len;
  }
  return X2_ERR_NO_SPACE;
}

static struct DirEnt *x2mergeLeft(struct DirInodeR *dino) {
  struct DirEnt *ret;
  if (dino->prev_ptr) {
    dino->prev_ptr->rec_len += dino->ent_ptr->rec_len;
    ret = dino->prev_ptr;
  }
  ret = dino->ent_ptr;
  dino->ent_ptr->inode = 0;
  dino->ent_ptr->name_len = 0;
  dino->ent_ptr->file_type = 0;
  return ret;
}

static void x2mergeRight(struct DirEnt *ent_ptr) {
  struct DirEnt *nxt_ptr =
      (struct DirEnt *)(((u8 *)ent_ptr) + ent_ptr->rec_len);
  if (nxt_ptr /*cant be null tho*/ && nxt_ptr->inode == 0) {
    ent_ptr->rec_len += nxt_ptr->rec_len;
  }
}

static int x2searchDirInner(struct Inode *ino, u8 *name, usize namelen,
                            usize *res) {
  struct DirInodeR dino = x2dirInoInit(ino, 2);
  struct DirEnt dent = x2dirEntInit(namebuf[0]);
  for (; x2ReadNxtDirEnt(&dino, &dent);) {
    if (dent.name_len == namelen && !memcmp(name, dent.name, namelen)) {
      if (res)
        *res = dent.inode;
      return X2_OK;
    }
  }
  return X2_ERR_NO_ENT;
}

static int x2searchDirRaw(usize inode_idx, u8 *name, usize namelen,
                          usize *inode) {
  struct Inode ino;
  x2ReadInode(inode_idx, &ino);
  return x2searchDirInner(&ino, name, namelen, inode);
}

static int x2searchDir(usize inode_idx, u8 *name, usize namelen,
                       struct Inode *res, usize *res_ino_idx) {
  struct Inode ino;
  x2ReadInode(inode_idx, &ino);
  usize idx;
  int r = x2searchDirInner(&ino, name, namelen, &idx);
  if (r != X2_OK) {
    return r;
  }
  if (res) {
    x2ReadInode(idx, res);
  }
  if (res_ino_idx) {
    *res_ino_idx = idx;
  }
  return X2_OK;
}

static int x2dirIsEmptyInner(usize parent_idx, usize inode_idx,
                             struct Inode *ino) {
  struct DirInodeR dino = x2dirInoInit(ino, 3);
  struct DirEnt dent = x2dirEntInit(namebuf[0]);
  for (; x2ReadNxtDirEnt(&dino, &dent);) {
    if (dent.inode != 0 && dent.inode != parent_idx &&
        dent.inode != inode_idx) {
      return 0;
    }
  }
  return 1;
}

static int x2dirIsEmpty(usize parent_idx, usize inode_idx) {
  struct Inode ino;
  x2ReadInode(inode_idx, &ino);
  return x2dirIsEmptyInner(parent_idx, inode_idx, &ino);
}

static void x2deallocInode(struct Inode *parent, usize parent_idx,
                           usize inode_idx, u8 is_dir) {
  struct Inode ino;
  x2ReadInode(inode_idx, &ino);
  if (ino.links_count > 0) { /*lucky mf*/
    ino.links_count -= 1;
    x2WriteInode(inode_idx, &ino);
    return;
  }

  x2deallocInodeBlocks(&ino, x2getFileSize(&ino));
  /* TODO clear bitmap */
  x2dealloInodeBit(inode_idx, is_dir);

  u8 inode_is_dir = (ino.mode & EXT2_S_IFDIR) > 0;
  assert(inode_is_dir == is_dir);

  if (inode_is_dir) {
    parent->links_count -= 1; /*..*/
    x2WriteInode(parent_idx, parent);
  }

  memset(&ino, 0, sizeof(struct Inode));
  x2WriteInode(inode_idx, &ino);
}

u8 bb[BLOCKSIZE];

static int x2removeDirEntInner(usize parent_inode_idx, u8 *name,
                               usize namelen) {
  struct Inode ino;
  x2ReadInode(parent_inode_idx, &ino);

  struct DirInodeR dino = x2dirInoInit(&ino, 2);
  u8 namebuffer[255];
  struct DirEnt dent = x2dirEntInit(namebuffer);
  for (; x2ReadNxtDirEnt(&dino, &dent);) {
    if (dent.name_len == namelen && !memcmp(name, dent.name, namelen)) {
      usize victim_ino = dino.ent_ptr->inode;
      u8 victim_ino_is_dir = dino.ent_ptr->file_type == EXT2_FT_DIR;
      if (victim_ino && victim_ino_is_dir &&
          !x2dirIsEmpty(parent_inode_idx, victim_ino)) {
        return X2_ERR_DIR_NOT_EMPTY;
      }
      struct DirEnt *working_ptr = x2mergeLeft(&dino);
      x2mergeRight(working_ptr);
      x2writeBlocks(dino.ent_block, 1, blockbuf[dino.blockbuf]);
      if (victim_ino) {
        x2deallocInode(&ino, parent_inode_idx, victim_ino, victim_ino_is_dir);
      }
      return X2_OK;
    }
  }
  return X2_ERR_NO_ENT;
}

/* wont write inode */
/* add only for fulls */
static int x2inodeAddBlock(struct Inode *ino, usize block,
                           usize new_block_idx) {
  assert(block != 0);
  usize allocidx;
  int res;
  usize cur_fsize = x2getFileSize(ino);
  assert(cur_fsize % BLOCKSIZE == 0);
  if (new_block_idx < 12) {
    assert(ino->block[new_block_idx] == 0);
    ino->block[new_block_idx] = block;
    ino->blocks += BLOCKSIZE / 512;
    return X2_OK;
  }
  if (new_block_idx == 12) { /*adding 13th*/
    res = x2allocBlockX(&allocidx);
    if (res != X2_OK) {
      return res;
    }
    memset(blockbuf[0], 0, BLOCKSIZE);
    x2writeBlocks(allocidx, 1, blockbuf[0]);
    ino->block[12] = allocidx;
    ino->blocks += BLOCKSIZE / 512;
  }
  new_block_idx -= 12;
  if (new_block_idx < 1024) {
    x2readBlocks(ino->block[12], 1, blockbuf[1]); /*indirect shit*/
    u32 *indirect = (u32 *)blockbuf[1];
    assert(indirect[new_block_idx] == 0);
    indirect[new_block_idx] = block;
    ino->blocks += BLOCKSIZE / 512;
    x2writeBlocks(ino->block[12], 1, blockbuf[1]); /*indirect shit*/
    return X2_OK;
  }
  new_block_idx -= 1024;
  if (new_block_idx == 0) {
    res = x2allocBlockX(&allocidx);
    if (res != X2_OK) {
      return res;
    }
    memset(blockbuf[0], 0, BLOCKSIZE);
    x2writeBlocks(allocidx, 1, blockbuf[0]);
    assert(ino->block[13] == 0);
    ino->block[13] = allocidx;
    ino->blocks += BLOCKSIZE / 512;
  }

  if (new_block_idx < (1024 * 1024)) {
    x2readBlocks(ino->block[13], 1, blockbuf[1]); /*dubl indirect shit*/
    u32 *dindirect = (u32 *)blockbuf[1];
    usize ddidx = (new_block_idx >> 10) & 0x3ff;

    if (dindirect[ddidx] == 0) {
      res = x2allocBlockX(&allocidx);
      assert(new_block_idx % 1024 == 0);
      if (res != X2_OK) {
        return res;
      }
      memset(blockbuf[0], 0, BLOCKSIZE);
      x2writeBlocks(allocidx, 1, blockbuf[0]);
      dindirect[ddidx] = allocidx;
      ino->blocks += BLOCKSIZE / 512;
      x2writeBlocks(ino->block[13], 1, blockbuf[1]);
    }

    usize indirect_block = dindirect[ddidx];
    x2readBlocks(indirect_block, 1, blockbuf[1]);
    u32 *indirect = (u32 *)blockbuf[1];
    assert(indirect[new_block_idx & 0x3ff] == 0);
    indirect[new_block_idx & 0x3ff] = block;
    x2writeBlocks(indirect_block, 1, blockbuf[1]);
    ino->blocks += BLOCKSIZE / 512;
    return X2_OK;
  }
  assert("Unhandled case..." == NULL);
}

/*wont write inode*/
static int x2inodeAddBlocks(struct Inode *ino, usize n) {
  usize new_block_idx = alignF(x2getFileSize(ino), BLOCKSIZE) / BLOCKSIZE;
  usize idx;
  for (usize i = 0; i < n; i++) {
    int res = x2allocBlockX(&idx);
    if (res != X2_OK) {
      return res;
    }
    x2inodeAddBlock(ino, idx, new_block_idx + i);
  }
  return X2_OK;
}

static void x2initDirBlock(usize block_idx) {
  x2readBlocks(block_idx, 1, blockbuf[0]);
  struct DirEnt *null_ent = (void *)blockbuf[0];
  null_ent->file_type = 0;
  null_ent->inode = 0;
  null_ent->name_len = 0;
  null_ent->rec_len = BLOCKSIZE;
  x2writeBlocks(block_idx, 1, blockbuf[0]);
}

/* wont write inode */
static int x2addDirEntInner(struct Inode *ino, struct DirEnt *new_ent) {
  /* TODO alloc inode */
  usize block, i, total_blocks;
  total_blocks = x2getInodeBlockCount(ino);
  int res;
  for (i = 0; i < total_blocks; i++) {
    block = x2getFileBlock(ino, i);
    res = x2addDirEntToBlock(block, new_ent);
    if (res != X2_ERR_NO_SPACE) {
      return res;
    }
  }
  /* no space */
  res = x2allocBlockX(&block);
  if (res != X2_OK) {
    return res;
  }

  x2initDirBlock(block);

  res = x2addDirEntToBlock(block, new_ent);

  if (res != X2_OK) {
    return res;
  }

  x2inodeAddBlock(ino, block, i);
  x2setFileSize(ino, x2getFileSize(ino) + BLOCKSIZE);
  return X2_OK;
}

static int x2direntAllocInode(struct DirEnt *ent) {
  usize ino_idx;
  int res = x2allocInodeX(&ino_idx, ent->file_type == EXT2_FT_DIR);
  if (res != X2_OK) {
    return res;
  }
  ent->inode = ino_idx;

  struct Inode ino = {0};

  if (ent->file_type == EXT2_FT_DIR) {
    usize first_block_idx;
    res = x2allocBlockX(&first_block_idx);
    if (res != X2_OK) {
      return res;
    }
    ino.block[0] = first_block_idx;
    ino.blocks = BLOCKSIZE / 512;
    ino.size = BLOCKSIZE;

    x2initDirBlock(first_block_idx);
  }

  ino.mode = 0;

  if (ent->file_type != EXT2_FT_REG_FILE) {
    ino.dir_acl = 0;
  }

  switch (ent->file_type) {
  case EXT2_FT_REG_FILE:
    ino.mode |= EXT2_S_IFREG;
    break;
  case EXT2_FT_DIR:
    ino.mode |= EXT2_S_IFDIR;
    break;
  case EXT2_FT_SYMLINK:
    ino.mode |= EXT2_S_IFLNK;
    break;
  default:
    assert(0);
  }

  ino.ctime = x2readTimestamp();
  ino.dtime = 0;
  ino.mtime = x2readTimestamp();
  ino.atime = x2readTimestamp();
  ino.file_acl = 0;
  ino.links_count = 1;

  x2WriteInode(ino_idx, &ino);
  return X2_OK;
}

/*if inode is 0 i alloc*/
static int x2addDirEnt(usize inode_idx, struct DirEnt *ent) {
  int res;
  struct Inode ent_inode;

  if (ent->inode == 0) {
    res = x2direntAllocInode(ent);
    if (res != 0) {
      return res;
    }
  }

  x2ReadInode(ent->inode, &ent_inode);

  struct Inode inode;
  x2ReadInode(inode_idx, &inode);

  res = x2addDirEntInner(&inode, ent);
  if (res != X2_OK) {
    return res;
  }

  struct DirEnt tmp = {
      .file_type = EXT2_FT_DIR,
      .inode = ent->inode,
      .name_len = 1,
      .name = "..",
  };

  if (ent->file_type == EXT2_FT_DIR) {
    res = x2addDirEntInner(&ent_inode, &tmp);
    if (res != X2_OK) {
      return res;
    }
    inode.links_count += 1;

    tmp.name_len = 2;
    tmp.inode = inode_idx;
    res = x2addDirEntInner(&ent_inode, &tmp);
    if (res != X2_OK) {
      return res;
    }
    ent_inode.links_count += 1;
    x2WriteInode(ent->inode, &ent_inode);
  }

  x2WriteInode(inode_idx, &inode);
  return X2_OK;
}

static int x2removeDirEnt(usize inode_idx, const char *name) {
  usize namelen = strnlen(name, 255);
  int res = x2removeDirEntInner(inode_idx, name, namelen);
  if (res != X2_OK) {
    return res;
  }
  return X2_OK;
}

static usize x2writeFileBlock(struct FileInodeRW *fino, u8 *buf, usize len) {
  if (fino->block == 0) {
    x2readBlocks(fino->ino->block[12], 1, blockbuf[0]);
    u32 *ptr = (void *)blockbuf[0];
  }
  assert(fino->block != 0);
  usize offset = fino->offt % BLOCKSIZE;
  assert((BLOCKSIZE - offset) >= len);
  if (offset == 0 && len == BLOCKSIZE) {
  } else {
    x2readBlocks(fino->block, 1, blockbuf[0]);
  }
  memcpy(blockbuf[0] + offset, buf, len);
  x2writeBlocks(fino->block, 1, blockbuf[0]);
  fino->offt += len;
  if (fino->offt % BLOCKSIZE == 0) {
    x2FileInoNxtBlock(fino);
  }
  return len;
}

static isize x2writeFile(struct FileInodeRW *fino, u8 *buf, isize len) {
  if (len <= 0)
    return 0;

  u8 update_inode = 0;

  u64 final_offt = fino->offt + len;
  usize final_blocks = alignF(final_offt, BLOCKSIZE) / BLOCKSIZE;
  usize current_blocks = alignF(fino->filesz, BLOCKSIZE) / BLOCKSIZE;

  if (final_blocks > current_blocks) {
    int res = x2inodeAddBlocks(fino->ino, final_blocks - current_blocks);
    if (res != X2_OK) {
      return res;
    }
    update_inode = 1;
    x2finoRefresh(fino);
  }

  if (final_offt > fino->filesz) {
    x2setFileSize(fino->ino, final_offt);
    update_inode = 1;
    x2finoRefresh(fino);
  }

  usize remaining_in_block = (BLOCKSIZE - (fino->offt % BLOCKSIZE));
  usize n = 0;

  if (len <= remaining_in_block) {
    n = x2writeFileBlock(fino, buf, len);
    if (update_inode) {
      x2WriteInode(fino->inode_idx, fino->ino);
    }
    return n;
  }

  if (remaining_in_block > 0) {
    assert(x2writeFileBlock(fino, buf, remaining_in_block) ==
           remaining_in_block);
    n = remaining_in_block;
  }

  len -= n;
  buf += n;

  /*at block boundary*/
  assert(fino->offt % BLOCKSIZE == 0);

  usize remains = len % BLOCKSIZE;
  usize full_blocks = len / BLOCKSIZE;

  for (usize i = 0; i < full_blocks; i++) {
    assert(x2writeFileBlock(fino, buf, BLOCKSIZE) == BLOCKSIZE);
    n += BLOCKSIZE;
    buf += BLOCKSIZE;
  }

  /*still at block boundary*/
  assert(x2writeFileBlock(fino, buf, remains) == remains);
  n += remains;

  if (update_inode) {
    x2WriteInode(fino->inode_idx, fino->ino);
  }

  return n;
}

int x2readLink(usize inode_idx, const char *name, char *result,
               usize resultlen) {
  usize dir_ino;
  usize res_ino;
  struct Inode ino;
  int res = x2searchDir(inode_idx, name, strnlen(name, 255), &ino, &res_ino);
  if (res != X2_OK) {
    return res;
  }

  if (!(ino.mode & EXT2_S_IFLNK)) {
    return X2_ERR_NOT_SYMLINK;
  }

  char *linkbuf;
  usize i;
  usize filesize = x2getFileSize(&ino);

  if (filesize <= 60) {
    linkbuf = (char *)&ino.block;
  } else {
    usize block = x2getFileBlock(&ino, 0);
    x2readBlocks(block, 1, blockbuf[0]);
    linkbuf = (char *)blockbuf[0];
  }

  for (i = 0; i < filesize && i < resultlen; i++) {
    result[i] = linkbuf[i];
  }
  return i;
}

int x2createLink(usize inode_idx, const char *link_name,
                 const char *target_name) {
  struct Inode parent;
  x2ReadInode(inode_idx, &parent);

  if (!(parent.mode & EXT2_S_IFDIR)) {
    return X2_ERR_NOT_DIR;
  }

  usize target_name_len = strnlen(target_name, 255);
  usize link_name_len = strnlen(link_name, 255);

  struct DirEnt ent = {
      .file_type = EXT2_FT_SYMLINK,
      .name_len = link_name_len,
      .name = link_name,
  };

  int res = x2direntAllocInode(&ent);

  if (res != X2_OK) {
    return res;
  }

  struct Inode ino;
  x2ReadInode(ent.inode, &ino);

  char *linkbuf;
  usize block;

  if (target_name_len <= 60) {
    linkbuf = (char *)&ino.block;
  } else {
    res = x2allocBlockX(&block);
    if (res != X2_OK) {
      return res;
    }
    ino.blocks = BLOCKSIZE / 512;
    ino.block[0] = block;
    memset(blockbuf[0], 0, BLOCKSIZE);
    linkbuf = (char *)blockbuf[0];
  }

  for (usize i = 0; i < target_name_len; i++) {
    linkbuf[i] = target_name[i];
  }

  if (target_name_len > 60) {
    x2writeBlocks(block, 1, blockbuf[0]);
  }

  x2setFileSize(&ino, target_name_len);
  x2WriteInode(ent.inode, &ino);

  res = x2addDirEntInner(&parent, &ent);

  if (res != X2_OK) {
    return res;
  }

  x2WriteInode(inode_idx, &parent);
  return X2_OK;
}

static int x2createFile(usize dir_inode_idx, const char *name) {
  struct Inode parent;
  x2ReadInode(dir_inode_idx, &parent);

  if (!(parent.mode & EXT2_S_IFDIR)) {
    return X2_ERR_NOT_DIR;
  }

  usize name_len = strnlen(name, 255);
  struct DirEnt ent = {
      .file_type = EXT2_FT_REG_FILE, .name = name, .name_len = name_len};

  int res = x2direntAllocInode(&ent);

  if (res != X2_OK) {
    return res;
  }

  res = x2addDirEntInner(&parent, &ent);
  if (res != X2_OK) {
    return res;
  }
  x2WriteInode(dir_inode_idx, &parent);
  return X2_OK;
}

void x2Init(struct BlockDev *d) {
  dev = d;
  x2ReadSuperBlock();
  assert(sb.inode_size == 128);
  usize sz = x2totalGroups() * sizeof(struct GroupDesc);
  usize gdescblocks = alignF(sz, BLOCKSIZE) / BLOCKSIZE;
  assert(gdescblocks == 1);
  gdesc = malloc(sz); /*new*/
  x2ReadBGDescs();
  assert(x2blockSize() == 4096);
  assert(x2blocksHoldingBitmap(sb.blocks_per_group) == 1);
  assert(x2blocksHoldingBitmap(sb.inodes_per_group) == 1);
  /* TODO */
}

struct BlockDev Dummy(FILE *f);
static void DummyFlush(FILE *f);

FILE *openImage(const char *path) {
  FILE *i = fopen(path, "rb+");
  assert(i);
  return i;
}

u8 readbuf[BLOCKSIZE * 16];
u8 nb[255];
/*MAIN*/
i32 main() {
  assert(sizeof(blockbuf[0]) == BLOCKSIZE);
  FILE *img = openImage("disk.img");
  // __attribute__((defer()));
  struct BlockDev bd = Dummy(img);
  x2Init(&bd);
  struct Inode ino;
  // struct DirInodeR dino = x2dirInoInit(&ino);
  // struct DirEnt dirent = x2dirEntInit(namebuf[0]);

  struct DirEnt tmp = {
      .inode = 0,
      .file_type = EXT2_FT_DIR,
      .name_len = 3,
      .name = "m.c",
  };
  usize res_ino;

  u8 linkname[255];

  int l = x2createFile(2, "musakwezz");
  assert(l == 0);
  // printString(linkname, l);

  // assert(!x2searchDir(2, tmp.name, tmp.name_len, &ino, &res_ino));
  // struct FileInodeRW fino = x2fileInoInit(&ino, res_ino);
  // memcpy(nb,
  //        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345679"
  //        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
  //        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
  //        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
  //        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
  //        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
  //        255);

  // for (usize i = 0; i < 250; i++) {
  //   int r = x2direntAllocInode(&tmp);

  //   assert(r == 0);
  //   x2ReadInode(tmp.inode, &ino);
  //   assert(ino.mode == EXT2_S_IFDIR);
  //   r = x2addDirEnt(2, &tmp);
  // printf(".. %d %c\n", r, namebuf[0][0]);
  // assert(r == 0);
  // tmp.name_len += 1;
  // }

  // tmp.name_len = 1;

  // for (usize i = 0; i < 250; i++) {
  // int r = x2removeDirEntInner(2, tmp.name, tmp.name_len);
  // assert(r == 0);
  // tmp.name_len += 1;
  // }

  // memset(readbuf, 'z', BLOCKSIZE);
  // usize r;

  // char c = 'a';
  // for (int i = 0; i < 1040; i++) {
  // memset(readbuf, 'a' + i, BLOCKSIZE);
  // r = x2writeFile(&fino, &c, 1);
  // printf("writing %c\n", c);
  // c+=1;
  // assert(r == 1);
  // break;
  // }

  // printf("fino->offt: %d\n", fino.offt);
  // printf("fino->fsize: %d\n", fino.filesz);
  // printf("fino->block: %d\n", fino.block);
  // printf("fino->block_idx: %d\n", fino.block_idx);

  // assert(x2FileSeekBy(&fino, 0, 1000)==0);
  // r = x2readFile(&fino, readbuf, BLOCKSIZE * 2);

  // printString(readbuf, r);

  // x2ReadInode(res_ino, &ino);
  // printf("total file size %d\n", x2getFileSize(&ino));

  // printf("ino.blocks %d\n", ino.block);
  // char *c = (char*)&ino.block;
  // printf("ino.blocks %c\n", c[0]);
  // printf("ino.blocks %c\n", c[1]);
  // printf("ino.blocks %c\n", c[2]);
  // printf("ino.blocks %c\n", c[3]);
  // printf("ino.blocks %c\n", c[4]);
  // printf("ino.blocks %c\n", c[5]);
  // printf("ino.blocks %c\n", c[6]);
  // printf("ino.blocks %c\n", c[7]);

  // printf("removed = %d\n", x2removeDirEnt(2, tmp.name));
  // printf("removed = %d %d\n", x2addDirEnt(2, &tmp), ino.file_acl);
  DummyFlush(img);
  return 0;
  // usize j;
  // printf("removed = %d\n", x2allocInodeX(&j));
  // struct Inode jino;
  // x2ReadInode(12, &jino);
  // printf("atime %d\n", jino.atime);
  // printf("dtime %d\n", jino.dtime);
  // printf("mtime %d\n", jino.mtime);
  // printf("ctime %d\n", jino.ctime);
  // printf("blocks %d\n", jino.blocks);
  // printf("block[0] %d\n", jino.block[0]);
  // printf("size %d\n", jino.size);
  // printf("links_count %d\n", jino.links_count);
  // printf("mode %d\n", jino.mode);
  // assert(x2direntAllocInode(&tmp) == X2_OK);
  // return 0;

  // printf("added = %d\n", x2readTimestamp());
  // return 0;

  // tmp.name_len = 5, tmp.name = "file2";
  // tmp.inode = 4050;
  // tmp.file_type = 2;

  // printf("added = %d\n", x2addDirEntToBlock(dino.block, &tmp, 0));

  // tmp.name_len = 10, tmp.name = "1234567890";
  // tmp.inode = 4050;
  // tmp.file_type = 2;

  // printf("added = %d\n", x2addDirEntToBlock(dino.block, &tmp, 0));

  // tmp.name_len = 10, tmp.name = "fifa30.exe";
  // tmp.inode = 40;
  // tmp.file_type = 2;
  // struct Inode new_ino;

  // x2ReadInode(12, &new_ino);

  // printf("size %d\n", new_ino.size);
  // printf("blocks %d\n", new_ino.blocks);
  // printf("block[0] %d\n", new_ino.block[0]);
  // return 0;
  // dino = x2dirInoInit(&new_ino);

  // x2dealloInodeBit(192);
  // x2dealloInodeBit(192);
  // x2dealloInodeBit(193);
  // x2dealloInodeBit(194);

  // printf("removed = %d\n", x2dirRemoveEntry(3, tmp.name));
  // printf("removed = %d %d\n", x2dirAddEntry(3, &tmp), 0);
  // return 0;
  // printf("removed = %d\n", x2searchDir(&ino, "file2", 5, NULL));
  // printf("removed = %d\n", x2searchDir(&ino, "lost+found", 10, NULL));

  // printf("%u\n", ino.atime);
  // printf("%lu %lu\n", new_ino.links_count, x2getInodeBlockCount(&new_ino));
  // dino.offt = 0;
  // dino.done = 0;
  // dino.block_idx = 0;
  // for (;;) {
  //   if (!x2ReadNxtDirEnt(&dino, &dirent))
  //     break;
  //   printf("Name -> %s inode %d reclen %d\n", dirent.name, dirent.inode,
  //          dirent.rec_len);
  // if(dirent.inode == 0) break;
  // break;
  // }

  // printf("bug = %d %d\n", x2getInodeBlockCount(dino.ino), dino.block_idx);

  // x2readBlocks(gdesc[0].block_bitmap, 1, blockbuf[0]);
  // x2bitmapBlockClear(blockbuf[0], 0);
  // usize first_free;
  // struct BlockLoc r = x2getFileBlockLoc(&ino, 0);
  // x2readBlocks(gdesc[0].block_bitmap, 1, blockbuf[0]);
  // x2deallocBlock(ino.block[0]);
  // x2allocBlocks(30, &r);
  // printf("  idx: %d on group %d get %d\n", r.bitmap_idx, r.group,
  // x2bitmapBlockGet(blockbuf[0], r.bitmap_idx));
  // memset(blockbuf[0], 0xff, BLOCKSIZE-3);
  // int done = x2bitmapFirstFree(blockbuf[0], &first_free);
  // if (done == 0) {
  // printf("SUCCESS..\n");
  // } else {
  // printf("FAIL..\n");
  // }
  // printf("FIRST FREE: %lu\n", first_free);
  // x2bitmapBlockSet(blockbuf[0], first_free);
  // done = x2bitmapFirstFree(blockbuf[0], &first_free);
  // x2bitmapBlockClear(blockbuf[0], first_free-1);
  // done = x2bitmapFirstFree(blockbuf[0], &first_free);
  // struct Inode ino;
  // x2ReadInode(18, &ino);
  // struct FileInodeRW fino = x2fileInoInit(&ino);
  // assert(x2FileSeekTo(&fino, 4090) == 0);
  // printf("file size %d\n", x2getFileSize(&ino));
  // for (;;) {
  //   usize n = x2readFile(&fino, readbuf, 1);
  //   printf("%lu bytes were read..\n", n);
  //   if (n == 0)
  //     break;
  //   for (u32 i = 0; i < 1; i++) {
  //     printf("%c", readbuf[i]);
  //   }
  // }

  // struct DirInodeR dino = x2dirInoInit(&ino);
  // struct DirEnt dirent = x2dirEntInit(namebuf);
  // printf("%u\n", ino.atime);
  // printf("%lu %lu\n", x2getFileBlock(&ino, 0), x2getInodeBlockCount(&ino));
  // for (;;) {
  //   if(!x2ReadNxtDirEnt(&dino, &dirent)) break;
  //   printf("Name -> %d %s\n", dirent.inode, dirent.name);
  // }
  return 0;
}

u8 rdbuf[1024 * 1024 * 8];

u64 read(FILE *f, u8 *buf, u64 len) {
  u64 read = 0;
  while (read < len) {
    u64 n = fread(buf + read, 1, len - read, f);
    // printf(" read chunk len: %lu\n", n);
    read += n;
    if (n == 0) {
      if (ferror(f)) {
        printf("FileReader::read() failed\n");
        assert(0);
      }
      break;
    }
  }
  return read;
}

u64 write(FILE *f, const u8 *buf, u64 len) {
  u64 written = 0;
  while (written < len) {
    u64 amnt = len - written;
    u64 n = fwrite(buf + written, 1, amnt, f);
    if (n != amnt) {
      if (ferror(f)) {
        printf("FileReader::write() failed\n");
        assert(0);
      }
      break;
    }
    written += n;
  }
  return written;
}

void seekBy(FILE *f, i64 n) {
  if (fseek(f, n, SEEK_CUR)) {
    printf("FileReader::seekBy() failed.\n");
    assert(0);
  }
}

void seekTo(FILE *f, i64 n) {
  if (fseek(f, n, SEEK_SET)) {
    printf("FileReader::seekBy() failed.\n");
    assert(0);
  }
  assert(ftell(f) == n);
}

u64 getPos(FILE *f) { return ftell(f); }

u32 getFileSize(FILE *f) {
  if (fseek(f, 0, SEEK_END)) {
    printf("FileReader::getFileSize() failed.\n");
    assert(0);
  }
  u32 size = ftell(f);
  seekTo(f, 0);
  return size;
}

void readBlock(void *f, usize pos, u8 *buf) {
  // seekTo(f, pos * BLOCKSIZE);
  // printf("\n---------------> reading block %lu pb %ld ftell %ld\n", pos, pos
  // * BLOCKSIZE, ftell(f));
  // assert(read(f, buf, BLOCKSIZE) == BLOCKSIZE);
  memcpy(buf, rdbuf + pos * BLOCKSIZE, BLOCKSIZE);
}

void writeBlock(void *f, usize pos, const u8 *buf) {
  // seekTo(f, pos * BLOCKSIZE);
  // assert(write(f, buf, BLOCKSIZE) == BLOCKSIZE);
  memcpy(rdbuf + pos * BLOCKSIZE, buf, BLOCKSIZE);
}

void dummyR(void *d, usize pos, u8 *buf) {
  return readBlock(((struct BlockDev *)d)->ctx, pos, buf);
}

void dummyW(void *d, usize pos, const u8 *buf) {
  return writeBlock(((struct BlockDev *)d)->ctx, pos, buf);
}

struct BlockDev Dummy(FILE *f) {
  seekTo(f, 0);
  assert(read(f, rdbuf, sizeof(rdbuf)) == sizeof(rdbuf));
  return (struct BlockDev){
      .readBlock = &dummyR,
      .writeBlock = &dummyW,
      .ctx = (void *)f,
  };
}

static void DummyFlush(FILE *f) {
  seekTo(f, 0);
  assert(write(f, rdbuf, sizeof(rdbuf)) == sizeof(rdbuf));
  printf("image written to file..\n");
}
