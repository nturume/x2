#include "x2.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

struct SuperBlock sb;
struct BlockDev *dev;
struct GroupDesc *gdesc;
u8 blockbuf[4][BLOCKSIZE];

static inline u8 checkBits(u32 value, u32 bits) {
  return (value & bits) == bits;
}

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

void x2readInode(usize inode_idx, struct Inode *inode) {
  struct InodeLoc loc = x2getInodeLoc(inode_idx);
  x2readBlocks(loc.block, 1, blockbuf[0]);
  *inode = ((struct Inode *)blockbuf[0])[loc.idx];
}

static void x2WriteInode(usize inode_idx, struct Inode *inode) {
  struct InodeLoc loc = x2getInodeLoc(inode_idx);
  x2readBlocks(loc.block, 1, blockbuf[0]);
  ((struct Inode *)blockbuf[0])[loc.idx] = *inode;
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

static struct DirEnt x2dirEntInit(u8 *name) {
  return (struct DirEnt){.name = name};
}
/*inits*/

/*must be dir*/
static struct DirEnt *x2ReadNxtDirEnt(struct DirInodeR *dino,
                                      struct DirEnt *dirent) {
  if (dino->done || dino->block == 0)
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
  if (tmp->name_len < 255)
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

static struct DirEnt *x2nextEntry(struct DirInodeR *dino,
                                  struct DirEnt *dirent) {
  return x2ReadNxtDirEnt(dino, dirent);
}

static void x2bitmapBlockSet(u8 *bitmap, usize bitpos) {
  assert(bitpos < BLOCKSIZE * 8);
  usize byte = bitpos / 8;
  usize bit = bitpos % 8;
  /*must be clear*/
  assert((bitmap[byte] & (1u << bit)) == 0);
  bitmap[byte] |= (1u << bit);
}

static u8 x2bitmapBlockGet(u8 *bitmap, usize bitpos) {
  assert(bitpos < BLOCKSIZE * 8);
  usize byte = bitpos / 8;
  usize bit = bitpos % 8;
  return (bitmap[byte] >> bit) & 1;
}

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

static int x2allocBlockInner(struct AllocRes *res) {
  for (usize i = 0; i < x2totalGroups(); i++) {
    if (!x2allocGroupBlocks(i, 1, &res->start_idx)) {
      res->group = i;
      return X2_OK;
    }
  }
  return X2_ERR_NO_SPACE;
}

static int x2allocBlockX(usize *idx) {
  struct AllocRes ar;
  int res = x2allocBlockInner(&ar);
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

static void x2deallocInodeBlocks(struct Inode *ino) {
  u64 file_size = x2getFileSize(ino);
  if (checkBits(ino->mode, EXT2_S_IFLNK) && file_size <= 60) {
    return;
  }
  usize total_blocks = alignF(file_size, BLOCKSIZE) / BLOCKSIZE;
  for (usize i = 0; i < total_blocks; i++) {
    usize victim = x2getFileBlock(ino, i);
    assert(victim != 0);
    x2deallocBlock(victim);
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
  assert("Too large file" == NULL);
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
      new_rec->name_len = ent->name_len;
      new_rec->inode = ent->inode;
      new_rec->file_type = ent->file_type;
      ptr += 8;
      memcpy(ptr, ent->name, ent->name_len);
      usize old = record->rec_len;
      new_rec->rec_len = record->rec_len - actual_rec_len; /* update new */
      record->rec_len = actual_rec_len;                    /* update old */
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
  if (nxt_ptr && nxt_ptr->inode == 0) {
    ent_ptr->rec_len += nxt_ptr->rec_len;
  }
}

static int x2searchDirInner(struct Inode *ino, u8 *name, usize namelen,
                            usize *res) {
  struct DirInodeR dino = x2dirInoInit(ino, 2);
  u8 namebuf[255];
  struct DirEnt dent = x2dirEntInit(namebuf);
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
  x2readInode(inode_idx, &ino);
  return x2searchDirInner(&ino, name, namelen, inode);
}

static int x2searchDir(struct Inode *parent, u8 *name, usize namelen,
                       struct Inode *res, usize *res_ino_idx) {
  if (!checkBits(parent->mode, EXT2_S_IFDIR)) {
    return X2_ERR_NOT_DIR;
  }

  usize idx;
  int r = x2searchDirInner(parent, name, namelen, &idx);
  if (r != X2_OK) {
    return r;
  }
  if (res) {
    x2readInode(idx, res);
  }
  if (res_ino_idx) {
    *res_ino_idx = idx;
  }
  return X2_OK;
}

static int x2dirIsEmptyInner(usize parent_idx, usize inode_idx,
                             struct Inode *ino) {
  struct DirInodeR dino = x2dirInoInit(ino, 3);
  u8 namebuf[255];
  struct DirEnt dent = x2dirEntInit(namebuf);
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
  x2readInode(inode_idx, &ino);
  return x2dirIsEmptyInner(parent_idx, inode_idx, &ino);
}

static void x2deallocInode(struct Inode *parent, usize parent_idx,
                           usize inode_idx, u8 is_dir) {
  struct Inode ino;
  x2readInode(inode_idx, &ino);
  assert(ino.links_count > 0);
  if (checkBits(ino.mode, EXT2_S_IFDIR)) {
    ino.links_count = 0;
  } else {
    ino.links_count -= 1;
  }
  if (ino.links_count > 0) { /*lucky mf*/
    x2WriteInode(inode_idx, &ino);
    return;
  }

  x2deallocInodeBlocks(&ino);
  x2dealloInodeBit(inode_idx, is_dir);

  u8 inode_is_dir = checkBits(ino.mode, EXT2_S_IFDIR);
  assert(inode_is_dir == is_dir);

  if (inode_is_dir) {
    parent->links_count -= 1; /*..*/
    x2WriteInode(parent_idx, parent);
  }

  // memset(&ino, 0, sizeof(struct Inode));
  ino.dtime = x2readTimestamp();
  x2WriteInode(inode_idx, &ino);
}

static int x2removeDirEntInner(struct Inode *parent, usize parent_inode_idx,
                               u8 *name, usize namelen) {
  struct DirInodeR dino = x2dirInoInit(parent, 2);
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
        x2deallocInode(parent, parent_inode_idx, victim_ino, victim_ino_is_dir);
      }
      return X2_OK;
    }
  }
  return X2_ERR_NO_ENT;
}

/* wont write inode */
static int x2inodeAddBlock(struct Inode *ino, usize block,
                           usize new_block_idx) {
  assert(block != 0);
  usize allocidx;
  int res;
  if (sb.free_blocks_count < 2) {
    return X2_ERR_NO_SPACE;
  }
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
    x2readBlocks(ino->block[12], 1, blockbuf[1]); /*indirect*/
    u32 *indirect = (u32 *)blockbuf[1];
    assert(indirect[new_block_idx] == 0);
    indirect[new_block_idx] = block;
    ino->blocks += BLOCKSIZE / 512;
    x2writeBlocks(ino->block[12], 1, blockbuf[1]); /*indirect*/
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
    x2readBlocks(ino->block[13], 1, blockbuf[1]); /*dubl indirect*/
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
  assert("4GB+ file" == NULL); /*4GB+*/
}

/*wont write inode*/
static int x2inodeAddBlocks(struct Inode *ino, usize n, usize *added) {
  usize new_block_idx = alignF(x2getFileSize(ino), BLOCKSIZE) / BLOCKSIZE;
  usize idx;
  *added = 0;
  for (usize i = 0; i < n; i++) {
    int res = x2allocBlockX(&idx);

    if (res == X2_ERR_NO_SPACE && i > 0) {
      return X2_OK;
    }

    if (res != X2_OK) { /*other error*/
      return res;
    }

    res = x2inodeAddBlock(ino, idx, new_block_idx + i);

    if (res == X2_ERR_NO_SPACE && i > 0) {
      x2deallocBlock(idx);
      return X2_OK;
    }

    if (res != X2_OK) { /*other error*/
      x2deallocBlock(idx);
      return res;
    }

    *added += 1;
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

/*wont write inode*/
static int x2direntAllocInode(struct DirEnt *ent, struct Inode *ino) {

  if (ino == NULL) {
    return X2_ERR_NULL_PTR;
  }

  usize ino_idx;
  int res = x2allocInodeX(&ino_idx, ent->file_type == EXT2_FT_DIR);
  if (res != X2_OK) {
    return res;
  }
  ent->inode = ino_idx;

  memset(ino, 0, sizeof(struct Inode));

  if (ent->file_type == EXT2_FT_DIR) {
    usize first_block_idx;
    res = x2allocBlockX(&first_block_idx);
    if (res != X2_OK) {
      return res;
    }
    ino->block[0] = first_block_idx;
    ino->blocks = BLOCKSIZE / 512;
    ino->size = BLOCKSIZE;

    x2initDirBlock(first_block_idx);
  }

  ino->mode = 0;

  if (ent->file_type != EXT2_FT_REG_FILE) {
    ino->dir_acl = 0;
  }

  switch (ent->file_type) {
  case EXT2_FT_REG_FILE:
    ino->mode |= EXT2_S_IFREG;
    break;
  case EXT2_FT_DIR:
    ino->mode |= EXT2_S_IFDIR;
    break;
  case EXT2_FT_SYMLINK:
    ino->mode |= EXT2_S_IFLNK;
    break;
  default:
    assert(0);
  }

  ino->ctime = x2readTimestamp();
  ino->dtime = 0;
  ino->mtime = x2readTimestamp();
  ino->atime = x2readTimestamp();
  ino->file_acl = 0;
  ino->links_count = 1;

  return X2_OK;
}

static int x2addDirEnt(struct Inode *parent, usize parent_inode_idx,
                       struct DirEnt *ent, struct Inode *ent_inode) {
  int res;
  assert(ent->inode != 0);
  res = x2addDirEntInner(parent, ent);
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
    res = x2addDirEntInner(ent_inode, &tmp);
    if (res != X2_OK) {
      return res;
    }
    parent->links_count += 1;

    tmp.name_len = 2;
    tmp.inode = parent_inode_idx;
    res = x2addDirEntInner(ent_inode, &tmp);
    if (res != X2_OK) {
      return res;
    }
    ent_inode->links_count += 1;
  }

  x2WriteInode(ent->inode, ent_inode);
  x2WriteInode(parent_inode_idx, parent);
  return X2_OK;
}

static int x2createFileInner(struct Inode *parent, usize parent_idx,
                             struct Inode *child, usize *child_idx,
                             const char *name, usize name_len, u32 file_type) {

  if (file_type & EXT2_FT_DIR) {
    if (sb.free_inodes_count < 1 || sb.free_blocks_count < 1)
      return X2_ERR_NO_SPACE;
  } else {
    if (sb.free_inodes_count < 1)
      return X2_ERR_NO_SPACE;
  }

  if (!checkBits(parent->mode, EXT2_S_IFDIR)) {
    return X2_ERR_NOT_DIR;
  }

  struct DirEnt ent = {
      .file_type = file_type, .name = (u8 *)name, .name_len = name_len};

  int res = x2direntAllocInode(&ent, child);

  if (res != X2_OK) {
    return res;
  }

  res = x2addDirEnt(parent, parent_idx, &ent, child);
  if (res != X2_OK) {
    return res;
  }
  if (child_idx)
    *child_idx = ent.inode;
  return X2_OK;
}

static inline usize x2ReadFileBlock(struct Inode *ino, u64 file_offt, u8 *buf,
                                    usize len) {
  usize block_idx = file_offt / BLOCKSIZE;
  usize block_offt = file_offt % BLOCKSIZE;
  assert(block_offt < BLOCKSIZE && (BLOCKSIZE - block_offt) >= len);
  usize block = x2getFileBlock(ino, block_idx);
  assert(block != 0);
  x2readBlocks(block, 1, blockbuf[0]);
  memcpy(buf, blockbuf[0] + block_offt, len);
  return len;
}

usize x2read(struct Inode *ino, u8 *buf, usize len, u64 offt) {
  if (len == 0)
    return 0;

  u64 orig_offt = offt;
  u64 filesz = x2getFileSize(ino);

  if (offt >= filesz) {
    return 0;
  }

  if (len > (filesz - offt)) {
    len = filesz - offt;
  }

  usize remaining_in_block = BLOCKSIZE - (offt % BLOCKSIZE);

  usize n = x2ReadFileBlock(
      ino, offt, buf, remaining_in_block > len ? len : remaining_in_block);

  if (n == len) {
    return n;
  }

  offt += n;
  buf += n;
  len -= n;
  assert(offt % BLOCKSIZE == 0);

  /*at block boundary*/
  usize full_blocks_to_read = len / BLOCKSIZE;

  for (u32 i = 0; i < full_blocks_to_read; i++) {
    assert(x2ReadFileBlock(ino, offt, buf, BLOCKSIZE) == BLOCKSIZE);
    buf += BLOCKSIZE;
    offt += BLOCKSIZE;
  }

  usize remaining = len % BLOCKSIZE;

  if (remaining > 0) {
    n = x2ReadFileBlock(ino, offt, buf, remaining);
    assert(n == remaining);
    offt += n;
  }

  return offt - orig_offt;
}

static usize x2writeFileBlock(struct Inode *ino, u64 file_offt, u8 *buf,
                              usize len) {
  usize block_idx = file_offt / BLOCKSIZE;
  usize block_offt = file_offt % BLOCKSIZE;
  assert(block_offt < BLOCKSIZE && (BLOCKSIZE - block_offt) >= len);
  usize block = x2getFileBlock(ino, block_idx);
  assert(block != 0);

  if (!(block_offt == 0 && len == BLOCKSIZE)) {
    x2readBlocks(block, 1, blockbuf[0]);
  }

  memcpy(blockbuf[0] + block_offt, buf, len);
  x2writeBlocks(block, 1, blockbuf[0]);
  return len;
}

isize x2write(struct Inode *ino, usize inode_idx, u8 *buf, usize len,
              u64 offt) {

  if (!checkBits(ino->mode, EXT2_S_IFREG)) {
    return X2_ERR_NOT_FILE;
  }

  if (len <= 0)
    return 0;

  usize filesz = x2getFileSize(ino);

  if (offt > filesz) {
    return X2_ERR_NO_SPACE;
  }

  u8 update_inode = 0;

  u64 orig_offt = offt;
  u64 final_offt = offt + len;
  usize final_blocks = alignF(final_offt, BLOCKSIZE) / BLOCKSIZE;
  usize current_blocks = alignF(filesz, BLOCKSIZE) / BLOCKSIZE;

  if (final_blocks > current_blocks) {
    usize needed = final_blocks - current_blocks;
    usize added;
    int res = x2inodeAddBlocks(ino, needed, &added);
    if (res != X2_OK) {
      return res;
    }

    if (added < needed) {
      len = added * BLOCKSIZE;
      final_offt = offt + len;
    }

    update_inode = 1;
  }

  if (final_offt > filesz) {
    x2setFileSize(ino, final_offt);
    update_inode = 1;
  }

  usize remaining_in_block = (BLOCKSIZE - (offt % BLOCKSIZE));
  usize n = x2writeFileBlock(
      ino, offt, buf, remaining_in_block > len ? len : remaining_in_block);

  if (n == len) {
    if (update_inode) {
      x2WriteInode(inode_idx, ino);
    }
    return n;
  }

  offt += n;
  len -= n;
  buf += n;

  /*at block boundary*/
  assert(offt % BLOCKSIZE == 0);

  usize remains = len % BLOCKSIZE;
  usize full_blocks = len / BLOCKSIZE;

  for (usize i = 0; i < full_blocks; i++) {
    assert(x2writeFileBlock(ino, offt, buf, BLOCKSIZE) == BLOCKSIZE);
    offt += BLOCKSIZE;
    buf += BLOCKSIZE;
  }

  /*still at block boundary*/
  if (remains) {
    n = x2writeFileBlock(ino, offt, buf, remains);
    offt += remains;
  }

  if (update_inode) {
    x2WriteInode(inode_idx, ino);
  }

  return offt - orig_offt;
}

int x2readLink(struct Inode *ino, char *result, usize resultlen) {
  if (!checkBits(ino->mode, EXT2_S_IFLNK)) {
    return X2_ERR_NOT_SYMLINK;
  }

  char *linkbuf;
  usize i;
  usize filesize = x2getFileSize(ino);

  if (filesize <= 60) {
    linkbuf = (char *)&ino->block;
  } else {
    usize block = x2getFileBlock(ino, 0);
    x2readBlocks(block, 1, blockbuf[0]);
    linkbuf = (char *)blockbuf[0];
  }

  for (i = 0; i < filesize && i < resultlen; i++) {
    result[i] = linkbuf[i];
  }

  if (i < resultlen) {
    result[i] = '\0';
  }

  return i;
}

int x2createLink(struct Inode *parent, usize parent_idx, struct Inode *child,
                 usize *child_idx, const char *link_name,
                 const char *target_name) {
  if (!checkBits(parent->mode, EXT2_S_IFDIR)) {
    return X2_ERR_NOT_DIR;
  }

  usize target_name_len = strnlen(target_name, 255);
  usize link_name_len = strnlen(link_name, 255);

  struct DirEnt ent = {
      .file_type = EXT2_FT_SYMLINK,
      .name_len = link_name_len,
      .name = (u8 *)link_name,
  };

  int res = x2direntAllocInode(&ent, child);

  if (res != X2_OK) {
    return res;
  }

  char *linkbuf;
  usize block;

  if (target_name_len <= 60) {
    linkbuf = (char *)&child->block;
  } else {
    res = x2allocBlockX(&block);
    if (res != X2_OK) {
      return res;
    }
    child->blocks = BLOCKSIZE / 512;
    child->block[0] = block;
    memset(blockbuf[0], 0, BLOCKSIZE);
    linkbuf = (char *)blockbuf[0];
  }

  for (usize i = 0; i < target_name_len; i++) {
    linkbuf[i] = target_name[i];
  }

  if (target_name_len > 60) {
    x2writeBlocks(block, 1, blockbuf[0]);
  }

  x2setFileSize(child, target_name_len);
  x2WriteInode(ent.inode, child);

  res = x2addDirEntInner(parent, &ent);

  if (res != X2_OK) {
    return res;
  }

  x2WriteInode(parent_idx, parent);
  if (child_idx)
    *child_idx = ent.inode;
  return X2_OK;
}

void x2getRoot(struct Inode *inode, usize *idx) {
  if (inode)
    x2readInode(2, inode);
  if (idx)
    *idx = 2;
}

int x2createFile(struct Inode *parent, usize parent_idx, struct Inode *child,
                 usize *child_idx, const char *name) {
  return x2createFileInner(parent, parent_idx, child, child_idx, name,
                           strnlen(name, 255), EXT2_FT_REG_FILE);
}

int x2createDir(struct Inode *parent, usize parent_idx, struct Inode *child,
                usize *child_idx, const char *name) {
  return x2createFileInner(parent, parent_idx, child, child_idx, name,
                           strnlen(name, 255), EXT2_FT_DIR);
}

int x2findInode(struct Inode *parent, const char *name, struct Inode *ino,
                usize *ino_idx) {
  return x2searchDir(parent, (u8 *)name, strnlen(name, 255), ino, ino_idx);
}

int x2unlink(struct Inode *parent, usize parent_inode_idx, const char *name) {
  return x2removeDirEntInner(parent, parent_inode_idx, (u8 *)name,
                             strnlen(name, 255));
}

void x2Init(struct BlockDev *d) {
  dev = d;
  x2ReadSuperBlock();
  assert(sb.magic == 0xef53);
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
