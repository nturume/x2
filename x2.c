#include "x2.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

struct SuperBlock sb;
int sb_dirty = 0;
struct BlockDev *dev;
struct GroupDesc *gdesc;
int gdesc_dirty = 0;
// __attribute__((aligned(4))) u8 blockbuf[4][BLOCKSIZE];

#define CACHE_SIZE 8

__attribute__((aligned(4))) u8 blocks[CACHE_SIZE][BLOCKSIZE];
struct Node {
  struct Node *next;
  struct Node *prev;
  u8 *buf;
  int block_idx;
  int pinned;
  int dirty;
};

struct LRU {
  struct Node nodes[CACHE_SIZE + 2];
  struct Node *head;
  struct Node *tail;
};

struct LRU cache;

static void wb(u32 pos, u8 *buf) { dev->writeBlock(dev, pos, buf); }

static void rb(u32 pos, u8 *buf) { dev->readBlock(dev, pos, buf); }

static void cacheInit() {
  for (int i = 1; i <= CACHE_SIZE; i++) {
    rb(i, blocks[i - 1]);

    cache.nodes[i].buf = blocks[i - 1];
    cache.nodes[i].block_idx = i;

    cache.nodes[i].pinned = 0;

    cache.nodes[i].next = &cache.nodes[i + 1];
    cache.nodes[i].prev = &cache.nodes[i - 1];
  }

  cache.head = &cache.nodes[0];
  cache.tail = &cache.nodes[CACHE_SIZE + 1];

  cache.head->next = &cache.nodes[1];
  cache.head->prev = NULL;

  cache.tail->next = NULL;
  cache.tail->prev = &cache.nodes[CACHE_SIZE];

  assert(cache.nodes[CACHE_SIZE].next == cache.tail);
  assert(cache.nodes[1].prev == cache.head);
}

static void cacheAdd(struct Node *n) {
  cache.head->next->prev = n;

  n->next = cache.head->next;
  n->prev = cache.head;

  cache.head->next = n;
}

static struct Node *cacheHas(int block_idx) {
  struct Node *tmp = cache.head->next;
  while (tmp != cache.tail) {
    if (tmp->block_idx == block_idx) {
      return tmp;
    }
    tmp = tmp->next;
  }
  return NULL;
}

static struct Node *cacheEvict() {
  struct Node *tmp = cache.tail->prev;
  while (tmp != cache.head) {
    if (tmp->pinned == 0) {
      if (tmp->dirty) {
        wb(tmp->block_idx, tmp->buf);
      }
      tmp->next->prev = tmp->prev;
      tmp->prev->next = tmp->next;
      return tmp;
    }
    tmp = tmp->prev;
  }
  assert("no free nodes" == NULL);
}

static u8 *getIn(int block_idx, int pin, int read) {
  struct Node *node = cacheHas(block_idx);
  if (node == NULL) {
    node = cacheEvict();
    node->block_idx = block_idx;
    if (read) {
      rb(block_idx, node->buf);
    }
  } else {
    assert(!node->pinned);
    node->next->prev = node->prev;
    node->prev->next = node->next;
  }
  cacheAdd(node);
  node->pinned = pin ? 1 : 0;
  return node->buf;
}

static usize pinCount() {
  usize c = 0;
  struct Node *tmp = cache.head->next;
  while (tmp != cache.tail) {
    if (tmp->pinned) {
      c += 1;
    }
    tmp = tmp->next;
  }
  return c;
}

static u8 *get(int block_idx, int pin) { return getIn(block_idx, pin, 1); }

static u8 *getnr(int block_idx) { return getIn(block_idx, 1, 0); }

static void put(int block_idx, int dirty) {
  struct Node *tmp = cacheHas(block_idx);
  assert(tmp != NULL);
  assert(tmp->pinned);
  tmp->pinned = 0;
  tmp->dirty |= dirty;
}

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

static u32 x2readTimestamp() {
  time_t t;
  time(&t);
  return t;
}

static void x2ReadSuperBlock() {
  u8 *b = get(0, 0);
  sb = *((struct SuperBlock *)(b + 1024));
}

static void x2ReadBGDescs() {
  usize sz = x2totalGroups() * sizeof(struct GroupDesc);
  u8 *b = get(1, 0);
  memcpy(gdesc, b, sz);
}

static void x2writeSuperBlock() { sb_dirty = 1; }
static void x2witeBGDescs() { gdesc_dirty = 1; }

void x2sync() {
  if (sb_dirty) {
    u8 *b = get(0, 1);
    *((struct SuperBlock *)(b + 1024)) = sb;
    put(0, 1);
  }
  if (gdesc_dirty) {
    usize sz = x2totalGroups() * sizeof(struct GroupDesc);
    u8 *b = get(1, 1);
    memcpy(b, gdesc, sz);
    put(1, 1);
  }
  for (int i = 1; i <= CACHE_SIZE; i++) {
    if (cache.nodes[i].dirty) {
      wb(cache.nodes[i].block_idx, cache.nodes[i].buf);
      cache.nodes[i].dirty = 0;
    }
  }
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
  u8 *b = get(loc.block, 0);
  *inode = ((struct Inode *)b)[loc.idx];
}

static void x2WriteInode(usize inode_idx, struct Inode *inode) {
  struct InodeLoc loc = x2getInodeLoc(inode_idx);
  u8 *b = get(loc.block, 1);
  ((struct Inode *)b)[loc.idx] = *inode;
  put(loc.block, 1);
}

static usize x2getFileBlock(struct Inode *inode, usize block_idx) {
  u64 fsize = x2getFileSize(inode);
  usize block;
  if (block_idx < 12) {
    block = inode->block[block_idx];
    return block;
  }
  block_idx -= 12;
  u8 *b;
  if (block_idx < 1024) {
    if (inode->block[12] == 0)
      return 0;
    b = get(inode->block[12], 0);
    u32 *indirect = (u32 *)b;
    block = indirect[block_idx];
    return block;
  }

  block_idx -= 1024;

  if (block_idx < 1024 * 1024) {
    if (inode->block[13] == 0)
      return 0;
    b = get(inode->block[13], 0);
    u32 dindirect = ((u32 *)b)[(block_idx >> 10) & 0x3ff];
    if (dindirect == 0)
      return 0;
    b = get(dindirect, 0);
    u32 *indirect = (u32 *)b;
    block = indirect[block_idx & 0x3ff];
    return block;
  }

  assert("Unhandled case..." == NULL);
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

  if(gdesc[group_idx].free_blocks_count < nblocks) return X2_ERR_NO_SPACE;
  
  u8 *b = get(gdesc[group_idx].block_bitmap, 1);
  
  if (!x2bitmapGetFreeRange(b, nblocks, start)) {
    x2bitmapSetFreeRange(b, *start, nblocks);
    put(gdesc[group_idx].block_bitmap, 1);
    gdesc[group_idx].free_blocks_count -= nblocks;
    x2witeBGDescs();

    sb.free_blocks_count -= nblocks;
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
  if(sb.free_blocks_count == 0) return X2_ERR_NO_SPACE;
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
  if(sb.free_inodes_count==0) return X2_ERR_NO_SPACE;
  for (usize i = 0; i < x2totalGroups(); i++) {
    if(gdesc[i].free_inodes_count == 0) continue;
    u8 *b = get(gdesc[i].inode_bitmap, 1);
    if (!x2bitmapFirstFree(b, &res->start_idx)) {
      x2bitmapBlockSet(b, res->start_idx);
      put(gdesc[i].inode_bitmap, 1);
      assert(x2bitmapBlockGet(b, res->start_idx));
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
  u8 *b = get(gdesc[group].inode_bitmap, 1);
  x2bitmapBlockClear(b, bit);
  put(gdesc[group].inode_bitmap, 1);

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
  u8 *b = get(gdesc[bloc.group].block_bitmap, 1);
  x2bitmapBlockClear(b, bloc.bitmap_idx);
  put(gdesc[bloc.group].block_bitmap, 1);

  sb.free_blocks_count += 1;
  x2writeSuperBlock();

  gdesc[bloc.group].free_blocks_count += 1;
  x2witeBGDescs();
}

static struct BlockLoc x2getFileBlockLoc(struct Inode *ino, usize block_idx) {
  usize realblockpos = x2getFileBlock(ino, block_idx);
  return x2getBlockLoc(realblockpos);
}

static void x2deallocIndirect(u32 *d) {
  for (usize i = 0; i < 1024; i++) {
    if (d[i]) {
      x2deallocBlock(d[i]);
    }
  }
}

static void x2deallocInodeBlocks(struct Inode *ino) {
  if (checkBits(ino->mode, EXT2_S_IFLNK) && x2getFileSize(ino) <= 60) {
    return;
  }
  usize i;
  u32 *dd;
  u8 *b;

  for (i = 0; i < 12; i++) {
    if (ino->block[i]) {
      x2deallocBlock(ino->block[i]);
    }
  }

  if (ino->block[12]) {
    b = get(ino->block[12], 1);
    x2deallocIndirect((u32 *)b);
    put(ino->block[12], 0);
    x2deallocBlock(ino->block[12]);
  }

  if (ino->block[13]) {
    b = get(ino->block[13], 1);
    dd = (u32 *)b;
    for (i = 0; i < 1024; i++) {
      if (dd[i] != 0) {
        u8 *bb = get(dd[i], 1);
        x2deallocIndirect((u32 *)bb);
        put(dd[i], 0);
        x2deallocBlock(dd[i]);
      }
    }
    put(ino->block[13], 0);
    x2deallocBlock(ino->block[13]);
  }

  // TODO tripple indirect
}

static void printString(u8 *s, usize len) {
  for (usize i = 0; i < len; i++) {
    printf("%c", s[i]);
  }
}

static int x2addDirEntToBlock(usize block_idx, struct DirEnt *ent) {
  assert(block_idx != 0);
  u8 *b = get(block_idx, 1);
  u16 rec_len = alignF(8 + ent->name_len, 4);
  u8 *ptr = b;
  u8 *endptr = ptr + BLOCKSIZE;
  for (; ptr < endptr;) {
    struct DirEnt *record = (struct DirEnt *)ptr;
    if ((record->inode == 0) && record->rec_len >= rec_len) {
      /* ovewrite shi */
      record->name_len = ent->name_len;
      record->file_type = ent->file_type;
      record->inode = ent->inode;
      memset(ptr + 8, 0, rec_len - 8);
      memcpy(ptr + 8, ent->name, ent->name_len);
      put(block_idx, 1);
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
      put(block_idx, 1);
      return X2_OK;
    }
    ptr += record->rec_len;
  }
  put(block_idx, 1);
  return X2_ERR_NO_SPACE;
}

static int x2searchDirInner(struct Inode *ino, u8 *name, usize namelen,
                            usize *res) {
  usize bcount = x2getInodeBlockCount(ino);
  for (usize block = 0; block < bcount; block += 1) {
    u8 *blockbuf = get(x2getFileBlock(ino, block), 0);
    struct DirEnt *cur = (struct DirEnt *)blockbuf;
    while ((u8 *)cur != blockbuf + BLOCKSIZE) {
      assert((u8*)cur<(blockbuf+BLOCKSIZE));
      if (cur->name_len == namelen && !memcmp(name, ((u8 *)cur) + 8, namelen)) {
        if (res)
          *res = cur->inode;
        return X2_OK;
      }
      cur = (struct DirEnt *)(((u8 *)cur) + cur->rec_len);
    }
  }

  return X2_ERR_NO_ENT;
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

static int x2dirIsEmpty(usize parent_idx, usize inode_idx, struct Inode *ino) {
  usize bcount = x2getInodeBlockCount(ino);
  for (usize block = 0; block < bcount; block += 1) {
    u8 *blockbuf = get(x2getFileBlock(ino, block), 0);
    struct DirEnt *cur = (struct DirEnt *)blockbuf;
    while ((u8 *)cur != blockbuf + BLOCKSIZE) {
      assert((u8*)cur<(blockbuf+BLOCKSIZE));
      if (cur->inode != 0 && cur->inode != parent_idx &&
          cur->inode != inode_idx) {
        return 0;
      }
      cur = (struct DirEnt *)(((u8 *)cur) + cur->rec_len);
    }
  }
  return 1;
}

static void x2deallocInode(struct Inode *parent, usize parent_idx,
                           usize inode_idx, u8 is_dir) {
  struct Inode ino;
  x2readInode(inode_idx, &ino);
  assert(ino.links_count > 0);
  if (checkBits(ino.mode, EXT2_S_IFDIR) &&
      x2dirIsEmpty(parent_idx, inode_idx, &ino)) {
    /*if not empt*/
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

  ino.dtime = x2readTimestamp();
  x2WriteInode(inode_idx, &ino);
}

static struct DirEnt *x2mergeLeft(struct DirEnt *prev, struct DirEnt *ent) {
  struct DirEnt *ret;
  if (prev) {
    prev->rec_len += ent->rec_len;
    ret = prev;
  } else {
    ret = ent;
  }
  ent->inode = 0;
  ent->name_len = 0;
  ent->file_type = 0;
  return ret;
}

static void x2mergeRight(struct DirEnt *ent_ptr) {
  struct DirEnt *nxt_ptr =
      (struct DirEnt *)(((u8 *)ent_ptr) + ent_ptr->rec_len);
  if (nxt_ptr && nxt_ptr->inode == 0) {
    ent_ptr->rec_len += nxt_ptr->rec_len;
  }
}

static int x2removeDirEntInner(struct Inode *parent, usize parent_inode_idx,
                               u8 *name, usize namelen) {

  usize bcount = x2getInodeBlockCount(parent);
  for (usize block = 0; block < bcount; block += 1) {
    usize block_pos = x2getFileBlock(parent, block);
    u8 *blockbuf = get(block_pos, 1);
    struct DirEnt *cur = (struct DirEnt *)blockbuf;
    struct DirEnt *prev = NULL;
    while ((u8 *)cur != blockbuf + BLOCKSIZE) {
      assert((u8*)cur<(blockbuf+BLOCKSIZE));
      if (cur->name_len == namelen && !memcmp(name, ((u8 *)cur) + 8, namelen)) {
        if (cur->inode != 0) {
          x2deallocInode(parent, parent_inode_idx, cur->inode,
                         cur->file_type == EXT2_FT_DIR);
        }

        struct DirEnt *working_ptr = x2mergeLeft(prev, cur);
        if ((((u8 *)working_ptr) + working_ptr->rec_len) <
            (blockbuf + BLOCKSIZE))
          x2mergeRight(working_ptr);

        put(block_pos, 1);
        return X2_OK;
      }

      prev = cur;
      cur = (struct DirEnt *)(((u8 *)cur) + cur->rec_len);
    }

    put(block_pos, 0); /* TODO */
  }
  return X2_ERR_NO_ENT;
}

/* wont write inode */
static int x2inodeAddBlock(struct Inode *ino, usize block,
                           usize new_block_idx) {
  assert(block != 0);
  usize allocidx;
  int res;
  u8 *b;
  if (sb.free_blocks_count < 2) {
    return X2_ERR_NO_SPACE;
  }
  if (new_block_idx < 12) {
    assert(ino->block[new_block_idx] == 0);
    ino->block[new_block_idx] = block;
    ino->blocks += BLOCKSIZE / 512;
    return X2_OK;
  }
  new_block_idx -= 12;
  if (new_block_idx < 1024) {

    if (ino->block[12] == 0) { /*adding 13th*/
      res = x2allocBlockX(&allocidx);
      if (res != X2_OK) {
        return res;
      }
      b = getnr(allocidx);
      memset(b, 0, BLOCKSIZE);
      put(allocidx, 1);
      ino->block[12] = allocidx;
      ino->blocks += BLOCKSIZE / 512;
    }

    b = get(ino->block[12], 1);
    u32 *indirect = (u32 *)b;
    assert(indirect[new_block_idx] == 0);
    indirect[new_block_idx] = block;
    ino->blocks += BLOCKSIZE / 512;
    put(ino->block[12], 1);
    return X2_OK;
  }
  new_block_idx -= 1024;
  if (new_block_idx < (1024 * 1024)) {

    if (ino->block[13] == 0) {
      res = x2allocBlockX(&allocidx);
      if (res != X2_OK) {
        return res;
      }
      b = getnr(allocidx);
      memset(b, 0, BLOCKSIZE);
      put(allocidx, 1);
      ino->block[13] = allocidx;
      ino->blocks += BLOCKSIZE / 512;
    }

    b = get(ino->block[13], 1);
    u32 *dindirect = (u32 *)b;
    usize ddidx = (new_block_idx >> 10) & 0x3ff;

    usize indirect_block = dindirect[ddidx];

    if (indirect_block == 0) {
      res = x2allocBlockX(&allocidx);
      if (res != X2_OK) {
        return res;
      }
      u8 *bb = getnr(allocidx);
      memset(bb, 0, BLOCKSIZE);
      put(allocidx, 1);
      dindirect[ddidx] = allocidx;
      ino->blocks += BLOCKSIZE / 512;
      put(ino->block[13], 1);
      indirect_block = allocidx;
    } else {
      put(ino->block[13], 0);
    }

    assert(indirect_block != 0);
    b = get(indirect_block, 1);
    u32 *indirect = (u32 *)b;
    assert(indirect[new_block_idx & 0x3ff] == 0);
    indirect[new_block_idx & 0x3ff] = block;
    put(indirect_block, 1);
    ino->blocks += BLOCKSIZE / 512;

    return X2_OK;
  }

  return X2_ERR_NO_SPACE;
}

static void x2initDirBlock(usize block_idx) {
  u8 *b = get(block_idx, 1);
  struct DirEnt *null_ent = (void *)b;
  null_ent->file_type = 0;
  null_ent->inode = 0;
  null_ent->name_len = 0;
  null_ent->rec_len = BLOCKSIZE;
  put(block_idx, 1);
}

/* wont write inode */
static int x2addDirEntInner(struct Inode *ino, struct DirEnt *new_ent) {
  int res;
  usize block, i, total_blocks;
  total_blocks = x2getInodeBlockCount(ino);
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

int x2createFile2(struct Inode *parent, usize parent_idx, struct Inode *child,
                  usize *child_idx, const char *name, usize name_len,
                  u32 file_type) {
  if(x2searchDir(parent, (u8 *)name, name_len, NULL,NULL)==0) return X2_ERR_ENT_EXISTS;

  if (!checkBits(parent->mode, EXT2_S_IFDIR)) {
    return X2_ERR_NOT_DIR;
  }

  if (file_type & EXT2_FT_DIR) {
    if (sb.free_inodes_count < 1 || sb.free_blocks_count < 1)
      return X2_ERR_NO_SPACE;
  } else {
    if (sb.free_inodes_count < 1)
      return X2_ERR_NO_SPACE;
  }

  struct DirEnt ent = {
      .file_type = file_type, .name = (u8 *)name, .name_len = name_len};

  int res = x2direntAllocInode(&ent, child);

  if (res != X2_OK) {
    assert(pinCount() == 0);
    return res;
  }

  res = x2addDirEnt(parent, parent_idx, &ent, child);
  if (res != X2_OK) {
    assert(pinCount() == 0);
    return res;
  }
  if (child_idx)
    *child_idx = ent.inode;
  assert(pinCount() == 0);
  return X2_OK;
}

static inline usize x2ReadFileBlock(struct Inode *ino, u64 file_offt, u8 *buf,
                                    usize len) {
  usize block_idx = file_offt / BLOCKSIZE;
  usize block_offt = file_offt % BLOCKSIZE;
  assert(block_offt < BLOCKSIZE && (BLOCKSIZE - block_offt) >= len);
  usize block = x2getFileBlock(ino, block_idx);
  if (block == 0) {
    memset(buf, 0, len);
  } else {
    u8 *b = get(block, 0);
    memcpy(buf, b + block_offt, len);
  }
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
    assert(pinCount() == 0);
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

  assert(pinCount() == 0);
  return offt - orig_offt;
}

static inline int x2writeFileBlock(struct Inode *ino, usize inode_idx,
                                   u64 file_offt, u8 *buf, usize len) {
  usize block_idx = file_offt / BLOCKSIZE;
  usize block_offt = file_offt % BLOCKSIZE;
  assert(block_offt < BLOCKSIZE && (BLOCKSIZE - block_offt) >= len);
  usize block = x2getFileBlock(ino, block_idx);
  if (block == 0) {
    assert(block_offt == 0);
    if (x2allocBlockX(&block) != X2_OK) {
      return X2_ERR_NO_SPACE;
    }

    if (x2inodeAddBlock(ino, block, block_idx) != X2_OK) {
      x2deallocBlock(block);
      return X2_ERR_NO_SPACE;
    }
    x2WriteInode(inode_idx, ino);
  }

  assert(block != 0);
  u8 *b;

  if (block_offt == 0 && len == BLOCKSIZE) {
    b = getnr(block);
  } else {
    b = get(block, 1);
  }

  memcpy(b + block_offt, buf, len);
  put(block, 1);
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

  u64 orig_offt = offt;
  int res;

  int remaining_in_block = (BLOCKSIZE - (offt % BLOCKSIZE));
  int n = x2writeFileBlock(ino, inode_idx, offt, buf,
                           remaining_in_block > len ? len : remaining_in_block);

  if (!(n == remaining_in_block || n == len)) {
    assert(pinCount() == 0);
    return n; /*no space*/
  }

  offt += n;

  if (n == len) {
    if (offt > filesz) {
      x2setFileSize(ino, offt);
      x2WriteInode(inode_idx, ino);
    }
    assert(pinCount() == 0);
    return n;
  }

  len -= n;
  buf += n;

  /*at block boundary*/
  assert(offt % BLOCKSIZE == 0);

  usize remains = len % BLOCKSIZE;
  usize full_blocks = len / BLOCKSIZE;

  for (usize i = 0; i < full_blocks; i++) {
    res = x2writeFileBlock(ino, inode_idx, offt, buf, BLOCKSIZE);
    if (res != BLOCKSIZE) {
      if (offt > filesz) {
        x2setFileSize(ino, offt);
        x2WriteInode(inode_idx, ino);
      }
      assert(pinCount() == 0);
      return offt - orig_offt;
    }
    offt += BLOCKSIZE;
    buf += BLOCKSIZE;
  }

  /*still at block boundary*/
  if (remains) {
    n = x2writeFileBlock(ino, inode_idx, offt, buf, remains);
    if (n == remains) {
      offt += remains;
    }
  }

  if (offt > filesz) {
    x2setFileSize(ino, offt);
    x2WriteInode(inode_idx, ino);
  }

  assert(pinCount() == 0);
  return offt - orig_offt;
}

int x2readLink(struct Inode *ino, char *result, usize resultlen) {
  if (!checkBits(ino->mode, EXT2_S_IFLNK)) {
    return X2_ERR_NOT_SYMLINK;
  }

  char *linkbuf;
  usize i;
  usize filesize = x2getFileSize(ino);
  u8 *b;

  if (filesize <= 60) {
    linkbuf = (char *)&ino->block;
  } else {
    usize block = x2getFileBlock(ino, 0);
    b = get(block, 0);
    linkbuf = (char *)b;
  }

  for (i = 0; i < filesize && i < resultlen; i++) {
    result[i] = linkbuf[i];
  }

  if (i < resultlen) {
    result[i] = '\0';
  }

  assert(pinCount() == 0);
  return i;
}

int x2createLink(struct Inode *parent, usize parent_idx, struct Inode *child,
                 usize *child_idx, const char *link_name,
                 const char *target_name) {
  
  if (!checkBits(parent->mode, EXT2_S_IFDIR)) {
    return X2_ERR_NOT_DIR;
  }

  usize link_name_len = strnlen(link_name, 255);

  if(x2searchDir(parent, (u8 *)link_name, link_name_len, NULL,NULL)==0) return X2_ERR_ENT_EXISTS;

  usize target_name_len = strnlen(target_name, 255);

  struct DirEnt ent = {
      .file_type = EXT2_FT_SYMLINK,
      .name_len = link_name_len,
      .name = (u8 *)link_name,
  };

  int res = x2direntAllocInode(&ent, child);

  if (res != X2_OK) {
    assert(pinCount() == 0);
    return res;
  }

  char *linkbuf;
  usize block;
  u8 *b;

  if (target_name_len <= 60) {
    linkbuf = (char *)&child->block;
  } else {
    res = x2allocBlockX(&block);
    if (res != X2_OK) {
      assert(pinCount() == 0);
      return res;
    }
    child->blocks = BLOCKSIZE / 512;
    child->block[0] = block;
    b = getnr(block);
    memset(b, 0, BLOCKSIZE);
    linkbuf = (char *)b;
  }

  for (usize i = 0; i < target_name_len; i++) {
    linkbuf[i] = target_name[i];
  }

  if (target_name_len > 60) {
    put(block, 1);
  }

  x2setFileSize(child, target_name_len);
  x2WriteInode(ent.inode, child);

  res = x2addDirEntInner(parent, &ent);

  if (res != X2_OK) {
    assert(pinCount() == 0);
    return res;
  }

  x2WriteInode(parent_idx, parent);
  if (child_idx)
    *child_idx = ent.inode;
  assert(pinCount() == 0);
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
  int res = x2createFile2(parent, parent_idx, child, child_idx, name,
                          strnlen(name, 255), EXT2_FT_REG_FILE);
  assert(pinCount() == 0);
  return res;
}

int x2createDir(struct Inode *parent, usize parent_idx, struct Inode *child,
                usize *child_idx, const char *name) {
  int res = x2createFile2(parent, parent_idx, child, child_idx, name,
                          strnlen(name, 255), EXT2_FT_DIR);
  assert(pinCount() == 0);
  return res;
}

int x2findInode(struct Inode *parent, const char *name, struct Inode *ino,
                usize *ino_idx) {
  int res = x2searchDir(parent, (u8 *)name, strnlen(name, 255), ino, ino_idx);
  assert(pinCount() == 0);
  return res;
}

int x2unlink2(struct Inode *parent, usize parent_inode_idx, const char *name,
              usize namelen) {
  int res = x2removeDirEntInner(parent, parent_inode_idx, (u8 *)name, namelen);
  assert(pinCount() == 0);
  return res;
}

int x2unlink(struct Inode *parent, usize parent_inode_idx, const char *name) {
  int res = x2removeDirEntInner(parent, parent_inode_idx, (u8 *)name,
                                strnlen(name, 255));
  assert(pinCount() == 0);
  return res;
}

void x2Init(struct BlockDev *d) {
  dev = d;
  cacheInit();
  x2ReadSuperBlock();
  assert(sb.magic == 0xef53);
  assert(x2blockSize() == 4096);
  assert(x2blocksHoldingBitmap(sb.blocks_per_group) == 1);
  assert(x2blocksHoldingBitmap(sb.inodes_per_group) == 1);
  assert(sb.inode_size == 128);
  usize sz = x2totalGroups() * sizeof(struct GroupDesc);
  usize gdescblocks = alignF(sz, BLOCKSIZE) / BLOCKSIZE;
  assert(gdescblocks == 1);
  gdesc = malloc(sz); /*new*/
  x2ReadBGDescs();
  /* TODO */
}
