#pragma once

#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/cdefs.h>
#include <time.h>

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
#define X2_ERR_NOT_FILE -8
#define X2_ERR_NULL_PTR -9
#define X2_ERR_BAD_PARENT -10

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

typedef int (*DirCB)(u32 inode, const char *name, u8 name_len, u8 file_type,
                     void *ctx);

#ifdef __cplusplus
extern "C" {
#endif

usize x2read(struct Inode *ino, u8 *buf, usize len, u64 offt);
isize x2write(struct Inode *ino, usize inode_idx, u8 *buf, usize len, u64 offt);
void x2getRoot(struct Inode *inode, usize *idx);
int x2readsymlink(struct Inode *ino, char *result, usize resultlen);
int x2symlink(struct Inode *parent, usize parent_idx, struct Inode *child,
                 usize *child_idx, const char *link_name,
                 const char *target_name);

int x2createFile(struct Inode *parent, usize parent_idx, struct Inode *child,
                 usize *child_idx, const char *name);
int x2createFile2(struct Inode *parent, usize parent_idx, struct Inode *child,
                  usize *child_idx, const char *name, usize name_len,
                  u32 file_type);
int x2createDir(struct Inode *parent, usize parent_idx, struct Inode *child,
                usize *child_idx, const char *name);

void x2readInode(usize inode_idx, struct Inode *inode);
int x2findInode(struct Inode *parent, const char *name, struct Inode *ino,
                usize *ino_idx);
int x2findInode2(struct Inode *parent, const char *name, usize name_len,
                 struct Inode *ino, usize *ino_idx);
int x2unlink(struct Inode *parent, usize parent_inode_idx, const char *name);
int x2unlink2(struct Inode *parent, usize parent_inode_idx, const char *name,
              u8 namelen);
int x2rmdir(struct Inode *parent, usize parent_inode_idx, const char *name);
int x2rmdir2(struct Inode *parent, usize parent_inode_idx, const char *name,
             usize namelen);
void x2loopDir(struct Inode *ino, DirCB cb, void *ctx);
void x2sync();
int x2access(struct Inode *inode, u32 inode_idx);
int x2chmod(struct Inode *inode, u32 inode_idx, u16 mode);
int x2chown(struct Inode *inode, u32 inode_idx, u64 uid, u64 gid);
int x2utimens(struct Inode *inode, u32 inode_idx, u32 atime, u32 mtime);
int x2rename(struct Inode *old_parent, u32 old_parent_idx,
             struct Inode *new_parent, u32 new_parent_idx, const char *name,
             const char *new_name);
int x2link2(struct Inode *parent, struct Inode *child, u32 child_idx,
            const char *name, u8 namelen);
int x2link(struct Inode *parent, struct Inode *child, u32 child_idx,
           const char *name);
void x2Init(struct BlockDev *d);

#ifdef __cplusplus
}
#endif
