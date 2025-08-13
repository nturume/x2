#include <cassert>
#include <cerrno>
#include <cstring>
#include <time.h>
#define FUSE_USE_VERSION 31
#include <fuse3/fuse.h>
#include <stdio.h>

#include "block.h"
#include "x2.h"

struct BlockDev bd;
// struct Inode root;
FILE *log_file;

static int get_inode_idx(usize parent_inode_idx, const char *path,
                         usize path_len, usize *res_idx) {
  Inode parent;
  x2readInode(parent_inode_idx, &parent);
  int res = x2findInode2(&parent, path, path_len, NULL, res_idx);
  if (res != X2_OK) {
    return res;
  }
  return 0;
}

static void put_strn(const char *s, int len) {
  for (int i = 0; i < len; i++) {
    printf("%c", s[i]);
  }
  printf("\n");
}

struct PathParser {
  const char *path;
  const char *cur;

  PathParser(const char *p) : path(p) {}

  struct Slice {

    Slice(const char *ptr, int len) : _ptr(ptr), _len(len) {}
    Slice() : _ptr(nullptr), _len(0) {}
    int len() { return _len; }
    const char *ptr() { return _ptr; }

  private:
    const char *_ptr;
    int _len;
  };

  Slice next() {
    if (path[0] == '\0')
      return Slice(path, 0);
    assert(path[0] == '/');
    path += 1;
    const char *cur_ptr = path;
    int len = 0;
    for (int i = 0;; i++) {
      switch (path[i]) {
      case '\0':
      case '/': {
        Slice s(path, len);
        path = path + len;
        return s;
      }
      default:
        len += 1;
        ;
      }
    }
    assert(false);
  }
};

static int path_to_inode_idx(const char *path, usize *r, usize *pr = nullptr, u8*name = nullptr) {
  PathParser p(path);
  usize parent_inode_idx = 2;
  usize res_inode_idx = 2;
  int res;
  while (1) {
    PathParser::Slice s = p.next();
    if (s.len() == 0)
      break;
    put_strn(s.ptr(), s.len());
    res = get_inode_idx(parent_inode_idx, s.ptr(), s.len(), &res_inode_idx);

    if (res != 0) {
      if(name) {
        memcpy(name, s.ptr(), s.len());
        name[s.len()] = '\0';
      }
      if (pr) {
        *pr = parent_inode_idx;
      }
      return -ENOENT;
    }

    parent_inode_idx = res_inode_idx;
  }
  if (r) {
    *r = res_inode_idx;
  }
  if (pr) {
    *pr = parent_inode_idx;
  }
  return 0;
}

static void *fs_init(struct fuse_conn_info *conn, struct fuse_config *cfg) {
  fprintf(log_file, "File syatem initialized.\n");
  return NULL;
}

static int fs_getattr(const char *path, struct stat *stbuf,
                      struct fuse_file_info *fi) {
  usize res_inode_idx;
  int res = path_to_inode_idx(path, &res_inode_idx);

  if (res != 0)
    return res;

  struct Inode ino;
  x2readInode(res_inode_idx, &ino);

  memset(stbuf, 0, sizeof(*stbuf));

  stbuf->st_atim = {.tv_sec = ino.atime, .tv_nsec = 0};
  stbuf->st_mtim = {.tv_sec = ino.mtime, .tv_nsec = 0};
  stbuf->st_ctim = {.tv_sec = ino.ctime, .tv_nsec = 0};
  stbuf->st_blksize = BLOCKSIZE;
  stbuf->st_blocks = ino.blocks;
  stbuf->st_gid = (u64(ino.gid_high) << 32) + ino.gid;
  stbuf->st_ino = res_inode_idx;
  stbuf->st_mode = ino.mode;
  stbuf->st_nlink = ino.links_count;
  stbuf->st_size = (u64(ino.dir_acl) << 32) + ino.size;
  stbuf->st_uid = (u64(ino.uid_high) << 32) + ino.uid;
  return 0;
}

struct FillCtx {
  fuse_fill_dir_t filler;
  void *buf;
};

void dirFillCallback(u32 inode, const char *name, u8 namelen, u8 file_type,
                     void *ctx) {
  if (namelen == 0)
    return;
  printf("--------------------------------> ");
  FillCtx *fctx = (FillCtx *)ctx;
  put_strn(name, namelen);
  u8 namebuf[256];
  memcpy(namebuf, name, namelen);
  namebuf[namelen] = '\0';
  fctx->filler(fctx->buf, (const char *)namebuf, NULL, 0, {});
}

static int fs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                      off_t offset, struct fuse_file_info *fi,
                      enum fuse_readdir_flags flags) {
  usize res_inode_idx;
  int res = path_to_inode_idx(path, &res_inode_idx);
  struct Inode ino;
  x2readInode(res_inode_idx, &ino);

  if ((ino.mode & EXT2_S_IFDIR) != EXT2_S_IFDIR) {
    return -ENOTDIR;
  }
  printf("================ent found %d %d\n", res_inode_idx, offset);

  FillCtx fctx = {.filler = filler, .buf = buf};
  x2loopDir(&ino, dirFillCallback, &fctx);

  return 0;
}

static int fs_getxattr(const char *path, const char *name, char *value,
                       size_t size) {
  // fprintf(log_file, "fn getxattr\n");
  return -1;
}

static int fs_access(const char *path, int mask) {
  // fprintf(log_file, "fn access\n");
  usize ino_idx;
  int res = path_to_inode_idx(path, &ino_idx);
  if (res != 0)
    return res;
  Inode inode;
  x2readInode(ino_idx, &inode);
  x2access(&inode, ino_idx);
  return 0;
}

static int fs_read(const char *path, char *buf, size_t size, off_t offset,
                   struct fuse_file_info *fi) {
  Inode inode;
  usize inode_idx;
  int res = path_to_inode_idx(path, &inode_idx);
  if(res!=0) {
    return res;
  }
  x2readInode(inode_idx, &inode);

  res = x2read(&inode, (u8 *)buf, size, offset);
  if(res < 0) {
    return -EIO;
  }

  return res;
  // fprintf(log_file, "fn read\n");
  // return 0;
}

static int fs_write(const char *path, const char *buf, size_t size, off_t offset,
                   struct fuse_file_info *fi) {
  Inode inode;
  usize inode_idx;
  int res = path_to_inode_idx(path, &inode_idx);
  if(res!=0) {
    return res;
  }
  x2readInode(inode_idx, &inode);

  res = x2write(&inode, inode_idx, (u8 *)buf, size, offset);
  if(res < 0) {
    return -EIO;
  }

  return res;
  // fprintf(log_file, "fn read\n");
  // return 0;
}

static int fs_open(const char *path, struct fuse_file_info *fi) {
  usize inode_idx;
  int res = path_to_inode_idx(path, &inode_idx);
  if(res!=0) {
    return res;
  }
  return 0;
}

static int fs_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
  printf("--------------------create %s\n", path);
  usize parent_idx, child_idx;
  u8 name[256];
  int res = path_to_inode_idx(path, NULL, &parent_idx, name);
  if(res!=-ENOENT) {
    return -EEXIST;
  }
  Inode parent, child;
  x2readInode(parent_idx, &parent);
  res = x2createFile(&parent, parent_idx, &child, &child_idx, (const char*)name);
  if(res!=0) {
    return -EIO;
  }
  return 0;
}

static int fs_release(const char *path, struct fuse_file_info *fi) { return 0; }

static int fs_flush(const char *path, struct fuse_file_info *fi) { 
  return 0; 
}

static int fs_fsync(const char *path, int isdatasync,
                    struct fuse_file_info *fi) {
  x2sync();
  return 0;
}

static int fs_chmod(const char *path, mode_t mode,
		     struct fuse_file_info *fi)
{
  Inode inode;
  usize inode_idx;
  int res = path_to_inode_idx(path, &inode_idx);
  if(res!=0) {
    return res;
  }
  x2readInode(inode_idx, &inode);
  x2chmod(&inode, inode_idx, mode);
	return 0;
}

static int fs_chown(const char *path, uid_t uid, gid_t gid,
		     struct fuse_file_info *fi)
{
  Inode inode;
  usize inode_idx;
  int res = path_to_inode_idx(path, &inode_idx);
  if(res!=0) {
    return res;
  }
  x2readInode(inode_idx, &inode);
  x2chown(&inode, inode_idx, uid, gid);
	return 0;
}

static int fs_utimens(const char *path, const struct timespec ts[2],
		       struct fuse_file_info *fi)
{
  Inode inode;
  usize inode_idx;
  int res = path_to_inode_idx(path, &inode_idx);
  if(res!=0) {
    return res;
  }
  x2readInode(inode_idx, &inode);
  x2utimens(&inode, inode_idx, ts[0].tv_nsec, ts[1].tv_nsec);
	return 0;
}

static int fs_mkdir(const char *path, mode_t mode)
{
  usize parent_idx, child_idx;
  u8 name[256];
  int res = path_to_inode_idx(path, NULL, &parent_idx, name);
  if(res!=-ENOENT) {
    return -EEXIST;
  }
  Inode parent, child;
  x2readInode(parent_idx, &parent);
  res = x2createDir(&parent, parent_idx, &child, &child_idx, (const char*)name);
  if(res!=0) {
    return -EIO;
  }
  return 0;
}

static const struct fuse_operations fs_ops = {
    .getattr = fs_getattr,
    .mkdir = fs_mkdir,
    .chmod = fs_chmod,
    .chown = fs_chown,
    .open = fs_open,
    .read = fs_read,
    .write = fs_write,
    .flush = fs_flush,
    .release = fs_release,
    .fsync = fs_fsync,
    .getxattr = fs_getxattr,
    .readdir = fs_readdir,
    .releasedir = fs_release,
    .init = fs_init,
    .access = fs_access,
    .create = fs_create,
    .utimens = fs_utimens,
};

static int fill_dir_plus = 0;

int main(int argc, char *argv[]) {
  // PathParser p("/autorun.inf");
  // while (1) {
  //   PathParser::Slice s = p.next();
  //   if (s.len()==0) break;
  //     // printf("chunked %s\n", p);
  //     put_strn(s.ptr(), s.len());
  // }
  // return 0;

  log_file = fopen("log.txt", "r+");
  bd = Dummy("disk.img");
  x2Init(&bd);

  // x2getRoot(&root, NULL);

  setbuf(stdout, NULL);
  setbuf(stdin, NULL);
  setbuf(log_file, NULL);

  // fprintf(log_file, "Hello ");
  // fprintf(log_file, "world\n");
  enum { MAX_ARGS = 10 };
  int i, new_argc;
  char *new_argv[MAX_ARGS];

  umask(0);
  /* Process the "--plus" option apart */
  for (i = 0, new_argc = 0; (i < argc) && (new_argc < MAX_ARGS); i++) {
    if (!strcmp(argv[i], "--plus")) {
      fill_dir_plus = FUSE_FILL_DIR_PLUS;
    } else {
      new_argv[new_argc++] = argv[i];
    }
  }
  // return fuse_main(new_argc, new_argv, NULL, NULL);
  return fuse_main(argc, argv, &fs_ops, NULL);
}
