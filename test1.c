#include "block.h"
#include <errno.h>
#include <time.h>
#define X2_CODE_STUFF
#include "x2.h"
#include <assert.h>

i32 main() {
  struct BlockDev bd = Dummy("disk.img");
  x2Init(&bd);

  struct Inode parent;
  usize parent_idx = 2;
  x2getRoot(&parent, NULL);

  struct Inode child;
  usize child_idx;

  struct Inode *parent_ptr = &parent;
  struct Inode *child_ptr = &child;


  for (;;) {
    int res = x2createDir(parent_ptr, parent_idx, child_ptr, &child_idx, "a");
    if (res == -ENOSPC)
      break;
    assert(res == X2_OK);
    usize tmp;
    assert(res == X2_OK);

    parent_idx = child_idx;
    struct Inode *n = parent_ptr;
    parent_ptr = child_ptr;
    child_ptr = n;
  }
  
  for (;child_idx!=2;) {
    int r = x2findInode(parent_ptr, "..", child_ptr, &child_idx);
    assert(r==0);
    r = x2unlink2(child_ptr,child_idx, "a", 1);
    assert(r == 0);
    parent_ptr = child_ptr;
  }
  
  x2sync();
  DummyFlush();
  return 0;
}
