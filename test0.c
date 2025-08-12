#include "block.h"
#include <time.h>
#define X2_CODE_STUFF
#include "x2.h"

const char *letters =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345679"
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345679"
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345679"
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345679"
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345679"
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345679"
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345679";

i32 main() {
  struct BlockDev bd = Dummy("disk.img");
  x2Init(&bd);

  struct Inode root;
  x2getRoot(&root, NULL);

  struct Inode c;
  usize c_idx;

  for (usize i = 1; i < 256; i++) {
    int r = x2createFile2(&root, 2, &c, &c_idx, letters, i, EXT2_FT_DIR);
    assert(r == 0);
  }

  for (usize i = 1; i < 256; i++) {
    int r = x2unlink2(&root, 2, letters, i);
    assert(r == 0);
  }

  for (usize i = 1; i < 256; i++) {
    int r = x2createFile2(&root, 2, &c, &c_idx, letters, i, EXT2_FT_REG_FILE);
    assert(r == 0);
  }

  for (usize i = 1; i < 256; i++) {
    int r = x2unlink2(&root, 2, letters, i);
    assert(r == 0);
  }
  
  x2sync();
  DummyFlush();
  return 0;
}
