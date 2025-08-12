#include "block.h"
#include "x2.h"
#include <assert.h>
#include <stdio.h>

u8 rbuf[BLOCKSIZE * 32] = {0xff};

void putsl(const char *s, usize len) {
  for (usize i = 0; i < len; i++) {
    printf("%c", s[i]);
  }
}

i32 main() {
  struct BlockDev bd = Dummy("disk.img");
  x2Init(&bd);

  int l;
  usize ino_idx;
  usize n;
  struct Inode root;
  x2getRoot(&root, NULL);

  struct Inode ino;
  usize txt_idx;

  l = x2createFile(&root, 2, &ino, &ino_idx, "file.txt");
  assert(l == 0);
  // x2readInode(ino_idx, &ino);

  l = x2write(&ino, ino_idx, "a", 1, 1024 * 1024 * 30);
  assert(l == 1);

  assert(ino.size == 1024 * 1024 * 30 + 1);

  l = x2read(&ino, rbuf, BLOCKSIZE * 2, 0);
  assert(l == BLOCKSIZE * 2);
  for (usize i = 0; i < BLOCKSIZE * 2; i++) {
    assert(rbuf[i] == 0);
  }

  l = x2unlink(&root, 2, "file.txt");
  assert(l == 0);

  x2sync();
  DummyFlush();
  return 0;
}
