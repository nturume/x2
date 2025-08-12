#include "block.h"
#include "x2.h"
#include <assert.h>
#include <stdio.h>
#include <time.h>

u8 rbuf[BLOCKSIZE * 16];

void putsl(const char *s, usize len) {
  for (usize i = 0; i < len; i++) {
    printf("%c", s[i]);
  }
}

i32 main() {
  struct BlockDev bd = Dummy("disk.img");
  x2Init(&bd);

  struct Inode root;
  x2getRoot(&root, NULL);

  int l;
  usize ino_idx;
  usize n;
  struct Inode ino;

  l = x2findInode(&root, "x2.c", &ino, &ino_idx);
  assert(l == 0);
 usize total_r = 0;
  for (usize i = 0;; i += 3) {
    n = x2read(&ino, rbuf, 3, i);
    putsl(rbuf, n);
    if (n == 0)
      break;
    total_r += n;
  }
  assert(total_r == ino.size);
  x2sync();
  DummyFlush();
  return 0;
}
