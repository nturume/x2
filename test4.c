#include "block.h"
#include "x2.h"
#include <assert.h>
#include <stdio.h>

u8 rbuf[BLOCKSIZE * 32];

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

  l = x2createFile(&root , 2, &ino, &ino_idx, "file.txt");
  assert(l == 0);

  n = x2write(&ino, ino_idx, rbuf, BLOCKSIZE, 0);
  assert(n == BLOCKSIZE);

  assert(ino.size == BLOCKSIZE);

  n = x2write(&ino, ino_idx, "z", 1, BLOCKSIZE);
  assert(n == 1);

  assert(ino.size == BLOCKSIZE + 1);

  n = x2write(&ino, ino_idx, rbuf, BLOCKSIZE, 0);
  assert(n == BLOCKSIZE);

  assert(ino.size == BLOCKSIZE + 1);

  n = x2write(&ino, ino_idx, rbuf, BLOCKSIZE + 2, 0);
  assert(n == BLOCKSIZE + 2);

  assert(ino.size == BLOCKSIZE + 2);

  usize i;

 for (i = 0;; i += BLOCKSIZE * 29) {
    n = x2write(&ino, ino_idx, rbuf, BLOCKSIZE * 29, i);
    if (n == X2_ERR_NO_SPACE)
      break;
    assert(n > 0);
  }

  for (i = 0;/*i < (BLOCKSIZE*1038)*/; i += BLOCKSIZE) {
    n = x2write(&ino, ino_idx, rbuf, BLOCKSIZE, i);
    if (n == X2_ERR_NO_SPACE)
      break;
    assert(n > 0);
  }

  assert(ino.size == (i));

  for (i = 0;; i += BLOCKSIZE * 2) {
    n = x2write(&ino, ino_idx, rbuf, BLOCKSIZE * 2, i);
    if (n == X2_ERR_NO_SPACE)
      break;
    assert(n > 0);
  }


 for (i = 0;; i += BLOCKSIZE * 16) {
    n = x2write(&ino, ino_idx, rbuf, BLOCKSIZE * 16, i);
    if (n == X2_ERR_NO_SPACE)
      break;
    assert(n > 0);
  }


  x2sync();  
  DummyFlush();
  return 0;
}
