#include "block.h"
#include "x2.h"
#include <assert.h>
#include <stdio.h>


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

  l = x2truncate(&ino, ino_idx, 40);
  assert(l==0);

  assert(ino.size == 40);

  l = x2truncate(&ino, ino_idx, 0);
  assert(l==0);
  assert(ino.size == 0);
  assert(ino.blocks == 0);
  
  l = x2truncate(&ino, ino_idx, BLOCKSIZE*BLOCKSIZE);
  assert(l==0);
  
  l = x2truncate(&ino, ino_idx, 0);
  assert(l==0);
  assert(ino.size == 0);


  l = x2fallocate(&ino, ino_idx, 0, 0, BLOCKSIZE*100);
  assert(l==0);
  assert(ino.size == BLOCKSIZE*100);

  x2sync();
  DummyFlush();
  return 0;
}
