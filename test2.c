#include "block.h"
#include "x2.h"
#include <assert.h>
#include <stdio.h>
#include <time.h>

u8 string[64];

int str(u32 n) {
 return sprintf(string, "%u", n); 
}

i32 main() {
  struct BlockDev bd = Dummy("disk.img");
  x2Init(&bd);

  struct Inode root;
  x2getRoot(&root, NULL);

  struct Inode child;
  usize child_idx;
  
  int l;
  usize i;
  for(i = 1;;i++) {
    l = str(i);
    assert(l>0);
    l = x2createFile(&root, 2, &child, &child_idx,  string);
    if(l==X2_ERR_NO_SPACE) break;
    assert(l==X2_OK);
  }
  i -= 1;
  for(;i > 0;i--) {
    l = str(i);
    assert(l>0);
    l = x2unlink(&root, 2, string);
    assert(l==X2_OK);
  }
  
  for(i = 1;;i++) {
    l = str(i);
    assert(l>0);
    l = x2createDir(&root, 2, &child, &child_idx,  string);
    if(l==X2_ERR_NO_SPACE) break;
    assert(l==X2_OK);
  }
  i -= 1;
  for(;i > 0;i--) {
    l = str(i);
    assert(l>0);
    l = x2unlink(&root, 2, string);
    assert(l==X2_OK);
  }
  x2sync();
  DummyFlush();
  return 0;
}
