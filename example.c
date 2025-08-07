#include "block.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

i32 main() {
  struct BlockDev bd = Dummy("disk.img");
  x2Init(&bd);

  struct Inode root;
  usize root_idx;
  x2getRoot(&root, &root_idx);

  struct Inode lostfound = {0};
  usize lostfound_idx;
  x2findInode(&root, "lost+found", &lostfound, &lostfound_idx);

  struct Inode lf;
  usize lf_idx;
  x2findInode(&lostfound, "..", &lf, &lf_idx);

  assert(memcmp(&root, &lf, sizeof(struct Inode)) == 0);

  usize link1_idx;
  struct Inode link_ino;
  x2createLink(&lostfound, lostfound_idx, &link_ino, &link1_idx, "lost-link",
               "/home/lost-target");

  char link_result[255];
  int link_len = x2readLink(&link_ino, (char *)&link_result, 254);
  assert(memcmp(link_result, "/home/lost-target", link_len) == 0);

  struct Inode new_dir;
  usize new_dir_idx;
  assert(x2createDir(&root, root_idx, &new_dir, &new_dir_idx, "xfeedf") == 0);

  struct Inode new_file;
  usize new_file_idx;
  assert(x2createFile(&new_dir, new_dir_idx, &new_file, &new_file_idx,
                      "a.txt") == 0);

  assert(x2write(&new_file, new_file_idx, (u8 *)"12345678", 8, 0) == 8);
  u8 readbuf[8];
  assert(x2read(&new_file, readbuf, 8, 0) == 8);
  assert(memcmp(readbuf, "12345678", 8) == 0);

  DummyFlush();
  return 0;
}
