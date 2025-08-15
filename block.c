#include "block.h"

u8 rdbuf[1024 * 1024 * 256];

static u64 read(FILE *f, u8 *buf, u64 len) {
  u64 read = 0;
  while (read < len) {
    u64 n = fread(buf + read, 1, len - read, f);
    read += n;
    if (n == 0) {
      assert(!ferror(f));
      break;
    }
  }
  return read;
}

static u64 write(FILE *f, const u8 *buf, u64 len) {
  u64 written = 0;
  while (written < len) {
    u64 amnt = len - written;
    u64 n = fwrite(buf + written, 1, amnt, f);
    if (n != amnt) {
      assert(!ferror(f));
      break;
    }
    written += n;
  }
  return written;
}

static void seekBy(FILE *f, i64 n) {
  assert(!fseek(f, n, SEEK_CUR));
}

static void seekTo(FILE *f, i64 n) {
  assert(!fseek(f, n, SEEK_SET));
}

static u64 getPos(FILE *f) { return ftell(f); }

static u32 getFileSize(FILE *f) {
  assert(!fseek(f, 0, SEEK_END));
  u32 size = ftell(f);
  seekTo(f, 0);
  return size;
}

void readBlock(void *f, usize pos, u8 *buf) {
  memcpy(buf, rdbuf + pos * BLOCKSIZE, BLOCKSIZE);
}

void writeBlock(void *f, usize pos, const u8 *buf) {
  memcpy(rdbuf + pos * BLOCKSIZE, buf, BLOCKSIZE);
}

void dummyR(void *d, usize pos, u8 *buf) {
  return readBlock(((struct BlockDev *)d)->ctx, pos, buf);
}

void dummyW(void *d, usize pos, const u8 *buf) {
  return writeBlock(((struct BlockDev *)d)->ctx, pos, buf);
}

FILE *openImage(const char *path) {
  FILE *i = fopen(path, "rb+");
  assert(i);
  return i;
}

FILE *f;

struct BlockDev Dummy(const char *img_path) {
  f = openImage(img_path);
  seekTo(f, 0);
  assert(read(f, rdbuf, sizeof(rdbuf)) == sizeof(rdbuf));
  return (struct BlockDev){
      .readBlock = &dummyR,
      .writeBlock = &dummyW,
      .ctx = (void *)f,
  };
}

void DummyFlush() {
  seekTo(f, 0);
  assert(write(f, rdbuf, sizeof(rdbuf)) == sizeof(rdbuf));
  printf("image written to file..\n");
}
