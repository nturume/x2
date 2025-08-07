
#include "x2.h"

void readBlock(void *f, usize pos, u8 *buf);
void writeBlock(void *f, usize pos, const u8 *buf);
struct BlockDev Dummy(const char *img_path);
void DummyFlush();
