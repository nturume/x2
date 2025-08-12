GREEN="\e[1;32m"
RED="\e[1;31m"
NC="\e[0m"

mkdir -p m
rm -f disk.img 
sudo dd of=disk.img if=/dev/zero bs=1M count=8
echo "y" | mkfs.ext2 -c disk.img -b 4096 -I 128
gcc -g test0.c block.c x2.c -fsanitize=address && ./a.out
fsck.ext2 disk.img -f -n
if [ $? -ne 0 ]; then
  echo -e "${RED}test0 failed successfully.${NC}";
else
  echo -e "${GREEN}test0 failed to fail.${NC}"
fi

echo "y" | mkfs.ext2 -c disk.img -b 4096 -I 128
gcc -g test1.c block.c x2.c -fsanitize=address && ./a.out
fsck.ext2 disk.img -f -n
if [ $? -ne 0 ]; then
  echo -e "${RED}test1 failed successfully.${NC}";
else
  echo -e "${GREEN}test1 failed to fail.${NC}"
fi


echo "y" | mkfs.ext2 -c disk.img -b 4096 -I 128
gcc -g test2.c block.c x2.c -fsanitize=address && ./a.out
fsck.ext2 disk.img -f -n
if [ $? -ne 0 ]; then
  echo -e "${RED}test2 failed successfully.${NC}";
else
  echo -e "${GREEN}test2 failed to fail.${NC}"
fi

echo "y" | mkfs.ext2 -c disk.img -b 4096 -I 128
sudo mount disk.img m --rw
sudo cp x2.c m/x2.c
sudo umount m
gcc -g test3.c block.c x2.c -fsanitize=address && ./a.out
fsck.ext2 disk.img -f -n
if [ $? -ne 0 ]; then
  echo -e "${RED}test3 failed successfully.${NC}";
else
  echo -e "${GREEN}test3 failed to fail.${NC}"
fi

echo "y" | mkfs.ext2 -c disk.img -b 4096 -I 128
gcc -g test4.c block.c x2.c -fsanitize=address && ./a.out
fsck.ext2 disk.img -f -n
if [ $? -ne 0 ]; then
  echo -e "${RED}test4 failed successfully.${NC}";
else
  echo -e "${GREEN}test4 failed to fail.${NC}"
fi

echo "y" | mkfs.ext2 -c disk.img -b 4096 -I 128
gcc -g test5.c block.c x2.c -fsanitize=address && ./a.out
fsck.ext2 disk.img -f -n
if [ $? -ne 0 ]; then
  echo -e "${RED}test5 failed successfully.${NC}";
else
  echo -e "${GREEN}test5 failed to fail.${NC}"
fi
