gcc -c -g block.c -fsanitize=address -o block.o
gcc -c -g x2.c -fsanitize=address -o x2.o

g++ -g fuse.cpp x2.o block.o -fsanitize=address `pkg-config fuse3 --cflags --libs`


sudo dd of=disk.img if=/dev/zero bs=1M count=8
echo "y" | mkfs.ext2 -c disk.img -b 4096 -I 128
sudo mkdir mnt

./a.out disk.img -o max_threads=1 -d -s mnt
