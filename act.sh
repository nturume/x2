
sudo umount m
rm disk.img 
sudo dd of=disk.img if=/dev/zero bs=1M count=8
echo "y" | mkfs.ext2 -c disk.img -b 4096 -I 128
# sudo mount disk.img m --rw
# sudo cp x2.c m/x2.c
# sudo touch m/file.txt
# sudo touch m/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345679
# sudo ln -s m/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345679 m/m.c
# sudo umount m
gcc -g example.c block.c x2.c -fsanitize=address && ./a.out
# gcc main.c block.c && ./a.out
# sudo mount disk.img m --rw
