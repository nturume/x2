
sudo umount m
rm disk.img 
sudo dd of=disk.img if=/dev/zero bs=1M count=8
echo "y" | mkfs.ext2 -c disk.img -b 4096 -I 128
# sudo mount disk.img m --rw
# sudo touch m/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345679
# sudo ln -s m/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345679 m/m.c
# sudo umount m
gcc main.c -fsanitize=address && ./a.out
sudo mount disk.img m --rw
