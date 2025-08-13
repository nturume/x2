gcc -c -g block.c -fsanitize=address -o block.o
gcc -c -g x2.c -fsanitize=address -o x2.o

g++ -g fuse.cpp x2.o block.o -fsanitize=address `pkg-config fuse3 --cflags --libs`
 
./a.out -o max_threads=1 -d -s  m
