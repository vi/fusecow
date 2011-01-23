all:
	gcc -g3 -O2 `pkg-config fuse --cflags --libs` fusecow.c -o fusecow 

prefix=/usr

install:
	install fusecow ${prefix}/bin/	

