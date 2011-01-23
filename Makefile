all:
	gcc -g3 -O2 -Wall `pkg-config fuse --cflags --libs` fusecow.c -o fusecow 

prefix=/usr

install:
	install fusecow ${prefix}/bin/	

