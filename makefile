# this is a makefile for building without cmake

all: fusecow

fusecow: fusecow.c makefile
	gcc -g3 -O2 -Wall fusecow.c -o fusecow `pkg-config fuse --cflags --libs`

VERSION: .git/HEAD
	git describe --dirty | sed 's!^v!!' > VERSION || echo 0.0 > VERSION

.PHONY: test deb

deb: VERSION
	(cd deb && ./makedeb.sh)

deb_simple: fusecow VERSION deb_simple/control
	rm -Rf deb
	mkdir -p deb/usr/bin/
	mkdir -p deb/DEBIAN
	cp deb_simple/control deb/DEBIAN/control
	echo Version: `cat VERSION` >> deb/DEBIAN/control
	touch deb/DEBIAN/conffiles
	cp fusecow deb/usr/bin/
	strip deb/usr/bin/fusecow
	fakeroot dpkg-deb -b deb fusecow-`cat VERSION`.deb
	rm -Rf deb

clean:
	rm -f fusecow
