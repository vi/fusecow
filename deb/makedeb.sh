#!/bin/bash
set -e

P=fusecow
V=$(<../VERSION)
FILES="fusecow.c VERSION makefile"

rm -Rf "$P"-$V
trap "rm -fR \"$P\"-$V" EXIT 
mkdir "$P"-$V
for i in $FILES; do cp -v ../"$i" "$P"-$V/; done
tar -czf ${P}_$V.orig.tar.gz "$P"-$V

cp -R debian "$P"-$V
sed "s@VERSION@$V@" -i "$P"-$V/debian/changelog
(cd "$P"-$V && debuild)

