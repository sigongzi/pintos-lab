#!/bin/sh
cd ./build

rm -f tmp.dsk
pintos-mkdisk tmp.dsk --filesys-size=2
pintos -v -k -T 60 --qemu  --disk=tmp.dsk -p tests/filesys/extended/dir-vine -a dir-vine -p tests/filesys/extended/tar -a tar --swap-size=4 -- -q  -f run dir-vine