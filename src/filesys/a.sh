#!/bin/sh
cd ./build

rm -f tmp.dsk                                                                                                                                    
pintos-mkdisk tmp.dsk --filesys-size=2
pintos -v -k -T 60 --qemu  --disk=tmp.dsk -p tests/filesys/extended/syn-rw -a syn-rw -p tests/filesys/extended/tar -a tar -p tests/filesys/extended/child-syn-rw -a child-syn-rw --swap-size=4 -- -q  -f run syn-rw