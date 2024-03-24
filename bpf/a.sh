#!/bin/bash
PROGNAME=$(basename $0)
if [ $# -ne 1 ]; then
    echo "Usage: $PROGNAME <filename>"
    exit 1
fi

FILENAME=$1
if [ ! -f $FILENAME ]; then
    echo "$FILENAME not found"
    exit 1
fi

clang-13 -emit-llvm -g -O2 -D __TARGET_ARCH_x86 -target bpf -I/usr/src/linux-headers-$(uname -r)/include -c $FILENAME

FILENAME_NOEXT=${FILENAME%.c}
FILENAME_BC=$FILENAME_NOEXT.bc

llvm-dis-13 $FILENAME_BC