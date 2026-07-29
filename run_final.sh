#!/bin/sh
set -e
# cp testsuits-for-oskernel/sdcard/sdcard-rv.img ./sdcard-rv.img
# cp loongarch_img_info/sdcard-la.img ./sdcard-la.img

# ln -sfn testsuits-for-oskernel/sdcard/sdcard-rv.img "$ROOT_DIR/sdcard-rv.img"
# ln -sfn testsuits-for-oskernel/sdcard/sdcard-la.img "$ROOT_DIR/sdcard-la.img"
# rm if possible
# if [ -f output.md ]; then
#     rm output.md
# fi
# # read env arch

cd os

# EXT4_SIZE=${EXT4_SIZE:-4G}

# ARCH=$ARCH SUBMIT=1 make run_ext4 LOG=warn SMP=1 MEM=1G EXT4_REBUILD=1 EXT4_SIZE=$EXT4_SIZE > ../output.md 

ARCH=${ARCH:-riscv64}
MEM=${MEM:-4G}

make run_eval ARCH="$ARCH" MEM="$MEM"
