set -e
if [ -f testsuits-for-oskernel/sdcard/sdcard-rv.img ]; then
    cp testsuits-for-oskernel/sdcard/sdcard-rv.img ./sdcard-rv.img
fi

if [ -f loongarch_img_info/sdcard-la.img ]; then
    cp loongarch_img_info/sdcard-la.img ./sdcard-la.img
fi

# rm if possible
if [ -f output.md ]; then
    rm output.md
fi
# read env arch

cd os

EXT4_SIZE=${EXT4_SIZE:-4G}
SMP=${SMP:-1}

ARCH=$ARCH SUBMIT=1 make run_ext4 LOG=warn SMP=$SMP MEM=1G EXT4_REBUILD=1 EXT4_SIZE=$EXT4_SIZE > ../output.md
