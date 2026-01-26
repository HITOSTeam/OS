set -e
cp testsuits-for-oskernel/sdcard/sdcard-rv.img ./sdcard-rv.img
cp loongarch_img_info/sdcard-la.img ./sdcard-la.img

# rm if possible
if [ -f output.md ]; then
    rm output.md
fi
# read env arch

cd os


ARCH=$ARCH SUBMIT=1 make run_ext4 LOG=warn SMP=1 MEM=1G EXT4_REBUILD=1 > ../output.md 
