cd os
rm ../output.md
# read env arch
ARCH=$ARCH SUBMIT=1 make run_ext4 LOG=warn SMP=1 MEM=1G EXT4_REBUILD=1 > ../output.md 