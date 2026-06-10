#!/usr/bin/env bash
# eg: ARCH=loongarch64 MODE=debug bash os/run_debug.sh
# 配合  make client_gdb_xcy ARCH=loongarch64 MODE=debug
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

ln -sfn testsuits-for-oskernel/sdcard/sdcard-rv.img "$ROOT_DIR/sdcard-rv.img"
ln -sfn testsuits-for-oskernel/sdcard/sdcard-la.img "$ROOT_DIR/sdcard-la.img"

if [ -f "$ROOT_DIR/output.md" ]; then
    rm "$ROOT_DIR/output.md"
fi

cd "$SCRIPT_DIR"
# Default debug profile: easier source-level debugging.
ARCH=${ARCH:-loongarch64}
MODE=${MODE:-debug}
SMP=${SMP:-1}
MEM=${MEM:-1G}
EXT4_SIZE=${EXT4_SIZE:-4G}
EXT4_REBUILD=${EXT4_REBUILD:-1}
SUBMIT=${SUBMIT:-1}

echo "[run_debug] Starting QEMU in debug mode (-S -s), waiting GDB on :1234"
echo "[run_debug] ARCH=$ARCH MODE=$MODE SMP=$SMP MEM=$MEM EXT4_SIZE=$EXT4_SIZE"
echo "[run_debug] In another terminal run:"
echo "  cd $SCRIPT_DIR && make client_gdb_xcy ARCH=$ARCH MODE=$MODE"

ARCH=$ARCH MODE=$MODE SUBMIT=$SUBMIT make debug_ext4 LOG=warn SMP=$SMP MEM=$MEM EXT4_REBUILD=$EXT4_REBUILD EXT4_SIZE=$EXT4_SIZE 
