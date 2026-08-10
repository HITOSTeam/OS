#!/bin/sh
set -eu

# 无论从仓库根目录还是 os/ 目录调用，都以脚本所在目录为准。
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ARCH=${ARCH:-riscv64}

case "$ARCH" in
    riscv64)
        TEST_IMG=/images_host/final_img/sdcard-rv-pub.img
        MEM=${MEM:-16G}
        SMP=${SMP:-8}
        ;;
    loongarch64)
        TEST_IMG=/images_host/final_img/sdcard-la-pub.img
        MEM=${MEM:-16G}
        SMP=${SMP:-12}
        ;;
    *)
        echo "不支持的架构：$ARCH（仅支持 riscv64 或 loongarch64）" >&2
        exit 2
        ;;
esac

if [ ! -f "$TEST_IMG" ]; then
    echo "缺少决赛测试镜像：$TEST_IMG" >&2
    exit 1
fi

START_EPOCH=$(date +%s)
START_UTC=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
echo "[final-run] host_start_utc=$START_UTC"
echo "启动决赛测试：架构=$ARCH 核心数=$SMP 内存=$MEM 镜像=$TEST_IMG"
echo "测试顺序：CAgent -> BuildStorm"

if make -C "$SCRIPT_DIR" run ARCH="$ARCH" FINAL_TEST=1 TEST_IMG="$TEST_IMG" SMP="$SMP" MEM="$MEM"; then
    RUN_STATUS=0
else
    RUN_STATUS=$?
fi

END_EPOCH=$(date +%s)
END_UTC=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
echo "[final-run] host_finish_utc=$END_UTC elapsed_s=$((END_EPOCH - START_EPOCH)) exit_code=$RUN_STATUS"
exit "$RUN_STATUS"
