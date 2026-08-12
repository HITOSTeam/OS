#!/bin/sh
set -eu

# 无论从仓库根目录还是 os/ 目录调用，都以脚本所在目录为准。
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ARCH=${ARCH:-riscv64}
PREBUILT_ONLY=${PREBUILT_ONLY:-0}

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
if [ "$PREBUILT_ONLY" = "1" ]; then
    if [ "$ARCH" != "loongarch64" ]; then
        echo "PREBUILT_ONLY=1 目前仅用于 LoongArch 内层 QEMU 诊断" >&2
        exit 2
    fi
    echo "测试模式：跳过 CAgent/BuildStorm 编译，直接运行预编译 ArceOS UEFI 测试"
    PREBUILT_MAKE_ARG="FINAL_PREBUILT_ONLY=1"
else
    echo "测试顺序：CAgent -> BuildStorm"
    PREBUILT_MAKE_ARG=""
fi

if make -C "$SCRIPT_DIR" run ARCH="$ARCH" FINAL_TEST=1 TEST_IMG="$TEST_IMG" SMP="$SMP" MEM="$MEM" $PREBUILT_MAKE_ARG; then
    RUN_STATUS=0
else
    RUN_STATUS=$?
fi

END_EPOCH=$(date +%s)
END_UTC=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
echo "[final-run] host_finish_utc=$END_UTC elapsed_s=$((END_EPOCH - START_EPOCH)) exit_code=$RUN_STATUS"
exit "$RUN_STATUS"
