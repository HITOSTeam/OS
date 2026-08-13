# 双架构构建入口
#
# 常用命令：
#   make elf  ARCH=riscv64
#   make disk ARCH=riscv64
#   make run  ARCH=riscv64 FINAL_TEST=1
#
# FINAL_TEST=1 时使用官方决赛镜像，并由 0final_init 依次执行
# CAgent 和 BuildStorm；FINAL_TEST=0 时进入普通交互环境。
# :=的赋值是在makefile在被读取的时候立即做计算，也就是正常的覆盖
# ?=是在这个变量没有被定义的时候才会赋值，也就是当环境变量有对应值的时候不会覆盖

# 这些是死的路径，我们不需要外界传入，所以使用:=赋值，上传的时候这个root_dir需要修改
MAKEFILE_DIR     := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
ROOT_DIR         := $(abspath $(MAKEFILE_DIR)/..)
USER_DIR         := $(ROOT_DIR)/user
CARGO_TARGET_DIR := $(ROOT_DIR)/target

# 这个可以被外界赋值的变量，所以使用?修饰等于号
ARCH          ?= riscv64
BOARD         ?= qemu
MODE          ?= release
FINAL_TEST    ?= 0
SMP           ?= 12
# 国赛测试使用4G 然后初赛的测试使用1G 当然也可以自己指定
MEM           ?= $(if $(filter 1,$(FINAL_TEST)),4G,1G)
DISK_SIZE     ?= 1G
QEMU_TIMEOUT  ?= 0
QEMU_EXTRA_ARGS ?=

# VisionFive 2 使用 U-Boot 的 TFTP/booti 启动路径。
# `os` 是带调试信息的 ELF，只用于调试，不能由本板的启动跳板直接执行。
TFTP_ROOT     ?= $(CARGO_TARGET_DIR)/$(TARGET)/$(MODE)
TFTP_BIND     ?= 0.0.0.0
TFTP_PORT     ?= 69
TFTP_KERNEL_FILE ?= os.bin
TFTP_BOOT_FILE ?= vf2_booti.img
OBJCOPY        ?= llvm-objcopy
VF2_AS         ?= riscv64-unknown-elf-as

ifneq ($(filter 0 1,$(FINAL_TEST)),$(FINAL_TEST))
    $(error FINAL_TEST 只能取 0 或 1)
endif

ifeq ($(ARCH),riscv64)
    TARGET          := riscv64gc-unknown-none-elf
    CARGO_CONFIG    := $(ROOT_DIR)/cargo-config/config.toml
    QEMU_BIN        := qemu-system-riscv64
    QEMU_BIOS_ARGS  := -bios default
    QEMU_BLOCK0     := virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0
    QEMU_BLOCK1     := virtio-blk-device,drive=x1,bus=virtio-mmio-bus.1
    QEMU_NET        := -device virtio-net-device,netdev=net -netdev user,id=net
    GDB_ARCH        := riscv:rv64
    GDB_DEFAULT     := $(if $(wildcard $(ROOT_DIR)/bin/riscv64-unknown-elf-gdb),$(ROOT_DIR)/bin/riscv64-unknown-elf-gdb,riscv64-unknown-elf-gdb)
    BASE_IMG        := $(ROOT_DIR)/img/disk.img
    NORMAL_IMG      := $(ROOT_DIR)/sdcard-rv.img
    FINAL_IMG       := /images_host/final_img/sdcard-rv-pub.img
else ifeq ($(ARCH),loongarch64)
    # 决赛镜像仅提供该 LoongArch bare-metal 标准库；同时与 Cargo 配置保持一致。
    TARGET          := loongarch64-unknown-none
    CARGO_CONFIG    := $(ROOT_DIR)/cargo-config/config_loongarch64.toml
    QEMU_BIN        := qemu-system-loongarch64
    QEMU_BIOS_ARGS  :=
    QEMU_BLOCK0     := virtio-blk-pci,drive=x0
    QEMU_BLOCK1     := virtio-blk-pci,drive=x1
    QEMU_NET        := -device virtio-net-pci,netdev=net -netdev user,id=net
    GDB_ARCH        := loongarch
    GDB_DEFAULT     := $(if $(wildcard $(ROOT_DIR)/bin/loongarch64-linux-gnu-gdb),$(ROOT_DIR)/bin/loongarch64-linux-gnu-gdb,loongarch64-linux-gnu-gdb)
    BASE_IMG        := $(ROOT_DIR)/img/disk-la.img
    NORMAL_IMG      := $(ROOT_DIR)/sdcard-la.img
    FINAL_IMG       := /images_host/final_img/sdcard-la-pub.img
else
    $(error ARCH 只能取 riscv64 或 loongarch64)
endif

ifeq ($(BOARD),visionfive2)
    ifneq ($(ARCH),riscv64)
        $(error BOARD=visionfive2 仅支持 ARCH=riscv64)
    endif
    KERNEL_FEATURES := --features riscv-board
else ifneq ($(BOARD),qemu)
    $(error BOARD 只能取 qemu 或 visionfive2)
endif

GDB_BIN          ?= $(GDB_DEFAULT)
CARGO_MODE_FLAG := $(if $(filter release,$(MODE)),--release,)
HOST_TRIPLE      ?= $(shell rustc -vV | sed -n 's/^host: //p')
KERNEL_ELF       := $(CARGO_TARGET_DIR)/$(TARGET)/$(MODE)/os
KERNEL_BIN       := $(CARGO_TARGET_DIR)/$(TARGET)/$(MODE)/os.bin
VF2_BOOTI_IMAGE  := $(CARGO_TARGET_DIR)/$(TARGET)/$(MODE)/vf2_booti.img
VF2_BOOTI_OBJECT := $(CARGO_TARGET_DIR)/$(TARGET)/$(MODE)/vf2_booti_trampoline.o
VF2_BOOTI_SOURCE := $(MAKEFILE_DIR)tools/vf2_booti_trampoline.S
USER_TARGET_DIR  := $(USER_DIR)/target/$(TARGET)/$(MODE)
APP_DIR          := $(MAKEFILE_DIR)results
DISK_NAME        := fs-$(ARCH).ext4
DISK_IMG         := $(ROOT_DIR)/ext4-fs-packer/target/$(DISK_NAME)

ifeq ($(FINAL_TEST),1)
    USER_FEATURES := --features submit
    PACKER_ARGS   := --minimal-eval-root
    TEST_IMG      ?= $(FINAL_IMG)
    SNAPSHOT_ARG  := -snapshot
else
    USER_FEATURES :=
    PACKER_ARGS   := -e extra --arch-extra extra-$(ARCH) -b $(BASE_IMG)
    TEST_IMG      ?= $(NORMAL_IMG)
    SNAPSHOT_ARG  :=
endif

ifeq ($(QEMU_TIMEOUT),0)
    QEMU_RUN := $(QEMU_BIN)
else
    QEMU_RUN := timeout $(QEMU_TIMEOUT) $(QEMU_BIN)
endif

.DEFAULT_GOAL := elf
.NOTPARALLEL:

.PHONY: all elf kernel user_apps disk ext4_img run run_ext4 \
        debug gdb client_gdb vf2-image tftp-root tftp-server clean help prepare-cargo

# all只是编译镜像还有内核elf
all: elf disk

# 为 os 与 user 安装当前架构的 Cargo 配置。
prepare-cargo:
	@mkdir -p .cargo $(USER_DIR)/.cargo
	@cp $(CARGO_CONFIG) .cargo/config.toml
	@cp $(CARGO_CONFIG) $(USER_DIR)/.cargo/config.toml

# 编译用户态程序，并复制到磁盘打包目录。
user_apps: prepare-cargo
	@cd $(USER_DIR) && CARGO_TARGET_DIR=target \
		cargo build $(CARGO_MODE_FLAG) $(USER_FEATURES) --target $(TARGET)
	@mkdir -p $(APP_DIR)
	@for file in $(USER_TARGET_DIR)/*; do \
		[ -f "$$file" ] && [ -x "$$file" ] || continue; \
		name=$$(basename "$$file"); \
		cp "$$file" "$(APP_DIR)/$$name.bin"; \
	done

# 编译可由 QEMU 直接加载的内核 ELF。
elf: prepare-cargo user_apps
	@cargo build $(CARGO_MODE_FLAG) $(KERNEL_FEATURES) --target $(TARGET) --bin os
	@echo "内核 ELF：$(KERNEL_ELF)"


# 制作与架构绑定的本地磁盘，避免两个架构共用同一个输出文件。
disk: user_apps
	@if [ "$(FINAL_TEST)" = "0" ] && [ ! -f "$(BASE_IMG)" ]; then \
		echo "缺少基础镜像：$(BASE_IMG)"; \
		exit 1; \
	fi
	@cd $(ROOT_DIR)/ext4-fs-packer && \
		CARGO_BUILD_TARGET=$(HOST_TRIPLE) cargo run --release -- \
		-u $(APP_DIR) $(PACKER_ARGS) -t target -S $(DISK_SIZE) -o $(DISK_NAME)
	@echo "本地磁盘：$(DISK_IMG)"

# 启动 QEMU。disk0 是本地用户程序盘，disk1 是普通测试盘或官方决赛盘。
run: elf disk
	@if [ ! -f "$(TEST_IMG)" ]; then \
		echo "缺少测试镜像：$(TEST_IMG)"; \
		exit 1; \
	fi
	@echo "架构=$(ARCH) 核心数=$(SMP) 内存=$(MEM) 决赛测试=$(FINAL_TEST)"
	$(QEMU_RUN) -machine virt -kernel $(KERNEL_ELF) -m $(MEM) -smp $(SMP) \
		-nographic -rtc base=utc -no-reboot $(QEMU_BIOS_ARGS) \
		$(SNAPSHOT_ARG) $(QEMU_EXTRA_ARGS) \
		-drive file=$(DISK_IMG),if=none,format=raw,id=x0 -device $(QEMU_BLOCK0) \
		$(QEMU_NET) \
		-drive file=$(TEST_IMG),if=none,format=raw,id=x1 -device $(QEMU_BLOCK1)

# 启动后立即暂停 CPU，并在 1234 端口等待 GDB。
debug: elf disk
	@if [ ! -f "$(TEST_IMG)" ]; then \
		echo "缺少测试镜像：$(TEST_IMG)"; \
		exit 1; \
	fi
	$(QEMU_BIN) -machine virt -kernel $(KERNEL_ELF) -m $(MEM) -smp $(SMP) \
		-nographic -rtc base=utc -no-reboot $(QEMU_BIOS_ARGS) \
		$(SNAPSHOT_ARG) $(QEMU_EXTRA_ARGS) -s -S \
		-drive file=$(DISK_IMG),if=none,format=raw,id=x0 -device $(QEMU_BLOCK0) \
		$(QEMU_NET) \
		-drive file=$(TEST_IMG),if=none,format=raw,id=x1 -device $(QEMU_BLOCK1)

# 使用仓库内的 GDB 客户端连接暂停中的 QEMU。
gdb:
	@$(GDB_BIN) \
		-ex 'file $(KERNEL_ELF)' \
		-ex 'set architecture $(GDB_ARCH)' \
		-ex 'target remote :1234' \
		-ex 'display/10i $$pc'

# 保留旧目标名，现有脚本可以平滑迁移。
kernel: elf
ext4_img: disk
run_ext4: run
client_gdb: gdb

clean:
	@cargo clean
	@cd $(USER_DIR) && cargo clean
	@rm -f $(APP_DIR)/*.bin $(APP_DIR)/*.elf
	@rm -f $(ROOT_DIR)/ext4-fs-packer/target/fs-riscv64.ext4
	@rm -f $(ROOT_DIR)/ext4-fs-packer/target/fs-loongarch64.ext4

help:
	@echo "make elf  ARCH=riscv64|loongarch64 BOARD=qemu|visionfive2"
	@echo "BOARD=visionfive2 会启用 Cargo feature riscv-board"
	@echo "make disk ARCH=riscv64|loongarch64"
	@echo "make run  ARCH=riscv64|loongarch64 FINAL_TEST=0|1"
	@echo "make debug ARCH=riscv64|loongarch64"
	@echo "make gdb   ARCH=riscv64|loongarch64"
	@echo "make tftp-root ARCH=riscv64"
	@echo "  构建 VisionFive 2 内核，并生成 os.bin 与 vf2_booti.img"
	@echo "make tftp-server ARCH=riscv64"
	@echo "  构建 VisionFive 2 内核后，在 UDP/69 前台启动 TFTP 服务"
	@echo "FINAL_TEST=1：先运行 CAgent，再运行 BuildStorm"


# 生成 VisionFive 2 可启动文件。内核原始二进制必须放在 0x80200000，
# 跳板由 booti 迁移到安全地址后再跳回该内核入口。
# 用法：make vf2-image ARCH=riscv64 BOARD=visionfive2。
vf2-image: elf
	@if [ "$(ARCH)" != "riscv64" ] || [ "$(BOARD)" != "visionfive2" ]; then \
		echo "vf2-image 仅支持 ARCH=riscv64 BOARD=visionfive2"; exit 2; \
	fi
	@$(OBJCOPY) -O binary --strip-all $(KERNEL_ELF) $(KERNEL_BIN)
	@$(VF2_AS) -march=rv64gc -mabi=lp64d -o $(VF2_BOOTI_OBJECT) $(VF2_BOOTI_SOURCE)
	@$(OBJCOPY) -O binary --strip-all $(VF2_BOOTI_OBJECT) $(VF2_BOOTI_IMAGE)
	@echo "板端内核：$(KERNEL_BIN)（$$(stat -c%s $(KERNEL_BIN)) 字节，U-Boot 文件名：$(TFTP_KERNEL_FILE)）"
	@echo "启动跳板：$(VF2_BOOTI_IMAGE)（$$(stat -c%s $(VF2_BOOTI_IMAGE)) 字节，U-Boot 文件名：$(TFTP_BOOT_FILE)）"

# 将两个可启动文件放在 Cargo 编译产物目录中，作为 TFTP 根目录。
# 用法：make tftp-root ARCH=riscv64；用于只构建和核对下载文件。
tftp-root:
	@$(MAKE) --no-print-directory vf2-image ARCH=$(ARCH) BOARD=visionfive2 MODE=$(MODE)
	@test -f $(KERNEL_BIN) -a -f $(VF2_BOOTI_IMAGE)
	@echo "TFTP 根目录：$(TFTP_ROOT)"
	@echo "U-Boot 下载：tftpboot 0x80200000 $(TFTP_KERNEL_FILE)"
	@echo "U-Boot 下载：tftpboot 0xc0000000 $(TFTP_BOOT_FILE)"

# 在前台运行 TFTP 服务；69 端口通常需要 root 权限。
# 用法：make tftp-server ARCH=riscv64；保持命令运行，不要另起旧服务。
tftp-server: tftp-root
	@command -v in.tftpd >/dev/null || { echo "缺少 in.tftpd，请安装 tftpd-hpa"; exit 127; }
	@echo "TFTP 根目录：$(TFTP_ROOT)，监听 $(TFTP_BIND):$(TFTP_PORT)，按 Ctrl-C 停止"
	in.tftpd --foreground --listen --secure --address $(TFTP_BIND):$(TFTP_PORT) $(TFTP_ROOT)
