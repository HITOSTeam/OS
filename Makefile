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

# 这些是死的路径，我们不需要外界传入，所以使用:=赋值
MAKEFILE_DIR     := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
ROOT_DIR         := $(abspath $(MAKEFILE_DIR)/..)
USER_DIR         := $(ROOT_DIR)/user
CARGO_TARGET_DIR := $(ROOT_DIR)/target

# 这个可以被外界赋值的变量，所以使用?修饰等于号
ARCH          ?= riscv64
MODE          ?= release
FINAL_TEST    ?= 0
SMP           ?= 12
# 国赛测试使用4G 然后初赛的测试使用1G 当然也可以自己指定
MEM           ?= $(if $(filter 1,$(FINAL_TEST)),4G,1G)
DISK_SIZE     ?= 1G
QEMU_TIMEOUT  ?= 0
QEMU_EXTRA_ARGS ?=

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

GDB_BIN          ?= $(GDB_DEFAULT)
CARGO_MODE_FLAG := $(if $(filter release,$(MODE)),--release,)
HOST_TRIPLE      ?= $(shell rustc -vV | sed -n 's/^host: //p')
KERNEL_ELF       := $(CARGO_TARGET_DIR)/$(TARGET)/$(MODE)/os
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
        debug gdb client_gdb clean help prepare-cargo

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
	@cargo build $(CARGO_MODE_FLAG) --target $(TARGET)
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
	@echo "make elf  ARCH=riscv64|loongarch64"
	@echo "make disk ARCH=riscv64|loongarch64"
	@echo "make run  ARCH=riscv64|loongarch64 FINAL_TEST=0|1"
	@echo "make debug ARCH=riscv64|loongarch64"
	@echo "make gdb   ARCH=riscv64|loongarch64"
	@echo "FINAL_TEST=1：先运行 CAgent，再运行 BuildStorm"
