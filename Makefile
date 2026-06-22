# ======================================================================
# CongCore kernel Makefile
# ----------------------------------------------------------------------
# Builds the kernel in os/ together with the user-space apps in user/
# for two architectures (riscv64 / loongarch64) and launches them in
# QEMU, optionally attaching a packed ext4 root filesystem image.
#
# Common entry points:
#   make run_ext4    build kernel + ext4 image, run in QEMU (default)
#   make debug       start QEMU halted, waiting for GDB on :1234
#   make client_gdb  attach the bundled GDB client to `make debug`
#   make clean       wipe kernel, user apps and cached artefacts
#
# Overridable variables (VAR=value on the command line):
#   ARCH           riscv64 | loongarch64            [riscv64]
#   MODE           release | debug                  [release]
#   SMP            number of harts                  [4]
#   MEM            -m string                        [1G]
#   SUBMIT         0|1, pass `--features submit`    [0]
#   EXT4_REBUILD   0|1, force rebuild of fs.ext4    [0]
#   EXT4_SIZE      packer size (e.g. 1G, 4G)        [1G]
#   DISK_IMG       extra "test-card" image path     [sdcard-<arch>.img]
#   QEMU_TIMEOUT   seconds, 0 disables `timeout`    [0]
# ======================================================================

# ----------------------------------------------------------------------
# Workspace layout
# ----------------------------------------------------------------------
MAKEFILE_DIR     := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
ROOT_DIR         := $(abspath $(MAKEFILE_DIR)/..)
OS_DIR           := $(ROOT_DIR)/os
USER_DIR         := $(ROOT_DIR)/user
CARGO_TARGET_DIR := $(ROOT_DIR)/target

# ----------------------------------------------------------------------
# Arch-specific configuration
# ----------------------------------------------------------------------
ARCH ?= riscv64

ifeq ($(ARCH),riscv64)
    TARGET           := riscv64gc-unknown-none-elf
    QEMU_BIN         := qemu-system-riscv64
    QEMU_BLK_DEV0    := virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0
    QEMU_BLK_DEV1    := virtio-blk-device,drive=x1,bus=virtio-mmio-bus.1
    QEMU_NET_DEV     := virtio-net-device,netdev=net
    QEMU_BIOS_ARGS   := -bios default
    GDB_ARCH         := riscv:rv64
    CARGO_CONFIG     := $(ROOT_DIR)/cargo-config/config.toml
    DISK_IMG         ?= ../sdcard-rv.img
    EXT4_BASE_IMG    ?= ../img/disk.img
    EXT4_BASE_TAR    ?= ../img/disk.tar
    EXT4_BASE_TAR_XZ ?= ../img/disk.tar.xz
else ifeq ($(ARCH),loongarch64)
    TARGET           := loongarch64-unknown-none
    QEMU_BIN         := qemu-system-loongarch64
    QEMU_BLK_DEV0    := virtio-blk-pci,drive=x0
    QEMU_BLK_DEV1    := virtio-blk-pci,drive=x1
    QEMU_NET_DEV     := virtio-net-pci,netdev=net
    QEMU_BIOS_ARGS   :=
    GDB_ARCH         := loongarch
    CARGO_CONFIG     := $(ROOT_DIR)/cargo-config/config_loongarch64.toml
    DISK_IMG         ?= ../sdcard-la.img
    EXT4_BASE_IMG    ?= ../img/disk-la.img
    EXT4_BASE_TAR    ?= ../img/disk-la.tar
    EXT4_BASE_TAR_XZ ?= ../img/disk-la.tar.xz
else
    $(error Unsupported ARCH=$(ARCH); use riscv64 or loongarch64)
endif

# ----------------------------------------------------------------------
# Build-level configuration
# ----------------------------------------------------------------------
MODE         ?= release
CARGO_MODE_FLAG := $(if $(filter release,$(MODE)),--release,)
SMP          ?= 4
MEM          ?= 1G
QEMU_TIMEOUT ?= 0
SUBMIT       ?= 0
EXT4_REBUILD ?= 0
EXT4_SIZE    ?= 1G

# Native host triple for tools that must run on the build machine
# (currently just ext4-fs-packer). Resolved once at Make parse time so we
# don't fork rustc on every recipe line. Needed because the repo-root
# `.cargo/config.toml` (untracked, used by nvim's rust-analyzer) sets a
# riscv64 bare-metal `[build] target`, which would otherwise leak into
# packer's `cargo run` and break the host build / leave a stale image.
# Override on the command line if cross-building from an unusual host.
HOST_TRIPLE  ?= $(shell rustc -vV | sed -n 's/^host: //p')

# Forward `--features submit` to user apps when SUBMIT=1.
USER_FEATURES := $(if $(filter 1,$(SUBMIT)),--features submit,)

# ----------------------------------------------------------------------
# Derived paths
# ----------------------------------------------------------------------
KERNEL_ELF      := $(CARGO_TARGET_DIR)/$(TARGET)/$(MODE)/os
KERNEL_BIN      := kernel_$(MODE).bin
KERNEL_DBG_ELF  := kernel_$(MODE).elf
USER_TARGET_DIR := $(USER_DIR)/target/$(TARGET)/$(MODE)
APP_DIR         := ./results
EXT4_IMG        := ../ext4-fs-packer/target/fs.ext4

# Only pass -b <base> to the packer when a base image path is configured.
# `ext4_base_img` will lazily extract it from a tarball if needed.
ifneq ($(strip $(EXT4_BASE_IMG)),)
    EXT4_BASE_ARG := -b $(abspath $(EXT4_BASE_IMG))
    EXT4_BASE_DEP := ext4_base_img
else
    EXT4_BASE_ARG :=
    EXT4_BASE_DEP :=
endif

# ----------------------------------------------------------------------
# QEMU command-line fragments
# ----------------------------------------------------------------------
QEMU_BASE_ARGS  := -machine virt -kernel $(KERNEL_ELF) -m $(MEM) -smp $(SMP) \
                   -nographic -rtc base=utc -no-reboot
QEMU_DISK0_ARGS := -drive file=$(EXT4_IMG),if=none,format=raw,id=x0 \
                   -device $(QEMU_BLK_DEV0)
QEMU_NET_ARGS   := -device $(QEMU_NET_DEV) -netdev user,id=net

# Attach the optional "test-card" disk only if the file exists, so that
# running without the image still works.
ifneq (,$(wildcard $(DISK_IMG)))
    QEMU_DISK1_ARGS := -drive file=$(DISK_IMG),if=none,format=raw,id=x1 \
                       -device $(QEMU_BLK_DEV1)
else
    QEMU_DISK1_ARGS :=
endif

# Optionally wrap QEMU with `timeout` for CI runs.
ifeq ($(QEMU_TIMEOUT),0)
    QEMU_RUN := $(QEMU_BIN)
else
    QEMU_RUN := timeout $(QEMU_TIMEOUT) $(QEMU_BIN)
endif

# ----------------------------------------------------------------------
# Phony target bookkeeping
# ----------------------------------------------------------------------
.PHONY: all run run_ext4 debug debug_ext4 client_gdb clean help \
        prepare-cargo kernel user_apps ext4_img ext4_base_img \
        KERNEL USER_APPS

.DEFAULT_GOAL := run_ext4

# ======================================================================
# Build steps
# ======================================================================

# Copy the shared cargo config into both os/ and user/ so cross-builds
# always pick up the correct linker script and target triple.
prepare-cargo:
	@mkdir -p .cargo $(USER_DIR)/.cargo
	@cp $(CARGO_CONFIG) .cargo/config.toml
	@cp $(CARGO_CONFIG) $(USER_DIR)/.cargo/config.toml

# Build the kernel ELF and (best-effort) a stripped raw binary copy.
# `rust-objcopy` is optional: QEMU boots the ELF directly when the raw
# binary cannot be produced.
kernel: prepare-cargo user_apps
	@cargo build $(CARGO_MODE_FLAG) --target $(TARGET)
	@OBJCOPY=$$(command -v rust-objcopy || command -v llvm-objcopy || true); \
	if [ -n "$$OBJCOPY" ]; then \
		$$OBJCOPY --strip-all $(KERNEL_ELF) -O binary $(KERNEL_BIN); \
		echo "Build $(KERNEL_BIN) successfully."; \
	else \
		echo "⚠️  No objcopy found; skip $(KERNEL_BIN) (QEMU uses ELF)."; \
	fi
	@cp $(KERNEL_ELF) $(KERNEL_DBG_ELF)

# Build user apps and mirror each executable into ./results/*.bin so
# that the ext4 packer (and build.rs) can discover them. `cmp -s` keeps
# the log quiet when a binary has not actually changed.
user_apps: prepare-cargo
	@cd $(USER_DIR) && CARGO_TARGET_DIR=target \
	    cargo build $(CARGO_MODE_FLAG) $(USER_FEATURES) --target $(TARGET)
	@mkdir -p $(APP_DIR)
	@for f in $(USER_TARGET_DIR)/*; do \
		[ -f "$$f" ] && [ -x "$$f" ] || continue; \
		base=$$(basename $$f); \
		dst=$(APP_DIR)/$$base.bin; \
		if [ ! -f "$$dst" ] || ! cmp -s "$$f" "$$dst"; then \
			cp "$$f" "$$dst"; \
			echo "find user app (updated): $$base"; \
		else \
			echo "find user app (cached): $$base"; \
		fi; \
	done
	@echo "Build user apps successfully."

# Backward-compat aliases for the old upper-case target names.
KERNEL:    kernel
USER_APPS: user_apps

# ======================================================================
# Ext4 filesystem image
# ======================================================================

# Rebuild the ext4 image when any of the following holds:
#   1. the image itself is missing
#   2. any user-app binary is newer than the image
#   3. any file under ext4-fs-packer/extra or extra-$(ARCH) is newer than the image
#   4. the base image is newer than the packed image
#   5. the caller forces it with EXT4_REBUILD=1
ext4_img: user_apps $(EXT4_BASE_DEP)
	@needs=0; \
	[ -f "$(EXT4_IMG)" ] || needs=1; \
	if [ $$needs -eq 0 ] && find "$(APP_DIR)" -type f -newer "$(EXT4_IMG)" \
	    2>/dev/null | head -n1 | grep -q .; then needs=1; fi; \
	if [ $$needs -eq 0 ]; then \
		for dir in ../ext4-fs-packer/extra ../ext4-fs-packer/extra-$(ARCH); do \
			[ -d "$$dir" ] || continue; \
			if find "$$dir" -type f -newer "$(EXT4_IMG)" \
			    2>/dev/null | head -n1 | grep -q .; then needs=1; break; fi; \
		done; \
	fi; \
	if [ $$needs -eq 0 ] && [ -n "$(EXT4_BASE_IMG)" ] && [ -f "$(EXT4_BASE_IMG)" ] \
	    && [ "$(EXT4_BASE_IMG)" -nt "$(EXT4_IMG)" ]; then needs=1; fi; \
	[ "$(EXT4_REBUILD)" = "1" ] && needs=1; \
	if [ $$needs -eq 0 ]; then \
		echo "✅ Reusing existing ext4 image: $(EXT4_IMG)"; \
	else \
		echo "🔧 Building ext4 filesystem image..."; \
		cd ../ext4-fs-packer && CARGO_BUILD_TARGET=$(HOST_TRIPLE) cargo run --release -- \
			-u ../os/$(APP_DIR) -e extra --arch-extra extra-$(ARCH) $(EXT4_BASE_ARG) \
			-t target -S $(EXT4_SIZE); \
		echo "✅ Ext4 image created: $(EXT4_IMG)"; \
	fi

# Ensure the ext4 "base" image exists, extracting it from a shipped
# tarball when only the archive is available.
ext4_base_img:
	@if [ ! -f "$(EXT4_BASE_IMG)" ]; then \
		if [ -f "$(EXT4_BASE_TAR)" ]; then \
			echo "📦 Extracting base image from $(EXT4_BASE_TAR)..."; \
			tar -xf "$(EXT4_BASE_TAR)" -C "$(dir $(EXT4_BASE_IMG))"; \
		elif [ -f "$(EXT4_BASE_TAR_XZ)" ]; then \
			echo "📦 Extracting base image from $(EXT4_BASE_TAR_XZ)..."; \
			tar -xf "$(EXT4_BASE_TAR_XZ)" -C "$(dir $(EXT4_BASE_IMG))"; \
		else \
			echo "❌ Base image not found: $(EXT4_BASE_IMG)"; \
			exit 1; \
		fi; \
	fi

# ======================================================================
# Run / debug
# ======================================================================

# Boot the kernel in QEMU with the packed ext4 disk attached.
# `run` is kept as a legacy alias of `run_ext4`.
# Inside QEMU press CTRL-A X to quit.
run run_ext4: kernel ext4_img
	@echo "🔍 Running QEMU with VirtIO block device..."
	@echo "   ➜ File System Image: $(EXT4_IMG)"
	$(QEMU_RUN) $(QEMU_BASE_ARGS) $(QEMU_BIOS_ARGS) \
	    $(QEMU_DISK0_ARGS) $(QEMU_NET_ARGS) $(QEMU_DISK1_ARGS)

# QEMU halts at reset and listens for a GDB client on :1234. The
# `timeout` wrapper is intentionally not applied here so GDB sessions
# are not killed mid-debug.
debug debug_ext4: kernel ext4_img
	@echo "🐛 Starting QEMU in debug mode (gdb target: localhost:1234)..."
	@$(QEMU_BIN) $(QEMU_BASE_ARGS) $(QEMU_BIOS_ARGS) $(QEMU_DISK0_ARGS) -s -S

# Companion to `debug` / `debug_ext4`: attach the bundled GDB client.
client_gdb:
	@./elf-gdb \
		-ex 'file $(KERNEL_ELF)' \
		-ex 'set arch $(GDB_ARCH)' \
		-ex 'target remote localhost:1234' \
		-ex 'display/10i $$pc'

# ======================================================================
# Housekeeping
# ======================================================================
clean:
	@cargo clean
	@cd $(USER_DIR) && cargo clean
	@rm -f $(APP_DIR)/*.bin $(APP_DIR)/*.elf
	@rm -f *.bin *.elf

help:
	@echo "CongCore kernel Makefile – common targets:"
	@echo "  make run_ext4    build + run kernel in QEMU with ext4 disk (default)"
	@echo "  make debug       start QEMU halted, waiting for GDB on :1234"
	@echo "  make client_gdb  connect the bundled GDB client to a running debug"
	@echo "  make clean       wipe kernel, user apps and cached artefacts"
	@echo "  make help        show this message"
	@echo "See the comment header of this Makefile for overridable variables."
