# ======================================================================
# CongCore kernel Makefile
# ----------------------------------------------------------------------
# Builds the kernel and independent system/user ext4 images, then launches
# one of the supported disk layouts in QEMU.
#
# Common entry points:
#   make run_ext4    preliminary layout: system + user + optional test disk
#   make run_final   final layout: official final root + user disk
#   make debug       start QEMU halted, waiting for GDB on :1234
#   make client_gdb  attach the bundled GDB client to `make debug`
#   make board_smoke  build a RAM-only LS2K1000LA UART bring-up ELF
#   make board_kernel build the full RAM-only LS2K1000LA kernel ELF
#   make clean       wipe kernel, user apps and cached artefacts
#
# Overridable variables (VAR=value on the command line):
#   ARCH           riscv64 | loongarch64            [riscv64]
#   MODE           release | debug                  [release]
#   SMP            number of harts                  [4]
#   MEM            -m string                        [1G]
#   SUBMIT         0|1, pass `--features submit`    [0]
#   EXT4_REBUILD   0|1, force rebuild of generated images [0]
#   EXT4_SIZE      system image size (e.g. 1G, 4G)  [1G]
#   USER_EXT4_SIZE standalone /user image size      [256M]
#   DISK_IMG       preliminary test-card image      [sdcard-<arch>.img]
#   FINAL_IMG      official final root image        [required by run_final]
#   BASH_SHELL     0|1, start real /bin/bash         [0]
#   QEMU_TIMEOUT   seconds, 0 disables `timeout`    [0]
#   QEMU_EXTRA_ARGS extra QEMU flags (e.g. -snapshot) [empty]
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
    QEMU_BLK_DEV2    := virtio-blk-device,drive=x2,bus=virtio-mmio-bus.2
    QEMU_NET_DEV     := virtio-net-device,netdev=net
    QEMU_BIOS_ARGS   := -bios default
    GDB_ARCH         := riscv:rv64
    CARGO_CONFIG     := $(ROOT_DIR)/cargo-config/config.toml
    DISK_IMG         ?= ../sdcard-rv.img
    EXT4_BASE_IMG    ?= ../img/disk.img
    EXT4_BASE_TAR    ?= ../img/disk.tar
    EXT4_BASE_TAR_XZ ?= ../img/disk.tar.xz
else ifeq ($(ARCH),loongarch64)
    TARGET           := loongarch64-unknown-none-softfloat
    QEMU_BIN         := qemu-system-loongarch64
    QEMU_BLK_DEV0    := virtio-blk-pci,drive=x0
    QEMU_BLK_DEV1    := virtio-blk-pci,drive=x1
    QEMU_BLK_DEV2    := virtio-blk-pci,drive=x2
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
QEMU_EXTRA_ARGS ?=
SUBMIT       ?= 0
BASH_SHELL   ?= 0
EXT4_REBUILD ?= 0
EXT4_SIZE    ?= 1G
USER_EXT4_SIZE ?= 256M
FINAL_IMG    ?=

# Native host triple for tools that must run on the build machine
# (currently just ext4-fs-packer). Resolved once at Make parse time so we
# don't fork rustc on every recipe line. Needed because the repo-root
# `.cargo/config.toml` (untracked, used by nvim's rust-analyzer) sets a
# riscv64 bare-metal `[build] target`, which would otherwise leak into
# packer's `cargo run` and break the host build / leave a stale image.
# Override on the command line if cross-building from an unusual host.
HOST_TRIPLE  ?= $(shell rustc -vV | sed -n 's/^host: //p')

empty :=
space := $(empty) $(empty)
comma := ,

# Forward selected features to user apps.
USER_FEATURE_LIST := $(strip \
    $(if $(filter 1,$(SUBMIT)),submit) \
    $(if $(filter 1,$(BASH_SHELL)),bash-shell))
USER_FEATURES := $(if $(USER_FEATURE_LIST),--features "$(subst $(space),$(comma),$(USER_FEATURE_LIST))",)

# ----------------------------------------------------------------------
# Derived paths
# ----------------------------------------------------------------------
KERNEL_ELF      := $(CARGO_TARGET_DIR)/$(TARGET)/$(MODE)/os
KERNEL_BIN      := kernel_$(MODE).bin
KERNEL_DBG_ELF  := kernel_$(MODE).elf
USER_TARGET_DIR := $(USER_DIR)/target/$(TARGET)/$(MODE)
APP_DIR         := ./results
PACKER_DIR      := $(ROOT_DIR)/ext4-fs-packer
SYSTEM_IMG      ?= $(PACKER_DIR)/target/system.ext4
USER_IMG        ?= $(PACKER_DIR)/target/user.ext4

# The LS2K1000LA smoke payload has its own Cargo target directory so enabling
# board-only code cannot perturb normal QEMU build artefacts.
BOARD_SMOKE_TARGET_DIR  := $(ROOT_DIR)/target/ls2k1000la-smoke
BOARD_SMOKE_BUILD_ELF   := $(BOARD_SMOKE_TARGET_DIR)/$(TARGET)/release/os
BOARD_SMOKE_ARTIFACT_DIR := $(BOARD_SMOKE_TARGET_DIR)/artifacts
BOARD_SMOKE_ELF         := $(BOARD_SMOKE_ARTIFACT_DIR)/congcore-2k1000la-smoke.elf
BOARD_KERNEL_TARGET_DIR := $(ROOT_DIR)/target/ls2k1000la-kernel
BOARD_KERNEL_BUILD_ELF  := $(BOARD_KERNEL_TARGET_DIR)/$(TARGET)/release/os
BOARD_KERNEL_ARTIFACT_DIR := $(BOARD_KERNEL_TARGET_DIR)/artifacts
BOARD_KERNEL_ELF        := $(BOARD_KERNEL_ARTIFACT_DIR)/congcore-2k1000la-kernel.elf
BOARD_KERNEL_UIMAGE     := $(BOARD_KERNEL_ELF).uimg
BOARD_RAM_IMAGE_SIZE    ?= 8M
BOARD_RAM_IMAGE_DIR     := $(BOARD_KERNEL_ARTIFACT_DIR)
BOARD_MIN_USER_DIR      := $(BOARD_KERNEL_TARGET_DIR)/minimal-user
BOARD_MIN_USER_BINS     := init_proc 00shell ls cat ps
BOARD_SYSTEM_IMG        := $(BOARD_RAM_IMAGE_DIR)/congcore-2k1000la-system.ext4
BOARD_USER_IMG          := $(BOARD_RAM_IMAGE_DIR)/congcore-2k1000la-user.ext4
BOARD_SYSTEM_UIMAGE     := $(BOARD_SYSTEM_IMG).uimg
BOARD_USER_UIMAGE       := $(BOARD_USER_IMG).uimg
BOARD_UIMAGE_TOOL       := $(ROOT_DIR)/tools/mk_legacy_uimage.py
# LA264 does not provide the transparent unaligned-access behavior assumed by
# Rust's generic LoongArch bare-metal target. Keep these flags board-local so
# QEMU builds retain their existing feature policy, and apply the same ABI/code
# generation constraints to the kernel and every userspace binary in the RAM
# bundle.
BOARD_RUSTFLAGS         := -Cforce-frame-pointers=yes -Ctarget-feature=-ual,-lsx,-lasx,-lvz
# The distributed LoongArch bare-metal `core` is built with `+ual`. Rebuild the
# board sysroot crates under BOARD_RUSTFLAGS as well; otherwise routines such as
# core::fmt can still issue unaligned word loads before the kernel trap handler
# exists, even though CongCore itself was compiled with `-ual`.
BOARD_BUILD_STD         := -Z build-std=core,alloc,compiler_builtins
LLVM_STRIP              ?= llvm-strip

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
QEMU_NET_ARGS   := -device $(QEMU_NET_DEV) -netdev user,id=net
QEMU_SYSTEM_ARGS := -drive file=$(SYSTEM_IMG),if=none,format=raw,id=x0 \
                    -device $(QEMU_BLK_DEV0)
QEMU_USER_AS_SECOND_ARGS := -drive file=$(USER_IMG),if=none,format=raw,id=x1 \
                            -device $(QEMU_BLK_DEV1)

# Attach the optional "test-card" disk only if the file exists, so that
# running without the image still works.
ifneq (,$(wildcard $(DISK_IMG)))
    QEMU_TEST_ARGS := -drive file=$(DISK_IMG),if=none,format=raw,id=x2 \
                      -device $(QEMU_BLK_DEV2)
else
    QEMU_TEST_ARGS :=
endif

ifneq (,$(wildcard $(FINAL_IMG)))
    QEMU_FINAL_ARGS := -drive file=$(FINAL_IMG),if=none,format=raw,id=x0 \
                       -device $(QEMU_BLK_DEV0)
else
    QEMU_FINAL_ARGS :=
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
.PHONY: all run run_ext4 run_preliminary run_final debug debug_ext4 \
        debug_final client_gdb clean help prepare-cargo kernel user_apps \
        ext4_img system_img user_img ext4_base_img check_final_img \
        board_smoke board_kernel board_ram_images board_bundle KERNEL USER_APPS

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

# Minimal, non-persistent LS2K1000LA bring-up payload.  It does not build or
# embed userspace and is intended for U-Boot `loady` + `bootelf -p` + `go`.
board_smoke:
	@if [ "$(ARCH)" != "loongarch64" ]; then \
		echo "❌ board_smoke requires ARCH=loongarch64"; \
		exit 2; \
	fi
	@mkdir -p "$(ROOT_DIR)/.tmp" "$(BOARD_SMOKE_ARTIFACT_DIR)"
	@RUSTFLAGS="$(BOARD_RUSTFLAGS)" TMPDIR="$(ROOT_DIR)/.tmp" \
		CARGO_TARGET_DIR="$(BOARD_SMOKE_TARGET_DIR)" \
		cargo build $(BOARD_BUILD_STD) --release --bin os --target "$(TARGET)" \
		--features loongarch_board_smoke
	@$(LLVM_STRIP) --strip-all -o "$(BOARD_SMOKE_ELF)" "$(BOARD_SMOKE_BUILD_ELF)"
	@echo "✅ LS2K1000LA smoke ELF: $(BOARD_SMOKE_ELF)"
	@sha256sum "$(BOARD_SMOKE_ELF)"

# Full single-core LS2K1000LA kernel. PT_LOAD physical addresses use U-Boot's
# cached DMW alias while ELF virtual addresses remain low physical addresses.
board_kernel:
	@if [ "$(ARCH)" != "loongarch64" ]; then \
		echo "❌ board_kernel requires ARCH=loongarch64"; \
		exit 2; \
	fi
	@mkdir -p "$(ROOT_DIR)/.tmp" "$(BOARD_KERNEL_ARTIFACT_DIR)"
	@RUSTFLAGS="$(BOARD_RUSTFLAGS)" TMPDIR="$(ROOT_DIR)/.tmp" \
		CARGO_TARGET_DIR="$(BOARD_KERNEL_TARGET_DIR)" \
		cargo build $(BOARD_BUILD_STD) --release --bin os --target "$(TARGET)" \
		--features loongarch_board
	@$(LLVM_STRIP) --strip-all -o "$(BOARD_KERNEL_ELF)" "$(BOARD_KERNEL_BUILD_ELF)"
	@gzip -k -f -n -9 "$(BOARD_KERNEL_ELF)"
	@python3 "$(BOARD_UIMAGE_TOOL)" --input "$(BOARD_KERNEL_ELF).gz" \
		--output "$(BOARD_KERNEL_UIMAGE)" --load 0x98400000 --name CongCore-kernel-ELF
	@echo "✅ LS2K1000LA kernel ELF: $(BOARD_KERNEL_ELF)"
	@ls -lh "$(BOARD_KERNEL_ELF)" "$(BOARD_KERNEL_ELF).gz" "$(BOARD_KERNEL_UIMAGE)"
	@sha256sum "$(BOARD_KERNEL_ELF)" "$(BOARD_KERNEL_ELF).gz" "$(BOARD_KERNEL_UIMAGE)"

# Two compact writable ext4 images loaded into reserved low RAM. The system
# image contains only the common minimal root overlay; /user contains init,
# the interactive shell, and the first manual-inspection utilities. The
# deterministic legacy-image wrappers let U-Boot's `bootm start` + `bootm
# loados` decompress them even when the board firmware omits `unzip`.
board_ram_images:
	@if [ "$(ARCH)" != "loongarch64" ]; then \
		echo "❌ board_ram_images requires ARCH=loongarch64"; \
		exit 2; \
	fi
	@# Pass the target and board flags explicitly. Do not run prepare-cargo here:
	@# board bundles must not overwrite a developer's user/.cargo/config.toml.
	@cd "$(USER_DIR)" && RUSTFLAGS="$(BOARD_RUSTFLAGS)" CARGO_TARGET_DIR=target \
		cargo build $(BOARD_BUILD_STD) --release --target "$(TARGET)" \
		$(foreach bin,$(BOARD_MIN_USER_BINS),--bin $(bin))
	@rm -rf "$(BOARD_MIN_USER_DIR)"
	@mkdir -p "$(BOARD_MIN_USER_DIR)" "$(BOARD_RAM_IMAGE_DIR)"
	@for bin in $(BOARD_MIN_USER_BINS); do \
		cp "$(USER_TARGET_DIR)/$$bin" "$(BOARD_MIN_USER_DIR)/$$bin.bin"; \
	done
	@cd "$(PACKER_DIR)" && CARGO_BUILD_TARGET=$(HOST_TRIPLE) cargo run --release -- \
		--kind system -e extra -t "$(BOARD_RAM_IMAGE_DIR)" \
		-o "$(notdir $(BOARD_SYSTEM_IMG))" -L congcore-board-root -S "$(BOARD_RAM_IMAGE_SIZE)"
	@cd "$(PACKER_DIR)" && CARGO_BUILD_TARGET=$(HOST_TRIPLE) cargo run --release -- \
		--kind user -u "$(BOARD_MIN_USER_DIR)" -t "$(BOARD_RAM_IMAGE_DIR)" \
		-o "$(notdir $(BOARD_USER_IMG))" -L congcore-board-user -S "$(BOARD_RAM_IMAGE_SIZE)"
	@e2fsck -f -n "$(BOARD_SYSTEM_IMG)"
	@e2fsck -f -n "$(BOARD_USER_IMG)"
	@gzip -k -f -n -9 "$(BOARD_SYSTEM_IMG)"
	@gzip -k -f -n -9 "$(BOARD_USER_IMG)"
	@python3 "$(BOARD_UIMAGE_TOOL)" --input "$(BOARD_SYSTEM_IMG).gz" \
		--output "$(BOARD_SYSTEM_UIMAGE)" --load 0x0a000000 --name CongCore-system
	@python3 "$(BOARD_UIMAGE_TOOL)" --input "$(BOARD_USER_IMG).gz" \
		--output "$(BOARD_USER_UIMAGE)" --load 0x0a800000 --name CongCore-user
	@echo "✅ LS2K1000LA RAM filesystems:"
	@ls -lh "$(BOARD_SYSTEM_IMG)" "$(BOARD_SYSTEM_IMG).gz" \
		"$(BOARD_SYSTEM_UIMAGE)" "$(BOARD_USER_IMG)" \
		"$(BOARD_USER_IMG).gz" "$(BOARD_USER_UIMAGE)"
	@sha256sum "$(BOARD_SYSTEM_IMG)" "$(BOARD_SYSTEM_IMG).gz" \
		"$(BOARD_SYSTEM_UIMAGE)" "$(BOARD_USER_IMG)" \
		"$(BOARD_USER_IMG).gz" "$(BOARD_USER_UIMAGE)"

board_bundle: board_kernel board_ram_images
	@echo "✅ LS2K1000LA RAM-only bundle is ready in $(BOARD_KERNEL_ARTIFACT_DIR)"

# ======================================================================
# Ext4 filesystem images
# ======================================================================

# Legacy aggregate target: build both independent images.
ext4_img: system_img user_img

# The system image contains the base root and overlays, but no /user binaries.
system_img: $(EXT4_BASE_DEP)
	@set -e; \
	needs=0; \
	[ -f "$(SYSTEM_IMG)" ] || needs=1; \
	if [ $$needs -eq 0 ] && { [ "$(PACKER_DIR)/src/main.rs" -nt "$(SYSTEM_IMG)" ] \
	    || [ "$(PACKER_DIR)/Cargo.toml" -nt "$(SYSTEM_IMG)" ]; }; then needs=1; fi; \
	if [ $$needs -eq 0 ]; then \
		for dir in "$(PACKER_DIR)/extra" "$(PACKER_DIR)/extra-$(ARCH)"; do \
			[ -d "$$dir" ] || continue; \
			if find "$$dir" -type f -newer "$(SYSTEM_IMG)" \
			    2>/dev/null | head -n1 | grep -q .; then needs=1; break; fi; \
		done; \
	fi; \
	if [ $$needs -eq 0 ] && [ -n "$(EXT4_BASE_IMG)" ] && [ -f "$(EXT4_BASE_IMG)" ] \
	    && [ "$(EXT4_BASE_IMG)" -nt "$(SYSTEM_IMG)" ]; then needs=1; fi; \
	[ "$(EXT4_REBUILD)" = "1" ] && needs=1; \
	if [ $$needs -eq 0 ]; then \
		echo "✅ Reusing system image: $(SYSTEM_IMG)"; \
	else \
		echo "🔧 Building system ext4 image..."; \
		cd "$(PACKER_DIR)" && CARGO_BUILD_TARGET=$(HOST_TRIPLE) cargo run --release -- \
			--kind system -e extra --arch-extra extra-$(ARCH) $(EXT4_BASE_ARG) \
			-t target -o system.ext4 -L congcore-system -S $(EXT4_SIZE); \
		echo "✅ System image created: $(SYSTEM_IMG)"; \
	fi

# The user image contains app binaries at its filesystem root and is mounted
# at /user by the kernel.
user_img: user_apps
	@set -e; \
	needs=0; \
	[ -f "$(USER_IMG)" ] || needs=1; \
	if [ $$needs -eq 0 ] && { [ "$(PACKER_DIR)/src/main.rs" -nt "$(USER_IMG)" ] \
	    || [ "$(PACKER_DIR)/Cargo.toml" -nt "$(USER_IMG)" ]; }; then needs=1; fi; \
	if [ $$needs -eq 0 ] && find "$(APP_DIR)" -type f -newer "$(USER_IMG)" \
	    2>/dev/null | head -n1 | grep -q .; then needs=1; fi; \
	[ "$(EXT4_REBUILD)" = "1" ] && needs=1; \
	if [ $$needs -eq 0 ]; then \
		echo "✅ Reusing user image: $(USER_IMG)"; \
	else \
		echo "🔧 Building standalone /user ext4 image..."; \
		cd "$(PACKER_DIR)" && CARGO_BUILD_TARGET=$(HOST_TRIPLE) cargo run --release -- \
			--kind user -u "$(OS_DIR)/$(APP_DIR)" -t target -o user.ext4 \
			-L congcore-user -S $(USER_EXT4_SIZE); \
		echo "✅ User image created: $(USER_IMG)"; \
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

# Preliminary layout:
#   vda = generated system root
#   vdb = generated /user filesystem
#   vdc = optional OSComp preliminary test disk
# `run` and `run_ext4` remain compatibility aliases.
# Inside QEMU press CTRL-A X to quit.
run run_ext4 run_preliminary: kernel system_img user_img
	@echo "🔍 Running preliminary three-disk layout..."
	@echo "   ➜ /:      $(SYSTEM_IMG)"
	@echo "   ➜ /user:  $(USER_IMG)"
	@if [ -n "$(QEMU_TEST_ARGS)" ]; then echo "   ➜ tests:  $(DISK_IMG)"; fi
	$(QEMU_RUN) $(QEMU_BASE_ARGS) $(QEMU_BIOS_ARGS) \
	    $(QEMU_SYSTEM_ARGS) $(QEMU_USER_AS_SECOND_ARGS) $(QEMU_TEST_ARGS) \
	    $(QEMU_NET_ARGS) $(QEMU_EXTRA_ARGS)

check_final_img:
	@if [ -z "$(strip $(FINAL_IMG))" ]; then \
		echo "❌ FINAL_IMG is required by run_final"; \
		exit 2; \
	fi
	@if [ ! -f "$(FINAL_IMG)" ]; then \
		echo "❌ Final root image not found: $(FINAL_IMG)"; \
		exit 2; \
	fi

# Final layout:
#   vda = immutable/copy-on-write official final root
#   vdb = generated /user filesystem
run_final: check_final_img kernel user_img
	@echo "🔍 Running final two-disk layout..."
	@echo "   ➜ /:      $(FINAL_IMG)"
	@echo "   ➜ /user:  $(USER_IMG)"
	$(QEMU_RUN) $(QEMU_BASE_ARGS) $(QEMU_BIOS_ARGS) \
	    $(QEMU_FINAL_ARGS) $(QEMU_USER_AS_SECOND_ARGS) $(QEMU_NET_ARGS) \
	    $(QEMU_EXTRA_ARGS)

# QEMU halts at reset and listens for a GDB client on :1234. The
# `timeout` wrapper is intentionally not applied here so GDB sessions
# are not killed mid-debug.
debug debug_ext4: kernel ext4_img
	@echo "🐛 Starting QEMU in debug mode (gdb target: localhost:1234)..."
	@$(QEMU_BIN) $(QEMU_BASE_ARGS) $(QEMU_BIOS_ARGS) $(QEMU_SYSTEM_ARGS) \
	    $(QEMU_USER_AS_SECOND_ARGS) $(QEMU_TEST_ARGS) $(QEMU_EXTRA_ARGS) -s -S

debug_final: check_final_img kernel user_img
	@echo "🐛 Starting final-layout QEMU in debug mode (gdb target: localhost:1234)..."
	@$(QEMU_BIN) $(QEMU_BASE_ARGS) $(QEMU_BIOS_ARGS) $(QEMU_FINAL_ARGS) \
	    $(QEMU_USER_AS_SECOND_ARGS) $(QEMU_EXTRA_ARGS) -s -S

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
	@echo "  make run_ext4    preliminary: system + user + optional test disk"
	@echo "  make run_final   final: FINAL_IMG as root + standalone user disk"
	@echo "  make debug       start QEMU halted, waiting for GDB on :1234"
	@echo "  make client_gdb  connect the bundled GDB client to a running debug"
	@echo "  make board_smoke ARCH=loongarch64  build LS2K1000LA RAM smoke ELF"
	@echo "  make board_kernel ARCH=loongarch64 build full LS2K1000LA RAM kernel ELF"
	@echo "  make board_bundle ARCH=loongarch64 build kernel and two RAM ext4 images"
	@echo "  make clean       wipe kernel, user apps and cached artefacts"
	@echo "  make help        show this message"
	@echo "  QEMU_EXTRA_ARGS  append extra QEMU flags, such as -snapshot"
	@echo "See the comment header of this Makefile for overridable variables."
