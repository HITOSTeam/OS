# Building
ARCH ?= riscv64
ifeq ($(ARCH), riscv64)
TARGET := riscv64gc-unknown-none-elf
QEMU_BIN := qemu-system-riscv64
QEMU_BLK_DEV0 := virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0
QEMU_NET_DEV := virtio-net-device,netdev=net
DISK_DEV := virtio-blk-device,drive=x1,bus=virtio-mmio-bus.1
QEMU_BIOS_ARGS := -bios default
GDB_ARCH := riscv:rv64
CARGO_CONFIG := ../cargo-config/config.toml
else ifeq ($(ARCH), loongarch64)
TARGET := loongarch64-unknown-none
QEMU_BIN := qemu-system-loongarch64
QEMU_BLK_DEV0 := virtio-blk-pci,drive=x0
QEMU_NET_DEV := virtio-net-pci,netdev=net
DISK_DEV := virtio-blk-pci,drive=x1
QEMU_BIOS_ARGS :=
GDB_ARCH := loongarch
CARGO_CONFIG := ../cargo-config/config_loongarch64.toml
else
$(error "Unsupported architecture: $(ARCH), Use riscv64 or loongarch64")
endif
MODE := release
APP_DIR = ./results
KERNEL_ELF := target/$(TARGET)/$(MODE)/os
KERNEL_BIN := kernel_$(MODE).bin
DISASM_TMP := target/$(TARGET)/$(MODE)/asm
FS_IMG := ../user/target/$(TARGET)/$(MODE)/fs.img
KERNEL_ENTRY_PA = 0x80200000
SMP ?= 4
MEM ?= 512M
QEMU_TIMEOUT ?= 0
DISK_IMG ?= ../sdcard-rv.img
EXT4_REBUILD ?= 0
SUBMIT ?= 0
USER_FEATURES :=
ifeq ($(SUBMIT),1)
USER_FEATURES := --features submit
endif
# Optional OpenSBI fw_dynamic for HSM-enabled boot
FW_DYNAMIC ?=../firmware/fw_dynamic.bin
QEMU_BASE_ARGS := -machine virt -kernel $(KERNEL_ELF) -m $(MEM) -smp $(SMP) -nographic -rtc base=utc -no-reboot
QEMU_DISK0_ARGS := -drive file=$(EXT4_IMG),if=none,format=raw,id=x0 -device $(QEMU_BLK_DEV0)
QEMU_NET_ARGS := -device $(QEMU_NET_DEV) -netdev user,id=net

# Only append the extra virtio disk if the file exists
ifneq (,$(wildcard $(DISK_IMG)))
DISK_ARGS := -drive file=$(DISK_IMG),if=none,format=raw,id=x1 -device $(DISK_DEV)
else
DISK_ARGS :=
endif

ifeq ($(QEMU_TIMEOUT),0)
QEMU_RUN := $(QEMU_BIN)
else
QEMU_RUN := timeout $(QEMU_TIMEOUT) $(QEMU_BIN)
endif

prepare-cargo:
	@mkdir -p .cargo ../user/.cargo
	@cp $(CARGO_CONFIG) .cargo/config.toml
	@cp $(CARGO_CONFIG) ../user/.cargo/config.toml

# build kernel and copy it to save_dir 
KERNEL: prepare-cargo USER_APPS 
	@cargo build --$(MODE) --target $(TARGET)
	@# `rust-objcopy` is optional; QEMU boots the ELF directly.
	@OBJCOPY=$$(command -v rust-objcopy || command -v llvm-objcopy || true); \
	if [ -n "$$OBJCOPY" ]; then \
		$$OBJCOPY --strip-all $(KERNEL_ELF) -O binary $(KERNEL_BIN); \
		echo "Build $(KERNEL_BIN) successfully."; \
	else \
		echo "⚠️  No objcopy found; skip generating $(KERNEL_BIN) (QEMU uses ELF)."; \
	fi
	@cp $(KERNEL_ELF) kernel_$(MODE).elf

# find all excutable in the user's target dir strip it and copy to the os_str
USER_APPS: prepare-cargo
	@cd ../user  && cargo build --$(MODE) $(USER_FEATURES) --target $(TARGET)
	@mkdir -p $(APP_DIR)
	@for f in ../user/target/$(TARGET)/$(MODE)/*; do \
		if [ -f "$$f" ] && [ -x "$$f" ]; then \
			base=$$(basename $$f); \
			dst=$(APP_DIR)/$$base.bin; \
			if [ ! -f "$$dst" ] || ! cmp -s "$$f" "$$dst"; then \
				cp "$$f" "$$dst"; \
				echo "find user app (updated): $$base"; \
			else \
				echo "find user app (cached): $$base"; \
			fi; \
		fi; \
	done
	@echo "Build user apps successfully."

clean:
	@cargo clean
	@rm -f $(APP_DIR)/*.bin $(APP_DIR)/*.elf 
	@rm -f *.bin *.elf
	@cd ../user && cargo clean
# if stuck use CTRL-A X to exit QEMU
run: KERNEL ext4_img
# now address
	echo "🔍 Running QEMU with VirtIO block device..."
	echo "   ➜ File System Image: $(EXT4_IMG)"
	echo "pwd is $(shell pwd)"
	$(QEMU_RUN) $(QEMU_BASE_ARGS) $(QEMU_BIOS_ARGS) $(QEMU_DISK0_ARGS) $(QEMU_NET_ARGS) $(DISK_ARGS)



test:KERNEL
	@cd ../tests && cargo test -- --nocapture

debug:KERNEL ext4_img
	@$(QEMU_BIN) $(QEMU_BASE_ARGS) $(QEMU_BIOS_ARGS) $(QEMU_DISK0_ARGS) -s -S

# ===========================
# Ext4 Support
# ===========================
EXT4_IMG := ../ext4-fs-packer/target/fs.ext4
EXT4_SIZE?= 1G 
EXT4_BASE_IMG ?= ../img/disk.img
EXT4_BASE_TAR ?= ../img/disk.tar
EXT4_BASE_TAR_XZ ?= ../img/disk.tar.xz
EXT4_BASE_ARG :=
ifneq ($(strip $(EXT4_BASE_IMG)),)
EXT4_BASE_ARG := -b $(abspath $(EXT4_BASE_IMG))
EXT4_BASE_DEP := ext4_base_img
endif
# Build ext4 image from user apps
# check if need to rebuild
# 1. ext4 image not exist
# 2. any user app is newer than ext4 image
# 3. any file in extra/ is newer than ext4 image
# 4. base image is newer than ext4 image
# 5. EXT4_REBUILD is set to 1

ext4_img: USER_APPS $(EXT4_BASE_DEP)
	@needs=0; \
	if [ ! -f "$(EXT4_IMG)" ]; then needs=1; fi; \
	if [ $$needs -eq 0 ]; then \
		if find "$(APP_DIR)" -type f -newer "$(EXT4_IMG)" 2>/dev/null | head -n 1 | grep -q .; then needs=1; fi; \
	fi; \
	if [ $$needs -eq 0 ]; then \
		if find ../ext4-fs-packer/extra -type f -newer "$(EXT4_IMG)" 2>/dev/null | head -n 1 | grep -q .; then needs=1; fi; \
	fi; \
	if [ $$needs -eq 0 ] && [ -n "$(EXT4_BASE_IMG)" ] && [ -f "$(EXT4_BASE_IMG)" ]; then \
		if [ "$(EXT4_BASE_IMG)" -nt "$(EXT4_IMG)" ]; then needs=1; fi; \
	fi; \
	if [ "$(EXT4_REBUILD)" = "1" ]; then needs=1; fi; \
	if [ $$needs -eq 0 ]; then \
		echo "✅ Reusing existing ext4 image: $(EXT4_IMG)"; \
	else \
		echo "🔧 Building ext4 filesystem image..."; \
		cd ../ext4-fs-packer && cargo run --release -- \
			-u ../os/$(APP_DIR) \
			-e extra \
			$(EXT4_BASE_ARG) \
			-t target \
			-S $(EXT4_SIZE); \
		echo "✅ Ext4 image created: $(EXT4_IMG)"; \
	fi

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

# Run with ext4 filesystem
run_ext4: KERNEL ext4_img
	@echo "🔍 Running QEMU with ext4 VirtIO block device..."
	@echo "   ➜ File System Image: $(EXT4_IMG)"
	$(QEMU_RUN) $(QEMU_BASE_ARGS) $(QEMU_BIOS_ARGS) $(QEMU_DISK0_ARGS) $(QEMU_NET_ARGS) $(DISK_ARGS)
# Debug with ext4 filesystem
debug_ext4: KERNEL ext4_img
	@echo "🐛 Debugging with ext4 filesystem..."
	@$(QEMU_BIN) $(QEMU_BASE_ARGS) $(QEMU_BIOS_ARGS) $(QEMU_DISK0_ARGS) -s -S

client_gdb:
	@./elf-gdb \
		-ex 'file $(KERNEL_ELF)' \
		-ex 'set arch $(GDB_ARCH)' \
		-ex 'target remote localhost:1234'
		-ex 'display/10i $pc' 
