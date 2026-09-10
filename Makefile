PS5_HOST ?= ps5
PS5_PORT ?= 9021

ifdef PS5_PAYLOAD_SDK
    include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
else
    $(error PS5_PAYLOAD_SDK is undefined)
endif

OUT ?= build
HOST_CC ?= cc
CFLAGS := -Wall -Wextra -Werror -O2 -g -std=c17
SOURCES := main.c a53_transport.c notify.c ppr_patch.c

A53_ARM64_CC := $(PS5_PAYLOAD_SDK)/bin/clang
A53_ARM64_LD := $(PS5_PAYLOAD_SDK)/bin/ld.lld
A53_ARM64_OBJCOPY := $(PS5_PAYLOAD_SDK)/bin/llvm-objcopy

PPR403_A53_ELF ?= ../../MP4_1.00-12.00/4.03_mp4/4.03_mp4/a53.elf
PPR761_A53_ELF ?= ../../MP4_1.00-12.00/7.61_mp4/7.61_mp4/a53.elf
PPR940_A53_ELF ?= ../../MP4_1.00-12.00/9.40_mp4/9.40_mp4/a53.elf
PPR960_A53_ELF ?= ../../MP4_1.00-12.00/9.60_mp4/9.60_mp4/a53.elf

PATCHER := $(OUT)/a53_ppr_patcher.elf
INSTALL := $(OUT)/a53_ppr_install.elf
INSTALL_FAST := $(OUT)/a53_ppr_install_fast.elf
NATIVE := $(OUT)/a53_ppr_native.elf
PLAINTEXT := $(OUT)/a53_ppr_plaintext.elf
UNINSTALL := $(OUT)/a53_ppr_uninstall.elf
KMB_RANGE_INSTALL := $(OUT)/a53_kmb_range_install.elf
KMB_RANGE_UNINSTALL := $(OUT)/a53_kmb_range_uninstall.elf

.PHONY: all verify host-test clean deploy-install-fast

all: verify host-test $(PATCHER) $(INSTALL) $(INSTALL_FAST) $(NATIVE) \
	$(PLAINTEXT) $(UNINSTALL) $(KMB_RANGE_INSTALL) $(KMB_RANGE_UNINSTALL)

$(OUT):
	mkdir -p $@

$(PATCHER): $(SOURCES) | $(OUT)
	$(CC) $(CFLAGS) -o $@ $^

$(INSTALL): $(SOURCES) | $(OUT)
	$(CC) $(CFLAGS) -DPPR_DEFAULT_ACTION=PPR_PATCH_INSTALL \
		-DPPR_DEFAULT_IDLE_ACK=1 -DPPR_DEFAULT_BATCH=1 \
		-DPPR_DEFAULT_PERSISTENT=1 -o $@ $^

$(INSTALL_FAST): $(SOURCES) | $(OUT)
	$(CC) $(CFLAGS) -DPPR_DEFAULT_ACTION=PPR_PATCH_INSTALL \
		-DPPR_DEFAULT_IDLE_ACK=1 -DPPR_DEFAULT_FAST=1 \
		-DPPR_DEFAULT_BATCH=1 -DPPR_DEFAULT_PERSISTENT=1 \
		-DPPR_DEFAULT_MIXED_IO=1 -o $@ $^

$(NATIVE): $(SOURCES) | $(OUT)
	$(CC) $(CFLAGS) -DPPR_DEFAULT_ACTION=PPR_PATCH_MODE_NATIVE \
		-DPPR_DEFAULT_IDLE_ACK=1 -DPPR_DEFAULT_BATCH=1 \
		-DPPR_DEFAULT_PERSISTENT=1 -o $@ $^

$(PLAINTEXT): $(SOURCES) | $(OUT)
	$(CC) $(CFLAGS) -DPPR_DEFAULT_ACTION=PPR_PATCH_MODE_PLAINTEXT_NOAUTH \
		-DPPR_DEFAULT_IDLE_ACK=1 -DPPR_DEFAULT_BATCH=1 \
		-DPPR_DEFAULT_PERSISTENT=1 -o $@ $^

$(UNINSTALL): $(SOURCES) | $(OUT)
	$(CC) $(CFLAGS) -DPPR_DEFAULT_ACTION=PPR_PATCH_UNINSTALL \
		-DPPR_DEFAULT_IDLE_ACK=1 -DPPR_DEFAULT_BATCH=1 \
		-DPPR_DEFAULT_PERSISTENT=1 -o $@ $^

$(KMB_RANGE_INSTALL): $(SOURCES) | $(OUT)
	$(CC) $(CFLAGS) -DPPR_DEFAULT_ACTION=PPR_PATCH_KMB_RANGE_INSTALL \
		-DPPR_DEFAULT_IDLE_ACK=1 -DPPR_DEFAULT_BATCH=1 \
		-DPPR_DEFAULT_PERSISTENT=1 -o $@ $^

$(KMB_RANGE_UNINSTALL): $(SOURCES) | $(OUT)
	$(CC) $(CFLAGS) -DPPR_DEFAULT_ACTION=PPR_PATCH_KMB_RANGE_UNINSTALL \
		-DPPR_DEFAULT_IDLE_ACK=1 -DPPR_DEFAULT_BATCH=1 \
		-DPPR_DEFAULT_PERSISTENT=1 -o $@ $^

verify: ppr_wrapper.S ppr_wrapper.ld ppr_patch.c ppr_patch.h \
	verify_ppr_profiles.py
	python3 verify_ppr_profiles.py --host-cc $(HOST_CC) \
		--arm-cc $(A53_ARM64_CC) --arm-ld $(A53_ARM64_LD) \
		--objcopy $(A53_ARM64_OBJCOPY) --source ppr_patch.c \
		--asm ppr_wrapper.S --linker ppr_wrapper.ld \
		--elf 0x04030000=$(PPR403_A53_ELF) \
		--elf 0x07610000=$(PPR761_A53_ELF) \
		--elf 0x09400000=$(PPR940_A53_ELF) \
		--elf 0x09600000=$(PPR960_A53_ELF)

host-test: ppr_patch.c ppr_patch.h ppr_patch_test.c
	$(HOST_CC) -std=c17 -Wall -Wextra -Werror -O1 -g \
		-fsanitize=undefined -fno-omit-frame-pointer \
		ppr_patch.c ppr_patch_test.c -o /tmp/a53-ppr-patch-test
	/tmp/a53-ppr-patch-test

deploy-install-fast: verify $(INSTALL_FAST)
	$(PS5_DEPLOY) -h $(PS5_HOST) -p $(PS5_PORT) $(INSTALL_FAST)

clean:
	rm -rf $(OUT)
	rm -f ppr_wrapper.o ppr_wrapper.verified.elf \
		ppr_runtime.bin ppr_plaintext.bin
