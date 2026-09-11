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
PROFILE_INCLUDE := ppr_profiles.inc
KMB_RANGE_SOURCES := kmb_range_main.c a53_transport.c notify.c \
	kmb_range_patch.c
KMB_RANGE_PROFILE_INCLUDE := kmb_range_profiles.inc

A53_ARM64_CC := $(PS5_PAYLOAD_SDK)/bin/clang
A53_ARM64_LD := $(PS5_PAYLOAD_SDK)/bin/ld.lld
A53_ARM64_OBJCOPY := $(PS5_PAYLOAD_SDK)/bin/llvm-objcopy

PPR_FULL_ROOT ?= ../../MP4_1.00-12.00
PPR_DRAM_ROOT ?= /mnt/j/PS5Dev/mp4

PATCHER := $(OUT)/a53_ppr_patcher.elf
INSTALL := $(OUT)/a53_ppr_install.elf
INSTALL_FAST := $(OUT)/a53_ppr_install_fast.elf
NATIVE := $(OUT)/a53_ppr_native.elf
PLAINTEXT := $(OUT)/a53_ppr_plaintext.elf
UNINSTALL := $(OUT)/a53_ppr_uninstall.elf
KMB_RANGE_INSTALL := $(OUT)/a53_kmb_range_install.elf
KMB_RANGE_UNINSTALL := $(OUT)/a53_kmb_range_uninstall.elf

.PHONY: all profiles verify verify-ppr verify-kmb host-test host-test-ppr \
	host-test-kmb host-test-notify clean deploy-install-fast

all: verify host-test $(PATCHER) $(INSTALL) $(INSTALL_FAST) $(NATIVE) \
	$(PLAINTEXT) $(UNINSTALL) $(KMB_RANGE_INSTALL) $(KMB_RANGE_UNINSTALL)

$(OUT):
	mkdir -p $@

$(PATCHER): $(SOURCES) $(PROFILE_INCLUDE) | $(OUT)
	$(CC) $(CFLAGS) -o $@ $(SOURCES)

$(INSTALL): $(SOURCES) $(PROFILE_INCLUDE) | $(OUT)
	$(CC) $(CFLAGS) -DPPR_DEFAULT_ACTION=PPR_PATCH_INSTALL \
		-DPPR_DEFAULT_IDLE_ACK=1 -DPPR_DEFAULT_FAST=1 \
		-DPPR_DEFAULT_BATCH=1 -DPPR_DEFAULT_PERSISTENT=1 \
		-DPPR_DEFAULT_MIXED_IO=1 \
		-o $@ $(SOURCES)

$(INSTALL_FAST): $(SOURCES) $(PROFILE_INCLUDE) | $(OUT)
	$(CC) $(CFLAGS) -DPPR_DEFAULT_ACTION=PPR_PATCH_INSTALL \
		-DPPR_DEFAULT_IDLE_ACK=1 -DPPR_DEFAULT_FAST=1 \
		-DPPR_DEFAULT_BATCH=1 -DPPR_DEFAULT_PERSISTENT=1 \
		-DPPR_DEFAULT_MIXED_IO=1 \
		-o $@ $(SOURCES)

$(NATIVE): $(SOURCES) $(PROFILE_INCLUDE) | $(OUT)
	$(CC) $(CFLAGS) -DPPR_DEFAULT_ACTION=PPR_PATCH_MODE_NATIVE \
		-DPPR_DEFAULT_IDLE_ACK=1 -DPPR_DEFAULT_FAST=1 \
		-DPPR_DEFAULT_BATCH=1 -DPPR_DEFAULT_PERSISTENT=1 \
		-DPPR_DEFAULT_MIXED_IO=1 \
		-o $@ $(SOURCES)

$(PLAINTEXT): $(SOURCES) $(PROFILE_INCLUDE) | $(OUT)
	$(CC) $(CFLAGS) -DPPR_DEFAULT_ACTION=PPR_PATCH_MODE_PLAINTEXT_NOAUTH \
		-DPPR_DEFAULT_IDLE_ACK=1 -DPPR_DEFAULT_FAST=1 \
		-DPPR_DEFAULT_BATCH=1 -DPPR_DEFAULT_PERSISTENT=1 \
		-DPPR_DEFAULT_MIXED_IO=1 \
		-o $@ $(SOURCES)

$(UNINSTALL): $(SOURCES) $(PROFILE_INCLUDE) | $(OUT)
	$(CC) $(CFLAGS) -DPPR_DEFAULT_ACTION=PPR_PATCH_UNINSTALL \
		-DPPR_DEFAULT_IDLE_ACK=1 -DPPR_DEFAULT_FAST=1 \
		-DPPR_DEFAULT_BATCH=1 -DPPR_DEFAULT_PERSISTENT=1 \
		-DPPR_DEFAULT_MIXED_IO=1 \
		-o $@ $(SOURCES)

$(KMB_RANGE_INSTALL): $(KMB_RANGE_SOURCES) $(KMB_RANGE_PROFILE_INCLUDE) \
		ppr_patch.h kmb_range_patch.h | $(OUT)
	$(CC) $(CFLAGS) -DKMB_RANGE_DEFAULT_ACTION=KMB_RANGE_INSTALL \
		-DKMB_RANGE_DEFAULT_IDLE_ACK=1 \
		-o $@ $(KMB_RANGE_SOURCES)

$(KMB_RANGE_UNINSTALL): $(KMB_RANGE_SOURCES) $(KMB_RANGE_PROFILE_INCLUDE) \
		ppr_patch.h kmb_range_patch.h | $(OUT)
	$(CC) $(CFLAGS) -DKMB_RANGE_DEFAULT_ACTION=KMB_RANGE_UNINSTALL \
		-DKMB_RANGE_DEFAULT_IDLE_ACK=1 \
		-o $@ $(KMB_RANGE_SOURCES)

profiles: generate_ppr_profiles.py generate_kmb_range_profiles.py
	python3 generate_ppr_profiles.py --full-root $(PPR_FULL_ROOT) \
		--dram-root $(PPR_DRAM_ROOT) --output $(PROFILE_INCLUDE)
	python3 generate_kmb_range_profiles.py --full-root $(PPR_FULL_ROOT) \
		--dram-root $(PPR_DRAM_ROOT) --output $(KMB_RANGE_PROFILE_INCLUDE)

verify: verify-ppr verify-kmb

verify-ppr: ppr_wrapper.S ppr_wrapper.ld ppr_patch.c ppr_patch.h \
	verify_ppr_profiles.py generate_ppr_profiles.py $(PROFILE_INCLUDE)
	python3 verify_ppr_profiles.py --host-cc $(HOST_CC) \
		--arm-cc $(A53_ARM64_CC) --arm-ld $(A53_ARM64_LD) \
		--objcopy $(A53_ARM64_OBJCOPY) --source ppr_patch.c \
		--asm ppr_wrapper.S --linker ppr_wrapper.ld \
		--full-root $(PPR_FULL_ROOT) --dram-root $(PPR_DRAM_ROOT)

verify-kmb: verify_kmb_range_profiles.py generate_kmb_range_profiles.py \
		$(KMB_RANGE_PROFILE_INCLUDE)
	python3 verify_kmb_range_profiles.py --full-root $(PPR_FULL_ROOT) \
		--dram-root $(PPR_DRAM_ROOT) --profiles $(KMB_RANGE_PROFILE_INCLUDE)

host-test: host-test-ppr host-test-kmb host-test-notify

host-test-ppr: ppr_patch.c ppr_patch.h ppr_patch_test.c $(PROFILE_INCLUDE)
	$(HOST_CC) -std=c17 -Wall -Wextra -Werror -O1 -g \
		-fsanitize=undefined -fno-omit-frame-pointer \
		ppr_patch.c ppr_patch_test.c -o /tmp/a53-ppr-patch-test
	/tmp/a53-ppr-patch-test

host-test-kmb: kmb_range_patch.c kmb_range_patch.h \
		kmb_range_patch_test.c $(KMB_RANGE_PROFILE_INCLUDE)
	$(HOST_CC) -std=c17 -Wall -Wextra -Werror -O1 -g \
		-fsanitize=undefined -fno-omit-frame-pointer \
		kmb_range_patch.c kmb_range_patch_test.c \
		-o /tmp/a53-kmb-range-test
	/tmp/a53-kmb-range-test

host-test-notify: notify.c notify.h notify_test.c
	$(HOST_CC) -std=c17 -Wall -Wextra -Werror -O1 -g \
		-fsanitize=undefined -fno-omit-frame-pointer \
		notify.c notify_test.c -o /tmp/a53-notify-test
	/tmp/a53-notify-test

deploy-install-fast: verify $(INSTALL_FAST)
	$(PS5_DEPLOY) -h $(PS5_HOST) -p $(PS5_PORT) $(INSTALL_FAST)

clean:
	rm -rf $(OUT)
	rm -f ppr_wrapper.o ppr_wrapper.verified.elf \
		ppr_runtime.bin ppr_plaintext.bin
