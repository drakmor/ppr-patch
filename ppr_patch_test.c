#include "ppr_patch.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define MOCK_LAYOUT_PA 0x887f0000ULL
#define MOCK_SRAM_PA   0x00027000ULL
#define MOCK_G6_PA     0x88340000ULL
#define MOCK_IO_VA     0x04e27000ULL
#define MOCK_DEV_VA    0x06411000ULL
#define RUNTIME_CAVE_VA 0x04e5cf00ULL
#define LEGACY_PRECHECK_VA 0x04e5a738ULL
#define LEGACY_DISPATCH_VA 0x04e5a870ULL
#define LEGACY_PRECHECK_STOCK 0x35000b38U
#define LEGACY_DISPATCH_STOCK 0x97ffeff4U
#define MOCK_WRITE_LOG_CAPACITY 128U
#define MOCK_READ_MANY_LOG_CAPACITY 16U
#define MOCK_WRITE_MANY_LOG_CAPACITY 16U

struct mock_layout_record {
    uint32_t id;
    uint32_t flags;
    uint64_t g6_base;
    uint64_t g6_size;
    uint64_t sram_base;
    uint64_t sram_size;
    uint64_t unknown_28;
    uint64_t mapped_base;
    uint64_t unknown_38;
    uint64_t mapped_size;
    uint64_t name_va;
};

struct mock_a53 {
    uint8_t layout[0x148 + 32 * 0x50];
    uint8_t sram[0x3a000];
    uint8_t g6[0x33000];
    unsigned writes;
    uint64_t write_pa[MOCK_WRITE_LOG_CAPACITY];
    uint32_t write_value[MOCK_WRITE_LOG_CAPACITY];
    uint32_t write_size[MOCK_WRITE_LOG_CAPACITY];
    unsigned write_count;
    uint32_t max_read_many_count;
    uint32_t read_many_count[MOCK_READ_MANY_LOG_CAPACITY];
    unsigned read_many_calls;
    uint32_t write_many_count[MOCK_WRITE_MANY_LOG_CAPACITY];
    unsigned write_many_calls;
    uint64_t fail_write_once_pa;
    int fail_write_once_armed;
    uint64_t fail_write_after_apply_once_pa;
    int fail_write_after_apply_once_armed;
    uint64_t fail_write_always_pa;
    int fail_read_after_write_failure;
    int fail_read_active;
    uint64_t short_read_once_pa;
    int short_read_once_armed;
    int legacy_reboot_required_seen;
    int rollback_reboot_required_seen;
};

static const uint64_t call_va[10] = {
    0x04e4879cULL, 0x04e49048ULL, 0x06414f1cULL, 0x06416118ULL,
    0x064163a8ULL, 0x0641663cULL, 0x06417c50ULL, 0x0642313cULL,
    0x064251dcULL, 0x064278d0ULL,
};

static const uint32_t call_stock[10] = {
    0x940047c8U, 0x9400459dU, 0x97a915e8U, 0x97a91169U,
    0x97a910c5U, 0x97a91020U, 0x97a90a9bU, 0x97a8dd60U,
    0x97a8d538U, 0x97a8cb7bU,
};

static const uint64_t internal_site_va[3] = {
    0x04e569a8ULL, 0x04e56ad4ULL, 0x04e5a974ULL,
};

static const uint32_t internal_site_stock[3] = {
    0x97ff4d2bU, 0x97ff4ce0U, 0x97fff3c4U,
};

static uint8_t *mock_span(struct mock_a53 *mock, uint64_t pa, uint32_t size) {
    if (pa >= MOCK_LAYOUT_PA &&
        pa - MOCK_LAYOUT_PA <= sizeof(mock->layout) &&
        size <= sizeof(mock->layout) - (pa - MOCK_LAYOUT_PA))
        return mock->layout + (pa - MOCK_LAYOUT_PA);
    if (pa >= MOCK_SRAM_PA && pa - MOCK_SRAM_PA <= sizeof(mock->sram) &&
        size <= sizeof(mock->sram) - (pa - MOCK_SRAM_PA))
        return mock->sram + (pa - MOCK_SRAM_PA);
    if (pa >= MOCK_G6_PA && pa - MOCK_G6_PA <= sizeof(mock->g6) &&
        size <= sizeof(mock->g6) - (pa - MOCK_G6_PA))
        return mock->g6 + (pa - MOCK_G6_PA);
    return NULL;
}

static uint64_t mock_site_pa(size_t index) {
    if (index < 10) {
        if (index < 2)
            return MOCK_SRAM_PA + call_va[index] - MOCK_IO_VA;
        return MOCK_G6_PA + call_va[index] - MOCK_DEV_VA;
    }
    return MOCK_SRAM_PA + internal_site_va[index - 10] - MOCK_IO_VA;
}

static uint64_t mock_legacy_site_pa(size_t index) {
    uint64_t va = index == 0 ? LEGACY_PRECHECK_VA : LEGACY_DISPATCH_VA;
    return MOCK_SRAM_PA + va - MOCK_IO_VA;
}

static uint32_t mock_bl(uint64_t from, uint64_t to) {
    int64_t delta = (int64_t)to - (int64_t)from;
    assert((delta & 3) == 0);
    assert(delta >= -0x08000000LL && delta <= 0x07fffffcLL);
    return 0x94000000U | ((uint32_t)(delta / 4) & 0x03ffffffU);
}

static void mock_put32(struct mock_a53 *mock, uint64_t pa, uint32_t value) {
    uint8_t *destination = mock_span(mock, pa, sizeof(value));
    assert(destination != NULL);
    memcpy(destination, &value, sizeof(value));
}

static uint32_t mock_get32(struct mock_a53 *mock, uint64_t pa) {
    uint32_t value;
    uint8_t *source = mock_span(mock, pa, sizeof(value));
    assert(source != NULL);
    memcpy(&value, source, sizeof(value));
    return value;
}

static void mock_reset_write_log(struct mock_a53 *mock) {
    mock->writes = 0;
    mock->write_count = 0;
    memset(mock->write_pa, 0, sizeof(mock->write_pa));
    memset(mock->write_value, 0, sizeof(mock->write_value));
    memset(mock->write_size, 0, sizeof(mock->write_size));
    mock->max_read_many_count = 0;
    mock->read_many_calls = 0;
    memset(mock->read_many_count, 0, sizeof(mock->read_many_count));
    mock->write_many_calls = 0;
    memset(mock->write_many_count, 0, sizeof(mock->write_many_count));
    mock->legacy_reboot_required_seen = 0;
    mock->rollback_reboot_required_seen = 0;
}

static void mock_corrupt_caves(struct mock_a53 *mock) {
    uint64_t runtime_pa = MOCK_SRAM_PA + RUNTIME_CAVE_VA - MOCK_IO_VA;
    uint64_t plaintext_pa = runtime_pa + 0x50;
    uint8_t *runtime = mock_span(mock, runtime_pa, 0x4c);
    uint8_t *plaintext = mock_span(mock, plaintext_pa, 0xa0);
    assert(runtime != NULL && plaintext != NULL);
    memset(runtime, 0x5a, 0x4c);
    memset(plaintext, 0xc3, 0xa0);
}

static void mock_seed_legacy_patch(struct mock_a53 *mock) {
    mock_corrupt_caves(mock);

    for (size_t i = 0; i < 10; i++)
        mock_put32(mock, mock_site_pa(i),
                   mock_bl(call_va[i], RUNTIME_CAVE_VA));
    for (size_t i = 0; i < 3; i++)
        mock_put32(mock, mock_site_pa(10 + i), internal_site_stock[i]);
    mock_put32(mock, mock_legacy_site_pa(0),
               mock_bl(LEGACY_PRECHECK_VA, RUNTIME_CAVE_VA + 0x24));
    mock_put32(mock, mock_legacy_site_pa(1),
               mock_bl(LEGACY_DISPATCH_VA, RUNTIME_CAVE_VA + 0x3c));
}

static void mock_assert_current_restore_sequence(const struct mock_a53 *mock,
                                                 size_t first) {
    assert(mock->write_count >= first + 13);
    for (size_t i = 0; i < 10; i++) {
        assert(mock->write_pa[first + i] == mock_site_pa(i));
        assert(mock->write_value[first + i] == call_stock[i]);
        assert(mock->write_size[first + i] == 4);
    }
    for (size_t i = 0; i < 3; i++) {
        assert(mock->write_pa[first + 10 + i] == mock_site_pa(10 + i));
        assert(mock->write_value[first + 10 + i] == internal_site_stock[i]);
        assert(mock->write_size[first + 10 + i] == 4);
    }
}

static void mock_assert_no_legacy_writes(const struct mock_a53 *mock) {
    for (size_t i = 0; i < mock->write_count; i++) {
        assert(mock->write_pa[i] != mock_legacy_site_pa(0));
        assert(mock->write_pa[i] != mock_legacy_site_pa(1));
    }
}

static void mock_assert_pair_only(const struct mock_a53 *mock) {
    assert(mock->write_many_calls <= MOCK_WRITE_MANY_LOG_CAPACITY);
    for (unsigned i = 0; i < mock->write_many_calls; i++)
        assert(mock->write_many_count[i] == 2);
}

static void mock_init(struct mock_a53 *mock) {
    memset(mock, 0, sizeof(*mock));
    memset(mock->sram, 0xa5, sizeof(mock->sram));
    uint32_t segment_count = 2;
    memcpy(mock->layout + 0x0c, &segment_count, sizeof(segment_count));
    struct mock_layout_record *records =
        (struct mock_layout_record *)(mock->layout + 0x148);
    records[0] = (struct mock_layout_record) {
        .id = 3, .flags = 0x00030001U,
        .g6_base = 0x884a7000ULL, .g6_size = 0x35a54ULL,
        .sram_base = MOCK_SRAM_PA, .sram_size = sizeof(mock->sram),
        .mapped_base = MOCK_IO_VA, .mapped_size = 0x36000ULL,
    };
    records[1] = (struct mock_layout_record) {
        .id = 11, .flags = 0x00010011U,
        .g6_base = MOCK_G6_PA, .g6_size = 0x32e00ULL,
        .mapped_base = MOCK_DEV_VA, .mapped_size = 0x33000ULL,
    };
    for (size_t i = 0; i < 10; i++)
        mock_put32(mock, mock_site_pa(i), call_stock[i]);
    for (size_t i = 0; i < 3; i++)
        mock_put32(mock, mock_site_pa(10 + i), internal_site_stock[i]);
    mock_put32(mock, mock_legacy_site_pa(0), LEGACY_PRECHECK_STOCK);
    mock_put32(mock, mock_legacy_site_pa(1), LEGACY_DISPATCH_STOCK);
}

static int mock_read(void *context, uint64_t pa, void *dst, uint32_t size) {
    struct mock_a53 *mock = context;
    if (mock->fail_read_active && pa == mock->fail_write_always_pa)
        return -1;
    uint8_t *source = mock_span(mock, pa, size);
    if (!source)
        return -1;
    memcpy(dst, source, size);
    if (mock->short_read_once_armed && pa == mock->short_read_once_pa) {
        mock->short_read_once_armed = 0;
        return size > 1 ? (int)size - 1 : 0;
    }
    return (int)size;
}

static int mock_write(void *context, uint64_t pa, const void *src,
                      uint32_t size) {
    struct mock_a53 *mock = context;
    if (mock->fail_write_always_pa && pa == mock->fail_write_always_pa) {
        if (mock->fail_read_after_write_failure)
            mock->fail_read_active = 1;
        return -1;
    }
    if (mock->fail_write_once_armed && pa == mock->fail_write_once_pa) {
        mock->fail_write_once_armed = 0;
        return -1;
    }
    uint8_t *destination = mock_span(mock, pa, size);
    if (!destination)
        return -1;
    memcpy(destination, src, size);
    if (mock->write_count < MOCK_WRITE_LOG_CAPACITY) {
        mock->write_pa[mock->write_count] = pa;
        mock->write_size[mock->write_count] = size;
        if (size >= sizeof(uint32_t))
            memcpy(&mock->write_value[mock->write_count], src,
                   sizeof(uint32_t));
    }
    mock->write_count++;
    mock->writes++;
    if (mock->fail_write_after_apply_once_armed &&
        pa == mock->fail_write_after_apply_once_pa) {
        mock->fail_write_after_apply_once_armed = 0;
        return -1;
    }
    return 0;
}

static int mock_read_many(void *context, const uint64_t *addresses,
                          const uint32_t *sizes, void *const *destinations,
                          uint32_t count) {
    struct mock_a53 *mock = context;
    assert(count <= 16);
    if (mock->read_many_calls < MOCK_READ_MANY_LOG_CAPACITY)
        mock->read_many_count[mock->read_many_calls] = count;
    mock->read_many_calls++;
    if (count > mock->max_read_many_count)
        mock->max_read_many_count = count;
    for (uint32_t i = 0; i < count; i++) {
        if (mock_read(context, addresses[i], destinations[i], sizes[i]) !=
            (int)sizes[i])
            return -1;
    }
    return 0;
}

static int mock_pair(void *context,
                     uint64_t pa0, const void *src0, uint32_t size0,
                     void *readback0,
                     uint64_t pa1, const void *src1, uint32_t size1,
                     void *readback1) {
    struct mock_a53 *mock = context;
    if (mock->write_many_calls < MOCK_WRITE_MANY_LOG_CAPACITY)
        mock->write_many_count[mock->write_many_calls] = 2;
    mock->write_many_calls++;
    if (mock_write(context, pa0, src0, size0) != 0 ||
        mock_write(context, pa1, src1, size1) != 0 ||
        mock_read(context, pa0, readback0, size0) != (int)size0 ||
        mock_read(context, pa1, readback1, size1) != (int)size1)
        return -1;
    return 0;
}

static void mock_log(void *context, const char *message) {
    struct mock_a53 *mock = context;
    if (strstr(message, "LEGACY_REBOOT_REQUIRED") != NULL)
        mock->legacy_reboot_required_seen = 1;
    if (strstr(message, "ROLLBACK_REBOOT_REQUIRED") != NULL)
        mock->rollback_reboot_required_seen = 1;
}

int main(void) {
    struct mock_a53 mock;
    mock_init(&mock);
    const struct ppr_patch_transport transport = {
        .context = &mock,
        .read = mock_read,
        .write = mock_write,
        .read_many = mock_read_many,
        /* Match the production adapter: grouped mutation is deliberately
         * unavailable, while the bounded two-write/two-read path remains. */
        .write_many_read_many = NULL,
        .write_pair_read_pair = mock_pair,
        .log = mock_log,
        .fast_mode = 1,
        .batch_enabled = 1,
        .mixed_io_enabled = 1,
    };

    assert(ppr_patch_firmware_supported(0x01000000U));
    assert(ppr_patch_firmware_supported(0x04030000U));
    assert(ppr_patch_firmware_supported(0x07610000U));
    assert(ppr_patch_firmware_supported(0x09400000U));
    assert(ppr_patch_firmware_supported(0x09600000U));
    assert(ppr_patch_firmware_supported(0x11400000U));
    assert(!ppr_patch_firmware_supported(0x12000000U));

    assert(ppr_patch_run(&transport, 0x09400000U,
                         (enum ppr_patch_action)99, 1) != 0);
    assert(mock.writes == 0 && mock.read_many_calls == 0);

    assert(ppr_patch_run(&transport, 0x09400000U,
                         PPR_PATCH_STATUS, 0) == 0);
    assert(mock.writes == 0);

    /* A positive short scalar read is not a complete layout snapshot. */
    mock.short_read_once_pa = MOCK_LAYOUT_PA;
    mock.short_read_once_armed = 1;
    assert(ppr_patch_run(&transport, 0x09400000U,
                         PPR_PATCH_STATUS, 0) != 0);
    assert(!mock.short_read_once_armed);
    assert(mock.writes == 0);

    /* More than one exact IO or DEV record is an ambiguous live layout. */
    uint32_t duplicate_segment_count = 3;
    memcpy(mock.layout + 0x0c, &duplicate_segment_count,
           sizeof(duplicate_segment_count));
    struct mock_layout_record *layout_records =
        (struct mock_layout_record *)(mock.layout + 0x148);
    layout_records[2] = layout_records[1];
    assert(ppr_patch_run(&transport, 0x09400000U,
                         PPR_PATCH_STATUS, 0) != 0);
    assert(mock.writes == 0);
    duplicate_segment_count = 2;
    memcpy(mock.layout + 0x0c, &duplicate_segment_count,
           sizeof(duplicate_segment_count));
    memset(&layout_records[2], 0, sizeof(layout_records[2]));

    unsigned writes_before_install = mock.writes;
    assert(ppr_patch_run(&transport, 0x09400000U,
                         PPR_PATCH_INSTALL, 0) != 0);
    assert(mock.writes == writes_before_install);

    /* A cave-phase failure cannot trigger writes to disconnected sites. */
    uint64_t runtime_cave_pa =
        MOCK_SRAM_PA + RUNTIME_CAVE_VA - MOCK_IO_VA;
    mock.fail_write_once_pa = runtime_cave_pa;
    mock.fail_write_once_armed = 1;
    mock_reset_write_log(&mock);
    assert(ppr_patch_run(&transport, 0x09400000U,
                         PPR_PATCH_INSTALL, 1) != 0);
    assert(!mock.fail_write_once_armed);
    assert(mock.read_many_calls == 2);
    assert(mock.read_many_count[0] == 15);
    assert(mock.read_many_count[1] == 2);
    assert(mock.write_many_calls == 1);
    assert(mock.write_many_count[0] == 2);
    assert(mock.write_count == 1);
    assert(mock.write_pa[0] == runtime_cave_pa + 0x50);
    for (size_t i = 0; i < 13; i++)
        assert(mock_get32(&mock, mock_site_pa(i)) ==
               (i < 10 ? call_stock[i] : internal_site_stock[i - 10]));

    /* Internal-phase failure restores only the three possibly visible sites. */
    mock.fail_write_once_pa = mock_site_pa(11);
    mock.fail_write_once_armed = 1;
    mock_reset_write_log(&mock);
    assert(ppr_patch_run(&transport, 0x09400000U,
                         PPR_PATCH_INSTALL, 1) != 0);
    assert(!mock.fail_write_once_armed);
    assert(mock.read_many_calls == 3);
    assert(mock.read_many_count[0] == 15);
    assert(mock.read_many_count[1] == 2);
    assert(mock.read_many_count[2] == 3);
    assert(mock.write_many_calls == 2);
    mock_assert_pair_only(&mock);
    assert(mock.write_count == 6);
    for (size_t i = 0; i < 10; i++)
        assert(mock_get32(&mock, mock_site_pa(i)) == call_stock[i]);
    for (size_t i = 0; i < 3; i++)
        assert(mock_get32(&mock, mock_site_pa(10 + i)) ==
               internal_site_stock[i]);
    mock_assert_no_legacy_writes(&mock);

    mock_reset_write_log(&mock);
    assert(ppr_patch_run(&transport, 0x09400000U,
                         PPR_PATCH_INSTALL, 1) == 0);
    assert(mock.read_many_calls == 1);
    assert(mock.read_many_count[0] == 15);
    assert(mock.write_many_calls == 7);
    mock_assert_pair_only(&mock);
    for (size_t i = 0; i < 10; i++)
        assert(mock_get32(&mock, mock_site_pa(i)) != call_stock[i]);
    for (size_t i = 0; i < 3; i++)
        assert(mock_get32(&mock, mock_site_pa(10 + i)) !=
               internal_site_stock[i]);
    assert(ppr_patch_run(&transport, 0x09400000U,
                         PPR_PATCH_STATUS, 0) == 0);

    /* Exact mixed stock/current sites with complete caves must converge. */
    mock_put32(&mock, mock_site_pa(4), call_stock[4]);
    mock_put32(&mock, mock_site_pa(11), internal_site_stock[1]);
    mock_reset_write_log(&mock);
    assert(ppr_patch_run(&transport, 0x09400000U,
                         PPR_PATCH_INSTALL, 1) == 0);
    assert(mock.read_many_calls == 2);
    assert(mock.read_many_count[0] == 15);
    assert(mock.read_many_count[1] == 2);
    assert(mock.write_many_calls == 13);
    mock_assert_pair_only(&mock);
    assert(mock_get32(&mock, mock_site_pa(4)) != call_stock[4]);
    assert(mock_get32(&mock, mock_site_pa(11)) != internal_site_stock[1]);

    mock_reset_write_log(&mock);
    assert(ppr_patch_run(&transport, 0x09400000U,
                         PPR_PATCH_UNINSTALL, 1) == 0);
    assert(mock.read_many_calls == 2);
    assert(mock.read_many_count[0] == 15);
    assert(mock.read_many_count[1] == 2);
    assert(mock.write_many_calls == 6);
    mock_assert_pair_only(&mock);
    assert(mock.write_count == 13);
    mock_assert_current_restore_sequence(&mock, 0);
    mock_assert_no_legacy_writes(&mock);
    for (size_t i = 0; i < 10; i++)
        assert(mock_get32(&mock, mock_site_pa(i)) == call_stock[i]);
    for (size_t i = 0; i < 3; i++)
        assert(mock_get32(&mock, mock_site_pa(10 + i)) ==
               internal_site_stock[i]);

    /* A timeout reported after the last write in a pair is reconciled by a
     * fresh exact read; it must not turn a completed phase into rollback. */
    mock.fail_write_after_apply_once_pa = mock_site_pa(7);
    mock.fail_write_after_apply_once_armed = 1;
    mock_reset_write_log(&mock);
    assert(ppr_patch_run(&transport, 0x09400000U,
                         PPR_PATCH_INSTALL, 1) == 0);
    assert(!mock.fail_write_after_apply_once_armed);
    assert(mock.read_many_calls == 2);
    assert(mock.read_many_count[0] == 15);
    assert(mock.read_many_count[1] == 2);
    assert(mock.write_many_calls == 7);
    mock_assert_pair_only(&mock);
    for (size_t i = 0; i < 13; i++)
        assert(mock_get32(&mock, mock_site_pa(i)) !=
               (i < 10 ? call_stock[i] : internal_site_stock[i - 10]));

    /* If a timed-out public restore cannot be read back, rollback must not
     * disconnect the internal hooks underneath the remaining callers. */
    mock_reset_write_log(&mock);
    mock.fail_write_always_pa = mock_site_pa(4);
    mock.fail_read_after_write_failure = 1;
    assert(ppr_patch_run(&transport, 0x09400000U,
                         PPR_PATCH_UNINSTALL, 1) != 0);
    assert(mock.rollback_reboot_required_seen);
    for (size_t i = 0; i < 3; i++)
        assert(mock_get32(&mock, mock_site_pa(10 + i)) !=
               internal_site_stock[i]);
    mock_assert_no_legacy_writes(&mock);

    mock_init(&mock);

    /* Exact previous-generation entry points require reboot and stay untouched. */
    assert(mock_bl(LEGACY_PRECHECK_VA, RUNTIME_CAVE_VA + 0x24) ==
           0x940009fbU);
    assert(mock_bl(LEGACY_DISPATCH_VA, RUNTIME_CAVE_VA + 0x3c) ==
           0x940009b3U);
    mock_seed_legacy_patch(&mock);
    mock_reset_write_log(&mock);
    assert(ppr_patch_run(&transport, 0x09400000U,
                         PPR_PATCH_STATUS, 0) != 0);
    assert(mock.legacy_reboot_required_seen);
    assert(mock.writes == 0);

    mock_reset_write_log(&mock);
    assert(ppr_patch_run(&transport, 0x09400000U,
                         PPR_PATCH_INSTALL, 1) != 0);
    assert(mock.legacy_reboot_required_seen);
    assert(mock.writes == 0);
    assert(mock.read_many_calls == 1);
    assert(mock.read_many_count[0] == 15);
    assert(mock.write_many_calls == 0);
    mock_assert_no_legacy_writes(&mock);

    mock_reset_write_log(&mock);
    assert(ppr_patch_run(&transport, 0x09400000U,
                         PPR_PATCH_UNINSTALL, 1) != 0);
    assert(mock.legacy_reboot_required_seen);
    assert(mock.writes == 0);
    assert(mock.read_many_calls == 1);
    assert(mock.read_many_count[0] == 15);
    mock_assert_no_legacy_writes(&mock);

    /* Even one exact retired hook is a non-mutable legacy state. */
    for (size_t i = 0; i < 10; i++)
        mock_put32(&mock, mock_site_pa(i), call_stock[i]);
    for (size_t i = 0; i < 3; i++)
        mock_put32(&mock, mock_site_pa(10 + i), internal_site_stock[i]);
    mock_put32(&mock, mock_legacy_site_pa(1), LEGACY_DISPATCH_STOCK);
    mock_reset_write_log(&mock);
    assert(ppr_patch_run(&transport, 0x09400000U,
                         PPR_PATCH_INSTALL, 1) != 0);
    assert(mock.legacy_reboot_required_seen);
    assert(mock.writes == 0);
    assert(mock.read_many_calls == 1);
    assert(mock.read_many_count[0] == 15);

    /* A current hook mix with corrupt caves remains unknown and immutable. */
    mock_put32(&mock, mock_legacy_site_pa(0), LEGACY_PRECHECK_STOCK);
    mock_corrupt_caves(&mock);
    mock_put32(&mock, mock_site_pa(0),
               mock_bl(call_va[0], RUNTIME_CAVE_VA));
    mock_reset_write_log(&mock);
    assert(ppr_patch_run(&transport, 0x09400000U,
                         PPR_PATCH_INSTALL, 1) != 0);
    assert(mock.writes == 0);
    assert(mock.read_many_calls == 2);
    assert(mock.read_many_count[0] == 15);
    assert(mock.read_many_count[1] == 2);
    mock_put32(&mock, mock_site_pa(0), call_stock[0]);

    /* A failed native-to-current connect rolls back current sites only. */
    mock.fail_write_once_pa = mock_site_pa(4);
    mock.fail_write_once_armed = 1;
    mock_reset_write_log(&mock);
    assert(ppr_patch_run(&transport, 0x09400000U,
                         PPR_PATCH_INSTALL, 1) != 0);
    assert(!mock.fail_write_once_armed);
    assert(mock.read_many_calls == 4);
    assert(mock.read_many_count[0] == 15);
    assert(mock.read_many_count[1] == 2);
    assert(mock.read_many_count[2] == 10);
    assert(mock.read_many_count[3] == 3);
    assert(mock.write_many_calls == 5);
    mock_assert_pair_only(&mock);
    assert(mock.write_count == 22);
    assert(mock.write_pa[0] ==
           MOCK_SRAM_PA + RUNTIME_CAVE_VA + 0x50 - MOCK_IO_VA);
    assert(mock.write_pa[1] ==
           MOCK_SRAM_PA + RUNTIME_CAVE_VA - MOCK_IO_VA);
    for (size_t i = 0; i < 3; i++)
        assert(mock.write_pa[2 + i] == mock_site_pa(10 + i));
    for (size_t i = 0; i < 4; i++)
        assert(mock.write_pa[5 + i] == mock_site_pa(i));
    mock_assert_current_restore_sequence(&mock, 9);
    mock_assert_no_legacy_writes(&mock);
    for (size_t i = 0; i < 10; i++)
        assert(mock_get32(&mock, mock_site_pa(i)) == call_stock[i]);
    for (size_t i = 0; i < 3; i++)
        assert(mock_get32(&mock, mock_site_pa(10 + i)) ==
               internal_site_stock[i]);

    /* Unknown retired code is never overwritten. */
    mock_put32(&mock, mock_legacy_site_pa(0), 0xdeadbeefU);
    mock_reset_write_log(&mock);
    assert(ppr_patch_run(&transport, 0x09400000U,
                         PPR_PATCH_INSTALL, 1) != 0);
    assert(mock.writes == 0);
    assert(mock_get32(&mock, mock_legacy_site_pa(0)) == 0xdeadbeefU);
    assert(!mock.legacy_reboot_required_seen);
    assert(ppr_patch_run(&transport, 0x09400000U,
                         PPR_PATCH_UNINSTALL, 1) != 0);
    assert(mock.writes == 0);
    mock_assert_no_legacy_writes(&mock);
    mock_put32(&mock, mock_legacy_site_pa(0), LEGACY_PRECHECK_STOCK);

    /* An unknown connected instruction must fail without attempting writes. */
    mock_put32(&mock, mock_site_pa(0), 0xdeadbeefU);
    unsigned writes_before = mock.writes;
    assert(ppr_patch_run(&transport, 0x09400000U,
                         PPR_PATCH_INSTALL, 1) != 0);
    assert(mock.writes == writes_before);
    assert(mock_get32(&mock, mock_site_pa(0)) == 0xdeadbeefU);

    assert(ppr_patch_run(&transport, 0x12000000U,
                         PPR_PATCH_STATUS, 0) != 0);
    puts("ppr_patch host state-machine tests passed");
    return 0;
}
