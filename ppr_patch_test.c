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

#define KMB_RANGE_VA      0x06418d30ULL
#define KMB_RANGE_STOCK   0x1a8b018bU
#define KMB_RANGE_PATCHED 0x5280400bU

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
    if (index < 2)
        return MOCK_SRAM_PA + call_va[index] - MOCK_IO_VA;
    return MOCK_G6_PA + call_va[index] - MOCK_DEV_VA;
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
    mock_put32(mock, MOCK_SRAM_PA + 0x04e5a738ULL - MOCK_IO_VA,
               0x35000b38U);
    mock_put32(mock, MOCK_SRAM_PA + 0x04e5a870ULL - MOCK_IO_VA,
               0x97ffeff4U);
    mock_put32(mock, MOCK_G6_PA + KMB_RANGE_VA - MOCK_DEV_VA,
               KMB_RANGE_STOCK);
}

static int mock_read(void *context, uint64_t pa, void *dst, uint32_t size) {
    struct mock_a53 *mock = context;
    uint8_t *source = mock_span(mock, pa, size);
    if (!source)
        return -1;
    memcpy(dst, source, size);
    return (int)size;
}

static int mock_write(void *context, uint64_t pa, const void *src,
                      uint32_t size) {
    struct mock_a53 *mock = context;
    uint8_t *destination = mock_span(mock, pa, size);
    if (!destination)
        return -1;
    memcpy(destination, src, size);
    mock->writes++;
    return 0;
}

static int mock_read_many(void *context, const uint64_t *addresses,
                          const uint32_t *sizes, void *const *destinations,
                          uint32_t count) {
    for (uint32_t i = 0; i < count; i++) {
        if (mock_read(context, addresses[i], destinations[i], sizes[i]) <= 0)
            return -1;
    }
    return 0;
}

static int mock_pair(void *context,
                     uint64_t pa0, const void *src0, uint32_t size0,
                     void *readback0,
                     uint64_t pa1, const void *src1, uint32_t size1,
                     void *readback1) {
    if (mock_write(context, pa0, src0, size0) != 0 ||
        mock_write(context, pa1, src1, size1) != 0 ||
        mock_read(context, pa0, readback0, size0) <= 0 ||
        mock_read(context, pa1, readback1, size1) <= 0)
        return -1;
    return 0;
}

static void mock_log(void *context, const char *message) {
    (void)context;
    (void)message;
}

int main(void) {
    struct mock_a53 mock;
    mock_init(&mock);
    const struct ppr_patch_transport transport = {
        .context = &mock,
        .read = mock_read,
        .write = mock_write,
        .read_many = mock_read_many,
        .write_pair_read_pair = mock_pair,
        .log = mock_log,
        .fast_mode = 1,
        .batch_enabled = 1,
        .mixed_io_enabled = 1,
    };

    assert(ppr_patch_firmware_supported(0x04030000U));
    assert(ppr_patch_firmware_supported(0x07610000U));
    assert(ppr_patch_firmware_supported(0x09400000U));
    assert(ppr_patch_firmware_supported(0x09600000U));
    assert(!ppr_patch_firmware_supported(0x09000000U));

    assert(ppr_patch_run(&transport, 0x09400000U,
                         PPR_PATCH_STATUS, 0) == 0);
    assert(mock.writes == 0);

    assert(ppr_patch_run(&transport, 0x09400000U,
                         PPR_PATCH_KMB_RANGE_INSTALL, 0) != 0);
    assert(mock.writes == 0);
    assert(ppr_patch_run(&transport, 0x09400000U,
                         PPR_PATCH_KMB_RANGE_INSTALL, 1) == 0);
    assert(mock_get32(&mock, MOCK_G6_PA + KMB_RANGE_VA - MOCK_DEV_VA) ==
           KMB_RANGE_PATCHED);
    for (size_t i = 0; i < 10; i++)
        assert(mock_get32(&mock, mock_site_pa(i)) == call_stock[i]);
    assert(ppr_patch_run(&transport, 0x09400000U,
                         PPR_PATCH_KMB_RANGE_UNINSTALL, 1) == 0);
    assert(mock_get32(&mock, MOCK_G6_PA + KMB_RANGE_VA - MOCK_DEV_VA) ==
           KMB_RANGE_STOCK);
    mock_put32(&mock, MOCK_G6_PA + KMB_RANGE_VA - MOCK_DEV_VA,
               0xdeadbeefU);
    unsigned writes_before_unknown_range = mock.writes;
    assert(ppr_patch_run(&transport, 0x09400000U,
                         PPR_PATCH_KMB_RANGE_INSTALL, 1) != 0);
    assert(mock.writes == writes_before_unknown_range);
    mock_put32(&mock, MOCK_G6_PA + KMB_RANGE_VA - MOCK_DEV_VA,
               KMB_RANGE_STOCK);
    unsigned writes_after_range = mock.writes;
    assert(ppr_patch_run(&transport, 0x09400000U,
                         PPR_PATCH_INSTALL, 0) != 0);
    assert(mock.writes == writes_after_range);

    assert(ppr_patch_run(&transport, 0x09400000U,
                         PPR_PATCH_INSTALL, 1) == 0);
    assert(mock_get32(&mock, mock_site_pa(0)) != call_stock[0]);
    assert(ppr_patch_run(&transport, 0x09400000U,
                         PPR_PATCH_STATUS, 0) == 0);

    /* Exact mixed stock/current sites with complete caves must converge. */
    mock_put32(&mock, mock_site_pa(4), call_stock[4]);
    assert(ppr_patch_run(&transport, 0x09400000U,
                         PPR_PATCH_INSTALL, 1) == 0);
    assert(mock_get32(&mock, mock_site_pa(4)) != call_stock[4]);

    assert(ppr_patch_run(&transport, 0x09400000U,
                         PPR_PATCH_UNINSTALL, 1) == 0);
    for (size_t i = 0; i < 10; i++)
        assert(mock_get32(&mock, mock_site_pa(i)) == call_stock[i]);

    /* An unknown connected instruction must fail without attempting writes. */
    mock_put32(&mock, mock_site_pa(0), 0xdeadbeefU);
    unsigned writes_before = mock.writes;
    assert(ppr_patch_run(&transport, 0x09400000U,
                         PPR_PATCH_INSTALL, 1) != 0);
    assert(mock.writes == writes_before);
    assert(mock_get32(&mock, mock_site_pa(0)) == 0xdeadbeefU);

    assert(ppr_patch_run(&transport, 0x09000000U,
                         PPR_PATCH_STATUS, 0) != 0);
    puts("ppr_patch host state-machine tests passed");
    return 0;
}
