#include "ppr_patch.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PPR_CALL_COUNT 10U
#define PPR_SITE_COUNT (PPR_CALL_COUNT + 2U)
#define PPR_RUNTIME_SIZE 0x48U
#define PPR_PLAINTEXT_SIZE 0x98U
#define PPR_LAYOUT_HEADER_SIZE 0x148U
#define PPR_LAYOUT_MAX_SEGMENTS 32U

struct ppr_layout_record {
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

_Static_assert(sizeof(struct ppr_layout_record) == 0x50,
               "A53 layout record size");

struct ppr_profile {
    uint32_t firmware;
    const char *name;

    uint64_t io_mapped_base;
    uint64_t io_file_size;
    uint64_t io_mapped_size;
    uint64_t io_sram_base;
    uint64_t dev_mapped_base;
    uint64_t dev_file_size;
    uint64_t dev_mapped_size;

    uint64_t runtime_cave_va;
    uint64_t plaintext_cave_va;
    uint64_t helper_va;
    uint64_t precheck_normal_va;
    uint64_t precheck_special_va;
    uint64_t common_error_va;
    uint64_t dispatch_native_va;
    uint64_t plaintext_idma_va;
    uint64_t sha_wait_idma_aes_va;
    uint64_t submit_idma_va;
    uint64_t common_return_va;

    /*
     * ExtFs_EncryptAndCalculateSha validates its XTS/CMAC allocation against
     * a limit selected from the request class: 112 for the restricted class,
     * otherwise the full 9-bit KMB aperture (512).  Replace only that CSEL
     * with a MOV of 512; the XTS pair-size and CMAC range checks stay native.
     */
    uint64_t encrypt_kmb_range_va;
    uint32_t encrypt_kmb_range_stock;
    uint32_t encrypt_kmb_range_patch;

    uint64_t call_va[PPR_CALL_COUNT];
    uint32_t call_stock[PPR_CALL_COUNT];
    uint64_t precheck_va;
    uint32_t precheck_stock;
    uint64_t dispatch_va;
    uint32_t dispatch_stock;
};

/*
 * The four profiles were checked against the corresponding A53 ELFs in IDA.
 * In every image the common helper has the same 18-argument ABI, saves the
 * same registers, stores the terminal SHA notification at [x29-0xc], and
 * reaches its native dispatch at helper+0x1b4.  IdmaPt and the queue-submit
 * helper also have matching ABIs and data-structure offsets.
 */
static const struct ppr_profile ppr_profiles[] = {
    {
        .firmware = 0x04030000U, .name = "4.03",
        .io_mapped_base = 0x04e27000ULL,
        .io_file_size = 0x376d4ULL, .io_mapped_size = 0x38000ULL,
        .io_sram_base = 0x27000ULL,
        .dev_mapped_base = 0x06410000ULL,
        .dev_file_size = 0x2ecf8ULL, .dev_mapped_size = 0x2f000ULL,
        .runtime_cave_va = 0x04e5ef00ULL,
        .plaintext_cave_va = 0x04e5ef50ULL,
        .helper_va = 0x04e5c334ULL,
        .precheck_normal_va = 0x04e5c3b4ULL,
        .precheck_special_va = 0x04e5c3e8ULL,
        .common_error_va = 0x04e5c514ULL,
        .dispatch_native_va = 0x04e584c8ULL,
        .plaintext_idma_va = 0x04e58f88ULL,
        .sha_wait_idma_aes_va = 0x04e5941cULL,
        .submit_idma_va = 0x04e57008ULL,
        .common_return_va = 0x04e5c624ULL,
        .encrypt_kmb_range_va = 0x06417b68ULL,
        .encrypt_kmb_range_stock = 0x1a8e01edU,
        .encrypt_kmb_range_patch = 0x5280400dU,
        .call_va = {
            0x04e49418ULL, 0x04e49b5cULL, 0x06413e2cULL,
            0x06414ff0ULL, 0x06415280ULL, 0x06415514ULL,
            0x06416aecULL, 0x06421224ULL, 0x064231a8ULL,
            0x064256d8ULL,
        },
        .call_stock = {
            0x94004bc7U, 0x940049f6U, 0x97a92142U, 0x97a91cd1U,
            0x97a91c2dU, 0x97a91b88U, 0x97a91612U, 0x97a8ec44U,
            0x97a8e463U, 0x97a8db17U,
        },
        .precheck_va = 0x04e5c3b0ULL,
        .precheck_stock = 0x35000b38U,
        .dispatch_va = 0x04e5c4e8ULL,
        .dispatch_stock = 0x97ffeff8U,
    },
    {
        .firmware = 0x07610000U, .name = "7.61",
        .io_mapped_base = 0x04e27000ULL,
        .io_file_size = 0x35138ULL, .io_mapped_size = 0x36000ULL,
        .io_sram_base = 0x27000ULL,
        .dev_mapped_base = 0x06411000ULL,
        .dev_file_size = 0x31a80ULL, .dev_mapped_size = 0x32000ULL,
        .runtime_cave_va = 0x04e5cf00ULL,
        .plaintext_cave_va = 0x04e5cf50ULL,
        .helper_va = 0x04e59da0ULL,
        .precheck_normal_va = 0x04e59e20ULL,
        .precheck_special_va = 0x04e59e54ULL,
        .common_error_va = 0x04e59f80ULL,
        .dispatch_native_va = 0x04e55f24ULL,
        .plaintext_idma_va = 0x04e569e4ULL,
        .sha_wait_idma_aes_va = 0x04e56e78ULL,
        .submit_idma_va = 0x04e54a38ULL,
        .common_return_va = 0x04e5a090ULL,
        .encrypt_kmb_range_va = 0x06418e18ULL,
        .encrypt_kmb_range_stock = 0x1a8b018bU,
        .encrypt_kmb_range_patch = 0x5280400bU,
        .call_va = {
            0x04e480d4ULL, 0x04e48980ULL, 0x06415004ULL,
            0x06416200ULL, 0x06416490ULL, 0x06416724ULL,
            0x06417d38ULL, 0x064230d8ULL, 0x06425130ULL,
            0x064277f0ULL,
        },
        .call_stock = {
            0x94004733U, 0x94004508U, 0x97a91367U, 0x97a90ee8U,
            0x97a90e44U, 0x97a90d9fU, 0x97a9081aU, 0x97a8db32U,
            0x97a8d31cU, 0x97a8c96cU,
        },
        .precheck_va = 0x04e59e1cULL,
        .precheck_stock = 0x35000b38U,
        .dispatch_va = 0x04e59f54ULL,
        .dispatch_stock = 0x97ffeff4U,
    },
    {
        .firmware = 0x09400000U, .name = "9.40",
        .io_mapped_base = 0x04e27000ULL,
        .io_file_size = 0x35a54ULL, .io_mapped_size = 0x36000ULL,
        .io_sram_base = 0x27000ULL,
        .dev_mapped_base = 0x06411000ULL,
        .dev_file_size = 0x32e00ULL, .dev_mapped_size = 0x33000ULL,
        .runtime_cave_va = 0x04e5cf00ULL,
        .plaintext_cave_va = 0x04e5cf50ULL,
        .helper_va = 0x04e5a6bcULL,
        .precheck_normal_va = 0x04e5a73cULL,
        .precheck_special_va = 0x04e5a770ULL,
        .common_error_va = 0x04e5a89cULL,
        .dispatch_native_va = 0x04e56840ULL,
        .plaintext_idma_va = 0x04e57300ULL,
        .sha_wait_idma_aes_va = 0x04e57794ULL,
        .submit_idma_va = 0x04e55348ULL,
        .common_return_va = 0x04e5a9acULL,
        .encrypt_kmb_range_va = 0x06418d30ULL,
        .encrypt_kmb_range_stock = 0x1a8b018bU,
        .encrypt_kmb_range_patch = 0x5280400bU,
        .call_va = {
            0x04e4879cULL, 0x04e49048ULL, 0x06414f1cULL,
            0x06416118ULL, 0x064163a8ULL, 0x0641663cULL,
            0x06417c50ULL, 0x0642313cULL, 0x064251dcULL,
            0x064278d0ULL,
        },
        .call_stock = {
            0x940047c8U, 0x9400459dU, 0x97a915e8U, 0x97a91169U,
            0x97a910c5U, 0x97a91020U, 0x97a90a9bU, 0x97a8dd60U,
            0x97a8d538U, 0x97a8cb7bU,
        },
        .precheck_va = 0x04e5a738ULL,
        .precheck_stock = 0x35000b38U,
        .dispatch_va = 0x04e5a870ULL,
        .dispatch_stock = 0x97ffeff4U,
    },
    {
        .firmware = 0x09600000U, .name = "9.60",
        .io_mapped_base = 0x04e27000ULL,
        .io_file_size = 0x35a54ULL, .io_mapped_size = 0x36000ULL,
        .io_sram_base = 0x27000ULL,
        .dev_mapped_base = 0x06411000ULL,
        .dev_file_size = 0x32e00ULL, .dev_mapped_size = 0x33000ULL,
        .runtime_cave_va = 0x04e5cf00ULL,
        .plaintext_cave_va = 0x04e5cf50ULL,
        .helper_va = 0x04e5a6bcULL,
        .precheck_normal_va = 0x04e5a73cULL,
        .precheck_special_va = 0x04e5a770ULL,
        .common_error_va = 0x04e5a89cULL,
        .dispatch_native_va = 0x04e56840ULL,
        .plaintext_idma_va = 0x04e57300ULL,
        .sha_wait_idma_aes_va = 0x04e57794ULL,
        .submit_idma_va = 0x04e55348ULL,
        .common_return_va = 0x04e5a9acULL,
        .encrypt_kmb_range_va = 0x06418d30ULL,
        .encrypt_kmb_range_stock = 0x1a8b018bU,
        .encrypt_kmb_range_patch = 0x5280400bU,
        .call_va = {
            0x04e4879cULL, 0x04e49048ULL, 0x06414f1cULL,
            0x06416118ULL, 0x064163a8ULL, 0x0641663cULL,
            0x06417c50ULL, 0x0642313cULL, 0x064251dcULL,
            0x064278d0ULL,
        },
        .call_stock = {
            0x940047c8U, 0x9400459dU, 0x97a915e8U, 0x97a91169U,
            0x97a910c5U, 0x97a91020U, 0x97a90a9bU, 0x97a8dd60U,
            0x97a8d538U, 0x97a8cb7bU,
        },
        .precheck_va = 0x04e5a738ULL,
        .precheck_stock = 0x35000b38U,
        .dispatch_va = 0x04e5a870ULL,
        .dispatch_stock = 0x97ffeff4U,
    },
};

static const char *const ppr_call_names[PPR_CALL_COUNT] = {
    "PackageRead call 1",
    "PackageRead call 2",
    "FlashReadDecryptAndVerifySha",
    "ExtFs_UnpackPackage1Block",
    "ExtFs_UnpackPackage2Block A",
    "ExtFs_UnpackPackage2Block B",
    "ExtFs_DecryptAndVerifySha",
    "NSID2_FlashAppendFromDeltaSource",
    "NSID2_FlashReadPackageFile A",
    "NSID2_FlashReadPackageFile B",
};

struct ppr_images {
    uint32_t runtime[PPR_RUNTIME_SIZE / 4U];
    uint32_t plaintext[PPR_PLAINTEXT_SIZE / 4U];
    uint32_t site_hook[PPR_SITE_COUNT];
};

struct ppr_resolved {
    uint64_t runtime_cave;
    uint64_t plaintext_cave;
    uint64_t encrypt_kmb_range;
    uint64_t site[PPR_SITE_COUNT];
};

struct ppr_state {
    uint8_t runtime[PPR_RUNTIME_SIZE];
    uint8_t plaintext[PPR_PLAINTEXT_SIZE];
    uint32_t encrypt_kmb_range;
    uint32_t site[PPR_SITE_COUNT];
    int runtime_exact;
    int plaintext_exact;
    int sites_known;
    int sites_stock;
    int sites_hooked;
    int native;
    int dynamic;
    int recoverable;
    int encrypt_kmb_range_known;
    int encrypt_kmb_range_stock;
    int encrypt_kmb_range_patched;
};

struct ppr_context {
    const struct ppr_patch_transport *transport;
    const struct ppr_profile *profile;
    struct ppr_images images;
};

static void ppr_logf(const struct ppr_context *ctx, const char *format, ...) {
    char message[512];
    va_list args;
    va_start(args, format);
    (void)vsnprintf(message, sizeof(message), format, args);
    va_end(args);
    if (ctx->transport->log)
        ctx->transport->log(ctx->transport->context, message);
}

static const struct ppr_profile *ppr_find_profile(uint32_t firmware) {
    for (size_t i = 0; i < sizeof(ppr_profiles) / sizeof(ppr_profiles[0]); i++) {
        if (ppr_profiles[i].firmware == firmware)
            return &ppr_profiles[i];
    }
    return NULL;
}

int ppr_patch_firmware_supported(uint32_t firmware) {
    return ppr_find_profile(firmware) != NULL;
}

static int ppr_encode_branch26(uint32_t opcode, uint64_t from, uint64_t to,
                               uint32_t *result) {
    int64_t delta = (int64_t)to - (int64_t)from;
    if (!result || (delta & 3) != 0 || delta < -0x08000000LL ||
        delta > 0x07fffffcLL)
        return -1;
    *result = opcode | ((uint32_t)(delta / 4) & 0x03ffffffU);
    return 0;
}

static int ppr_encode_imm19(uint32_t instruction, uint64_t from, uint64_t to,
                            uint32_t *result) {
    int64_t delta = (int64_t)to - (int64_t)from;
    if (!result || (delta & 3) != 0 || delta < -0x00100000LL ||
        delta > 0x000ffffcLL)
        return -1;
    *result = (instruction & ~0x00ffffe0U) |
              (((uint32_t)(delta / 4) & 0x7ffffU) << 5);
    return 0;
}

static int ppr_build_images(struct ppr_context *ctx) {
    const struct ppr_profile *p = ctx->profile;

    static const uint32_t runtime_template[PPR_RUNTIME_SIZE / 4U] = {
        0x394063f0U, 0x7103fe1fU, 0x54000080U, 0xd503201fU,
        0xd503201fU, 0U, 0x52800ff0U, 0xb90013f0U, 0U,
        0x35000058U, 0U, 0x7101ff1fU, 0x54000041U, 0U, 0U,
        0x7101ff1fU, 0U, 0U,
    };
    static const uint32_t plaintext_template[PPR_PLAINTEXT_SIZE / 4U] = {
        0U, 0xd360ff50U, 0U, 0x2a0403e3U,
        0xaa1a03e4U, 0x2a1903e5U, 0x2a1703e6U, 0x52800027U,
        0xf90003fcU, 0U, 0x35000060U, 0x52a02000U,
        0U, 0xaa1303e0U, 0xaa1603e1U, 0xb85f43a2U,
        0xaa1c03e3U, 0U, 0xf85f83a8U, 0xb9452509U,
        0xb944fe6aU, 0x6b09015fU, 0x1a89a149U, 0x11066929U,
        0xb904fe69U, 0xb905b509U, 0x394c226aU, 0x6b0a02ffU,
        0x54000042U, 0xb9058509U, 0xaa1303e0U, 0x52800021U,
        0U, 0xaa1303e0U, 0x2a1f03e1U, 0U,
        0x2a1f03e0U, 0U,
    };
    memcpy(ctx->images.runtime, runtime_template, sizeof(runtime_template));
    memcpy(ctx->images.plaintext, plaintext_template,
           sizeof(plaintext_template));

#define B26(array, base, index, opcode, target)                                \
    do {                                                                        \
        if (ppr_encode_branch26((opcode),                                       \
                (base) + (uint64_t)(index) * 4U,                                \
                (target), &(array)[index]) != 0)                                \
            return -1;                                                          \
    } while (0)
#define I19(array, base, index, instruction, target)                            \
    do {                                                                        \
        if (ppr_encode_imm19((instruction),                                     \
                (base) + (uint64_t)(index) * 4U,                                \
                (target), &(array)[index]) != 0)                                \
            return -1;                                                          \
    } while (0)

    B26(ctx->images.runtime, p->runtime_cave_va, 5,
        0x14000000U, p->helper_va);
    B26(ctx->images.runtime, p->runtime_cave_va, 8,
        0x14000000U, p->helper_va);
    B26(ctx->images.runtime, p->runtime_cave_va, 10,
        0x14000000U, p->precheck_normal_va);
    B26(ctx->images.runtime, p->runtime_cave_va, 13,
        0x14000000U, p->precheck_normal_va);
    B26(ctx->images.runtime, p->runtime_cave_va, 14,
        0x14000000U, p->common_error_va);
    I19(ctx->images.runtime, p->runtime_cave_va, 16,
        0x54000001U, p->dispatch_native_va);
    B26(ctx->images.runtime, p->runtime_cave_va, 17,
        0x14000000U, p->plaintext_cave_va);

    I19(ctx->images.plaintext, p->plaintext_cave_va, 0,
        0x35000014U, p->common_error_va);
    I19(ctx->images.plaintext, p->plaintext_cave_va, 2,
        0xb4000010U, p->common_error_va);
    B26(ctx->images.plaintext, p->plaintext_cave_va, 9,
        0x94000000U, p->plaintext_idma_va);
    B26(ctx->images.plaintext, p->plaintext_cave_va, 12,
        0x14000000U, p->common_return_va);
    B26(ctx->images.plaintext, p->plaintext_cave_va, 17,
        0x94000000U, p->sha_wait_idma_aes_va);
    B26(ctx->images.plaintext, p->plaintext_cave_va, 32,
        0x94000000U, p->submit_idma_va);
    B26(ctx->images.plaintext, p->plaintext_cave_va, 35,
        0x94000000U, p->submit_idma_va);
    B26(ctx->images.plaintext, p->plaintext_cave_va, 37,
        0x14000000U, p->common_return_va);

    for (size_t i = 0; i < PPR_CALL_COUNT; i++) {
        if (ppr_encode_branch26(0x94000000U, p->call_va[i],
                                p->runtime_cave_va,
                                &ctx->images.site_hook[i]) != 0)
            return -1;
    }
    if (ppr_encode_branch26(0x94000000U, p->precheck_va,
                            p->runtime_cave_va + 0x24U,
                            &ctx->images.site_hook[PPR_CALL_COUNT]) != 0 ||
        ppr_encode_branch26(0x94000000U, p->dispatch_va,
                            p->runtime_cave_va + 0x3cU,
                            &ctx->images.site_hook[PPR_CALL_COUNT + 1U]) != 0)
        return -1;

#undef B26
#undef I19
    return 0;
}

static int ppr_read(const struct ppr_context *ctx, uint64_t pa, void *dst,
                    uint32_t size) {
    return ctx->transport->read(ctx->transport->context, pa, dst, size) > 0
               ? 0 : -1;
}

static int ppr_write(const struct ppr_context *ctx, uint64_t pa,
                     const void *src, uint32_t size) {
    return ctx->transport->write(ctx->transport->context, pa, src, size);
}

static int ppr_read_layout(const struct ppr_context *ctx,
                           struct ppr_layout_record *io,
                           struct ppr_layout_record *dev) {
    uint8_t header[PPR_LAYOUT_HEADER_SIZE] = {0};
    uint8_t *snapshot = NULL;
    struct ppr_layout_record *records = NULL;
    uint32_t segment_count = 0;
    int rc = -1;

    if (ctx->transport->fast_mode) {
        size_t snapshot_size = PPR_LAYOUT_HEADER_SIZE +
            PPR_LAYOUT_MAX_SEGMENTS * sizeof(struct ppr_layout_record);
        snapshot = calloc(1, snapshot_size);
        if (!snapshot || ppr_read(ctx, PPR_PATCH_LAYOUT_PA, snapshot,
                                  (uint32_t)snapshot_size) != 0)
            goto out;
        memcpy(header, snapshot, sizeof(header));
    } else if (ppr_read(ctx, PPR_PATCH_LAYOUT_PA, header,
                        sizeof(header)) != 0) {
        goto out;
    }

    memcpy(&segment_count, header + 0x0c, sizeof(segment_count));
    if (segment_count == 0 || segment_count > PPR_LAYOUT_MAX_SEGMENTS)
        goto out;

    size_t records_size =
        (size_t)segment_count * sizeof(struct ppr_layout_record);
    records = calloc(1, records_size);
    if (!records)
        goto out;
    if (snapshot) {
        memcpy(records, snapshot + PPR_LAYOUT_HEADER_SIZE, records_size);
    } else if (ppr_read(ctx, PPR_PATCH_LAYOUT_PA + PPR_LAYOUT_HEADER_SIZE,
                        records, (uint32_t)records_size) != 0) {
        goto out;
    }

    int have_io = 0, have_dev = 0;
    for (uint32_t i = 0; i < segment_count; i++) {
        if (records[i].id == 3) {
            *io = records[i];
            have_io = 1;
        } else if (records[i].id == 11) {
            *dev = records[i];
            have_dev = 1;
        }
    }
    if (!have_io || !have_dev)
        goto out;

    const struct ppr_profile *p = ctx->profile;
    if (io->flags != 0x00030001U ||
        io->g6_base == 0 || (io->g6_base & 0xfffU) != 0 ||
        io->g6_size != p->io_file_size ||
        io->sram_base != p->io_sram_base ||
        io->sram_size < p->io_mapped_size ||
        io->mapped_base != p->io_mapped_base ||
        io->mapped_size != p->io_mapped_size ||
        dev->flags != 0x00010011U ||
        dev->g6_base == 0 || (dev->g6_base & 0xfffU) != 0 ||
        dev->g6_size != p->dev_file_size ||
        dev->sram_base != 0 || dev->sram_size != 0 ||
        dev->mapped_base != p->dev_mapped_base ||
        dev->mapped_size != p->dev_mapped_size) {
        ppr_logf(ctx, "[!] live A53 segment layout differs from the exact %s profile",
                 p->name);
        goto out;
    }
    rc = 0;

out:
    free(records);
    free(snapshot);
    return rc;
}

static int ppr_map_sram(const struct ppr_layout_record *segment, uint64_t va,
                        uint32_t size, uint64_t *pa) {
    if (!segment || !pa || va < segment->mapped_base ||
        size > segment->mapped_size ||
        va - segment->mapped_base > segment->mapped_size - size ||
        size > segment->sram_size ||
        va - segment->mapped_base > segment->sram_size - size)
        return -1;
    *pa = segment->sram_base + (va - segment->mapped_base);
    return 0;
}

static int ppr_map_g6(const struct ppr_layout_record *segment, uint64_t va,
                      uint32_t size, uint64_t *pa) {
    if (!segment || !pa || va < segment->mapped_base ||
        size > segment->mapped_size ||
        va - segment->mapped_base > segment->mapped_size - size ||
        size > segment->g6_size ||
        va - segment->mapped_base > segment->g6_size - size)
        return -1;
    *pa = segment->g6_base + (va - segment->mapped_base);
    return 0;
}

static int ppr_resolve(const struct ppr_context *ctx,
                       struct ppr_resolved *resolved) {
    struct ppr_layout_record io = {0}, dev = {0};
    const struct ppr_profile *p = ctx->profile;
    if (ppr_read_layout(ctx, &io, &dev) != 0) {
        ppr_logf(ctx, "[!] PPR exact runtime-layout validation failed");
        return -1;
    }

    if (ppr_map_sram(&io, p->runtime_cave_va, PPR_RUNTIME_SIZE,
                     &resolved->runtime_cave) != 0 ||
        ppr_map_sram(&io, p->plaintext_cave_va, PPR_PLAINTEXT_SIZE,
                     &resolved->plaintext_cave) != 0 ||
        ppr_map_g6(&dev, p->encrypt_kmb_range_va, 4,
                   &resolved->encrypt_kmb_range) != 0)
        return -1;

    for (size_t i = 0; i < PPR_CALL_COUNT; i++) {
        const struct ppr_layout_record *segment =
            i < 2 ? &io : &dev;
        int mapped = i < 2
            ? ppr_map_sram(segment, p->call_va[i], 4,
                           &resolved->site[i])
            : ppr_map_g6(segment, p->call_va[i], 4,
                         &resolved->site[i]);
        if (mapped != 0) {
            ppr_logf(ctx, "[!] %s is outside its validated runtime segment",
                     ppr_call_names[i]);
            return -1;
        }
    }
    if (ppr_map_sram(&io, p->precheck_va, 4,
                     &resolved->site[PPR_CALL_COUNT]) != 0 ||
        ppr_map_sram(&io, p->dispatch_va, 4,
                     &resolved->site[PPR_CALL_COUNT + 1U]) != 0)
        return -1;

    ppr_logf(ctx, "[+] PPR %s addresses resolved from exact runtime layout",
             p->name);
    ppr_logf(ctx, "[*] IO fixed code: executable SRAM base 0x%lx, mapped VA 0x%lx",
             (unsigned long)io.sram_base,
             (unsigned long)io.mapped_base);
    return 0;
}

static uint32_t ppr_stock_site(const struct ppr_profile *p, size_t index) {
    if (index < PPR_CALL_COUNT)
        return p->call_stock[index];
    if (index == PPR_CALL_COUNT)
        return p->precheck_stock;
    return p->dispatch_stock;
}

static int ppr_read_state(const struct ppr_context *ctx,
                          const struct ppr_resolved *resolved,
                          struct ppr_state *state) {
    memset(state, 0, sizeof(*state));

    if (ctx->transport->fast_mode && ctx->transport->batch_enabled &&
        ctx->transport->read_many) {
        uint64_t addresses[3 + PPR_SITE_COUNT];
        uint32_t sizes[3 + PPR_SITE_COUNT];
        void *destinations[3 + PPR_SITE_COUNT];
        size_t n = 0;
#define STATE_READ(address, size, destination) do { \
        addresses[n] = (address);                  \
        sizes[n] = (size);                         \
        destinations[n] = (destination);           \
        n++;                                        \
    } while (0)
        STATE_READ(resolved->runtime_cave, PPR_RUNTIME_SIZE, state->runtime);
        STATE_READ(resolved->plaintext_cave, PPR_PLAINTEXT_SIZE,
                   state->plaintext);
        STATE_READ(resolved->encrypt_kmb_range, 4,
                   &state->encrypt_kmb_range);
        for (size_t i = 0; i < PPR_SITE_COUNT; i++)
            STATE_READ(resolved->site[i], 4, &state->site[i]);
#undef STATE_READ
        if (ctx->transport->read_many(ctx->transport->context, addresses,
                                      sizes, destinations, (uint32_t)n) != 0)
            return -1;
    } else {
        if (ppr_read(ctx, resolved->runtime_cave, state->runtime,
                     sizeof(state->runtime)) != 0 ||
            ppr_read(ctx, resolved->plaintext_cave, state->plaintext,
                     sizeof(state->plaintext)) != 0 ||
            ppr_read(ctx, resolved->encrypt_kmb_range,
                     &state->encrypt_kmb_range, 4) != 0)
            return -1;
        for (size_t i = 0; i < PPR_SITE_COUNT; i++) {
            if (ppr_read(ctx, resolved->site[i], &state->site[i], 4) != 0)
                return -1;
        }
    }

    state->runtime_exact =
        memcmp(state->runtime, ctx->images.runtime, PPR_RUNTIME_SIZE) == 0;
    state->plaintext_exact =
        memcmp(state->plaintext, ctx->images.plaintext,
               PPR_PLAINTEXT_SIZE) == 0;
    state->sites_known = 1;
    state->sites_stock = 1;
    state->sites_hooked = 1;
    for (size_t i = 0; i < PPR_SITE_COUNT; i++) {
        int stock = state->site[i] == ppr_stock_site(ctx->profile, i);
        int hooked = state->site[i] == ctx->images.site_hook[i];
        state->sites_known &= stock || hooked;
        state->sites_stock &= stock;
        state->sites_hooked &= hooked;
    }

    /* Cave padding is deliberately irrelevant while every entry is stock. */
    state->native = state->sites_stock;
    state->dynamic = state->runtime_exact && state->plaintext_exact &&
                     state->sites_hooked;
    state->recoverable = !state->native && !state->dynamic &&
                         state->runtime_exact && state->plaintext_exact &&
                         state->sites_known;
    state->encrypt_kmb_range_stock =
        state->encrypt_kmb_range == ctx->profile->encrypt_kmb_range_stock;
    state->encrypt_kmb_range_patched =
        state->encrypt_kmb_range == ctx->profile->encrypt_kmb_range_patch;
    state->encrypt_kmb_range_known = state->encrypt_kmb_range_stock ||
                                     state->encrypt_kmb_range_patched;
    return 0;
}

static void ppr_print_state(const struct ppr_context *ctx,
                            const struct ppr_state *state) {
    if (state->native) {
        ppr_logf(ctx, "[+] PPR patch state: STOCK/NATIVE (unused tail ignored)");
    } else if (state->dynamic) {
        ppr_logf(ctx, "[+] PPR patch state: DYNAMIC_INSTALLED (10 callers; AES ff => PLAINTEXT_NOAUTH)");
    } else if (state->recoverable) {
        ppr_logf(ctx, "[!] PPR patch state: INTERRUPTED BUT EXACTLY RECOVERABLE");
    } else {
        ppr_logf(ctx, "[!] PPR patch state: UNKNOWN OR PARTIALLY PATCHED");
        ppr_logf(ctx, "    runtime=%s plaintext=%s sites=%s",
                 state->runtime_exact ? "PATCH" : "UNKNOWN",
                 state->plaintext_exact ? "PATCH" : "UNKNOWN",
                 state->sites_known ? "KNOWN-MIX" : "UNKNOWN");
        ppr_logf(ctx, "    call1=%08x call2=%08x precheck=%08x dispatch=%08x",
                 state->site[0], state->site[1],
                 state->site[PPR_CALL_COUNT],
                 state->site[PPR_CALL_COUNT + 1U]);
    }
    if (state->encrypt_kmb_range_patched) {
        ppr_logf(ctx, "[+] encryption KMB aperture: EXTENDED (upper bound 512; lower bound retained)");
    } else if (state->encrypt_kmb_range_stock) {
        ppr_logf(ctx, "[*] encryption KMB aperture: STOCK (request-class limit)");
    } else {
        ppr_logf(ctx, "[!] encryption KMB aperture: UNKNOWN (%08x)",
                 state->encrypt_kmb_range);
    }
}

static int ppr_write_checked(const struct ppr_context *ctx, uint64_t pa,
                             const void *bytes, uint32_t size,
                             const char *name) {
    uint8_t verify[PPR_PLAINTEXT_SIZE];
    if (size > sizeof(verify) || ppr_write(ctx, pa, bytes, size) != 0 ||
        ppr_read(ctx, pa, verify, size) != 0 ||
        memcmp(verify, bytes, size) != 0) {
        ppr_logf(ctx, "[!] write/readback failed for %s @ PA 0x%lx",
                 name, (unsigned long)pa);
        return -1;
    }
    return 0;
}

static int ppr_write_pair_checked(const struct ppr_context *ctx,
                                  uint64_t pa0, const void *bytes0,
                                  uint32_t size0, const char *name0,
                                  uint64_t pa1, const void *bytes1,
                                  uint32_t size1, const char *name1) {
    if (!ctx->transport->fast_mode || !ctx->transport->batch_enabled ||
        !ctx->transport->mixed_io_enabled ||
        !ctx->transport->write_pair_read_pair) {
        if (ppr_write_checked(ctx, pa0, bytes0, size0, name0) != 0)
            return -1;
        return ppr_write_checked(ctx, pa1, bytes1, size1, name1);
    }

    uint8_t verify0[PPR_PLAINTEXT_SIZE];
    uint8_t verify1[PPR_PLAINTEXT_SIZE];
    if (size0 > sizeof(verify0) || size1 > sizeof(verify1) ||
        ctx->transport->write_pair_read_pair(
            ctx->transport->context,
            pa0, bytes0, size0, verify0,
            pa1, bytes1, size1, verify1) != 0 ||
        memcmp(verify0, bytes0, size0) != 0 ||
        memcmp(verify1, bytes1, size1) != 0) {
        ppr_logf(ctx, "[!] paired write/readback failed for %s / %s @ PA 0x%lx / 0x%lx",
                 name0, name1, (unsigned long)pa0, (unsigned long)pa1);
        return -1;
    }
    return 0;
}

static int ppr_write_sites(const struct ppr_context *ctx,
                           const struct ppr_resolved *resolved,
                           size_t first, size_t end, int install) {
    size_t i = first;
    for (; ctx->transport->fast_mode && ctx->transport->batch_enabled &&
           ctx->transport->mixed_io_enabled &&
           ctx->transport->write_pair_read_pair && i + 1 < end; i += 2) {
        uint32_t value0 = install ? ctx->images.site_hook[i]
                                  : ppr_stock_site(ctx->profile, i);
        uint32_t value1 = install ? ctx->images.site_hook[i + 1]
                                  : ppr_stock_site(ctx->profile, i + 1);
        const char *name0 = i < PPR_CALL_COUNT ? ppr_call_names[i]
                                               : (i == PPR_CALL_COUNT
                                                  ? "precheck" : "dispatch");
        const char *name1 = i + 1 < PPR_CALL_COUNT ? ppr_call_names[i + 1]
                                                   : (i + 1 == PPR_CALL_COUNT
                                                      ? "precheck" : "dispatch");
        if (ppr_write_pair_checked(ctx,
                resolved->site[i], &value0, 4, name0,
                resolved->site[i + 1], &value1, 4, name1) != 0)
            return -1;
    }
    for (; i < end; i++) {
        uint32_t value = install ? ctx->images.site_hook[i]
                                 : ppr_stock_site(ctx->profile, i);
        const char *name = i < PPR_CALL_COUNT ? ppr_call_names[i]
                                              : (i == PPR_CALL_COUNT
                                                 ? "precheck" : "dispatch");
        if (ppr_write_checked(ctx, resolved->site[i], &value, 4, name) != 0)
            return -1;
    }
    return 0;
}

static void ppr_restore_stock_best_effort(const struct ppr_context *ctx,
                                          const struct ppr_resolved *resolved) {
    /* Disconnect all entry points; dormant cave bytes are harmless. */
    for (size_t i = 0; i < PPR_SITE_COUNT; i++) {
        uint32_t stock = ppr_stock_site(ctx->profile, i);
        (void)ppr_write(ctx, resolved->site[i], &stock, 4);
    }
}

static void ppr_print_stats(const struct ppr_context *ctx) {
    if (!ctx->transport->fast_mode)
        return;
    uint64_t transactions = ctx->transport->transaction_count
        ? ctx->transport->transaction_count(ctx->transport->context) : 0;
    uint64_t opens = ctx->transport->transport_open_count
        ? ctx->transport->transport_open_count(ctx->transport->context) : 0;
    uint64_t ticks = ctx->transport->elapsed_ticks
        ? ctx->transport->elapsed_ticks(ctx->transport->context) : 0;
    ppr_logf(ctx, "[+] PPR FAST stats: %lu transactions, %lu transport opens, 0x%lx ticks",
             (unsigned long)transactions, (unsigned long)opens,
             (unsigned long)ticks);
}

int ppr_patch_run(const struct ppr_patch_transport *transport,
                  uint32_t firmware, enum ppr_patch_action action,
                  int idle_acknowledged) {
    if (!transport || !transport->read || !transport->write)
        return -1;
    const struct ppr_profile *profile = ppr_find_profile(firmware);
    if (!profile) {
        if (transport->log) {
            char message[128];
            (void)snprintf(message, sizeof(message),
                           "[!] unsupported PPR A53 firmware 0x%08x", firmware);
            transport->log(transport->context, message);
        }
        return -1;
    }

    struct ppr_context ctx = {
        .transport = transport,
        .profile = profile,
    };
    if (ppr_build_images(&ctx) != 0) {
        ppr_logf(&ctx, "[!] internal AArch64 branch generation failed for %s",
                 profile->name);
        return -1;
    }
    if (action != PPR_PATCH_STATUS && !idle_acknowledged) {
        ppr_logf(&ctx, "[!] refusing A53 mutation: halt/drain PackageRead and APR rings, then pass --i-know-ppr-idle");
        return -1;
    }
    if (transport->fast_mode)
        ppr_logf(&ctx, "[+] PPR mode: FAST (layout/state batching=%s, paired write/readback=%s)",
                 transport->batch_enabled && transport->read_many ? "on" : "off",
                 transport->batch_enabled && transport->mixed_io_enabled &&
                 transport->write_pair_read_pair ? "on" : "off");

    struct ppr_resolved resolved = {0};
    struct ppr_state before, after;
    if (ppr_resolve(&ctx, &resolved) != 0 ||
        ppr_read_state(&ctx, &resolved, &before) != 0)
        return -1;
    ppr_print_state(&ctx, &before);

    if (action == PPR_PATCH_STATUS) {
        ppr_logf(&ctx, "[*] runtime cave VA=0x%lx PA=0x%lx",
                 (unsigned long)profile->runtime_cave_va,
                 (unsigned long)resolved.runtime_cave);
        ppr_logf(&ctx, "[*] plaintext cave VA=0x%lx PA=0x%lx",
                 (unsigned long)profile->plaintext_cave_va,
                 (unsigned long)resolved.plaintext_cave);
        ppr_logf(&ctx, "[*] encryption KMB range VA=0x%lx PA=0x%lx",
                 (unsigned long)profile->encrypt_kmb_range_va,
                 (unsigned long)resolved.encrypt_kmb_range);
        ppr_print_stats(&ctx);
        return (before.native || before.dynamic) &&
               before.encrypt_kmb_range_known ? 0 : -1;
    }

    if (action == PPR_PATCH_KMB_RANGE_INSTALL ||
        action == PPR_PATCH_KMB_RANGE_UNINSTALL) {
        int range_install = action == PPR_PATCH_KMB_RANGE_INSTALL;
        if (!before.encrypt_kmb_range_known) {
            ppr_logf(&ctx, "[!] KMB range change refused: exact stock or patched instruction required");
            return -1;
        }
        if ((range_install && before.encrypt_kmb_range_patched) ||
            (!range_install && before.encrypt_kmb_range_stock)) {
            ppr_logf(&ctx, "[+] encryption KMB range is already %s",
                     range_install ? "extended" : "stock");
            ppr_print_stats(&ctx);
            return 0;
        }

        uint32_t value = range_install
            ? profile->encrypt_kmb_range_patch
            : profile->encrypt_kmb_range_stock;
        if (ppr_write_checked(&ctx, resolved.encrypt_kmb_range, &value, 4,
                              "ExtFs encrypt KMB upper-bound instruction") != 0 ||
            ppr_read_state(&ctx, &resolved, &after) != 0)
            return -1;
        ppr_print_state(&ctx, &after);
        ppr_print_stats(&ctx);
        return range_install ? (after.encrypt_kmb_range_patched ? 0 : -1)
                             : (after.encrypt_kmb_range_stock ? 0 : -1);
    }

    int install = action == PPR_PATCH_INSTALL ||
                  action == PPR_PATCH_MODE_PLAINTEXT_NOAUTH;
    if (install) {
        if (before.dynamic) {
            ppr_logf(&ctx, "[+] dynamic Native/PLAINTEXT_NOAUTH patch is already installed");
            ppr_print_stats(&ctx);
            return 0;
        }
        if (!before.native && !before.recoverable) {
            ppr_logf(&ctx, "[!] install refused: exact stock or recoverable signatures are required");
            return -1;
        }
        if (before.recoverable) {
            ppr_logf(&ctx, "[*] restoring exact stock entry points before retry");
            ppr_restore_stock_best_effort(&ctx, &resolved);
            if (ppr_read_state(&ctx, &resolved, &before) != 0 ||
                !before.native) {
                ppr_logf(&ctx, "[!] exact stock recovery failed");
                return -1;
            }
        }

        /* Build dormant code first, then connect control-flow sites. */
        if (ppr_write_pair_checked(
                &ctx, resolved.plaintext_cave, ctx.images.plaintext,
                PPR_PLAINTEXT_SIZE, "plaintext SRAM-tail cave",
                resolved.runtime_cave, ctx.images.runtime,
                PPR_RUNTIME_SIZE, "runtime controller cave") != 0 ||
            ppr_write_sites(&ctx, &resolved, PPR_CALL_COUNT,
                            PPR_SITE_COUNT, 1) != 0 ||
            ppr_write_sites(&ctx, &resolved, 0, PPR_CALL_COUNT, 1) != 0) {
            ppr_logf(&ctx, "[!] dynamic install failed; attempting stock rollback");
            ppr_restore_stock_best_effort(&ctx, &resolved);
            return -1;
        }
    } else {
        if (before.native) {
            ppr_logf(&ctx, "[+] patch is already absent");
            return 0;
        }
        if (!before.dynamic && !before.recoverable) {
            ppr_logf(&ctx, "[!] uninstall refused: state is neither installed nor exactly recoverable");
            return -1;
        }
        if (before.recoverable)
            ppr_logf(&ctx, "[*] rolling back an interrupted exact-image transaction");

        /* Disconnect public callers before the two internal entry points. */
        if (ppr_write_sites(&ctx, &resolved, 0, PPR_CALL_COUNT, 0) != 0 ||
            ppr_write_sites(&ctx, &resolved, PPR_CALL_COUNT,
                            PPR_SITE_COUNT, 0) != 0) {
            ppr_logf(&ctx, "[!] stock restore failed; leaving best-effort stock entry points");
            ppr_restore_stock_best_effort(&ctx, &resolved);
            return -1;
        }
    }

    if (ppr_read_state(&ctx, &resolved, &after) != 0)
        return -1;
    ppr_print_state(&ctx, &after);
    ppr_print_stats(&ctx);
    return install ? (after.dynamic ? 0 : -1)
                   : (after.native ? 0 : -1);
}
