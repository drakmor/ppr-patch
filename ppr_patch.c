#include "ppr_patch.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PPR_CALL_COUNT 10U
#define PPR_SITE_COUNT (PPR_CALL_COUNT + 2U)
#define PPR_RUNTIME_SIZE 0x4cU
#define PPR_PLAINTEXT_SIZE 0xa0U
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

    enum {
        PPR_ABI_LEGACY,
        PPR_ABI_CURRENT,
        PPR_ABI_LATE,
    } abi;
    int merged_text;
    int cave_in_dev;

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
     * FlashWriteEncryptAndCalculateSha (opcode 0x53) has a second, unrelated
     * whitelist for the 8-bit AES base index encoded in its command header.
     * Redirect only the out-of-range rejection to the native success path;
     * the stock per-index filter inside its original range remains intact.
     * The command format still limits AES/SHA indices to 0..255 and callers
     * must keep the AES-XTS pair within that aperture.
     */
    uint64_t fswrite_kmb_range_va;
    uint32_t fswrite_kmb_range_stock;
    uint32_t fswrite_kmb_range_patch;

    uint64_t call_va[PPR_CALL_COUNT];
    uint32_t call_stock[PPR_CALL_COUNT];
    uint64_t precheck_va;
    uint32_t precheck_stock;
    uint64_t dispatch_va;
    uint32_t dispatch_stock;
};

/* Generated from the complete MP4 A53 ELF set. */
#include "ppr_profiles.inc"

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
    uint64_t fswrite_kmb_range;
    uint64_t site[PPR_SITE_COUNT];
};

struct ppr_state {
    uint8_t runtime[PPR_RUNTIME_SIZE];
    uint8_t plaintext[PPR_PLAINTEXT_SIZE];
    uint32_t fswrite_kmb_range;
    uint32_t site[PPR_SITE_COUNT];
    int runtime_exact;
    int plaintext_exact;
    int sites_known;
    int sites_stock;
    int sites_hooked;
    int native;
    int dynamic;
    int recoverable;
    int fswrite_kmb_range_known;
    int fswrite_kmb_range_stock;
    int fswrite_kmb_range_patched;
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
    int far = p->cave_in_dev && !p->merged_text;

    static const uint32_t runtime_template[PPR_RUNTIME_SIZE / 4U] = {
        0x394063f0U, 0x7103fe1fU, 0x54000080U, 0xd503201fU,
        0xd503201fU, 0U, 0x52800ff0U, 0xb90013f0U, 0U,
        0x35000058U, 0U, 0x7101ff1fU, 0x54000041U, 0U, 0U,
        0x7101ff1fU, 0U, 0U, 0U,
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
    static const uint32_t legacy_far_template[PPR_PLAINTEXT_SIZE / 4U] = {
        0x34000054U, 0U, 0xd360ff50U, 0xb5000050U,
        0U, 0x2a0403e3U, 0xaa1a03e4U, 0x2a0603e5U,
        0x2a1703e6U, 0x52800027U, 0xf90003f9U, 0U,
        0x35000060U, 0x52a02000U, 0U, 0xaa1303e0U,
        0xaa1603e1U, 0xb85ac3a2U, 0xaa1903e3U, 0U,
        0x8b374a68U, 0xb9452509U, 0xb944fe6aU, 0x6b09015fU,
        0x1a89a149U, 0x11066929U, 0xb904fe69U, 0xb905b509U,
        0x394c226aU, 0x6b0a02ffU, 0x54000042U, 0xb9058509U,
        0xaa1303e0U, 0x52800021U, 0U, 0xaa1303e0U,
        0x2a1f03e1U, 0U, 0x2a1f03e0U, 0U,
    };
    memcpy(ctx->images.runtime, runtime_template, sizeof(runtime_template));
    memcpy(ctx->images.plaintext,
           far ? legacy_far_template : plaintext_template,
           sizeof(ctx->images.plaintext));

    if (far && p->abi != PPR_ABI_LEGACY)
        return -1;
    if (p->abi == PPR_ABI_LATE) {
        ctx->images.runtime[9] = 0x3500005cU;  /* cbnz w28 */
        ctx->images.runtime[11] = 0x7101ff9fU; /* cmp w28, #0x7f */
        ctx->images.runtime[15] = 0x7101ff9fU;
        ctx->images.plaintext[1] = 0xd360fcd0U; /* lsr x16, x6, #32 */
        ctx->images.plaintext[4] = 0xaa0603e4U; /* mov x4, x6 */
        ctx->images.plaintext[5] = 0x2a0603e5U; /* mov w5, w6 */
        ctx->images.plaintext[8] = 0xf90003f6U; /* str x22, [sp] */
        ctx->images.plaintext[14] = 0xaa1a03e1U; /* mov x1, x26 */
        ctx->images.plaintext[16] = 0xaa1603e3U; /* mov x3, x22 */
        ctx->images.plaintext[18] = 0xaa1903e8U; /* mov x8, x25 */
    } else if (p->abi == PPR_ABI_LEGACY && !far) {
        ctx->images.plaintext[5] = 0x2a0603e5U; /* mov w5, w6 */
        ctx->images.plaintext[8] = 0xf90003f9U; /* str x25, [sp] */
        ctx->images.plaintext[15] = 0xb85ac3a2U; /* ldur w2, [x29, #-0x54] */
        ctx->images.plaintext[16] = 0xaa1903e3U; /* mov x3, x25 */
        ctx->images.plaintext[18] = 0x8b374a68U; /* queue pointer */
        if (p->merged_text) {
            ctx->images.plaintext[19] = 0xb94a3909U;
            ctx->images.plaintext[20] = 0xb949f66aU;
            ctx->images.plaintext[24] = 0xb909f669U;
            ctx->images.plaintext[25] = 0xb90ac909U;
            ctx->images.plaintext[26] = 0x3950226aU;
            ctx->images.plaintext[29] = 0xb90a9909U;
        }
    }

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
    if (far) {
        ctx->images.runtime[16] = 0x54000040U; /* b.eq runtime + 0x48 */
        B26(ctx->images.runtime, p->runtime_cave_va, 17,
            0x14000000U, p->dispatch_native_va);
        B26(ctx->images.runtime, p->runtime_cave_va, 18,
            0x14000000U, p->plaintext_cave_va);

        B26(ctx->images.plaintext, p->plaintext_cave_va, 1,
            0x14000000U, p->common_error_va);
        B26(ctx->images.plaintext, p->plaintext_cave_va, 4,
            0x14000000U, p->common_error_va);
        B26(ctx->images.plaintext, p->plaintext_cave_va, 11,
            0x94000000U, p->plaintext_idma_va);
        B26(ctx->images.plaintext, p->plaintext_cave_va, 14,
            0x14000000U, p->common_return_va);
        B26(ctx->images.plaintext, p->plaintext_cave_va, 19,
            0x94000000U, p->sha_wait_idma_aes_va);
        B26(ctx->images.plaintext, p->plaintext_cave_va, 34,
            0x94000000U, p->submit_idma_va);
        B26(ctx->images.plaintext, p->plaintext_cave_va, 37,
            0x94000000U, p->submit_idma_va);
        B26(ctx->images.plaintext, p->plaintext_cave_va, 39,
            0x14000000U, p->common_return_va);
    } else {
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
    }

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

    const struct ppr_profile *p = ctx->profile;
    int have_io = p->merged_text, have_dev = 0;
    for (uint32_t i = 0; i < segment_count; i++) {
        if (!p->merged_text && records[i].flags == 0x00030001U &&
            records[i].g6_base != 0 &&
            (records[i].g6_base & 0xfffU) == 0 &&
            records[i].g6_size == p->io_file_size &&
            records[i].sram_base == p->io_sram_base &&
            records[i].sram_size >= p->io_mapped_size &&
            records[i].mapped_base == p->io_mapped_base &&
            records[i].mapped_size == p->io_mapped_size) {
            *io = records[i];
            have_io = 1;
        }
        if (records[i].flags == 0x00010011U &&
            records[i].g6_base != 0 &&
            (records[i].g6_base & 0xfffU) == 0 &&
            records[i].g6_size == p->dev_file_size &&
            records[i].sram_base == 0 && records[i].sram_size == 0 &&
            records[i].mapped_base == p->dev_mapped_base &&
            records[i].mapped_size == p->dev_mapped_size) {
            *dev = records[i];
            have_dev = 1;
        }
    }
    if (!have_io || !have_dev)
        goto out;

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

static int ppr_map_g6_padding(const struct ppr_layout_record *segment,
                              uint64_t va, uint32_t size, uint64_t *pa) {
    if (!segment || !pa || segment->g6_base == 0 ||
        va < segment->mapped_base || size > segment->mapped_size ||
        va - segment->mapped_base > segment->mapped_size - size)
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

    const struct ppr_layout_record *cave = p->cave_in_dev ? &dev : &io;
    int runtime_mapped = p->cave_in_dev
        ? ppr_map_g6_padding(cave, p->runtime_cave_va, PPR_RUNTIME_SIZE,
                             &resolved->runtime_cave)
        : ppr_map_sram(cave, p->runtime_cave_va, PPR_RUNTIME_SIZE,
                       &resolved->runtime_cave);
    int plaintext_mapped = p->cave_in_dev
        ? ppr_map_g6_padding(cave, p->plaintext_cave_va, PPR_PLAINTEXT_SIZE,
                             &resolved->plaintext_cave)
        : ppr_map_sram(cave, p->plaintext_cave_va, PPR_PLAINTEXT_SIZE,
                       &resolved->plaintext_cave);
    if (runtime_mapped != 0 || plaintext_mapped != 0 ||
        (p->fswrite_kmb_range_va != 0 &&
         ppr_map_g6(&dev, p->fswrite_kmb_range_va, 4,
                    &resolved->fswrite_kmb_range) != 0))
        return -1;

    for (size_t i = 0; i < PPR_CALL_COUNT; i++) {
        const struct ppr_layout_record *segment =
            !p->merged_text && i < 2 ? &io : &dev;
        int mapped = !p->merged_text && i < 2
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
    int precheck_mapped = p->merged_text
        ? ppr_map_g6(&dev, p->precheck_va, 4,
                     &resolved->site[PPR_CALL_COUNT])
        : ppr_map_sram(&io, p->precheck_va, 4,
                       &resolved->site[PPR_CALL_COUNT]);
    int dispatch_mapped = p->merged_text
        ? ppr_map_g6(&dev, p->dispatch_va, 4,
                     &resolved->site[PPR_CALL_COUNT + 1U])
        : ppr_map_sram(&io, p->dispatch_va, 4,
                       &resolved->site[PPR_CALL_COUNT + 1U]);
    if (precheck_mapped != 0 || dispatch_mapped != 0)
        return -1;

    ppr_logf(ctx, "[+] PPR %s addresses resolved from exact runtime layout",
             p->name);
    if (p->merged_text) {
        ppr_logf(ctx, "[*] merged DEV code: G6 base 0x%lx, mapped VA 0x%lx",
                 (unsigned long)dev.g6_base,
                 (unsigned long)dev.mapped_base);
    } else {
        ppr_logf(ctx, "[*] IO fixed code: executable SRAM base 0x%lx, mapped VA 0x%lx",
                 (unsigned long)io.sram_base,
                 (unsigned long)io.mapped_base);
    }
    return 0;
}

static uint32_t ppr_stock_site(const struct ppr_profile *p, size_t index) {
    if (index < PPR_CALL_COUNT)
        return p->call_stock[index];
    if (index == PPR_CALL_COUNT)
        return p->precheck_stock;
    return p->dispatch_stock;
}

static int ppr_kmb_supported(const struct ppr_context *ctx) {
    return ctx->profile->fswrite_kmb_range_va != 0;
}

static void ppr_classify_kmb_state(const struct ppr_context *ctx,
                                   struct ppr_state *state) {
    if (!ppr_kmb_supported(ctx)) {
        state->fswrite_kmb_range_known = 1;
        state->fswrite_kmb_range_stock = 1;
        return;
    }
    state->fswrite_kmb_range_stock = state->fswrite_kmb_range ==
                                     ctx->profile->fswrite_kmb_range_stock;
    state->fswrite_kmb_range_patched = state->fswrite_kmb_range ==
                                       ctx->profile->fswrite_kmb_range_patch;
    state->fswrite_kmb_range_known = state->fswrite_kmb_range_stock ||
                                     state->fswrite_kmb_range_patched;
}

static int ppr_read_kmb_state(const struct ppr_context *ctx,
                              const struct ppr_resolved *resolved,
                              struct ppr_state *state) {
    memset(state, 0, sizeof(*state));
    /*
     * Keep the mutation payload on scalar transactions.  Besides avoiding a
     * full unrelated selector-state read, this never emits the 16-command
     * SDBGP packet used by the general status path.
     */
    if (ppr_read(ctx, resolved->fswrite_kmb_range,
                 &state->fswrite_kmb_range, 4) != 0)
        return -1;
    ppr_classify_kmb_state(ctx, state);
    return 0;
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
        if (ppr_kmb_supported(ctx))
            STATE_READ(resolved->fswrite_kmb_range, 4,
                       &state->fswrite_kmb_range);
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
            (ppr_kmb_supported(ctx) &&
             ppr_read(ctx, resolved->fswrite_kmb_range,
                      &state->fswrite_kmb_range, 4) != 0))
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
    ppr_classify_kmb_state(ctx, state);
    return 0;
}

static int ppr_kmb_state_known(const struct ppr_state *state) {
    return state->fswrite_kmb_range_known;
}

static int ppr_kmb_state_stock(const struct ppr_state *state) {
    return state->fswrite_kmb_range_stock;
}

static int ppr_kmb_state_patched(const struct ppr_state *state) {
    return state->fswrite_kmb_range_patched;
}

static void ppr_print_kmb_state(const struct ppr_context *ctx,
                                const struct ppr_state *state) {
    if (!ppr_kmb_supported(ctx))
        return;
    if (ppr_kmb_state_patched(state)) {
        ppr_logf(ctx, "[+] FsWrite opcode 0x53 KMB range guard: BYPASSED");
    } else if (ppr_kmb_state_stock(state)) {
        ppr_logf(ctx, "[*] FsWrite opcode 0x53 KMB range guard: STOCK");
    } else {
        ppr_logf(ctx, "[!] FsWrite opcode 0x53 KMB range guard: UNKNOWN (%08x)",
                 state->fswrite_kmb_range);
    }
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
    ppr_print_kmb_state(ctx, state);
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

static int ppr_change_kmb_state(const struct ppr_context *ctx,
                                const struct ppr_resolved *resolved,
                                enum ppr_patch_action action) {
    struct ppr_state before, after;
    int install = action == PPR_PATCH_KMB_RANGE_INSTALL;
    if (!ppr_kmb_supported(ctx)) {
        ppr_logf(ctx, "[!] FsWrite KMB range patch is unavailable for MP4 %s",
                 ctx->profile->name);
        return -1;
    }
    if (ppr_read_kmb_state(ctx, resolved, &before) != 0)
        return -1;
    ppr_print_kmb_state(ctx, &before);
    if (!ppr_kmb_state_known(&before)) {
        ppr_logf(ctx, "[!] FsWrite KMB change refused: instruction must be an exact stock or patched value");
        return -1;
    }
    if ((install && ppr_kmb_state_patched(&before)) ||
        (!install && ppr_kmb_state_stock(&before))) {
        ppr_logf(ctx, "[+] FsWrite opcode 0x53 KMB range guard is already %s",
                 install ? "bypassed" : "stock");
        ppr_print_stats(ctx);
        return 0;
    }

    uint32_t desired = install ? ctx->profile->fswrite_kmb_range_patch
                               : ctx->profile->fswrite_kmb_range_stock;
    if (ppr_write_checked(ctx, resolved->fswrite_kmb_range, &desired, 4,
                          "FsWrite encrypt KMB range instruction") != 0 ||
        ppr_read_kmb_state(ctx, resolved, &after) != 0) {
        ppr_logf(ctx, "[!] FsWrite KMB update failed");
        return -1;
    }
    ppr_print_kmb_state(ctx, &after);
    ppr_print_stats(ctx);
    return install ? (ppr_kmb_state_patched(&after) ? 0 : -1)
                   : (ppr_kmb_state_stock(&after) ? 0 : -1);
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
    if (ppr_resolve(&ctx, &resolved) != 0)
        return -1;
    if (action == PPR_PATCH_KMB_RANGE_INSTALL ||
        action == PPR_PATCH_KMB_RANGE_UNINSTALL)
        return ppr_change_kmb_state(&ctx, &resolved, action);
    if (ppr_read_state(&ctx, &resolved, &before) != 0)
        return -1;
    ppr_print_state(&ctx, &before);

    if (action == PPR_PATCH_STATUS) {
        ppr_logf(&ctx, "[*] runtime cave VA=0x%lx PA=0x%lx",
                 (unsigned long)profile->runtime_cave_va,
                 (unsigned long)resolved.runtime_cave);
        ppr_logf(&ctx, "[*] plaintext cave VA=0x%lx PA=0x%lx",
                 (unsigned long)profile->plaintext_cave_va,
                 (unsigned long)resolved.plaintext_cave);
        if (ppr_kmb_supported(&ctx))
            ppr_logf(&ctx, "[*] FsWrite KMB range guard VA=0x%lx PA=0x%lx",
                     (unsigned long)profile->fswrite_kmb_range_va,
                     (unsigned long)resolved.fswrite_kmb_range);
        ppr_print_stats(&ctx);
        return (before.native || before.dynamic) &&
               (ppr_kmb_state_stock(&before) ||
                ppr_kmb_state_patched(&before)) ? 0 : -1;
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
                PPR_PLAINTEXT_SIZE, "plaintext executable-tail cave",
                resolved.runtime_cave, ctx.images.runtime,
                PPR_RUNTIME_SIZE, "runtime executable-tail cave") != 0 ||
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
