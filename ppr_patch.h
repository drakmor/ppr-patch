#ifndef A53_PPR_PATCH_H
#define A53_PPR_PATCH_H

#include <stdint.h>

enum ppr_patch_action {
    PPR_PATCH_STATUS = 0,
    PPR_PATCH_INSTALL,
    PPR_PATCH_UNINSTALL,
    PPR_PATCH_MODE_NATIVE,
    PPR_PATCH_MODE_PLAINTEXT_NOAUTH,
    PPR_PATCH_KMB_RANGE_INSTALL,
    PPR_PATCH_KMB_RANGE_UNINSTALL,
};

/*
 * The PPR patcher deliberately knows nothing about the PS5 kernel API or the
 * DECI5S packet format.  A frontend supplies the four transport operations
 * below. Scalar read returns a positive transferred-byte count; scalar write,
 * read_many and write_pair_read_pair return zero on success. The latter two
 * callbacks are optional accelerators.
 */
struct ppr_patch_transport {
    void *context;

    int (*read)(void *context, uint64_t pa, void *dst, uint32_t size);
    int (*write)(void *context, uint64_t pa, const void *src,
                 uint32_t size);
    int (*read_many)(void *context, const uint64_t *addresses,
                     const uint32_t *sizes, void *const *destinations,
                     uint32_t count);
    int (*write_pair_read_pair)(void *context,
                                uint64_t pa0, const void *src0,
                                uint32_t size0, void *readback0,
                                uint64_t pa1, const void *src1,
                                uint32_t size1, void *readback1);

    /* One complete, newline-free message per call. */
    void (*log)(void *context, const char *message);

    uint64_t (*transaction_count)(void *context);
    uint64_t (*transport_open_count)(void *context);
    uint64_t (*elapsed_ticks)(void *context);

    int fast_mode;
    int batch_enabled;
    int mixed_io_enabled;
};

/* Physical address of the PSP-populated A53 runtime layout. */
#define PPR_PATCH_LAYOUT_PA 0x887F0000ULL

int ppr_patch_firmware_supported(uint32_t firmware);
int ppr_patch_run(const struct ppr_patch_transport *transport,
                  uint32_t firmware, enum ppr_patch_action action,
                  int idle_acknowledged);

#endif
