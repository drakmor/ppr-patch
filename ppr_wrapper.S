/*
 * AArch64 wrappers for the MP4 PPR common read pipeline.  Link-time symbols
 * and section addresses come from the selected exact firmware profile.
 */

#ifndef PPR_ABI
#define PPR_ABI 1
#endif
#ifndef PPR_FAR_BRANCHES
#define PPR_FAR_BRANCHES 0
#endif
#ifndef PPR_MERGED_TEXT
#define PPR_MERGED_TEXT 0
#endif

/*
 * FE/FF are the values published by the kernel-side plaintext mount path.
 * Replace them with values outside the hardware descriptor fields after the
 * complete pair has matched.  The private markers scope the two internal
 * hooks to requests which passed this entry selector; unrelated users of the
 * shared descriptor producer retain native semantics.
 */
#define PPR_AES_MARKER 0x7ff
#define PPR_SHA_MARKER 0x7fe

#if PPR_MERGED_TEXT
#define PPR_Q1_CYCLE_OFFSET 0x22
#define PPR_ZCN_CONFIG_OFFSET 0x408
#define PPR_ZCN_RELEASE_OFFSET 0x460
#define PPR_ZCN_RELEASE_BITS_OFFSET 0x600
#else
#define PPR_Q1_CYCLE_OFFSET 0x14
#define PPR_ZCN_CONFIG_OFFSET 0x308
#define PPR_ZCN_RELEASE_OFFSET 0x360
#define PPR_ZCN_RELEASE_BITS_OFFSET 0x458
#endif

.section .runtime, "ax"
.balign 4
.global ppr_wrapper
.type ppr_wrapper, %function

.extern original_helper
.extern aes_descriptor
.extern plaintext_descriptor

ppr_wrapper:
    /* Match the complete full-width pair.  Do not alias valid KMB indices. */
    ldr     w16, [sp, #0x18]       /* kmbIdxKeyAes */
    cmp     w16, #0xff
    b.ne    1f
    ldr     w16, [sp, #0x20]       /* kmbIdxKeySha */
    cmp     w16, #0xfe
    b.ne    1f
    mov     w16, #PPR_AES_MARKER
    str     w16, [sp, #0x18]
    mov     w16, #PPR_SHA_MARKER
    str     w16, [sp, #0x20]
1:
    b       original_helper

.global ppr_aes_or_plaintext
.type ppr_aes_or_plaintext, %function
ppr_aes_or_plaintext:
    /*
     * Both native dispatch modes call the same descriptor producer:
     *   x0 queue, w1 size, x2 source, w3 ZCN destination, w4 PASID,
     *   w5 direction, w6 AES command, w7 KMB index.
     * The stock plaintext descriptor has the same first five arguments;
     * engine 5 is the firmware's physical-to-ZCN passthrough engine.
     */
    cmp     w7, #PPR_AES_MARKER
    b.ne    2f
    mov     w5, #5
    b       plaintext_descriptor
2:
    b       aes_descriptor

    .space  0x4c - (. - ppr_wrapper), 0

.size ppr_wrapper, . - ppr_wrapper

.section .plaintext, "ax"
.balign 4
.global ppr_sha_or_noauth
.type ppr_sha_or_noauth, %function

.extern sha_authenticate
.extern sha_wait_idma_aes
.extern submit_idma_aes

ppr_sha_or_noauth:
    cmp     w7, #PPR_SHA_MARKER
    b.ne    5f

    /*
     * The common helper has already appended its first queue-1
     * WaitForIdmaAes carrying a4/source completion.  Append a second wait
     * carrying a6/terminal completion instead of four SHA descriptors.  This
     * preserves the independent E8 and E3 notifications used by the NSID2
     * paths while keeping the native queue dependency and publication order.
     */
    sub     sp, sp, #0x20
    stp     x0, x5, [sp]
    str     x30, [sp, #0x10]
    mov     w2, w3                 /* terminal notifySha */
    ldr     x3, [sp, #0x58]        /* common a18 / SHA a16 trace */
    bl      sha_wait_idma_aes
    cbz     w0, 4f                 /* preserve the helper's queue error */

    /* Release the ZCN buffer at the terminal wait's queue-1 cycle. */
    ldp     x0, x5, [sp]
    ldrh    w8, [x0, #PPR_Q1_CYCLE_OFFSET]
    sub     w8, w8, #1
    tbz     x5, #63, 3f
    ldr     w9, [x0, #PPR_ZCN_CONFIG_OFFSET]
    ubfx    w10, w9, #8, #8
    add     w9, w10, w9, uxtb
    ubfx    w11, w5, #16, #9
    cmp     w9, w11
    b.ls    3f
    add     x10, x0, w11, uxtw #1
    strh    w8, [x10, #PPR_ZCN_RELEASE_OFFSET]
    mov     w10, #1
    ldr     x9, [x0, #PPR_ZCN_RELEASE_BITS_OFFSET]
    lsl     x8, x10, x11
    orr     w8, w8, w9
    bfxil   x9, x8, #0, #24
    str     x9, [x0, #PPR_ZCN_RELEASE_BITS_OFFSET]
3:
    mov     w1, #1
    bl      submit_idma_aes
    mov     w0, #1
4:
    ldr     x30, [sp, #0x10]
    add     sp, sp, #0x20
    ret
5:
    b       sha_authenticate

    .space  0xa0 - (. - ppr_sha_or_noauth), 0

.size ppr_sha_or_noauth, . - ppr_sha_or_noauth
