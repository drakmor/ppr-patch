/*
 * AArch64 source for the three MP4 PPR helper ABIs.  Link-time symbols and
 * section addresses come from the selected exact firmware profile.
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

.section .runtime, "ax"
.balign 4
.global ppr_wrapper
.type ppr_wrapper, %function

.extern original_helper
.extern precheck_normal
.extern precheck_special
.extern common_error
.extern dispatch_native
.extern plaintext_idma
.extern sha_wait_idma_aes
.extern submit_idma_aes
.extern common_return
.extern ppr_plaintext_dispatch

ppr_wrapper:
    /*
     * Signed outer reads carry SHA=fe/AES=ff, but the unsigned inner PFS can
     * omit the SHA key and still carries the private AES sentinel.  FF is not
     * an allocatable KMB index; letting it reach IdmaDecrypt produces IOC
     * ILLEGAL_KMB_ACCESS.  Select plaintext on the AES sentinel alone.
     */
    ldrb    w16, [sp, #0x18] /* kmbIdxKeyAes */
    cmp     w16, #0xff
    b.eq    0f
    nop                         /* keep ppr_precheck at runtime + 0x24 */
    nop
    b       original_helper
0:
    mov     w16, #0x7f
    str     w16, [sp, #0x10]
    b       original_helper

ppr_precheck:
#if PPR_ABI == 2
    cbnz    w28, 1f
#else
    cbnz    w24, 1f
#endif
    b       precheck_normal
1:
#if PPR_ABI == 2
    cmp     w28, #0x7f
#else
    cmp     w24, #0x7f
#endif
    b.ne    2f
    /*
     * Re-enter before the stock SHA-capacity test.  The plaintext path still
     * appends one WaitForIdmaAes command; skipping this test can leave an IDMA
     * command staged without its terminal SHA completion when that queue is
     * full.
     */
    b       precheck_normal
2:
    b       common_error

ppr_dispatch:
#if PPR_ABI == 2
    cmp     w28, #0x7f
#else
    cmp     w24, #0x7f
#endif
#if PPR_FAR_BRANCHES
    b.eq    3f
    b       dispatch_native
3:
    b       ppr_plaintext_dispatch
#else
    b.ne    dispatch_native
    b       ppr_plaintext_dispatch
    .word   0
#endif

.size ppr_wrapper, . - ppr_wrapper

.section .plaintext, "ax"
.balign 4
.global ppr_plaintext_dispatch
.type ppr_plaintext_dispatch, %function

ppr_plaintext_dispatch:
#if PPR_FAR_BRANCHES
    cbz     w20, 4f
    b       common_error
4:
#else
    cbnz    w20, common_error
#endif
    /*
     * A package-backed source address contains the BFS/LVD LPAR in its high
     * word.  Sending an index-only value (for example 0x00102500) as an IDMA
     * physical source makes IOC reject opcode 0x24 and can poison unrelated
     * storage queues until reboot.  Fail the request before appending any
     * descriptor when the kernel mapping arrived without a container LPAR.
     */
#if PPR_ABI == 2
    lsr     x16, x6, #32
#else
    lsr     x16, x26, #32
#endif
#if PPR_FAR_BRANCHES
    cbnz    x16, 7f
    b       common_error
7:
#else
    cbz     x16, common_error
#endif
    /*
     * Preserve the native two-stage completion protocol.  The passthrough
     * command replaces AES and therefore carries deviceOpSource_notifyIdmaAes
     * from w4.  A separate SHA-queue wait below carries notifySha without
     * performing authentication.
     */
    mov     w3, w4
#if PPR_ABI == 2
    mov     x4, x6
    mov     w5, w6
#else
    mov     x4, x26
#if PPR_ABI == 0
    mov     w5, w6
#else
    mov     w5, w25
#endif
#endif
    mov     w6, w23
    /*
     * The stock package input path is the only native IdmaPt caller with
     * this MP4-physical-source -> ZCN-buffer direction.  It selects unit 1
     * (kZcnEnginePassthrough1), so keep the same engine here.
     */
    mov     w7, #1
#if PPR_ABI == 2
    str     x22, [sp]
#elif PPR_ABI == 0
    str     x25, [sp]
#else
    str     x28, [sp]
#endif
    bl      plaintext_idma
    cbnz    w0, 5f
    mov     w0, #0x01000000
    b       common_return
5:
    /*
     * Keep the native cross-queue dependency and second completion event, but
     * replace SHA3-CMAC with the existing WaitForIdmaAes command.  Its command
     * info is terminal notifySha, so both pipeline state bits are consumed in
     * their original order.
     */
    mov     x0, x19
#if PPR_ABI == 2
    mov     x1, x26
    ldur    w2, [x29, #-0xc]
    mov     x3, x22
#elif PPR_ABI == 0
    mov     x1, x22
    ldur    w2, [x29, #-0x54]
    mov     x3, x25
#else
    mov     x1, x22
    ldur    w2, [x29, #-0xc]
    mov     x3, x28
#endif
    bl      sha_wait_idma_aes

    /*
     * Preserve the stock queue-1 reservation.  WaitForIdmaAes replaces SHA,
     * but its completion still occupies the native 0x19a-cycle slot before
     * the selected ZCN buffer may be reused.
     */
#if PPR_ABI == 2
    mov     x8, x25
#elif PPR_ABI == 0
    add     x8, x19, w23, uxtw #2
#else
    ldur    x8, [x29, #-8]
#endif
#if PPR_MERGED_TEXT
    ldr     w9, [x8, #0xa38]
    ldr     w10, [x19, #0x9f4]
#else
    ldr     w9, [x8, #0x524]
    ldr     w10, [x19, #0x4fc]
#endif
    cmp     w10, w9
    csel    w9, w10, w9, ge
    add     w9, w9, #0x19a
#if PPR_MERGED_TEXT
    str     w9, [x19, #0x9f4]
    str     w9, [x8, #0xac8]
    ldrb    w10, [x19, #0x408]
#else
    str     w9, [x19, #0x4fc]
    str     w9, [x8, #0x5b4]
    ldrb    w10, [x19, #0x308]
#endif
    cmp     w23, w10
    b.hs    6f
#if PPR_MERGED_TEXT
    str     w9, [x8, #0xa98]
#else
    str     w9, [x8, #0x584]
#endif
6:
    /*
     * IdmaPt is much shorter than the native AES operation and only appends a
     * descriptor.  Arm the dependent queue before ringing queue 0 so IOC can
     * never observe a completed producer before its waiter is visible.  This
     * is the publish-time equivalent of the stock plaintext producer, which
     * builds both queues before either becomes runnable.
     */
    mov     x0, x19
    mov     w1, #1
    bl      submit_idma_aes /* submit SHA wait queue */
    mov     x0, x19
    mov     w1, wzr
    bl      submit_idma_aes /* submit plaintext IDMA queue */
    mov     w0, wzr
    b       common_return

#if !PPR_FAR_BRANCHES
    .space  8, 0
#endif

.size ppr_plaintext_dispatch, . - ppr_plaintext_dispatch
