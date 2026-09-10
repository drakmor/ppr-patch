/*
 * Firmware-neutral AArch64 source for the PPR selector and plaintext queue
 * continuation.  Link-time symbols and section addresses come from the
 * selected firmware profile.
 */

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
    cbnz    w24, 1f
    b       precheck_normal
1:
    cmp     w24, #0x7f
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
    cmp     w24, #0x7f
    b.ne    dispatch_native
    b       ppr_plaintext_dispatch

.size ppr_wrapper, . - ppr_wrapper

.section .plaintext, "ax"
.balign 4
.global ppr_plaintext_dispatch
.type ppr_plaintext_dispatch, %function

ppr_plaintext_dispatch:
    cbnz    w20, common_error
    /*
     * A package-backed source address contains the BFS/LVD LPAR in its high
     * word.  Sending an index-only value (for example 0x00102500) as an IDMA
     * physical source makes IOC reject opcode 0x24 and can poison unrelated
     * storage queues until reboot.  Fail the request before appending any
     * descriptor when the kernel mapping arrived without a container LPAR.
     */
    lsr     x16, x26, #32
    cbz     x16, common_error
    /*
     * Preserve the native two-stage completion protocol.  The passthrough
     * command replaces AES and therefore carries deviceOpSource_notifyIdmaAes
     * from w4.  A separate SHA-queue wait below carries notifySha without
     * performing authentication.
     */
    mov     w3, w4
    mov     x4, x26
    mov     w5, w25
    mov     w6, w23
    /*
     * The stock package input path is the only native IdmaPt caller with
     * this MP4-physical-source -> ZCN-buffer direction.  It selects unit 1
     * (kZcnEnginePassthrough1), so keep the same engine here.
     */
    mov     w7, #1
    str     x28, [sp]
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
    mov     x1, x22
    ldur    w2, [x29, #-0xc]
    mov     x3, x28
    bl      sha_wait_idma_aes

    /*
     * Preserve the stock queue-1 reservation.  WaitForIdmaAes replaces SHA,
     * but its completion still occupies the native 0x19a-cycle slot before
     * the selected ZCN buffer may be reused.
     */
    ldur    x8, [x29, #-8]
    ldr     w9, [x8, #0x524]
    ldr     w10, [x19, #0x4fc]
    cmp     w10, w9
    csel    w9, w10, w9, ge
    add     w9, w9, #0x19a
    str     w9, [x19, #0x4fc]
    str     w9, [x8, #0x5b4]
    ldrb    w10, [x19, #0x308]
    cmp     w23, w10
    b.hs    6f
    str     w9, [x8, #0x584]
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

.size ppr_plaintext_dispatch, . - ppr_plaintext_dispatch
