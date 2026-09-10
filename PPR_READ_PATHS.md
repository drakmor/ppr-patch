# A53 PPR-PFS read paths

**English** | [Русский](PPR_READ_PATHS_RU.md)

This document describes the contract of the dynamic `NATIVE` /
`PLAINTEXT_NOAUTH` patch. The description is firmware-neutral: addresses and
instruction words belong to the exact profile for the selected A53 image.
Only the 9.40 profile is shown below as an example.

The patch replaces only the cryptographic part of one 64 KiB package read. It
does not change ZCN-buffer selection or lifetime, queue dependencies, or the
caller's completion notifications.

## Common interception point

Ten paths call the shared
`zcnDriverAddCommandsPackageDecryptToZcnBufferAndVerifySign` helper. Its
relevant ABI arguments have the same meaning in every supported profile:

| ABI | Meaning |
| --- | --- |
| `a4` / `w3` | source of the intermediate dependency command |
| `a5` / `w4` | IDMA/AES-stage completion notification |
| `a6` / `w5` | terminal SHA/CMAC-stage completion notification |
| `a7` / `x6` | physical MP4 source address |
| `a8` / `w7` | PASID |
| `[sp+0x10]` | encryption type |
| `[sp+0x18]` | AES key index |
| `[sp+0x20]` | SHA key index |

Static profile verification checks the helper signature, the saved terminal
SHA notification, and all ten direct `BL` instructions. The profile also pins
two internal helper sites: the SHA-queue capacity check and the native
dispatch.

## Ten entry paths

| No. | Functional path | ZCN buffer |
| ---: | --- | --- |
| 1 | `FlashReadPackage1Block` | input |
| 2 | `FlashReadPackage2Block` | input |
| 3 | `FlashReadDecryptAndVerifySha` | input |
| 4 | `ExtFs_UnpackPackage1Block` | input |
| 5 | `ExtFs_UnpackPackage2Block`, branch A | input |
| 6 | `ExtFs_UnpackPackage2Block`, branch B | input |
| 7 | `ExtFs_DecryptAndVerifySha` | output |
| 8 | `NSID2_FlashAppendFromDeltaSource` | input |
| 9 | `NSID2_FlashReadPackageFile`, branch A | input |
| 10 | `NSID2_FlashReadPackageFile`, branch B | input |

The first three paths read package/NVM data into ZCN input. ExtFs uses the same
physical MP4 source, but one decrypt path selects the output buffer. NSID2 and
delta paths continue into their own decompression/PT/ODMA pipeline after the
read. The common helper is therefore the smallest correct switch point;
hooking individual high-level functions would create several incompatible
implementations.

### Single address example: the 9.40 profile

In this profile the common helper is at `0x04e5a6bc`, and its direct calls are:

| No. | `BL` address |
| ---: | ---: |
| 1 | `0x04e4879c` |
| 2 | `0x04e49048` |
| 3 | `0x06414f1c` |
| 4 | `0x06416118` |
| 5 | `0x064163a8` |
| 6 | `0x0641663c` |
| 7 | `0x06417c50` |
| 8 | `0x0642313c` |
| 9 | `0x064251dc` |
| 10 | `0x064278d0` |

These values are examples only. Before installation, the payload reads the
A53 release, selects an exact profile, validates the live layout and expected
instructions, and refuses to write on any mismatch.

## Stock `NATIVE` chain

A native request is simplified as follows:

```text
caller
  -> common helper and WaitForBufferFree(selected ZCN buffer)
  -> dependency / queue-capacity checks
  -> IDMA + AES-XTS, queue 0, notify=a5
  -> SHA3-CMAC, queue 1, notify=a6
  -> next ExtFs/NSID2/Package consumer
```

`WaitForBufferFree` accounts for the last SHA, PT/ODMA, and ZDE commands for
the selected buffer. Input/output selection and prediction state are handled
by the stock helper before dispatch. The SHA queue does not read the same
bytes in parallel: it depends on the AES/IDMA result and publishes the
operation's terminal event.

The existing `zcnDriverAddCommandsCopyBuffer` is not a suitable replacement.
It builds a complete DRAM-to-DRAM `IDMA-PT + ODMA` chain, while these paths must
leave data in the already selected ZCN input/output buffer.

## Per-request mode selection

The wrapper tests only `kmbIdxKeyAes == 0xff`:

- `AES != 0xff` tail-calls the original helper unchanged;
- `AES == 0xff` selects `PLAINTEXT_NOAUTH` and replaces the internal
  encryption type with `0x7f`.

A signed outer PFS normally supplies `SHA=0xfe, AES=0xff`, but an unsigned
inner PFS may omit the SHA key while retaining the AES sentinel. The exact
`fe/ff` pair is therefore no longer the dispatch condition. `0xff` cannot be a
deferred native key: it is not an allocatable KMB index, and the stock helper
immediately emits `IdmaDecrypt`; IOC rejects that request with
`ILLEGAL_KMB_ACCESS`.

The selector has no global mode or latch. After one installation, native and
marked plaintext requests can alternate without patching A53 again.
Kernel-side code must set the sentinel only for a validated plaintext mount;
an A53 profile does not provide that marker by itself.

## `PLAINTEXT_NOAUTH` chain

The plaintext continuation retains the stock wait, dependency, buffer
selection, and SHA-queue capacity check. Before appending a descriptor, it
also requires a complete package-backed source with a non-zero BFS/LVD LPAR in
the high word of the physical address. An index-only source is rejected before
IDMA starts.

After those checks, it performs:

```text
IdmaPt(source physical -> selected ZCN buffer,
       passthrough unit 1, queue 0, commandInfo=native a5)
  -> WaitForIdmaAes(queue 1, commandInfo=native a6)
  -> prediction = max(lastSha, IdmaPt) + 0x19a
  -> update lastSha and selected-buffer watermarks
  -> submit queue 1
  -> submit queue 0
  -> common success return
```

No SHA3-CMAC or AES-XTS command is emitted, but both stock completion stages
are preserved. `IdmaPt` carries the intermediate `a5` notification, while the
queue-1 wait carries terminal `a6`. The stock plaintext producer constructs
both queues before publishing its batch. The standalone wrapper therefore
arms queue 1 first and only then starts the short PT producer in queue 0, so
the waiter is visible before completion. The `0x19a` reservation prevents
premature ZCN-buffer reuse.

Passthrough unit 1 is intentional: it is the same engine used by the sole
stock `IdmaPt` caller for the MP4-physical-source to ZCN-buffer direction. The
passthrough-unit number is not a queue number; the command still runs in queue
0.

## Separate KMB-range patch

The KMB-range extension is independent of the read-path selector and is
controlled separately. `--kmb-range-install` changes only the selected upper
bound in `ExtFs_EncryptAndCalculateSha`: instead of the request-class limit,
it uses the full 9-bit hardware aperture with an exclusive upper bound of 512
(indices through 511). The lower bound, XTS pair-size check, and CMAC range
check remain stock. `--kmb-range-uninstall` restores the exact original
instruction.

The operation is allowed only when the current instruction exactly matches
the known stock or patched word. Its state is reported by `--status` and is
not changed when the dynamic selector is installed or removed.

## Compatibility invariants

1. A native request never enters the plaintext continuation and calls the
   original helper with all arguments unchanged.
2. Mode is selected per request by AES sentinel `0xff`; a SHA sentinel is not
   required.
3. All ten direct callers are intercepted, or some ExtFs/NSID2 paths would
   enter native crypto with a non-allocatable index.
4. `WaitForBufferFree`, input/output selection, dependency, PASID, both
   prediction states, and publication of both queues are preserved.
5. `IdmaPt` receives native `a5`, and the queue-1 wait receives native `a6`,
   retaining the caller-specific completion contract.
6. A package-backed source without an LPAR is rejected before an IDMA
   descriptor is appended.
7. An unknown layout, instruction, or state fails before any write. An
   interrupted transaction is recoverable only with complete current
   trampolines and an exact mixture of stock/current entry words.
8. Install and removal require all PPR/APR queues to be fully drained;
   `--idle` is an explicit acknowledgement, not an automatic check.

## Verification plan

1. Run `make -C ppr-patcher verify` to check every supplied profile ELF, the
   ABIs, twelve patch sites, wrapper, and KMB guard.
2. Run `make -C ppr-patcher host-test`, then build the payloads with
   `make -C ppr-patcher`.
3. After reboot and a complete queue drain, run `--status`. Expect an exact
   profile, `STOCK` or the exact current image, and a known KMB-range state.
4. Install the selector and first launch a known-good native game. It must use
   the original helper and complete both native PPR-PFS mount stages and APR
   bind.
5. Only after native regression, mount a test plaintext package. For a
   sentinel request, expect one passthrough IDMA command in queue 0, a terminal
   wait in queue 1, no AES/SHA commands, and successful outer-metadata reads.
6. Repeat mount/unmount and test ExtFs, inner PFS, APR, and NSID2/delta paths.
   An IOC dump or a hang after IDMA usually points to submit/completion order
   or buffer lifetime; an inode/L2P parse error points to the test-image format
   rather than the dispatch wrapper.
7. If the extended KMB range is needed, test it with a separate
   install/status/uninstall cycle and confirm that selector state does not
   change.
