# A53 PPR patcher

**English** | [Русский](README_RU.md)

This project builds a profile-driven A53 patcher with two independent
features:

- a dynamic per-request `NATIVE` / `PLAINTEXT_NOAUTH` PPR-PFS read selector;
- an optional ExtFs/opcode-0x53 encryption KMB-range extension.

The selector replaces only the cryptographic part of marked 64 KiB package
reads. Native requests still use the original A53 helper with unchanged
arguments. There is no global plaintext mode: native and marked plaintext
mounts can alternate after one installation.

> **Safety:** every action that changes A53 code requires `--idle`. This flag
> confirms that the operator has already drained all PPR reads, mounts, APR
> binds, and unmount work; the payload cannot prove that condition itself.

The detailed queue and caller analysis is available in
[`PPR_READ_PATHS.md`](../PPR_READ_PATHS.md). Its Russian version is
[`PPR_READ_PATHS_RU.md`](../PPR_READ_PATHS_RU.md).

## Contents

- a small `/dev/mp4/dump` DECI5S transport;
- an exact-profile state machine that fails closed on unknown layouts or
  instructions;
- AArch64 runtime and plaintext wrappers generated from one shared template;
- console and `/dev/notification0` output for every complete log line;
- host state-machine tests and static profile/wrapper verification.

## Build

From WSL with `PS5_PAYLOAD_SDK` set:

```sh
cd ppr-patcher
export PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk
make -j2
```

The verification target expects one A53 ELF for every profile compiled into
`ppr_patch.c`. Default paths and their override variables are defined in the
`Makefile`.

Artifacts are written to `build/`:

- `a53_ppr_patcher.elf` — argument-driven status/control payload;
- `a53_ppr_install.elf` — install with verified batching and persistent
  transport enabled;
- `a53_ppr_install_fast.elf` — install using every verified fast transport;
- `a53_ppr_plaintext.elf` — install alias for launchers without arguments;
- `a53_ppr_native.elf` — stock-restore alias for launchers without arguments;
- `a53_ppr_uninstall.elf` — restore the exact stock entry instructions;
- `a53_kmb_range_install.elf` — extend the ExtFs allocator and bypass the
  independent opcode-0x53 AES-index whitelist;
- `a53_kmb_range_uninstall.elf` — restore all three exact stock instructions.

## Exact profiles, not firmware assumptions

Each binary reads the full A53 `releases/XX.XX` suffix and selects an exact
profile. The resolver then validates the live IO and DRAM-IO segment records,
maps executable SRAM and G6 addresses, and compares every connected patch
site with its expected stock or current word. An unknown release, layout,
instruction, or connected trampoline fails before the first write.

Addresses are data owned by a profile, not assumptions in the algorithm. For
example only, the 9.40 profile places the shared package decrypt/auth helper at
`0x04e5a6bc`. Other images must provide their own fully verified profile.

Before a patch write, the transport also compares scalar and two-command batch
reads and verifies two consecutive transactions through one persistent
fd/kqueue pair. Unsupported optimizations are disabled while verified
fallbacks remain available. Mixed write/readback packets are used only after
the batch ABI has been validated.

## Command line

```text
--status
--install --idle
--uninstall --idle
--mode native --idle
--mode plaintext-noauth --idle
--kmb-range-install --idle
--kmb-range-uninstall --idle
--fast --persistent --batch --mixed-io
--conservative
```

`--idle` is also accepted as `--i-know-ppr-idle`.

`--install` installs the dynamic selector; `--uninstall` restores exact stock
entry instructions. The two `--mode` commands are compatibility aliases:
`plaintext-noauth` installs the same dynamic selector, while `native` removes
it. They do not set a persistent global mode.

`--status` is read-only. It reports selector state, resolved cave addresses,
the independent KMB-range state, and transport counters. It succeeds only for
a complete stock or installed selector image and a known stock or extended
KMB-range instruction.

## Read-path coverage

Ten direct callers of
`zcnDriverAddCommandsPackageDecryptToZcnBufferAndVerifySign` are redirected to
one runtime wrapper:

| No. | Functional path | ZCN buffer |
| ---: | --- | --- |
| 1 | `FlashReadPackage1Block` | input |
| 2 | `FlashReadPackage2Block` | input |
| 3 | `FlashReadDecryptAndVerifySha` | input |
| 4 | `ExtFs_UnpackPackage1Block` | input |
| 5–6 | both `ExtFs_UnpackPackage2Block` branches | input |
| 7 | `ExtFs_DecryptAndVerifySha` | output |
| 8 | `NSID2_FlashAppendFromDeltaSource` | input |
| 9–10 | both `NSID2_FlashReadPackageFile` branches | input |

Hooking the common helper keeps each caller's existing buffer selection,
dependency, PASID, queue state, and terminal notification. Hooking fewer paths
would leave some ExtFs or NSID2 requests entering native crypto with the
plaintext sentinel.

## Per-request selector

The wrapper reads `kmbIdxKeyAes` from `[sp+0x18]`:

- any allocatable AES index tail-calls the original helper unchanged;
- the private invalid AES index `0xff` selects `PLAINTEXT_NOAUTH` and becomes
  internal encryption type `0x7f`.

A signed outer PFS normally supplies `SHA=0xfe, AES=0xff`, while an unsigned
inner PFS may omit the SHA key and retain only the AES sentinel. Dispatch
therefore depends on `AES == 0xff`, not on an exact `fe/ff` pair. Passing
`0xff` to the stock path is not valid: the helper immediately emits
`IdmaDecrypt`, and IOC rejects the non-allocatable index with
`ILLEGAL_KMB_ACCESS`.

The sentinel must be installed by matching kernel-side mount logic only for a
validated plaintext mount. Adding an A53 profile does not add or authorize the
kernel-side marker.

## Queue contract

The stock native chain is:

```text
WaitForBufferFree
  -> IDMA + AES-XTS, queue 0, intermediate notify
  -> SHA3-CMAC, queue 1, terminal notify
  -> caller-specific consumer
```

For `PLAINTEXT_NOAUTH`, the wrapper retains the stock wait, SHA-queue capacity
check, selected input/output buffer, dependency, PASID, prediction state, and
both completion events. It also rejects a package source whose physical
address lacks a non-zero BFS/LVD LPAR before appending any descriptor.

```text
IdmaPt(passthrough unit 1, queue 0, native IDMA/AES notify)
  -> WaitForIdmaAes(queue 1, native terminal SHA notify)
  -> preserve max(lastSha, IdmaPt) + 0x19a and buffer watermarks
  -> submit queue 1
  -> submit queue 0
```

No AES-XTS or SHA3-CMAC command is emitted for the marked read. Queue 1 is
armed before the short queue-0 producer so that its waiter is visible before
IDMA can complete. Passthrough unit 1 is the stock engine for the
MP4-physical-source to ZCN-buffer direction; it must not be confused with the
queue number.

## Independent KMB-range extension

`--kmb-range-install` changes two independent validators. In
`ExtFs_EncryptAndCalculateSha`, it selects the complete 9-bit hardware
aperture with exclusive upper bound 512. In
`FlashWriteEncryptAndCalculateSha` (opcode `0x53`), it redirects both
AES-index whitelist rejection branches to the native success block. Opcode
`0x53` still has 8-bit AES/SHA fields, so its callers are limited to slots
0..255 and an XTS base no greater than 254.

This operation neither installs nor removes the read selector. It is accepted
only when all three current instructions exactly match known stock or patched
words, and every write is read back. A prior ExtFs-only install is recognized
as a recoverable partial state. `--kmb-range-uninstall` restores all three
exact profile-specific stock instructions.

## Patch-state safety

Installation writes dormant cave code first, connects the two internal helper
hooks next, and redirects the ten public callers last. Removal disconnects the
public callers before restoring the internal sites. Every write is verified
by readback and the complete final state is reread.

An interrupted transaction is recoverable only when both current trampolines
are complete and every entry word is an exact stock/current value. Unknown
connected bytes are never repaired speculatively. The three KMB-range
instructions have the same exact stock/patched policy but remain a separate
state.

## Verification

```sh
make verify
make host-test
```

`make verify` checks the supplied A53 ELFs, segment sizes and flags, all twelve
patch sites and branch targets, helper/IdmaPt/submit ABIs, plaintext queue
ordering and notifications, the KMB allocator guard, unused executable-tail
space, and byte-for-byte equality of C-generated and assembled wrappers.

`make host-test` exercises status, idle gating, install, interrupted-state
recovery, uninstall, independent KMB install/uninstall, unknown-instruction
rejection, and unsupported-profile rejection with a mock A53 layout.

On a console, verify `--status` after a reboot and complete queue drain. Test a
known-good native package before a marked plaintext package, then repeat
mount/unmount across ExtFs, inner PFS, APR, and NSID2/delta paths. See the
detailed read-path document for the expected queue behavior and failure
triage.

## Deploy the verified fast installer

```sh
make deploy-install-fast PS5_HOST=192.168.1.2 PS5_PORT=9021
```

Deployment is deliberately separate from `all`; a normal build never writes
to the console.
