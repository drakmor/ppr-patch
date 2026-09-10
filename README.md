# A53 PPR patcher

**English** | [Русский](README_RU.md)

This project builds a profile-driven A53 patcher with two independent
features:

- a dynamic per-request `NATIVE` / `PLAINTEXT_NOAUTH` PPR-PFS read selector;
- an optional opcode-0x53 encryption KMB-whitelist bypass.

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

The checked-in `ppr_profiles.inc` contains all 54 archived MP4 releases from
1.00 through 11.40. `make profiles` regenerates it from `PPR_FULL_ROOT`
(`../../MP4_1.00-12.00` by default), using `PPR_DRAM_ROOT`
(`/mnt/j/PS5Dev/mp4`) as a fallback. `make verify` independently extracts and
checks every profile against those ELFs.

Artifacts are written to `build/`:

- `a53_ppr_patcher.elf` — argument-driven status/control payload;
- `a53_ppr_install.elf` — install with verified batching and persistent
  transport enabled;
- `a53_ppr_install_fast.elf` — install using every verified fast transport;
- `a53_ppr_plaintext.elf` — install alias for launchers without arguments;
- `a53_ppr_native.elf` — stock-restore alias for launchers without arguments;
- `a53_ppr_uninstall.elf` — restore the exact stock entry instructions;
- `a53_kmb_range_install.elf` — bypass the opcode-0x53 AES-index whitelist;
- `a53_kmb_range_uninstall.elf` — restore its exact stock instruction.

## Exact profiles, not firmware assumptions

Each binary reads the full A53 `releases/XX.XX` suffix and selects an exact
profile. Releases 1.x use their merged DEV text layout, 2.x/3.x use the legacy
split ABI, 4.x through 10.x use the current ABI, and 11.x use the late ABI.
The resolver validates the matching live segment records, maps executable
SRAM or G6 addresses, and compares every connected patch site with its
expected stock or current word. An unknown release, layout, instruction, or
connected trampoline fails before the first write.

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
the independent KMB-range state when that guard exists, and transport
counters. It succeeds for a complete stock or installed selector image.

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

`--kmb-range-install` changes only
`FlashWriteEncryptAndCalculateSha` (opcode `0x53`). It redirects only the
out-of-range rejection branch to the native success block; the stock
per-index filter inside its original range is unchanged. Opcode
`0x53` still has 8-bit AES/SHA fields, so its callers are limited to slots
0..255 and an XTS base no greater than 254.

The ExtFs encryption range instruction is not read, changed, or restored by
this payload.

This operation neither installs nor removes the read selector. It is accepted
only when the current instruction exactly matches the known stock or patched
word, and every write is read back. `--kmb-range-uninstall` restores the exact
profile-specific stock instruction. The independently patchable guard exists
in the 4.x through 10.x ABI; the KMB-range commands fail as unsupported on
1.x through 3.x and 11.x, without affecting selector support.

## Patch-state safety

Installation writes dormant cave code first, connects the two internal helper
hooks next, and redirects the ten public callers last. Removal disconnects the
public callers before restoring the internal sites. Every write is verified
by readback and the complete final state is reread.

An interrupted transaction is recoverable only when both current trampolines
are complete and every entry word is an exact stock/current value. Unknown
connected bytes are never repaired speculatively. The opcode-0x53 KMB
instruction has the same exact stock/patched policy but remains a separate
state.

## Verification

```sh
make verify
make host-test
```

`make verify` checks all 54 supplied A53 ELFs, all twelve patch sites and
branch targets, helper/IdmaPt/submit ABIs, executable-tail placement, the
available opcode-0x53 KMB guards, and byte-for-byte equality of C-generated
and assembled legacy/current/late wrappers.

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
