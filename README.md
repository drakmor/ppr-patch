# A53 PPR patcher

**English** | [Русский](README_RU.md)

This project builds two profile-driven A53 tools:

- a dynamic per-request `NATIVE` / `PLAINTEXT_NOAUTH` PPR-PFS read selector;
- a standalone optional opcode-0x53 encryption KMB-whitelist bypass.

The KMB tool has its own main, state machine, profile table, verifier, and
tests. It is not linked into any `a53_ppr_*` payload, so selector install and
status never resolve, read, classify, or change the FsWrite instruction.

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
- console output plus `/dev/notification0`; payloads aggregate their log into
  one final popup instead of issuing one syscall per line;
- host state-machine tests and static profile/wrapper verification.

## Build

From WSL with `PS5_PAYLOAD_SDK` set:

```sh
cd ppr-patcher
export PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk
make -j2
```

The checked-in `ppr_profiles.inc` contains all 54 archived MP4 releases from
1.00 through 11.40. The separate `kmb_range_profiles.inc` contains the 31
verified KMB layouts from 4.00 through 10.60. `make profiles` regenerates both
tables from `PPR_FULL_ROOT`
(`../../MP4_1.00-12.00` by default), using `PPR_DRAM_ROOT`
(`/mnt/j/PS5Dev/mp4`) as a fallback. `make verify` independently extracts and
checks every profile against those ELFs. Source labels are accepted only when
the embedded AArch64 ELF contains the matching release marker, so a mislabeled
full image cannot shadow the correct DRAM fallback. The available `6.00.01`,
`7.01.01`, and `8.20.02` images are verified as exact aliases of `6.00`,
`7.01`, and `8.20`; they share the same runtime firmware IDs and therefore do
not create duplicate profile rows.

Artifacts are written to `build/`:

- `a53_ppr_patcher.elf` — argument-driven status/control payload;
- `a53_ppr_install.elf` — install using the verified pair-only fast transport;
- `a53_ppr_install_fast.elf` — compatibility-named alias with the same action
  and transport defaults;
- `a53_ppr_plaintext.elf` — install alias for launchers without arguments;
- `a53_ppr_native.elf` — stock-restore alias for launchers without arguments;
- `a53_ppr_uninstall.elf` — restore the exact stock entry instructions;
- `a53_kmb_range_install.elf` — standalone fixed-action payload that bypasses
  the opcode-0x53 AES-index whitelist;
- `a53_kmb_range_uninstall.elf` — standalone fixed-action payload that restores
  its exact stock instruction.

Deploy only these `build/` outputs. Root-level files copied from an older
build may still contain the retired implementation and must not be reused.

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

Before a patch write, the transport compares a scalar read with a sixteen-
command read-only batch and verifies two consecutive transactions through one
persistent fd/kqueue pair. The maximum read envelope covers the 15-command
preflight without a synthetic A53 write. Production mutations are deliberately
limited to the packet shape proven by the working fast path: two writes followed
by their two exact readbacks. The newer eight-write grouping is not exposed to
the state machine. Unsupported optimizations are disabled while verified
fallbacks remain available. Every response is bounded by its complete
DECI5S/SDBGP envelope and must echo the current request sequence; stale result
records left by an earlier, longer packet are rejected.

For a clean fixed-action install, GET_CONF costs one transaction. A successful
capability probe then costs two transactions and one open, whose descriptor is
retained. The clean install uses another eleven transactions: one layout
snapshot, one exact 15-site preflight, one paired cave write/readback, three
transactions for the three internal hooks (one pair plus one scalar
write/readback), and five paired transactions for the ten public callers. The
normal path is therefore fourteen DECI5S requests in total, in addition to the
one-time mailbox discovery handshake. FsWrite/KMB is absent from every one of
these reads and writes.

## Command line

```text
--status
--install --idle
--uninstall --idle
--mode native --idle
--mode plaintext-noauth --idle
--fast --persistent --batch --mixed-io
--conservative
```

`--idle` is also accepted as `--i-know-ppr-idle`.

`--install` installs the dynamic selector; `--uninstall` restores exact stock
entry instructions. The two `--mode` commands are compatibility aliases:
`plaintext-noauth` installs the same dynamic selector, while `native` removes
it. They do not set a persistent global mode. Mutating actions selected through
the argument-driven payload also default to all verified fast transports;
`--conservative` explicitly disables them.

`--status` is read-only. It reports only selector state, resolved cave
addresses, and transport counters. It succeeds for a complete stock or
installed selector image.

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

The wrapper loads the complete 32-bit `kmbIdxKeyAes` and `kmbIdxKeySha`
arguments from `[sp+0x18]` and `[sp+0x20]`. It selects
`PLAINTEXT_NOAUTH` only for the exact kernel-published pair
`AES=0x000000ff, SHA=0x000000fe`; every other request tail-calls the original
helper unchanged.

The fields are nine bits wide in A53. Byte-only matching is unsafe because a
real key slot can have the same low byte, and AES-only matching also catches
native requests. The kernel outer and inner NAPS read builders both propagate
the complete pair, so an unsigned inner PFS does not require a relaxed
selector. After the exact match, private `0x7ff` / `0x7fe` values carry the
selection through the stock helper; they are outside the native nine-bit KMB
range and are consumed by the internal hooks before descriptor encoding.

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

For `PLAINTEXT_NOAUTH`, the original common helper and native dispatch retain
control of buffer selection, capacity checks, continuation, completion-table
updates, clocks, and queue-0 publication. The two AES-builder hooks replace
only a marked AES data descriptor with the firmware's own physical-to-ZCN
plaintext descriptor.

```text
stock common helper / native dispatch
  -> queue-0 setup descriptor, completion a4
  -> IdmaPt(engine 5 / unit 0, queue 0, completion a5)
  -> stock queue-0 bookkeeping and submit
  -> stock queue-1 WaitForIdmaAes, completion a4
  -> terminal WaitForIdmaAes, completion a6
  -> publish per-buffer q1 release id and low-24 dependency mask
  -> submit queue 1
```

No marked AES-XTS or SHA3-CMAC descriptor reaches hardware. Keeping `a5` and
`a6` independent is essential: `a5` completes an NVM internal-buffer command,
while `a6` is the terminal read notification. The q1 release entry and mask
prevent later queue-0 reuse from overtaking that terminal wait.

## Independent KMB-range extension

`a53_kmb_range_install.elf` changes only
`FlashWriteEncryptAndCalculateSha` (opcode `0x53`): it replaces the exact
`b.hi` rejection at the profiled site with an unconditional branch to
`site+0x24`. This skips that range/bitmask classification and forces its stock
permitted path for every request. Only this one instruction changes; all code
and checks downstream of the permitted path remain stock. The AES base is
still extracted as an 8-bit field, so slots remain 0..255 and an XTS base may
not exceed 254.

No `a53_ppr_*` selector payload reads, changes, or restores this FsWrite
instruction; only the two standalone `a53_kmb_range_*` payloads touch it.

This operation neither installs nor removes the read selector. Its binary does
not link `ppr_patch.c`. It validates one exact DEV-layout snapshot, performs
one instruction-state read, and only when a change is needed performs one
write plus one readback. The current word must exactly match the profile's
stock or patched word. `a53_kmb_range_uninstall.elf` restores the exact
profile-specific stock instruction. The standalone table covers all 31
archived 4.00-through-10.60 profiles; 1.x through 3.x and 11.x fail as
unsupported before any write, without affecting selector support.
If the mutation readback fails, the payload makes a best-effort exact restore
of the prior instruction and verifies that rollback before returning failure.
An unconfirmed standalone timeout is likewise reconciled by a fresh state
read; an unverified restore reports `KMB_ROLLBACK_REBOOT_REQUIRED`.

## Patch-state safety

Installation writes dormant cave code first, connects the three internal helper
hooks next, and redirects the ten public callers last. Removal disconnects the
public callers before restoring the internal sites. Every mutation is verified
immediately by exact readback. Because a transport timeout does not prove that
A53 skipped a write, the failure path first performs a fresh exact read and
accepts an already-applied desired value. Rollback is phase-ordered and
verified; if the public callers cannot be confirmed stock, internal hooks are
deliberately left intact and the payload reports `ROLLBACK_REBOOT_REQUIRED`.
The fast action preflight batches all thirteen
current and two retired entry words in one 15-command transaction. A clean
stock install does not read stale cave bytes which it will overwrite; caves are
read only to classify an exact current hooked/mixed state. No redundant final
full-state snapshot is issued after all checked writes succeed.

State validation also reads the retired precheck and dispatch hook sites used
by the previous patch generation. A state is current stock or current installed
only when both retired sites contain their exact stock words. Exact old branch
targets are reported as `LEGACY_REBOOT_REQUIRED`; install and uninstall both
stop before their first write. The current payload never repairs, migrates, or
overwrites either retired site. Reboot into a known-stock A53 image (or use the
matching old uninstaller in its validated environment) before applying the
current patch. An unknown word at either retired site is also fail-closed.

An interrupted current transaction is recoverable only when both current
trampolines are complete, every current entry word is an exact stock/current
value, and both retired sites are exact stock. Unknown connected bytes are
never repaired speculatively. FsWrite KMB state is not part of this state
machine and is handled only by the standalone payloads.

## Verification

```sh
make verify
make host-test
```

`make verify` checks all 54 supplied A53 ELFs, the three patch-version aliases,
all thirteen selector sites and
branch targets, the native AES and stock plaintext descriptor builders, the
terminal SHA release/submit layout, executable-tail placement, exact FE/FF
selector semantics, and byte-for-byte equality of C-generated and assembled
wrappers. Its separate KMB verifier checks the exact 20-word FsWrite context,
DEV layout, site, stock word, and replacement branch for all 31 KMB profiles.

`make host-test` exercises status, idle gating, install, interrupted-state
recovery, uninstall, unknown-instruction rejection, and unsupported-profile
rejection for the selector. A separate standalone test exercises KMB
install/uninstall, exact-layout rejection, unknown words, and readback failure.

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
