# A53 PPR patcher

The payload contains:

- a small `/dev/mp4/dump` DECI5S transport;
- the firmware-independent patch state machine;
- console plus `/dev/notification0` output for every complete log line;
- a host state-machine test and static profile/wrapper verification.

## Build

From WSL with `PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk`:

```sh
cd ppr-patcher
make -j2
```

Artifacts are written to `build/`:

- `a53_ppr_patcher.elf` — argument-driven status/control payload;
- `a53_ppr_install.elf` — install with batched reads and a persistent transport;
- `a53_ppr_install_fast.elf` — fast install on every supported profile;
- `a53_ppr_native.elf` and `a53_ppr_plaintext.elf` — explicit mode aliases;
- `a53_ppr_uninstall.elf` — restore the exact stock entry points.
- `a53_kmb_range_install.elf` — extend the encrypt allocator's KMB upper
  bound from the restricted runtime aperture to all 512 hardware slots;
- `a53_kmb_range_uninstall.elf` — restore the exact stock range instruction.

All binaries automatically parse the A53 `releases/XX.XX` string and reject
firmwares without an exact profile.
Before any patch write, the payload compares a scalar read with a two-command
batch read and verifies two consecutive transactions through one persistent
fd/kqueue pair. A failed capability is disabled automatically while
the remaining verified paths continue to work.

The SDBGP dispatchers in all four A53 images were checked to iterate over
`num_commands` and advance by each command's `total_size`, which is the ABI
required by batch and mixed write/readback packets.

## Command-line payload

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

`--idle` (alias `--i-know-ppr-idle`) is mandatory for changes. Run only while
no PPR mount, read, APR bind or unmount operation is active.

The installed controller is dynamic: the private invalid AES index `0xff`
selects `PLAINTEXT_NOAUTH`; every allocatable AES index retains the native path.
The signed outer PFS normally carries the full SHA=FE/AES=FF pair, while an
unsigned inner PFS may omit SHA and still carries AES=FF. You do not need to
rerun the installer when switching between a native package and a marked
plaintext package.
The selector runs only at the common package-decrypt helper. At that point an
AES index of FF cannot be a deferred native key: the stock helper immediately
emits `IdmaDecrypt`, and IOC rejects FF as `ILLEGAL_KMB_ACCESS`. Thus native
requests with real, allocated AES indices remain on the original path.

The plaintext continuation preserves both native completion stages. After the
native SHA-queue capacity check, a passthrough-unit-1 IDMA transfer carries
`deviceOpSource_notifyIdmaAes`, then the stock SHA-queue `WaitForIdmaAes`
command carries the terminal `deviceOpSource_notifySha`. The stock plaintext
producer constructs both descriptors before publishing its batch. Because the
standalone wrapper must submit them itself, it arms queue 1 first and rings the
short PT producer on queue 0 last; this prevents a lost fast completion. The
queue-1 predictor retains the stock `0x19a` reservation. No SHA3-CMAC command
is issued, but cross-queue dependency, buffer lifetime, and both pipeline-state
transitions remain intact.

## Deploy the verified fast installer

```sh
make deploy-install-fast PS5_HOST=192.168.1.2 PS5_PORT=9021
```

The deploy target is deliberately separate from `all`; a normal build never
writes to the console.
