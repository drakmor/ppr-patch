#!/usr/bin/env python3
"""Generate exact PPR profiles from full or mp4_dram-wrapped A53 ELFs."""

import argparse
import pathlib
import re
import struct


PPR_CALL_COUNT = 10
EXPECTED_RELEASES = [
    (1, 0), (1, 1), (1, 2), (1, 5), (1, 10), (1, 11), (1, 12),
    (1, 13), (1, 14), (2, 0), (2, 20), (2, 25), (2, 26), (2, 30),
    (2, 50), (2, 70), (3, 0), (3, 10), (3, 20), (3, 21), (4, 0),
    (4, 2), (4, 3), (4, 50), (4, 51), (5, 0), (5, 2), (5, 10),
    (5, 50), (6, 0), (6, 2), (6, 50), (7, 0), (7, 1), (7, 20),
    (7, 40), (7, 60), (7, 61), (8, 0), (8, 20), (8, 40), (8, 60),
    (9, 0), (9, 20), (9, 40), (9, 60), (10, 0), (10, 1), (10, 20),
    (10, 40), (10, 60), (11, 0), (11, 20), (11, 40),
]

# Discovery is deliberately limited to the reviewed 1.00-11.40 set.  Merely
# placing another MP4 in either archive root must not make it patchable.
AVAILABLE_EXACT_RELEASES = tuple(EXPECTED_RELEASES)
SOURCE_ALIASES = {
    (6, 0, 1): (6, 0),
    (7, 1, 1): (7, 1),
    (8, 20, 2): (8, 20),
}

ABI_SIGNATURES = {
    "PPR_ABI_LEGACY": struct.pack(
        "<10I",
        0xD10303FF, 0xA9066FFC, 0xA90767FA, 0xA9085FF8,
        0xA90957F6, 0xA90A4FF4, 0xA90B7BFD, 0x9102C3FD,
        0xB94053B4, 0x2A0703F9,
    ),
    "PPR_ABI_CURRENT": bytes.fromhex(
        "ff0303d1fd7b06a9fd830191fc6f07a9fa6708a9f85f09a9"
        "f6570aa9f44f0ba9b4a340b9"
    ),
    "PPR_ABI_LATE": struct.pack(
        "<10I",
        0xD10303FF, 0xA9067BFD, 0xA9076FFC, 0xA90867FA,
        0xA9095FF8, 0xA90A57F6, 0xA90B4FF4, 0x910183FD,
        0xB940A3B4, 0xAA0203FA,
    ),
}

ABI_LAYOUTS = {
    "PPR_ABI_LEGACY": {
        "precheck": 0x7C,
        "precheck_normal": 0x80,
        "precheck_special": 0xB4,
        "bies_dispatch": 0x198,
        "sha_wait": 0x220,
        "common_return": 0x2D4,
        "submit_call": 0x330,
    },
    "PPR_ABI_CURRENT": {
        "precheck": 0x7C,
        "precheck_normal": 0x80,
        "precheck_special": 0xB4,
        "bies_dispatch": 0x1B4,
        "sha_wait": 0x240,
        "common_return": 0x2F0,
        "submit_call": 0x334,
    },
    "PPR_ABI_LATE": {
        "precheck": 0x68,
        "precheck_normal": 0x6C,
        "precheck_special": 0xA0,
        "bies_dispatch": 0x190,
        "sha_wait": 0x210,
        "common_return": 0x2BC,
        "submit_call": 0x324,
    },
}

ABI_DISPATCH_SETUPS = {
    "PPR_ABI_LEGACY": bytes.fromhex(
        "a92b40b9e1031caae20316aaeb1300f9e303152af41b00b9e4031b2a"
        "e80b00f9e5031aaae90b00b9e603192af80300b9e703172af9030baa"
    ),
    "PPR_ABI_CURRENT": bytes.fromhex(
        "e1031caae20316aae303152ae4031b2ae5031aaae603192ae7030b2a"
        "ec1300f9fc030caaf41b00b9f7030b2ae80b00f9e90b00b9f80300b9"
    ),
    "PPR_ABI_LATE": bytes.fromhex(
        "282705b9a84740f9e00313aaa97b40b9e2031aaae50306aae603072a"
        "e703172af61300f9f41b00b9f503032ae80b00f9e90b00b9fc0300b9"
    ),
}

AES_SITE_OFFSETS = {
    ("PPR_ABI_LEGACY", True): (0x15C, 0x25C),
    ("PPR_ABI_LEGACY", False): (0x16C, 0x290),
    ("PPR_ABI_CURRENT", False): (0x168, 0x294),
    ("PPR_ABI_LATE", False): (0x15C, 0x284),
}

# These words describe the independently verified argument dataflow rather
# than merely identifying the surrounding functions.  The common helper
# receives AES/SHA at incoming SP+0x18/SP+0x20, preserves trace/a18 from
# incoming SP+0x48 and saves a6 from w5.  A profile must retain that exact
# chain before the internal descriptor-call hooks are considered safe.
COMMON_DATAFLOW_WORDS = {
    "PPR_ABI_LEGACY": (
        (0x0DC, 0xF9402FAB),  # ldr x11, [x29, #0x58] (trace/a18)
        (0x0E0, 0xB81AC3A5),  # stur w5, [x29, #-0x54] (a6)
        (0x160, 0xB9402BA9),  # ldr w9, [x29, #0x28] (AES)
        (0x184, 0xB9000BE9),  # str w9, [sp, #8] (dispatch AES)
        (0x194, 0xAA0B03F9),  # mov x25, x11 (preserve trace)
        (0x1DC, 0xAA1903EB),  # mov x11, x25 (restore trace)
        (0x214, 0xAA0B03E3),  # mov x3, x11 (first queue-1 wait)
        (0x21C, 0xAA0B03FB),  # mov x27, x11 (SHA outgoing trace)
    ),
    "PPR_ABI_CURRENT": (
        (0x0DC, 0xF94057AC),  # ldr x12, [x29, #0xa8] (trace/a18)
        (0x0E4, 0xB81F43A5),  # stur w5, [x29, #-0xc] (a6)
        (0x178, 0xB9407BA9),  # ldr w9, [x29, #0x78] (AES)
        (0x1AC, 0xB9000BE9),  # str w9, [sp, #8] (dispatch AES)
        (0x19C, 0xAA0C03FC),  # mov x28, x12 (preserve trace)
        (0x200, 0xAA1C03EC),  # mov x12, x28 (restore trace)
        (0x230, 0xAA0C03E3),  # mov x3, x12 (first queue-1 wait)
        (0x23C, 0xAA0C03FB),  # mov x27, x12 (SHA outgoing trace)
    ),
    "PPR_ABI_LATE": (
        (0x0C8, 0xF94057B6),  # ldr x22, [x29, #0xa8] (trace/a18)
        (0x0D0, 0xB81F43A5),  # stur w5, [x29, #-0xc] (a6)
        (0x164, 0xB9407BA9),  # ldr w9, [x29, #0x78] (AES)
        (0x188, 0xB9000BE9),  # str w9, [sp, #8] (dispatch AES)
        (0x208, 0xAA1603E3),  # mov x3, x22 (first queue-1 wait)
    ),
}

# The native dispatch receives the AES index at its incoming SP+8.  The
# following exact chains keep the complete w32 value until w7 is reloaded at
# each of the two AES descriptor calls; no byte mask or range reduction may
# be introduced between these points.
AES_DISPATCH_DATAFLOW_WORDS = {
    ("PPR_ABI_LEGACY", True): (
        (0x038, 0xB9401BAA),  # ldr w10, [x29, #0x18]
        (0x058, 0xB90037EA),  # str w10, [sp, #0x34]
    ),
    ("PPR_ABI_LEGACY", False): (
        (0x038, 0xB9401BAA),
        (0x058, 0xB90037EA),
    ),
    ("PPR_ABI_CURRENT", False): (
        (0x020, 0xB9406BA8),  # ldr w8, [x29, #0x68]
        (0x040, 0xB81EC3A8),  # stur w8, [x29, #-0x14]
    ),
    ("PPR_ABI_LATE", False): (
        (0x040, 0xB9406BBB),  # ldr w27, [x29, #0x68]
    ),
}

AES_SITE_SETUP_WORDS = {
    ("PPR_ABI_LEGACY", True): (
        (-0x18, (0x294693E7, 0x321403E1, 0x321D03E6,
                 0x8B3B4102, 0xAA1C03E0, 0x2A1F03E5)),
        (-0x1C, (0x294693E7, 0xB24103E3, 0x321003E1,
                 0x321E07E6, 0xAA1C03E0, 0x2A1F03E5,
                 0xB3707D03)),
    ),
    ("PPR_ABI_LEGACY", False): (
        (-0x0C, (0x294693E7, 0xAA1403E0, 0x2A1F03E5)),
        (-0x10, (0x294693E7, 0xAA1403E0, 0x2A1F03E5,
                 0xB3707D83)),
    ),
    ("PPR_ABI_CURRENT", False): (
        (-0x2C, (0xB85EC3A7, 0xAA1403E0, 0xCB090108,
                 0x52820001, 0x8B0A1169, 0xF85F03AA,
                 0x2A1F03E5, 0x52800106, 0xD37FF908,
                 0x8B3B4142, 0xB828693C)),
        (-0x28, (0xB85EC3A7, 0xD2F00003, 0xCB0A0129,
                 0xAA1403E0, 0x52A00021, 0x2A1F03E5,
                 0x52800186, 0xD37FF929, 0xB3707D83,
                 0xB829691C)),
    ),
    ("PPR_ABI_LATE", False): (
        (-0x10, (0x2A1B03E7, 0xB829691C, 0xF85F03A8,
                 0x8B080142)),
        (-0x0C, (0x2A1B03E7, 0xD37FF908, 0xB828693C)),
    ),
}

# Starts at the full-width SHA-index load and ends immediately before the
# terminal SHA BL.  Besides w7, these signatures fix a6 in w3 and trace/a18
# in the second register of STP [sp,#0x30], i.e. SHA outgoing SP+0x38.
SHA_AUTH_SETUP_SIGNATURES = {
    "PPR_ABI_LEGACY": (0x240, bytes.fromhex(
        "a73340b9eb0b0032a9934079ec031d32aa2340f9ed031f32"
        "c812080ba3c35ab8084d4092eba30039ae008052ec830039"
        "e4031032ed630039e63f0032e86f03a9e00313aaee430039"
        "e10316aae9130079e203152aea0300f9e52270b3"
    )),
    "PPR_ABI_CURRENT": (0x25C, bytes.fromhex(
        "a78340b90500f0d2a93341790c018052aa4b40f94d008052"
        "c816080ba3435fb8084d4092eba30039ab008052e00313aa"
        "e10316aae203152a2400a052e6ff9f52852270b3ec830039"
        "ed630039eb430039e9130079ea0300f9e86f03a9"
    )),
    "PPR_ABI_LATE": (0x234, bytes.fromhex(
        "a78340b90c018052a93341794d008052aa4b40f94817080b"
        "a3435fb8084d4092eba30039ab008052e00313aae1031aaa"
        "e203192a2400a052e6ff9f52ec830039ed630039eb430039"
        "e9130079ea0300f9e85b03a9"
    )),
}

# 4.00 through 5.50 use w22 where 6.00 through 10.60 use w27 for
# the same selected-buffer addition.  Neither register carries SHA, a6 or
# trace; keep both observed compiler allocations explicit and reject any
# other drift in the setup.
SHA_AUTH_SETUP_WORD_ALTERNATES = {
    "PPR_ABI_CURRENT": {
        0x18: (0x0B0812C8, 0x0B0816C8),
    },
}

AES_APPEND_CALL_OFFSETS = {
    "PPR_ABI_LEGACY": 0xE8,
    "PPR_ABI_CURRENT": 0xA4,
    "PPR_ABI_LATE": 0x9C,
}

PLAINTEXT_APPEND_CALL_OFFSETS = {
    ("PPR_ABI_LEGACY", True): 0x58,
    ("PPR_ABI_LEGACY", False): 0x58,
    ("PPR_ABI_CURRENT", False): 0x58,
    ("PPR_ABI_LATE", False): 0x54,
}

AES_DESCRIPTOR_SIGNATURES = {
    "PPR_ABI_LEGACY": bytes.fromhex(
        "ffc300d1fd7b02a9fd830091e9071d32ff7f01a9e8031faa"
        "297c60b3e97f00a9c200f8b74afc6fd3"
    ),
    "PPR_ABI_CURRENT": bytes.fromhex(
        "ffc300d1fd7b02a9fd83009148fc6fd36afc6fd3e803282a"
        "ea032a2a08011f125f0000f16900e0d2"
    ),
    "PPR_ABI_LATE": bytes.fromhex(
        "ffc300d1fd7b02a9fd83009148fc6fd3490080522801280a"
        "5f0000f16a00e0d24bbc60d3083d50d3"
    ),
}

PLAINTEXT_DESCRIPTOR_SIGNATURES = {
    ("PPR_ABI_LEGACY", True): bytes.fromhex(
        "ffc300d1fd7b02a9fd83009148fc6fd38d2c0012e803282a"
        "08011f1249bc60d3eb03032a08fd41d34a7c4092ac100c53"
    ),
    ("PPR_ABI_LEGACY", False): bytes.fromhex(
        "ffc300d1fd7b02a9fd83009148fc6fd38d2c0012e803282a"
        "08011f1249bc60d3eb03032a08fd41d34a7c4092ac100c53"
    ),
    ("PPR_ABI_CURRENT", False): bytes.fromhex(
        "ffc300d1fd7b02a9fd8300918a2c001248fc6fd3e803282a"
        "ec03032a08011f1249bc60d34c2d4eb308fd41d34b7c4092"
    ),
    ("PPR_ABI_LATE", False): bytes.fromhex(
        "ffc300d1fd7b02a9fd83009148fc6fd3490080528a2c0012"
        "2801280ae903032a08fd41d329c90aaa4a3c6092ac100c53"
    ),
}

SHA_RELEASE_OFFSETS = {
    ("PPR_ABI_LEGACY", True): 0x230,
    ("PPR_ABI_LEGACY", False): 0x268,
    ("PPR_ABI_CURRENT", False): 0x278,
    ("PPR_ABI_LATE", False): 0x260,
}

SHA_RELEASE_SIGNATURES = {
    ("PPR_ABI_LEGACY", True): bytes.fromhex(
        "690a44b988fe50d32a3d08534901290b3f01086b49010054"
        "c90e00116a46288b49c10879ea030032690243f94821c89a"
        "0801092a095d40b3690203f9e1030032"
    ),
    ("PPR_ABI_LEGACY", False): bytes.fromhex(
        "690a43b988fe50d32a3d08534901290b3f01086b49010054"
        "c90e00116a46288b49c10679ea030032692e42f94821c89a"
        "0801092a095d40b3692e02f9e1030032"
    ),
    ("PPR_ABI_CURRENT", False): bytes.fromhex(
        "680a43b9093d08532901280b88fe50d33f01086b49010054"
        "c90e00116a46288b49c106792a008052692e42f94821c89a"
        "0801092a095d40b3692e02f9e00313aa"
    ),
    ("PPR_ABI_LATE", False): bytes.fromhex(
        "680a43b9093d08532901280ba8fe50d33f01086b49010054"
        "c90e00116a46288b49c106792a008052692e42f94821c89a"
        "0801092a095d40b3692e02f9e00313aa"
    ),
}

COMPLETION_TAILS = {
    ("PPR_ABI_LEGACY", True): bytes.fromhex(
        "89024039286b061168f609b9ff02096b62000054690a178b28990ab9"
        "690a178be0031f2a28c90ab903000014e0030832005d0033"
    ),
    ("PPR_ABI_LEGACY", False): bytes.fromhex(
        "89024039286b061168fe04b9ff02096b62000054690a178b288505b9"
        "690a178be0031f2a28b505b903000014e0030832005d0033"
    ),
    ("PPR_ABI_CURRENT", False): bytes.fromhex(
        "69224c39286b061168fe04b95f03096b62000054690a148b288505b9"
        "690a148be0031f2a28b505b9030000140020a052005d0033"
    ),
    ("PPR_ABI_LATE", False): bytes.fromhex(
        "ddf3ff976a224c39086b0611690a148b68fe04b9ff020a6b42000054"
        "288505b9e0031f2a28b505b9030000140020a052005d0033"
    ),
}

IDMA_SIGNATURES = {
    ("PPR_ABI_LEGACY", True): bytes.fromhex(
        "f90f1bf8f85f01a9f65702a9f44f03a9fd7b04a9fd03019108bc4079"
    ),
    ("PPR_ABI_LEGACY", False): bytes.fromhex(
        "f90f1bf8f85f01a9f65702a9f44f03a9fd7b04a9fd03019108684079"
    ),
    ("PPR_ABI_CURRENT", False): bytes.fromhex(
        "fd7bbba9f90b00f9fd030091f85f02a9f65703a9f44f04a908684079"
    ),
    ("PPR_ABI_LATE", False): bytes.fromhex(
        "fd7bbba9fa6701a9f85f02a9f65703a9f44f04a9fd03009108684079"
    ),
}

DIRECT_SIGNATURES = {
    ("PPR_ABI_LEGACY", True): bytes.fromhex(
        "fc6fbaa9fa6701a9f85f02a9f65703a9f44f04a9fd7b05a9fd430191"
        "08bc4079f30300aaa80b003769da40793f090071"
    ),
    ("PPR_ABI_LEGACY", False): bytes.fromhex(
        "fc6fbaa9fa6701a9f85f02a9f65703a9f44f04a9fd7b05a9fd430191"
        "08684079f30300aa080b0037699a40793f090071"
    ),
    ("PPR_ABI_CURRENT", False): bytes.fromhex(
        "fd7bbaa9fc6f01a9fd030091fa6702a9f85f03a9f65704a9f44f05a9"
        "08684079f30300aa080b0037699a40793f090071"
    ),
    ("PPR_ABI_LATE", False): bytes.fromhex(
        "fd7bbaa9fc6f01a9fa6702a9f85f03a9f65704a9f44f05a9fd030091"
        "08684079f30300aa080b0037699a40793f090071"
    ),
}

DIRECT_COMPLETION_SIGNATURES = {
    True: bytes.fromhex(
        "69f209b909390ab969f609b94900005409990ab9"
    ),
    False: bytes.fromhex(
        "69fa04b9092505b969fe04b949000054098505b9"
    ),
}

SUBMIT_SIGNATURES = {
    "PPR_ABI_LEGACY": bytes.fromhex("f30f1ef8fd7b01a9fd430091"),
    "PPR_ABI_CURRENT": bytes.fromhex("fd7bbea9f44f01a9fd030091"),
    "PPR_ABI_LATE": bytes.fromhex("fd7bbea9f30b00f9fd030091"),
}


def fail(message):
    raise SystemExit(f"PPR profile generation failed: {message}")


def signed(value, bits):
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign


def branch26_target(vaddr, word):
    return vaddr + (signed(word & 0x03FFFFFF, 26) << 2)


def imm19_target(vaddr, word):
    return vaddr + (signed((word >> 5) & 0x7FFFF, 19) << 2)


def release_key(name):
    match = re.fullmatch(r"(\d+)\.(\d+)(?:\.(\d+))?", name)
    return tuple(int(part) for part in match.groups() if part is not None) \
        if match else None


def release_name(release):
    return ".".join([str(release[0]), *(f"{part:02d}" for part in release[1:])])


def firmware_value(release):
    if len(release) != 2:
        fail(f"{release_name(release)} is an alias, not a firmware profile")
    major, minor = release
    return ((major // 10) << 28) | ((major % 10) << 24) | \
           ((minor // 10) << 20) | ((minor % 10) << 16)


class Elf64:
    PT_LOAD = 1
    EM_AARCH64 = 183

    def __init__(self, path):
        self.path = pathlib.Path(path)
        raw = self.path.read_bytes()
        if raw[:6] != b"\x7fELF\x02\x01":
            fail(f"{path}: expected little-endian ELF64")
        if struct.unpack_from("<H", raw, 0x12)[0] != self.EM_AARCH64:
            embedded = raw.find(b"\x7fELF\x02\x01", 1)
            if embedded < 0 or \
               struct.unpack_from("<H", raw, embedded + 0x12)[0] != \
               self.EM_AARCH64:
                fail(f"{path}: no embedded AArch64 ELF")
            raw = raw[embedded:]
        self.data = raw
        phoff = struct.unpack_from("<Q", raw, 0x20)[0]
        phentsize, phnum = struct.unpack_from("<HH", raw, 0x36)
        self.loads = []
        for index in range(phnum):
            off = phoff + index * phentsize
            p_type, p_flags = struct.unpack_from("<II", raw, off)
            if p_type != self.PT_LOAD:
                continue
            p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = \
                struct.unpack_from("<QQQQQQ", raw, off + 8)
            self.loads.append({
                "offset": p_offset,
                "vaddr": p_vaddr,
                "paddr": p_paddr,
                "filesz": p_filesz,
                "memsz": p_memsz,
                "flags": p_flags,
                "align": p_align,
            })

    def segment_at(self, vaddr):
        for segment in self.loads:
            if segment["vaddr"] <= vaddr < \
               segment["vaddr"] + segment["filesz"]:
                return segment
        fail(f"{self.path}: VA {vaddr:#x} is not file-backed")

    def read_va(self, vaddr, size):
        segment = self.segment_at(vaddr)
        delta = vaddr - segment["vaddr"]
        if delta + size > segment["filesz"]:
            fail(f"{self.path}: VA range {vaddr:#x}+{size:#x} crosses segment")
        start = segment["offset"] + delta
        return self.data[start:start + size]

    def sheath(self, segment, vaddr, size):
        delta = vaddr - segment["vaddr"]
        start = segment["offset"] + delta
        return self.data[start:start + size]

    def word(self, vaddr):
        return struct.unpack("<I", self.read_va(vaddr, 4))[0]

    def find(self, signature):
        matches = []
        for segment in self.loads:
            start = segment["offset"]
            end = start + segment["filesz"]
            cursor = start
            while True:
                cursor = self.data.find(signature, cursor, end)
                if cursor < 0:
                    break
                matches.append(segment["vaddr"] + cursor - start)
                cursor += 1
        return matches

    def callers(self, target):
        matches = []
        for segment in self.loads:
            if not segment["flags"] & 1:
                continue
            start = segment["offset"]
            for delta in range(0, segment["filesz"] - 3, 4):
                word = struct.unpack_from("<I", self.data, start + delta)[0]
                vaddr = segment["vaddr"] + delta
                if word & 0xFC000000 == 0x94000000 and \
                   branch26_target(vaddr, word) == target:
                    matches.append(vaddr)
        return matches


def has_exact_release_marker(source, release):
    marker = f"releases/{release[0]:02d}.{release[1]:02d}".encode()
    data = source.data if isinstance(source, Elf64) else Elf64(source).data
    cursor = 0
    while True:
        cursor = data.find(marker, cursor)
        if cursor < 0:
            return False
        end = cursor + len(marker)
        if end == len(data) or data[end] not in b".0123456789":
            return True
        cursor += 1


def source_matches_release(path, release):
    base_release = SOURCE_ALIASES.get(release, release)
    try:
        return has_exact_release_marker(path, base_release)
    except SystemExit:
        return False


def discover_source_inventory(full_root, dram_root):
    sources = {}
    aliases = {}

    def consider(release, path):
        if release in SOURCE_ALIASES:
            destination = aliases
        elif release in AVAILABLE_EXACT_RELEASES:
            destination = sources
        else:
            return
        if release not in destination and \
           source_matches_release(path, release):
            destination[release] = path

    if full_root:
        for directory in pathlib.Path(full_root).iterdir():
            match = re.fullmatch(r"(\d+\.\d+(?:\.\d+)?)_mp4",
                                 directory.name)
            if not match:
                continue
            release = release_key(match.group(1))
            for candidate in sorted(directory.rglob("a53.elf")):
                consider(release, candidate)
                if release in sources or release in aliases:
                    break
    if dram_root:
        for directory in pathlib.Path(dram_root).iterdir():
            release = release_key(directory.name)
            candidate = directory / "mp4_dram.elf"
            if release and candidate.is_file() and \
               release not in sources and release not in aliases:
                consider(release, candidate)
    return sources, aliases


def discover_sources(full_root, dram_root):
    sources, _ = discover_source_inventory(full_root, dram_root)
    return sources


def one(items, description, elf):
    if len(items) != 1:
        fail(f"{elf.path}: expected one {description}, found {items}")
    return items[0]


def expect_relative_words(elf, base, expected, description):
    for offset, wanted in expected:
        actual = elf.word(base + offset)
        if actual != wanted:
            fail(f"{elf.path}: {description} changed at +{offset:#x}: "
                 f"expected {wanted:#010x}, found {actual:#010x}")


def expect_word_signature(elf, address, expected, alternates, description):
    actual = elf.read_va(address, len(expected))
    for offset in range(0, len(expected), 4):
        wanted = struct.unpack_from("<I", expected, offset)[0]
        found = struct.unpack_from("<I", actual, offset)[0]
        allowed = alternates.get(offset, (wanted,))
        if found not in allowed:
            fail(f"{elf.path}: {description} changed at +{offset:#x}: "
                 f"expected one of {[hex(word) for word in allowed]}, "
                 f"found {found:#010x}")


def is_str_w_to_sp(word, byte_offset):
    return word & 0xFFC003E0 == 0xB90003E0 and \
           ((word >> 10) & 0xFFF) * 4 == byte_offset


def checked_bl_target(elf, address, description):
    word = elf.word(address)
    if word & 0xFC000000 != 0x94000000:
        fail(f"{elf.path}: {description} is not BL")
    return branch26_target(address, word)


def extract_profile(release, path):
    elf = Elf64(path)
    expected_release = f"releases/{release[0]:02d}.{release[1]:02d}".encode()
    if not has_exact_release_marker(elf, release):
        fail(f"{path}: missing {expected_release.decode()} release marker")

    helpers = []
    for abi, signature in ABI_SIGNATURES.items():
        helpers.extend((abi, address) for address in elf.find(signature))
    abi, helper = one(helpers, "PPR common helper", elf)
    layout = ABI_LAYOUTS[abi]
    expect_relative_words(elf, helper, COMMON_DATAFLOW_WORDS[abi],
                          "common AES/SHA/trace dataflow")
    sha_setup_offset, sha_setup_signature = \
        SHA_AUTH_SETUP_SIGNATURES[abi]
    expect_word_signature(
        elf, helper + sha_setup_offset, sha_setup_signature,
        SHA_AUTH_SETUP_WORD_ALTERNATES.get(abi, {}),
        "terminal SHA w7/a6/trace setup")

    calls = elf.callers(helper)
    if len(calls) != PPR_CALL_COUNT:
        fail(f"{path}: common helper has {len(calls)} callers")
    for address in calls:
        for stack_offset, name in ((0x18, "AES"), (0x20, "SHA")):
            if not any(is_str_w_to_sp(elf.word(candidate), stack_offset)
                       for candidate in range(address - 0x70, address, 4)):
                fail(f"{path}: caller {address:#x} does not publish the "
                     f"full-width {name} field at SP+{stack_offset:#x}")

    call_segments = []
    for address in calls:
        segment = elf.segment_at(address)
        if segment not in call_segments:
            call_segments.append(segment)
    if len(call_segments) not in (1, 2):
        fail(f"{path}: PPR calls span {len(call_segments)} segments")
    merged_text = len(call_segments) == 1
    io = None if merged_text else elf.segment_at(helper)
    dev = call_segments[-1]
    io_padding = 0 if merged_text else \
        ((io["filesz"] + 0xFFF) & ~0xFFF) - io["filesz"]
    cave_in_dev = merged_text or io_padding < 0xF0
    cave_segment = dev if cave_in_dev else io
    mapped_size = (cave_segment["filesz"] + 0xFFF) & ~0xFFF
    runtime_cave = cave_segment["vaddr"] + mapped_size - 0x100
    cave_delta = runtime_cave - cave_segment["vaddr"]
    cave_size = 0xF0
    if cave_delta < cave_segment["filesz"] or \
       cave_delta + cave_size > mapped_size:
        fail(f"{path}: selected executable tail is not page padding")

    dispatch_va = helper + layout["bies_dispatch"]
    dispatch_word = elf.word(dispatch_va)
    if dispatch_word & 0xFC000000 != 0x94000000:
        fail(f"{path}: BIoEngineSource dispatch site is not BL")
    dispatch_native = branch26_target(dispatch_va, dispatch_word)
    if elf.read_va(dispatch_va - 0x38, 0x38) != ABI_DISPATCH_SETUPS[abi]:
        fail(f"{path}: native dispatch register setup changed")
    abi_key = (abi, merged_text)
    submit_offset = 0x30C if merged_text else layout["submit_call"]
    expect_relative_words(
        elf, dispatch_native, AES_DISPATCH_DATAFLOW_WORDS[abi_key],
        "native full-width AES-marker dataflow")

    aes_site_va = [dispatch_native + offset
                   for offset in AES_SITE_OFFSETS[abi_key]]
    for address, (relative_start, expected_words) in zip(
            aes_site_va, AES_SITE_SETUP_WORDS[abi_key]):
        expected_bytes = struct.pack(
            f"<{len(expected_words)}I", *expected_words)
        if elf.read_va(address + relative_start,
                       len(expected_bytes)) != expected_bytes:
            fail(f"{path}: native AES call argument setup changed at "
                 f"{address:#x}")
    aes_site_stock = [elf.word(address) for address in aes_site_va]
    if any(word & 0xFC000000 != 0x94000000
           for word in aes_site_stock):
        fail(f"{path}: native AES descriptor site is not BL")
    aes_targets = {
        branch26_target(address, word)
        for address, word in zip(aes_site_va, aes_site_stock)
    }
    if len(aes_targets) != 1:
        fail(f"{path}: the two native AES sites do not share one producer")
    aes_descriptor = next(iter(aes_targets))
    dispatch_end = dispatch_native + submit_offset + 0x40
    actual_dispatch_aes_sites = []
    for address in range(dispatch_native, dispatch_end, 4):
        word = elf.word(address)
        if word & 0xFC000000 == 0x94000000 and \
           branch26_target(address, word) == aes_descriptor:
            actual_dispatch_aes_sites.append(address)
    if actual_dispatch_aes_sites != aes_site_va:
        fail(f"{path}: native dispatch AES call set changed: "
             f"{actual_dispatch_aes_sites}")
    aes_signature = AES_DESCRIPTOR_SIGNATURES[abi]
    if elf.read_va(aes_descriptor, len(aes_signature)) != aes_signature:
        fail(f"{path}: native AES descriptor producer changed")

    sha_call = helper + layout["sha_wait"]
    sha_word = elf.word(sha_call)
    if sha_word & 0xFC000000 != 0x94000000:
        fail(f"{path}: native WaitForIdmaAes site is not BL")
    sha_wait = branch26_target(sha_call, sha_word)
    stock_sha_callers = [address for address in elf.callers(sha_wait)
                         if address != sha_call]
    stock_sha_call = one(stock_sha_callers, "stock plaintext SHA wait", elf)
    idma_call = stock_sha_call - 0x18
    idma_word = elf.word(idma_call)
    if idma_word & 0xFC000000 != 0x94000000:
        fail(f"{path}: stock plaintext IdmaPt site is not BL")
    plaintext_idma = branch26_target(idma_call, idma_word)
    idma_signature = IDMA_SIGNATURES[abi_key]
    if elf.read_va(plaintext_idma, len(idma_signature)) != idma_signature:
        fail(f"{path}: IdmaPt ABI signature changed")

    sha_auth_sites = []
    for address in range(sha_call + 4,
                         helper + layout["common_return"], 4):
        word = elf.word(address)
        if word & 0xFC000000 == 0x94000000:
            sha_auth_sites.append(address)
    sha_auth_site = one(sha_auth_sites,
                        "terminal SHA authenticate call", elf)
    sha_auth_stock = elf.word(sha_auth_site)
    sha_authenticate = branch26_target(sha_auth_site, sha_auth_stock)
    sha_release_offset = SHA_RELEASE_OFFSETS[abi_key]
    sha_release_signature = SHA_RELEASE_SIGNATURES[abi_key]
    if elf.read_va(sha_authenticate + sha_release_offset,
                   len(sha_release_signature)) != sha_release_signature:
        fail(f"{path}: terminal SHA release/submit layout changed")

    submit_call = dispatch_native + submit_offset
    submit_word = elf.word(submit_call)
    if submit_word & 0xFC000000 != 0x94000000:
        fail(f"{path}: native queue-0 submit site is not BL")
    submit_idma = branch26_target(submit_call, submit_word)
    submit_signature = SUBMIT_SIGNATURES[abi]
    if elf.read_va(submit_idma, len(submit_signature)) != submit_signature:
        fail(f"{path}: queue submit ABI signature changed")

    direct_signature = DIRECT_SIGNATURES[abi_key]
    plaintext_direct = one(elf.find(direct_signature),
                           "stock terminal plaintext producer", elf)
    engine_offset = 0x74 if abi == "PPR_ABI_LATE" else 0x68
    if elf.word(plaintext_direct + engine_offset) != 0x528000A5:
        fail(f"{path}: stock plaintext producer no longer selects engine 5")
    direct_submit_offset = 0x18C if merged_text else 0x178
    direct_submit_va = plaintext_direct + direct_submit_offset
    direct_submit_word = elf.word(direct_submit_va)
    if direct_submit_word & 0xFC000000 != 0x94000000 or \
       branch26_target(direct_submit_va, direct_submit_word) != submit_idma:
        fail(f"{path}: stock plaintext producer queue-0 submit changed")
    completion_offset = 0x16C if merged_text else 0x158
    completion_signature = DIRECT_COMPLETION_SIGNATURES[merged_text]
    if elf.read_va(plaintext_direct + completion_offset,
                   len(completion_signature)) != completion_signature:
        fail(f"{path}: stock plaintext producer completion layout changed")
    plaintext_descriptor_call = plaintext_direct + 0x80
    plaintext_descriptor_word = elf.word(plaintext_descriptor_call)
    if plaintext_descriptor_word & 0xFC000000 != 0x94000000:
        fail(f"{path}: stock plaintext descriptor site is not BL")
    plaintext_descriptor = branch26_target(plaintext_descriptor_call,
                                           plaintext_descriptor_word)
    plaintext_descriptor_signature = PLAINTEXT_DESCRIPTOR_SIGNATURES[abi_key]
    if elf.read_va(plaintext_descriptor,
                   len(plaintext_descriptor_signature)) != \
       plaintext_descriptor_signature:
        fail(f"{path}: stock plaintext descriptor producer changed")
    aes_append_call = aes_descriptor + AES_APPEND_CALL_OFFSETS[abi]
    plaintext_append_call = plaintext_descriptor + \
        PLAINTEXT_APPEND_CALL_OFFSETS[abi_key]
    aes_append = checked_bl_target(
        elf, aes_append_call, "native AES descriptor append site")
    plaintext_append = checked_bl_target(
        elf, plaintext_append_call, "plaintext descriptor append site")
    if aes_append != plaintext_append:
        fail(f"{path}: AES/plaintext descriptors use different queue "
             f"append primitives ({aes_append:#x} != "
             f"{plaintext_append:#x})")

    common_return = helper + layout["common_return"]
    completion_tail = COMPLETION_TAILS[abi_key]
    if elf.read_va(common_return - len(completion_tail),
                   len(completion_tail)) != completion_tail:
        fail(f"{path}: queue completion layout changed")

    precheck_va = helper + layout["precheck"]
    precheck_word = elf.word(precheck_va)
    if precheck_word & 0x7F000000 != 0x35000000:
        fail(f"{path}: precheck is not CBNZ")
    expected_precheck_register = 28 if abi == "PPR_ABI_LATE" else 24
    if precheck_word & 0x1F != expected_precheck_register:
        fail(f"{path}: precheck selector register changed")
    common_error = imm19_target(precheck_va, precheck_word)

    return {
        "firmware": firmware_value(release),
        "name": f"{release[0]}.{release[1]:02d}",
        "abi": abi,
        "merged_text": int(merged_text),
        "cave_in_dev": int(cave_in_dev),
        "io_mapped_base": 0 if merged_text else io["vaddr"],
        "io_file_size": 0 if merged_text else io["filesz"],
        "io_mapped_size": 0 if merged_text else
                          ((io["filesz"] + 0xFFF) & ~0xFFF),
        "io_sram_base": 0 if merged_text else io["paddr"] - 0x7F000000,
        "dev_mapped_base": dev["vaddr"],
        "dev_file_size": dev["filesz"],
        "dev_mapped_size": (dev["filesz"] + 0xFFF) & ~0xFFF,
        "runtime_cave_va": runtime_cave,
        "plaintext_cave_va": runtime_cave + 0x50,
        "helper_va": helper,
        "precheck_normal_va": helper + layout["precheck_normal"],
        "precheck_special_va": helper + layout["precheck_special"],
        "common_error_va": common_error,
        "dispatch_native_va": dispatch_native,
        "aes_descriptor_va": aes_descriptor,
        "plaintext_descriptor_va": plaintext_descriptor,
        "plaintext_direct_va": plaintext_direct,
        "plaintext_idma_va": plaintext_idma,
        "sha_wait_idma_aes_va": sha_wait,
        "sha_authenticate_va": sha_authenticate,
        "submit_idma_va": submit_idma,
        "common_return_va": common_return,
        "call_va": calls,
        "call_stock": [elf.word(address) for address in calls],
        "aes_site_va": aes_site_va,
        "aes_site_stock": aes_site_stock,
        "sha_auth_site_va": sha_auth_site,
        "sha_auth_site_stock": sha_auth_stock,
        "precheck_va": precheck_va,
        "precheck_stock": precheck_word,
        "dispatch_va": dispatch_va,
        "dispatch_stock": dispatch_word,
    }


def fmt64(value):
    return f"0x{value:08x}ULL"


def fmt32(value):
    return f"0x{value:08x}U"


def emit_profile(profile):
    lines = [
        "    {",
        f"        .firmware = {fmt32(profile['firmware'])}, "
        f".name = \"{profile['name']}\",",
        f"        .abi = {profile['abi']}, "
        f".merged_text = {profile['merged_text']},",
        f"        .cave_in_dev = {profile['cave_in_dev']},",
        f"        .io_mapped_base = {fmt64(profile['io_mapped_base'])},",
        f"        .io_file_size = {fmt64(profile['io_file_size'])}, "
        f".io_mapped_size = {fmt64(profile['io_mapped_size'])},",
        f"        .io_sram_base = {fmt64(profile['io_sram_base'])},",
        f"        .dev_mapped_base = {fmt64(profile['dev_mapped_base'])},",
        f"        .dev_file_size = {fmt64(profile['dev_file_size'])}, "
        f".dev_mapped_size = {fmt64(profile['dev_mapped_size'])},",
        f"        .runtime_cave_va = {fmt64(profile['runtime_cave_va'])},",
        f"        .plaintext_cave_va = {fmt64(profile['plaintext_cave_va'])},",
        f"        .helper_va = {fmt64(profile['helper_va'])},",
        f"        .precheck_normal_va = {fmt64(profile['precheck_normal_va'])},",
        f"        .precheck_special_va = {fmt64(profile['precheck_special_va'])},",
        f"        .common_error_va = {fmt64(profile['common_error_va'])},",
        f"        .dispatch_native_va = {fmt64(profile['dispatch_native_va'])},",
        f"        .aes_descriptor_va = {fmt64(profile['aes_descriptor_va'])},",
        f"        .plaintext_descriptor_va = "
        f"{fmt64(profile['plaintext_descriptor_va'])},",
        f"        .plaintext_direct_va = "
        f"{fmt64(profile['plaintext_direct_va'])},",
        f"        .plaintext_idma_va = {fmt64(profile['plaintext_idma_va'])},",
        f"        .sha_wait_idma_aes_va = "
        f"{fmt64(profile['sha_wait_idma_aes_va'])},",
        f"        .sha_authenticate_va = "
        f"{fmt64(profile['sha_authenticate_va'])},",
        f"        .submit_idma_va = {fmt64(profile['submit_idma_va'])},",
        f"        .common_return_va = {fmt64(profile['common_return_va'])},",
        "        .call_va = {",
        "            " + ", ".join(fmt64(value)
                                   for value in profile["call_va"][:3]) + ",",
        "            " + ", ".join(fmt64(value)
                                   for value in profile["call_va"][3:6]) + ",",
        "            " + ", ".join(fmt64(value)
                                   for value in profile["call_va"][6:9]) + ",",
        "            " + fmt64(profile["call_va"][9]) + ",",
        "        },",
        "        .call_stock = {",
        "            " + ", ".join(fmt32(value)
                                   for value in profile["call_stock"][:4]) + ",",
        "            " + ", ".join(fmt32(value)
                                   for value in profile["call_stock"][4:8]) + ",",
        "            " + ", ".join(fmt32(value)
                                   for value in profile["call_stock"][8:]) + ",",
        "        },",
        "        .aes_site_va = {" + ", ".join(
            fmt64(value) for value in profile["aes_site_va"]) + "},",
        "        .aes_site_stock = {" + ", ".join(
            fmt32(value) for value in profile["aes_site_stock"]) + "},",
        f"        .sha_auth_site_va = "
        f"{fmt64(profile['sha_auth_site_va'])},",
        f"        .sha_auth_site_stock = "
        f"{fmt32(profile['sha_auth_site_stock'])},",
        f"        .precheck_va = {fmt64(profile['precheck_va'])},",
        f"        .precheck_stock = {fmt32(profile['precheck_stock'])},",
        f"        .dispatch_va = {fmt64(profile['dispatch_va'])},",
        f"        .dispatch_stock = {fmt32(profile['dispatch_stock'])},",
        "    },",
    ]
    return "\n".join(lines)


def validate_alias_profiles(sources, aliases, require_all=False):
    missing = [alias for alias in SOURCE_ALIASES if alias not in aliases]
    if require_all and missing:
        fail("missing source aliases: " + ", ".join(
            release_name(alias) for alias in missing))
    for alias, base in SOURCE_ALIASES.items():
        if alias not in aliases:
            continue
        if base not in sources:
            fail(f"source alias {release_name(alias)} has no base "
                 f"{release_name(base)}")
        expected = extract_profile(base, sources[base])
        actual = extract_profile(base, aliases[alias])
        differences = [key for key in expected if expected[key] != actual[key]]
        if differences:
            fail(f"source alias {release_name(alias)} differs from "
                 f"{release_name(base)} in {', '.join(differences)}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--full-root", type=pathlib.Path)
    parser.add_argument("--dram-root", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    sources, aliases = discover_source_inventory(args.full_root,
                                                 args.dram_root)
    missing = [release for release in EXPECTED_RELEASES
               if release not in sources]
    if missing:
        fail("missing releases: " + ", ".join(
            f"{major}.{minor:02d}" for major, minor in missing))
    validate_alias_profiles(sources, aliases)
    profiles = [extract_profile(release, sources[release])
                for release in EXPECTED_RELEASES]
    generated = [
        "/* Generated by generate_ppr_profiles.py; do not edit manually. */",
        "static const struct ppr_profile ppr_profiles[] = {",
        *(emit_profile(profile) for profile in profiles),
        "};",
        "",
    ]
    args.output.write_text("\n".join(generated), encoding="utf-8")
    print(f"generated {len(profiles)} exact profiles in {args.output}")


if __name__ == "__main__":
    main()
