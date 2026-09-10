#!/usr/bin/env python3
"""Generate exact PPR profiles from full or mp4_dram-wrapped A53 ELFs."""

import argparse
import pathlib
import re
import struct


PPR_CALL_COUNT = 10
MIN_RELEASE = (1, 0)
MAX_RELEASE = (11, 40)
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
    match = re.fullmatch(r"(\d+)\.(\d+)", name)
    return tuple(map(int, match.groups())) if match else None


def firmware_value(release):
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


def discover_sources(full_root, dram_root):
    sources = {}
    if full_root:
        for directory in pathlib.Path(full_root).iterdir():
            match = re.fullmatch(r"(\d+\.\d+)_mp4", directory.name)
            if not match:
                continue
            release = release_key(match.group(1))
            candidates = sorted(directory.rglob("a53.elf"))
            if candidates:
                sources[release] = candidates[0]
    if dram_root:
        for directory in pathlib.Path(dram_root).iterdir():
            release = release_key(directory.name)
            candidate = directory / "mp4_dram.elf"
            if release and candidate.is_file() and release not in sources:
                sources[release] = candidate
    return {
        release: path for release, path in sources.items()
        if MIN_RELEASE <= release <= MAX_RELEASE
    }


def one(items, description, elf):
    if len(items) != 1:
        fail(f"{elf.path}: expected one {description}, found {items}")
    return items[0]


def extract_profile(release, path):
    elf = Elf64(path)
    expected_release = f"releases/{release[0]:02d}.{release[1]:02d}".encode()
    if expected_release not in elf.data:
        fail(f"{path}: missing {expected_release.decode()} release marker")

    helpers = []
    for abi, signature in ABI_SIGNATURES.items():
        helpers.extend((abi, address) for address in elf.find(signature))
    abi, helper = one(helpers, "PPR common helper", elf)
    layout = ABI_LAYOUTS[abi]
    calls = elf.callers(helper)
    if len(calls) != PPR_CALL_COUNT:
        fail(f"{path}: common helper has {len(calls)} callers")

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
    abi_key = (abi, merged_text)
    idma_signature = IDMA_SIGNATURES[abi_key]
    if elf.read_va(plaintext_idma, len(idma_signature)) != idma_signature:
        fail(f"{path}: IdmaPt ABI signature changed")

    submit_offset = 0x30C if merged_text else layout["submit_call"]
    submit_call = dispatch_native + submit_offset
    submit_word = elf.word(submit_call)
    if submit_word & 0xFC000000 != 0x94000000:
        fail(f"{path}: native queue-0 submit site is not BL")
    submit_idma = branch26_target(submit_call, submit_word)
    submit_signature = SUBMIT_SIGNATURES[abi]
    if elf.read_va(submit_idma, len(submit_signature)) != submit_signature:
        fail(f"{path}: queue submit ABI signature changed")

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

    fswrite_va = 0
    fswrite_stock = 0
    fswrite_patch = 0
    if abi == "PPR_ABI_CURRENT":
        candidates = []
        for mov in elf.find(struct.pack("<I", 0xD280002C)):
            site = mov - 4
            word = elf.word(site)
            if word & 0xFF00001F == 0x54000008 and \
               elf.word(mov + 8) == 0xF2A2120C:
                candidates.append(site)
        fswrite_va = one(candidates, "FsWrite KMB range guard", elf)
        fswrite_stock = elf.word(fswrite_va)
        fswrite_patch = 0x14000009

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
        "plaintext_idma_va": plaintext_idma,
        "sha_wait_idma_aes_va": sha_wait,
        "submit_idma_va": submit_idma,
        "common_return_va": common_return,
        "fswrite_kmb_range_va": fswrite_va,
        "fswrite_kmb_range_stock": fswrite_stock,
        "fswrite_kmb_range_patch": fswrite_patch,
        "call_va": calls,
        "call_stock": [elf.word(address) for address in calls],
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
        f"        .plaintext_idma_va = {fmt64(profile['plaintext_idma_va'])},",
        f"        .sha_wait_idma_aes_va = "
        f"{fmt64(profile['sha_wait_idma_aes_va'])},",
        f"        .submit_idma_va = {fmt64(profile['submit_idma_va'])},",
        f"        .common_return_va = {fmt64(profile['common_return_va'])},",
        f"        .fswrite_kmb_range_va = "
        f"{fmt64(profile['fswrite_kmb_range_va'])},",
        f"        .fswrite_kmb_range_stock = "
        f"{fmt32(profile['fswrite_kmb_range_stock'])},",
        f"        .fswrite_kmb_range_patch = "
        f"{fmt32(profile['fswrite_kmb_range_patch'])},",
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
        f"        .precheck_va = {fmt64(profile['precheck_va'])},",
        f"        .precheck_stock = {fmt32(profile['precheck_stock'])},",
        f"        .dispatch_va = {fmt64(profile['dispatch_va'])},",
        f"        .dispatch_stock = {fmt32(profile['dispatch_stock'])},",
        "    },",
    ]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--full-root", type=pathlib.Path)
    parser.add_argument("--dram-root", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    sources = discover_sources(args.full_root, args.dram_root)
    missing = [release for release in EXPECTED_RELEASES
               if release not in sources]
    if missing:
        fail("missing releases: " + ", ".join(
            f"{major}.{minor:02d}" for major, minor in missing))
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
