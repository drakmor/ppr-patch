#!/usr/bin/env python3
"""Verify every generated MP4 PPR profile and ABI-specific wrapper."""

import argparse
import pathlib
import shlex
import struct
import subprocess
import tempfile

import generate_ppr_profiles as generator


ABI_NUMBERS = {
    "PPR_ABI_LEGACY": 0,
    "PPR_ABI_CURRENT": 1,
    "PPR_ABI_LATE": 2,
}


def fail(message):
    raise SystemExit(f"PPR profile verification failed: {message}")


def run(command, **kwargs):
    try:
        return subprocess.run(command, check=True, **kwargs)
    except subprocess.CalledProcessError as error:
        fail(f"command failed ({shlex.join(command)}): {error}")


def signed(value, bits):
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign


def branch26_target(vaddr, word):
    return vaddr + (signed(word & 0x03FFFFFF, 26) << 2)


HARNESS = r'''
#include <stdio.h>
#include "ppr_patch.c"

int main(void) {
    for (size_t n = 0; n < sizeof(ppr_profiles) / sizeof(ppr_profiles[0]); n++) {
        const struct ppr_profile *p = &ppr_profiles[n];
        struct ppr_context ctx = {.profile = p};
        if (ppr_build_images(&ctx) != 0)
            return 2;
        printf("P %08x %s %d %d %d\n", p->firmware, p->name,
               p->abi, p->merged_text, p->cave_in_dev);
        printf("V %llx %llx %llx %llx %llx %llx %llx "
               "%llx %llx %llx %llx %llx %llx %llx "
               "%llx %llx %llx %llx %llx %llx %llx\n",
               (unsigned long long)p->io_mapped_base,
               (unsigned long long)p->io_file_size,
               (unsigned long long)p->io_mapped_size,
               (unsigned long long)p->io_sram_base,
               (unsigned long long)p->dev_mapped_base,
               (unsigned long long)p->dev_file_size,
               (unsigned long long)p->dev_mapped_size,
               (unsigned long long)p->runtime_cave_va,
               (unsigned long long)p->plaintext_cave_va,
               (unsigned long long)p->helper_va,
               (unsigned long long)p->precheck_normal_va,
               (unsigned long long)p->precheck_special_va,
               (unsigned long long)p->common_error_va,
               (unsigned long long)p->dispatch_native_va,
               (unsigned long long)p->plaintext_direct_va,
               (unsigned long long)p->plaintext_idma_va,
               (unsigned long long)p->sha_wait_idma_aes_va,
               (unsigned long long)p->submit_idma_va,
               (unsigned long long)p->common_return_va,
               (unsigned long long)p->precheck_va,
               (unsigned long long)p->dispatch_va);
        printf("F %llx %llx %llx\n",
               (unsigned long long)p->aes_descriptor_va,
               (unsigned long long)p->plaintext_descriptor_va,
               (unsigned long long)p->sha_authenticate_va);
        printf("A");
        for (size_t i = 0; i < PPR_CALL_COUNT; i++)
            printf(" %llx", (unsigned long long)p->call_va[i]);
        printf("\nW");
        for (size_t i = 0; i < PPR_CALL_COUNT; i++)
            printf(" %08x", p->call_stock[i]);
        printf("\nI");
        for (size_t i = 0; i < PPR_AES_SITE_COUNT; i++)
            printf(" %llx", (unsigned long long)p->aes_site_va[i]);
        printf(" %llx", (unsigned long long)p->sha_auth_site_va);
        printf("\nJ");
        for (size_t i = 0; i < PPR_AES_SITE_COUNT; i++)
            printf(" %08x", p->aes_site_stock[i]);
        printf(" %08x", p->sha_auth_site_stock);
        printf("\nR");
        for (size_t i = 0; i < PPR_RUNTIME_SIZE / 4; i++)
            printf(" %08x", ctx.images.runtime[i]);
        printf("\nX");
        for (size_t i = 0; i < PPR_PLAINTEXT_SIZE / 4; i++)
            printf(" %08x", ctx.images.plaintext[i]);
        printf("\nH");
        for (size_t i = 0; i < PPR_SITE_COUNT; i++)
            printf(" %08x", ctx.images.site_hook[i]);
        printf("\nL");
        for (size_t i = 0; i < PPR_LEGACY_SITE_COUNT; i++)
            printf(" %08x", ctx.images.legacy_hook[i]);
        printf("\n");
    }
    return 0;
}
'''


VALUE_KEYS = [
    "io_mapped_base", "io_file_size", "io_mapped_size", "io_sram_base",
    "dev_mapped_base", "dev_file_size", "dev_mapped_size",
    "runtime_cave_va", "plaintext_cave_va", "helper_va",
    "precheck_normal_va", "precheck_special_va", "common_error_va",
    "dispatch_native_va", "plaintext_direct_va", "plaintext_idma_va",
    "sha_wait_idma_aes_va", "submit_idma_va", "common_return_va",
    "precheck_va", "dispatch_va",
]


def read_compiled_profiles(source, host_cc, temp):
    harness = temp / "profile_harness.c"
    executable = temp / "profile_harness"
    harness.write_text(HARNESS, encoding="utf-8")
    run([host_cc, "-std=c17", "-O2", "-I", str(source.parent),
         str(harness), "-o", str(executable)])
    output = run([str(executable)], capture_output=True, text=True).stdout
    profiles = {}
    current = None
    for line in output.splitlines():
        fields = line.split()
        kind = fields[0]
        if kind == "P":
            current = {
                "firmware": int(fields[1], 16), "name": fields[2],
                "abi": int(fields[3]), "merged_text": int(fields[4]),
                "cave_in_dev": int(fields[5]),
            }
            profiles[current["firmware"]] = current
        elif current is None:
            fail("harness emitted data before a profile")
        elif kind == "V":
            current.update(zip(VALUE_KEYS,
                               (int(value, 16) for value in fields[1:])))
        elif kind == "F":
            current.update(zip(
                ["aes_descriptor_va", "plaintext_descriptor_va",
                 "sha_authenticate_va"],
                (int(value, 16) for value in fields[1:])))
        elif kind in ("I", "J"):
            key = "internal_site_va" if kind == "I" else \
                  "internal_site_stock"
            current[key] = [int(value, 16) for value in fields[1:]]
        elif kind in ("A", "W", "R", "X", "H", "L"):
            key = {"A": "call_va", "W": "call_stock", "R": "runtime",
                   "X": "plaintext", "H": "hooks",
                   "L": "legacy_hooks"}[kind]
            current[key] = [int(value, 16) for value in fields[1:]]
        else:
            fail(f"unknown harness record: {line}")
    return profiles


def link_wrapper(profile, args, temp):
    far = int(profile["cave_in_dev"] and not profile["merged_text"])
    key = (profile["abi"], far, profile["merged_text"])
    obj = temp / f"ppr_wrapper_{key[0]}_{key[1]}_{key[2]}.o"
    if not obj.exists():
        run([args.arm_cc, "--target=aarch64-none-elf",
             f"-DPPR_ABI={key[0]}", f"-DPPR_FAR_BRANCHES={key[1]}",
             f"-DPPR_MERGED_TEXT={key[2]}", "-c", str(args.asm),
             "-o", str(obj)])
    linked = temp / f"ppr_wrapper_{profile['firmware']:08x}.elf"
    runtime = temp / f"ppr_runtime_{profile['firmware']:08x}.bin"
    plaintext = temp / f"ppr_plaintext_{profile['firmware']:08x}.bin"
    symbols = {
        "PPR_RUNTIME_CAVE_VA": profile["runtime_cave_va"],
        "PPR_PLAINTEXT_CAVE_VA": profile["plaintext_cave_va"],
        "original_helper": profile["helper_va"],
        "precheck_normal": profile["precheck_normal_va"],
        "precheck_special": profile["precheck_special_va"],
        "common_error": profile["common_error_va"],
        "dispatch_native": profile["dispatch_native_va"],
        "aes_descriptor": profile["aes_descriptor_va"],
        "plaintext_descriptor": profile["plaintext_descriptor_va"],
        "plaintext_direct": profile["plaintext_direct_va"],
        "plaintext_idma": profile["plaintext_idma_va"],
        "sha_wait_idma_aes": profile["sha_wait_idma_aes_va"],
        "sha_authenticate": profile["sha_authenticate_va"],
        "submit_idma_aes": profile["submit_idma_va"],
        "common_return": profile["common_return_va"],
    }
    command = [args.arm_ld, "-T", str(args.linker), "-o", str(linked)]
    command.extend(f"--defsym={name}={value:#x}"
                   for name, value in symbols.items())
    command.append(str(obj))
    run(command)
    run([args.objcopy, "--dump-section", f".runtime={runtime}", str(linked)])
    run([args.objcopy, "--dump-section", f".plaintext={plaintext}",
         str(linked)])
    return runtime.read_bytes(), plaintext.read_bytes()


def compare_profile(actual, expected):
    name = actual["name"]
    scalar_keys = [
        "name", "merged_text", "cave_in_dev", *VALUE_KEYS,
        "aes_descriptor_va", "plaintext_descriptor_va",
        "sha_authenticate_va",
    ]
    normalized = dict(expected)
    normalized["abi"] = ABI_NUMBERS[expected["abi"]]
    normalized["internal_site_va"] = [
        *expected["aes_site_va"], expected["sha_auth_site_va"]]
    normalized["internal_site_stock"] = [
        *expected["aes_site_stock"], expected["sha_auth_site_stock"]]
    for key in ["abi", *scalar_keys, "call_va", "call_stock",
                "internal_site_va", "internal_site_stock"]:
        if actual[key] != normalized[key]:
            fail(f"{name}: generated {key} differs from source analysis")
    if actual["plaintext_cave_va"] != actual["runtime_cave_va"] + 0x50:
        fail(f"{name}: cave split changed")


def verify_hooks(profile):
    sites = [*profile["call_va"], *profile["internal_site_va"]]
    targets = [profile["runtime_cave_va"]] * 10 + [
        profile["runtime_cave_va"] + 0x2C,
        profile["runtime_cave_va"] + 0x2C,
        profile["plaintext_cave_va"],
    ]
    if len(profile["hooks"]) != len(sites):
        fail(f"{profile['name']}: wrong hook count")
    for index, (site, hook, target) in enumerate(
            zip(sites, profile["hooks"], targets)):
        if hook & 0xFC000000 != 0x94000000 or \
           branch26_target(site, hook) != target:
            fail(f"{profile['name']}: hook {index} has wrong target")
    legacy_sites = [profile["precheck_va"], profile["dispatch_va"]]
    legacy_targets = [profile["runtime_cave_va"] + 0x24,
                      profile["runtime_cave_va"] + 0x3C]
    if len(profile["legacy_hooks"]) != len(legacy_sites):
        fail(f"{profile['name']}: wrong legacy hook count")
    for index, (site, hook, target) in enumerate(
            zip(legacy_sites, profile["legacy_hooks"], legacy_targets)):
        if hook & 0xFC000000 != 0x94000000 or \
           branch26_target(site, hook) != target:
            fail(f"{profile['name']}: legacy hook {index} has wrong target")
def verify_wrapper_semantics(profile):
    runtime = profile["runtime"]
    plaintext = profile["plaintext"]
    runtime_base = profile["runtime_cave_va"]
    plaintext_base = profile["plaintext_cave_va"]

    expected_runtime = [
        0xB9401BF0, 0x7103FE1F, 0x54000101, 0xB94023F0,
        0x7103FA1F, 0x540000A1, 0x5280FFF0, 0xB9001BF0,
        0x5280FFD0, 0xB90023F0, None, 0x711FFCFF,
        0x54000061, 0x528000A5, None, None, 0, 0, 0,
    ]
    for index, expected in enumerate(expected_runtime):
        if expected is not None and runtime[index] != expected:
            fail(f"{profile['name']}: selector/AES wrapper word {index} "
                 "changed")
    runtime_targets = {
        10: profile["helper_va"],
        14: profile["plaintext_descriptor_va"],
        15: profile["aes_descriptor_va"],
    }
    for index, target in runtime_targets.items():
        word = runtime[index]
        if word & 0xFC000000 != 0x14000000 or \
           branch26_target(runtime_base + index * 4, word) != target:
            fail(f"{profile['name']}: runtime tail branch {index} changed")
    expected_plaintext = [
        0x711FF8FF, 0x54000401, 0xD10083FF, 0xA90017E0,
        0xF9000BFE, 0x2A0303E2, 0xF9402FE3, None,
        0x340002C0, 0xA94017E0,
        0x79404408 if profile["merged_text"] else 0x79402808,
        0x51000508, 0xB6F801E5,
        0xB9440809 if profile["merged_text"] else 0xB9430809,
        0x53083D2A, 0x0B290149, 0x531060AB,
        0x6B0B013F, 0x54000129, 0x8B2B440A,
        0x7908C148 if profile["merged_text"] else 0x7906C148,
        0x5280002A,
        0xF9430009 if profile["merged_text"] else 0xF9422C09,
        0x9ACB2148, 0x2A090108, 0xB3405D09,
        0xF9030009 if profile["merged_text"] else 0xF9022C09,
        0x52800021, None, 0x52800020, 0xF9400BFE,
        0x910083FF, 0xD65F03C0, None,
    ]
    for index, expected in enumerate(expected_plaintext):
        if expected is not None and plaintext[index] != expected:
            fail(f"{profile['name']}: noauth completion wrapper word "
                 f"{index} changed")
    plaintext_call_targets = {
        7: profile["sha_wait_idma_aes_va"],
        28: profile["submit_idma_va"],
    }
    for index, target in plaintext_call_targets.items():
        word = plaintext[index]
        if word & 0xFC000000 != 0x94000000 or \
           branch26_target(plaintext_base + index * 4, word) != target:
            fail(f"{profile['name']}: plaintext call branch {index} "
                 "changed")
    plaintext_tail_targets = {
        33: profile["sha_authenticate_va"],
    }
    for index, target in plaintext_tail_targets.items():
        word = plaintext[index]
        if word & 0xFC000000 != 0x14000000 or \
           branch26_target(plaintext_base + index * 4, word) != target:
            fail(f"{profile['name']}: plaintext tail branch {index} changed")
    if any(plaintext[34:]):
        fail(f"{profile['name']}: plaintext cave padding is not zero")


def verify_wrapper(profile, args, temp):
    asm_runtime, asm_plaintext = link_wrapper(profile, args, temp)
    c_runtime = struct.pack(f"<{len(profile['runtime'])}I",
                            *profile["runtime"])
    c_plaintext = struct.pack(f"<{len(profile['plaintext'])}I",
                              *profile["plaintext"])
    if len(c_runtime) != 0x4C or len(c_plaintext) != 0xA0:
        fail(f"{profile['name']}: wrapper size changed")
    if c_runtime != asm_runtime:
        fail(f"{profile['name']}: C runtime wrapper differs from assembly")
    if c_plaintext != asm_plaintext:
        differences = []
        for index, (c_word, asm_word) in enumerate(zip(
                struct.iter_unpack("<I", c_plaintext),
                struct.iter_unpack("<I", asm_plaintext))):
            if c_word != asm_word:
                differences.append(
                    f"{index}: C={c_word[0]:08x} asm={asm_word[0]:08x}")
        fail(f"{profile['name']}: C plaintext wrapper differs from assembly "
             f"({'; '.join(differences)})")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host-cc", default="cc")
    parser.add_argument("--arm-cc", required=True)
    parser.add_argument("--arm-ld", required=True)
    parser.add_argument("--objcopy", required=True)
    parser.add_argument("--source", type=pathlib.Path, required=True)
    parser.add_argument("--asm", type=pathlib.Path, required=True)
    parser.add_argument("--linker", type=pathlib.Path, required=True)
    parser.add_argument("--full-root", type=pathlib.Path)
    parser.add_argument("--dram-root", type=pathlib.Path)
    args = parser.parse_args()

    sources, aliases = generator.discover_source_inventory(
        args.full_root, args.dram_root)
    missing = [release for release in generator.EXPECTED_RELEASES
               if release not in sources]
    if missing:
        fail("missing releases: " + ", ".join(
            f"{major}.{minor:02d}" for major, minor in missing))
    generator.validate_alias_profiles(sources, aliases, require_all=True)

    with tempfile.TemporaryDirectory(prefix="ppr-profile-check-") as name:
        temp = pathlib.Path(name)
        profiles = read_compiled_profiles(args.source.resolve(),
                                          args.host_cc, temp)
        expected_firmwares = {
            generator.firmware_value(release)
            for release in generator.EXPECTED_RELEASES
        }
        if set(profiles) != expected_firmwares:
            fail("compiled profile set is incomplete or contains extras")
        for release in generator.EXPECTED_RELEASES:
            firmware = generator.firmware_value(release)
            expected = generator.extract_profile(release, sources[release])
            actual = profiles[firmware]
            compare_profile(actual, expected)
            verify_hooks(actual)
            verify_wrapper_semantics(actual)
            verify_wrapper(actual, args, temp)

    print("PPR profile verification passed: 54 releases from 1.00 through "
          "11.40, exact sites, three ABIs, caves, aliases, and generated "
          "wrappers")


if __name__ == "__main__":
    main()
