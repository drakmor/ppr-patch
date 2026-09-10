#include "a53_transport.h"
#include "notify.h"
#include "ppr_patch.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>

#include <ps5/kernel.h>

#define printf ppr_printf
#define puts ppr_puts

#ifndef PPR_DEFAULT_ACTION
#define PPR_DEFAULT_ACTION PPR_PATCH_STATUS
#endif
#ifndef PPR_DEFAULT_IDLE_ACK
#define PPR_DEFAULT_IDLE_ACK 0
#endif
#ifndef PPR_DEFAULT_FAST
#define PPR_DEFAULT_FAST 0
#endif
#ifndef PPR_DEFAULT_PERSISTENT
#define PPR_DEFAULT_PERSISTENT 0
#endif
#ifndef PPR_DEFAULT_BATCH
#define PPR_DEFAULT_BATCH 0
#endif
#ifndef PPR_DEFAULT_MIXED_IO
#define PPR_DEFAULT_MIXED_IO 0
#endif

static void raise_fd_limit(void) {
    struct rlimit limit;
    if (getrlimit(RLIMIT_NOFILE, &limit) == 0 &&
        limit.rlim_cur < limit.rlim_max) {
        limit.rlim_cur = limit.rlim_max;
        (void)setrlimit(RLIMIT_NOFILE, &limit);
    }
}

static void usage(const char *program) {
    printf("usage: %s [action] [transport options]\n", program);
    puts("actions:");
    puts("  --status                  inspect the installed patch");
    puts("  --install --idle          install the dynamic selector");
    puts("  --uninstall --idle        restore exact stock bytes");
    puts("  --mode native --idle      select native mode");
    puts("  --mode plaintext-noauth --idle");
    puts("                            select FE/FF plaintext mode");
    puts("  --kmb-range-install --idle");
    puts("                            bypass the opcode-0x53 AES range guard");
    puts("  --kmb-range-uninstall --idle");
    puts("                            restore the opcode-0x53 range guard");
    puts("transport options (read-only verified before use):");
    puts("  --fast --persistent --batch --mixed-io");
    puts("  --conservative            disable all fast transports");
}

int main(int argc, char **argv) {
    setbuf(stdout, NULL);
    (void)atexit(ppr_notify_flush);
    raise_fd_limit();

    enum ppr_patch_action action =
        (enum ppr_patch_action)PPR_DEFAULT_ACTION;
    int idle_acknowledged = PPR_DEFAULT_IDLE_ACK;
    int fast_mode = PPR_DEFAULT_FAST;
    struct a53_transport_options options = {
        .persistent = PPR_DEFAULT_PERSISTENT,
        .batch = PPR_DEFAULT_BATCH,
        .mixed_io = PPR_DEFAULT_MIXED_IO,
    };
    int selected = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--status") == 0 ||
            strcmp(argv[i], "--ppr-status") == 0) {
            if (selected++) goto conflict;
            action = PPR_PATCH_STATUS;
        } else if (strcmp(argv[i], "--install") == 0 ||
                   strcmp(argv[i], "--ppr-install") == 0) {
            if (selected++) goto conflict;
            action = PPR_PATCH_INSTALL;
        } else if (strcmp(argv[i], "--uninstall") == 0 ||
                   strcmp(argv[i], "--ppr-uninstall") == 0) {
            if (selected++) goto conflict;
            action = PPR_PATCH_UNINSTALL;
        } else if (strcmp(argv[i], "--kmb-range-install") == 0) {
            if (selected++) goto conflict;
            action = PPR_PATCH_KMB_RANGE_INSTALL;
        } else if (strcmp(argv[i], "--kmb-range-uninstall") == 0) {
            if (selected++) goto conflict;
            action = PPR_PATCH_KMB_RANGE_UNINSTALL;
        } else if ((strcmp(argv[i], "--mode") == 0 ||
                    strcmp(argv[i], "--ppr-mode") == 0) && i + 1 < argc) {
            if (selected++) goto conflict;
            const char *mode = argv[++i];
            if (strcmp(mode, "native") == 0)
                action = PPR_PATCH_MODE_NATIVE;
            else if (strcmp(mode, "plaintext-noauth") == 0)
                action = PPR_PATCH_MODE_PLAINTEXT_NOAUTH;
            else {
                printf("[!] unknown mode: %s\n", mode);
                return 2;
            }
        } else if (strcmp(argv[i], "--idle") == 0 ||
                   strcmp(argv[i], "--i-know-ppr-idle") == 0) {
            idle_acknowledged = 1;
        } else if (strcmp(argv[i], "--fast") == 0) {
            fast_mode = 1;
        } else if (strcmp(argv[i], "--persistent") == 0) {
            options.persistent = 1;
        } else if (strcmp(argv[i], "--batch") == 0) {
            options.batch = 1;
        } else if (strcmp(argv[i], "--mixed-io") == 0) {
            options.mixed_io = 1;
        } else if (strcmp(argv[i], "--conservative") == 0) {
            fast_mode = 0;
            options.persistent = 0;
            options.batch = 0;
            options.mixed_io = 0;
        } else if (strcmp(argv[i], "--help") == 0 ||
                   strcmp(argv[i], "-h") == 0) {
            usage(argv[0]);
            return 0;
        } else {
            printf("[!] unknown or incomplete option: %s\n", argv[i]);
            usage(argv[0]);
            return 2;
        }
    }

    uint32_t system_firmware = kernel_get_fw_version() & 0xffff0000U;
    printf("[+] FW: 0x%x\n", system_firmware);
    if (options.mixed_io && !options.batch) {
        puts("[*] mixed I/O requires batch mode; disabling mixed I/O");
        options.mixed_io = 0;
    }

    const struct a53_transport_options conservative = {0, 0, 0};
    if (a53_transport_initialize(&conservative) != 0)
        return 1;

    char version[160];
    if (a53_transport_get_version(version, sizeof(version)) != 0) {
        puts("[!] initial GET_CONF failed");
        return 1;
    }
    printf("[*] version string: \"%s\"\n", version);

    uint32_t a53_firmware = a53_transport_parse_release(version);
    if (a53_firmware)
        printf("[*] A53 release parsed as FW 0x%08x\n", a53_firmware);
    else
        puts("[!] A53 release suffix missing; using system firmware");
    if (a53_firmware && a53_firmware != system_firmware)
        printf("[!] system FW 0x%08x != A53 FW 0x%08x\n",
               system_firmware, a53_firmware);

    uint32_t target_firmware = a53_firmware ? a53_firmware : system_firmware;
    if (!ppr_patch_firmware_supported(target_firmware)) {
        printf("[!] no exact PPR profile for FW 0x%08x\n", target_firmware);
        return 1;
    }

    int fast_probe = a53_transport_verify_and_enable_fast(&options);
    if (fast_probe < 0) {
        puts("[!] could not initialize the verified fast transport");
        return 1;
    }
    if (fast_probe > 0)
        puts("[*] one or more fast transports failed validation; continuing with verified fallbacks");

    struct ppr_patch_transport transport;
    a53_transport_make_ppr(&transport, fast_mode);
    return ppr_patch_run(&transport, target_firmware, action,
                         idle_acknowledged) == 0 ? 0 : 1;

conflict:
    puts("[!] select exactly one action");
    usage(argv[0]);
    return 2;
}
