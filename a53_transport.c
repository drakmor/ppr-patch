#include "a53_transport.h"
#include "notify.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/event.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <ps5/kernel.h>

#define printf ppr_printf
#define puts ppr_puts
#define perror ppr_perror

#define DECI5S_MAGIC        0x73354450U
#define DECI5S_SRC_KERNEL   0x80FF0180U
#define DECI5S_DST_MP4      0x80FF0201U
#define DECI5S_PROTO_SDBGP  0x20000201U
#define DECI5S_DCMP         0x18U
#define DECI5S_CODE         0x50U

#define SDBGP_READ_MEMORY       0x01040021U
#define SDBGP_WRITE_MEMORY      0x01040031U
#define SDBGP_GET_CONF          0x01010010U
#define SDBGP_RES_READ_MEMORY   0x02040021U
#define SDBGP_MAX_WRITE_CHUNK   0x10000U
#define SDBGP_BATCH_READ_MAX    16U
#define SDBGP_RESPONSE_SCAN     0x800U
#define SDBGP_BATCH_SCAN_CAP    0x4000U

#define SYSCORE_AUTH_ID      0x4800000000000007ULL
#define MEM_TYPE_PA_TO_EL3   0x020000U
#define MP4_COREDUMP_CMD     0x20303000U
#define IOCTL_START          0x800c410bU
#define IOCTL_FINISH         0x8008410fU
#define IOCTL_ALTER_STATE    0x40184115U

struct deci5s_hdr {
    uint32_t magic, self_size, packet_size;
    uint32_t src, dst, protocol_id, attr, user_data;
    uint64_t timestamp;
};

struct deci5s_cmd_hdr {
    struct deci5s_hdr header;
    uint32_t dcmp, code;
    uint64_t pad0;
    uint8_t unknown0[4], num_commands, unknown1[3];
};

struct deci5s_mem_arg {
    uint32_t self_size;
    uint32_t access_size : 8, mem_type : 24;
    uint64_t addr, size;
};

struct sdbgp_command {
    uint32_t self_size;
    uint32_t total_size;
    uint32_t type;
    uint32_t flags;
    uint32_t command_no;
    uint32_t packet_no;
};

struct sdbgp_read_command {
    struct sdbgp_command common;
    uint32_t reserved;
    uint32_t n_args;
};

struct sdbgp_write_command {
    struct sdbgp_command common;
    uint32_t pid;
    uint32_t tid;
    uint32_t n_args;
    uint32_t padding;
};

struct sdbgp_read_result {
    uint32_t self_size;
    uint32_t access_and_type;
    uint64_t addr;
    uint64_t requested;
    uint64_t transferred;
    uint32_t status;
    uint32_t padding;
};

_Static_assert(sizeof(struct deci5s_hdr) == 0x28, "DECI5S header ABI");
_Static_assert(sizeof(struct deci5s_cmd_hdr) == 0x40, "SDBGP outer ABI");
_Static_assert(sizeof(struct sdbgp_command) == 0x18, "SDBGP command ABI");
_Static_assert(sizeof(struct sdbgp_read_command) == 0x20,
               "SDBGP read ABI");
_Static_assert(sizeof(struct sdbgp_write_command) == 0x28,
               "SDBGP write ABI");
_Static_assert(sizeof(struct sdbgp_read_result) == 0x28,
               "SDBGP result ABI");

extern uint64_t sceKernelReadTsc(void);

static int g_initialized;
static uint64_t g_mp4sc;
static uint64_t g_zcn_bar2;
static uint64_t g_state_addr;
static uint64_t g_flags_addr;
static uint64_t g_buffer_slot;
static uint64_t g_iommu_slot;
static uint64_t g_size_slot;
static int g_persistent;
static int g_batch;
static int g_mixed_io;
static int g_transport_fd = -1;
static int g_transport_kq = -1;
static int g_atexit_registered;
static uint64_t g_transactions;
static uint64_t g_transport_opens;
static uint64_t g_elapsed_ticks;

static uint32_t kread32(uint64_t address) {
    uint32_t value = 0;
    (void)kernel_copyout(address, &value, sizeof(value));
    return value;
}

static uint64_t kread64(uint64_t address) {
    uint64_t value = 0;
    (void)kernel_copyout(address, &value, sizeof(value));
    return value;
}

static void kwrite32(uint64_t address, uint32_t value) {
    (void)kernel_copyin(&value, address, sizeof(value));
}

static uint64_t swap_auth(uint64_t auth_id) {
    pid_t pid = getpid();
    uint64_t original = kernel_get_ucred_authid(pid);
    kernel_set_ucred_authid(pid, auth_id);
    return original;
}

static uint32_t access_size(uint64_t address, uint32_t length) {
    uint32_t combined = (uint32_t)address | length;
    if (combined & 1U) return 1;
    if (combined & 2U) return 3;
    if (combined & 4U) return 4;
    if (combined & 8U) return 5;
    return 6;
}

static int find_mp4_device(void) {
    uint64_t bus = KERNEL_ADDRESS_BUS_DATA_DEVICES;
    if (!bus) {
        puts("[!] kernel bus_data_devices address is unavailable");
        return -1;
    }
    uint64_t device = kread64(bus);
    if (!device) {
        puts("[!] bus_data_devices is empty");
        return -1;
    }

    while (device) {
        uint64_t nameunit = kread64(device + 0x58);
        if (nameunit && kread32(nameunit) == 0x3034706dU) {
            g_mp4sc = kread64(device + 0x88);
            uint64_t bar2_resource = kread64(g_mp4sc + 0x18);
            g_zcn_bar2 = kread64(bar2_resource + 0x10);
            printf("[+] mp4sc=0x%lx zcn_bar2=0x%lx\n",
                   (unsigned long)g_mp4sc,
                   (unsigned long)g_zcn_bar2);
            return 0;
        }
        device = kread64(device + 0x18);
    }
    puts("[!] MP4 device was not found");
    return -1;
}

static int initialize_mailbox(void) {
    const char *path = "/dev/mp4/dump";
    uint64_t original_auth = swap_auth(SYSCORE_AUTH_ID);
    int result = -1;
    int fd = -1;
    int kq = -1;
    int started = 0;

    if (revoke(path) < 0)
        printf("[!] revoke %s: %s (errno=%d)\n",
               path, strerror(errno), errno);

    fd = open(path, O_RDONLY);
    if (fd < 0) {
        printf("[!] open %s: %s (errno=%d)\n",
               path, strerror(errno), errno);
        goto out;
    }
    kq = kqueue();
    if (kq < 0) {
        perror("[!] kqueue");
        goto out;
    }

    struct kevent event;
    EV_SET(&event, fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
    if (kevent(kq, &event, 1, NULL, 0, NULL) < 0) {
        perror("[!] kevent register");
        goto out;
    }

    uint32_t context[6] = {12, 0, 0, 0, 0, 0};
    if (ioctl(fd, IOCTL_START, context) < 0) {
        perror("[!] ioctl START");
        goto out;
    }
    started = 1;

    struct timespec timeout = {10, 0};
    int events = kevent(kq, NULL, 0, &event, 1, &timeout);
    if (events <= 0 || (event.flags & EV_ERROR) != 0) {
        if (events == 0)
            puts("[!] timeout waiting for the initial coredump event");
        else if (events < 0)
            perror("[!] initial coredump event");
        else
            printf("[!] initial coredump event error: %ld\n",
                   (long)event.data);
        goto out;
    }
    if (ioctl(fd, IOCTL_ALTER_STATE, context) < 0) {
        perror("[!] ioctl ALTER_STATE");
        goto out;
    }

    uint64_t state_slot = 0;
    uint64_t flags_slot = 0;
    uint64_t buffer_slot = 0;
    for (uint32_t offset = 8; offset < 0x1000; offset += 4) {
        uint32_t flags = kread32(g_mp4sc + offset);
        uint32_t state = kread32(g_mp4sc + offset - 8);
        if ((flags & 0xffffU) == 0x212U &&
            (state & ~0x10U) == 0xfU) {
            state_slot = g_mp4sc + offset - 8;
            flags_slot = g_mp4sc + offset;
            break;
        }
    }

    uint32_t finish[2] = {8, 0};
    if (ioctl(fd, IOCTL_FINISH, finish) < 0) {
        perror("[!] ioctl FINISH");
        goto out;
    }
    started = 0;

    if (!state_slot || !flags_slot) {
        puts("[!] coredump mailbox state/flags were not found");
        goto out;
    }
    uint64_t first = (flags_slot - g_mp4sc) / 8;
    for (uint64_t index = first; index < 0x1000 / 8; index++) {
        uint64_t slot = g_mp4sc + index * 8;
        uint64_t value = kread64(slot);
        if ((value >> 40) == 0xffffffULL &&
            (value & 0xfffffULL) == 0) {
            buffer_slot = slot;
            break;
        }
    }
    if (!buffer_slot) {
        puts("[!] coredump mailbox buffer was not found");
        goto out;
    }

    uint64_t buffer = kread64(buffer_slot);
    if ((buffer >> 40) != 0xffffffULL || (buffer & 0xfffffULL) != 0) {
        printf("[!] invalid coredump buffer pointer: 0x%lx\n",
               (unsigned long)buffer);
        goto out;
    }

    g_state_addr = state_slot;
    g_flags_addr = flags_slot;
    g_buffer_slot = buffer_slot;
    g_iommu_slot = buffer_slot - 8;
    g_size_slot = buffer_slot - 16;
    g_initialized = 1;
    printf("[+] state=0x%lx flags=0x%lx buf=0x%lx\n",
           (unsigned long)g_state_addr,
           (unsigned long)g_flags_addr,
           (unsigned long)g_buffer_slot);
    result = 0;

out:
    if (started && fd >= 0) {
        uint32_t finish_failed[2] = {8, 0};
        (void)ioctl(fd, IOCTL_FINISH, finish_failed);
    }
    if (kq >= 0)
        close(kq);
    if (fd >= 0)
        close(fd);
    swap_auth(original_auth);
    return result;
}

static int open_transport_pair(int *fd_out, int *kq_out) {
    const char *path = "/dev/mp4/dump";
    *fd_out = -1;
    *kq_out = -1;

    if (revoke(path) < 0)
        printf("[!] revoke %s: %s (errno=%d)\n",
               path, strerror(errno), errno);
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        printf("[!] open %s: %s (errno=%d)\n",
               path, strerror(errno), errno);
        return -1;
    }
    int kq = kqueue();
    if (kq < 0) {
        perror("[!] kqueue");
        close(fd);
        return -1;
    }
    struct kevent event;
    EV_SET(&event, fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
    if (kevent(kq, &event, 1, NULL, 0, NULL) < 0) {
        perror("[!] kevent register");
        close(kq);
        close(fd);
        return -1;
    }
    *fd_out = fd;
    *kq_out = kq;
    ++g_transport_opens;
    return 0;
}

void a53_transport_shutdown(void) {
    if (g_transport_kq < 0 && g_transport_fd < 0)
        return;
    uint64_t original_auth = swap_auth(SYSCORE_AUTH_ID);
    if (g_transport_kq >= 0) {
        close(g_transport_kq);
        g_transport_kq = -1;
    }
    if (g_transport_fd >= 0) {
        close(g_transport_fd);
        g_transport_fd = -1;
    }
    swap_auth(original_auth);
}

static int open_persistent_transport(void) {
    if (g_transport_fd >= 0 && g_transport_kq >= 0)
        return 0;
    if (open_transport_pair(&g_transport_fd, &g_transport_kq) != 0)
        return -1;
    if (!g_atexit_registered) {
        if (atexit(a53_transport_shutdown) != 0) {
            a53_transport_shutdown();
            return -1;
        }
        g_atexit_registered = 1;
    }
    return 0;
}

static int send_packet(struct deci5s_hdr *packet, uint32_t packet_length,
                       const void *data, uint32_t data_length) {
    uint64_t started = sceKernelReadTsc();
    uint64_t original_auth = swap_auth(SYSCORE_AUTH_ID);
    int result = -1;
    int fd = -1;
    int kq = -1;
    int owns_pair = 0;
    ++g_transactions;

    if (g_persistent) {
        if (open_persistent_transport() != 0)
            goto out;
        fd = g_transport_fd;
        kq = g_transport_kq;
    } else {
        if (open_transport_pair(&fd, &kq) != 0)
            goto out;
        owns_pair = 1;
    }

    kwrite32(g_state_addr, ~0x10U);
    kwrite32(g_flags_addr, 0x210U);
    packet->timestamp = sceKernelReadTsc();

    uint64_t buffer = kread64(g_buffer_slot);
    (void)kernel_copyin(packet, buffer, packet_length - data_length);
    if (data && data_length)
        (void)kernel_copyin(data, buffer + packet_length - data_length,
                            data_length);

    uint64_t iommu = kread64(g_iommu_slot);
    uint32_t buffer_size = (uint32_t)kread64(g_size_slot);
    kwrite32(g_zcn_bar2 + 0xf7000, (uint32_t)(iommu >> 32));
    kwrite32(g_zcn_bar2 + 0xf8000, (uint32_t)iommu);
    kwrite32(g_zcn_bar2 + 0xf9000, buffer_size);

    uint32_t request = kread32(g_mp4sc + 0x160) + 1;
    kwrite32(g_mp4sc + 0x160, request);
    kwrite32(g_mp4sc + 0x164, MP4_COREDUMP_CMD);
    kwrite32(g_zcn_bar2 + 0xf6000, MP4_COREDUMP_CMD);

    struct kevent event;
    struct timespec timeout = {15, 0};
    int events = kevent(kq, NULL, 0, &event, 1, &timeout);
    if (events <= 0) {
        if (events == 0)
            puts("[!] DECI5S response timeout");
        else
            perror("[!] DECI5S response");
        result = -2;
    } else if ((event.flags & EV_ERROR) != 0) {
        printf("[!] DECI5S kqueue event error: %ld\n", (long)event.data);
        result = -2;
    } else {
        result = 0;
    }

    uint32_t finish[2] = {8, 0};
    if (ioctl(fd, IOCTL_FINISH, finish) < 0) {
        perror("[!] ioctl FINISH");
        if (result == 0)
            result = -3;
    }

out:
    if (owns_pair) {
        if (kq >= 0)
            close(kq);
        if (fd >= 0)
            close(fd);
    } else if (result != 0 && g_persistent) {
        a53_transport_shutdown();
    }
    swap_auth(original_auth);
    g_elapsed_ticks += sceKernelReadTsc() - started;
    return result;
}

static void initialize_outer(struct deci5s_cmd_hdr *header,
                             uint32_t total_size, uint8_t count) {
    memset(header, 0, sizeof(*header));
    header->header.magic = DECI5S_MAGIC;
    header->header.self_size = sizeof(struct deci5s_hdr);
    header->header.packet_size = total_size;
    header->header.src = DECI5S_SRC_KERNEL;
    header->header.dst = DECI5S_DST_MP4;
    header->header.protocol_id = DECI5S_PROTO_SDBGP;
    header->dcmp = DECI5S_DCMP;
    header->code = count == 1 ? DECI5S_CODE
                              : total_size - sizeof(struct deci5s_hdr);
    header->num_commands = count;
}

static int read_memory(uint64_t address, void *destination, uint32_t size) {
    struct {
        struct deci5s_cmd_hdr header;
        struct { uint32_t self, total, type, pad[4], args; } command;
        struct deci5s_mem_arg argument;
    } packet;
    if (!g_initialized || !destination || size == 0 || size > INT_MAX)
        return -1;

    memset(&packet, 0, sizeof(packet));
    initialize_outer(&packet.header, sizeof(packet), 1);
    packet.command.self = sizeof(packet.command);
    packet.command.total = sizeof(packet.command) + sizeof(packet.argument);
    packet.command.type = SDBGP_READ_MEMORY;
    packet.command.args = 1;
    packet.argument.self_size = sizeof(packet.argument);
    packet.argument.access_size = access_size(address, size);
    packet.argument.mem_type = MEM_TYPE_PA_TO_EL3;
    packet.argument.addr = address;
    packet.argument.size = size;

    uint64_t buffer = kread64(g_buffer_slot);
    if (send_packet(&packet.header.header, sizeof(packet), NULL, 0) != 0)
        return -1;
    int64_t transferred = (int64_t)kread64(buffer + 0xf8);
    if (transferred <= 0 || (uint64_t)transferred < size) {
        printf("[!] A53 read 0x%lx returned %lld bytes\n",
               (unsigned long)address, (long long)transferred);
        return -1;
    }
    (void)kernel_copyout(buffer + 0x108, destination, size);
    /* ppr_patch's scalar-read callback follows the original transport ABI:
     * a positive transferred-byte count is success, zero/negative is error. */
    return (int)transferred;
}

static int write_memory(uint64_t address, const void *source, uint32_t size) {
    struct {
        struct deci5s_cmd_hdr header;
        struct { uint32_t self, total, type, pad[5], args, padding; } command;
        struct deci5s_mem_arg argument;
    } packet;
    if (!g_initialized || !source || size == 0 ||
        size > SDBGP_MAX_WRITE_CHUNK)
        return -1;

    memset(&packet, 0, sizeof(packet));
    uint32_t total = sizeof(packet) + size;
    initialize_outer(&packet.header, total, 1);
    packet.command.self = sizeof(packet.command);
    packet.command.total = sizeof(packet.command) + sizeof(packet.argument);
    packet.command.type = SDBGP_WRITE_MEMORY;
    packet.command.args = 1;
    packet.argument.self_size = sizeof(packet.argument);
    packet.argument.access_size = access_size(address, size);
    packet.argument.mem_type = MEM_TYPE_PA_TO_EL3;
    packet.argument.addr = address;
    packet.argument.size = size;
    if (total > (uint32_t)kread64(g_size_slot)) {
        puts("[!] SDBGP write packet exceeds the mailbox buffer");
        return -1;
    }
    return send_packet(&packet.header.header, total, source, size);
}

static int parse_read_response(const uint8_t *raw, size_t raw_size,
                               uint32_t command_number,
                               uint64_t expected_address,
                               uint32_t expected_size, void *destination) {
    for (size_t type_offset = 8;
         type_offset + sizeof(uint32_t) <= raw_size;
         type_offset += sizeof(uint32_t)) {
        uint32_t type;
        memcpy(&type, raw + type_offset, sizeof(type));
        if (type != SDBGP_RES_READ_MEMORY)
            continue;

        size_t command_offset = type_offset - 8;
        struct sdbgp_command command;
        if (command_offset + sizeof(command) > raw_size)
            continue;
        memcpy(&command, raw + command_offset, sizeof(command));
        if (command.command_no != command_number ||
            command.self_size < sizeof(command) ||
            command.total_size < command.self_size ||
            command.total_size > raw_size - command_offset)
            continue;

        size_t result_offset = command_offset + command.self_size;
        struct sdbgp_read_result result;
        if (result_offset + sizeof(result) >
            command_offset + command.total_size)
            continue;
        memcpy(&result, raw + result_offset, sizeof(result));
        if (result.self_size != sizeof(result) || result.status != 0 ||
            result.addr != expected_address ||
            result.requested != expected_size ||
            result.transferred != expected_size)
            continue;

        size_t data_offset = result_offset + sizeof(result);
        if (expected_size > command_offset + command.total_size - data_offset)
            continue;
        memcpy(destination, raw + data_offset, expected_size);
        return 0;
    }
    return -1;
}

static int read_many(void *context, const uint64_t *addresses,
                     const uint32_t *sizes, void *const *destinations,
                     uint32_t count) {
    (void)context;
    struct read_block {
        struct sdbgp_read_command command;
        struct deci5s_mem_arg argument;
    };
    if (!g_batch || !addresses || !sizes || !destinations || count == 0 ||
        count > SDBGP_BATCH_READ_MAX)
        return -1;

    size_t packet_size = sizeof(struct deci5s_cmd_hdr) +
                         count * sizeof(struct read_block);
    uint32_t mailbox_size = (uint32_t)kread64(g_size_slot);
    if (packet_size > mailbox_size)
        return -1;
    uint8_t *packet = calloc(1, packet_size);
    if (!packet)
        return -1;
    struct deci5s_cmd_hdr *header = (struct deci5s_cmd_hdr *)packet;
    initialize_outer(header, (uint32_t)packet_size, (uint8_t)count);
    struct read_block *blocks = (struct read_block *)(header + 1);
    for (uint32_t i = 0; i < count; i++) {
        if (!destinations[i] || sizes[i] == 0 || sizes[i] > 0x100U) {
            free(packet);
            return -1;
        }
        blocks[i].command.common.self_size = sizeof(blocks[i].command);
        blocks[i].command.common.total_size = sizeof(blocks[i]);
        blocks[i].command.common.type = SDBGP_READ_MEMORY;
        blocks[i].command.common.command_no = i;
        blocks[i].command.n_args = 1;
        blocks[i].argument.self_size = sizeof(blocks[i].argument);
        blocks[i].argument.access_size = access_size(addresses[i], sizes[i]);
        blocks[i].argument.mem_type = MEM_TYPE_PA_TO_EL3;
        blocks[i].argument.addr = addresses[i];
        blocks[i].argument.size = sizes[i];
    }
    int result = send_packet(&header->header, (uint32_t)packet_size, NULL, 0);
    free(packet);
    if (result != 0)
        return -1;

    size_t scan_size = mailbox_size;
    if (scan_size > SDBGP_BATCH_SCAN_CAP)
        scan_size = SDBGP_BATCH_SCAN_CAP;
    uint8_t *raw = calloc(1, scan_size);
    if (!raw)
        return -1;
    (void)kernel_copyout(kread64(g_buffer_slot), raw, scan_size);
    for (uint32_t i = 0; i < count; i++) {
        if (parse_read_response(raw, scan_size, i, addresses[i], sizes[i],
                                destinations[i]) != 0) {
            free(raw);
            return -1;
        }
    }
    free(raw);
    return 0;
}

static uint32_t round_up_8(uint32_t value) {
    return (value + 7U) & ~7U;
}

static int write_pair_read_pair(
        void *context, uint64_t address0, const void *source0, uint32_t size0,
        void *readback0, uint64_t address1, const void *source1,
        uint32_t size1, void *readback1) {
    (void)context;
    struct read_block {
        struct sdbgp_read_command command;
        struct deci5s_mem_arg argument;
    };
    const uint64_t addresses[2] = {address0, address1};
    const void *sources[2] = {source0, source1};
    void *destinations[2] = {readback0, readback1};
    const uint32_t sizes[2] = {size0, size1};
    uint32_t write_sizes[2];

    if (!g_mixed_io || !source0 || !source1 || !readback0 || !readback1 ||
        size0 == 0 || size1 == 0 || size0 > SDBGP_MAX_WRITE_CHUNK ||
        size1 > SDBGP_MAX_WRITE_CHUNK)
        return -1;
    for (uint32_t i = 0; i < 2; i++)
        write_sizes[i] = sizeof(struct sdbgp_write_command) +
                         sizeof(struct deci5s_mem_arg) + round_up_8(sizes[i]);

    uint32_t packet_size = sizeof(struct deci5s_cmd_hdr) + write_sizes[0] +
                           write_sizes[1] + 2 * sizeof(struct read_block);
    if (packet_size > (uint32_t)kread64(g_size_slot))
        return -1;
    uint8_t *packet = calloc(1, packet_size);
    if (!packet)
        return -1;
    struct deci5s_cmd_hdr *header = (struct deci5s_cmd_hdr *)packet;
    initialize_outer(header, packet_size, 4);

    uint32_t offset = sizeof(*header);
    for (uint32_t i = 0; i < 2; i++) {
        struct sdbgp_write_command *command =
            (struct sdbgp_write_command *)(packet + offset);
        struct deci5s_mem_arg *argument =
            (struct deci5s_mem_arg *)(packet + offset + sizeof(*command));
        command->common.self_size = sizeof(*command);
        command->common.total_size = write_sizes[i];
        command->common.type = SDBGP_WRITE_MEMORY;
        command->common.command_no = i;
        command->n_args = 1;
        argument->self_size = sizeof(*argument);
        argument->access_size = access_size(addresses[i], sizes[i]);
        argument->mem_type = MEM_TYPE_PA_TO_EL3;
        argument->addr = addresses[i];
        argument->size = sizes[i];
        memcpy(argument + 1, sources[i], sizes[i]);
        offset += write_sizes[i];
    }
    for (uint32_t i = 0; i < 2; i++) {
        struct read_block *block = (struct read_block *)(packet + offset);
        block->command.common.self_size = sizeof(block->command);
        block->command.common.total_size = sizeof(*block);
        block->command.common.type = SDBGP_READ_MEMORY;
        block->command.common.command_no = i + 2;
        block->command.n_args = 1;
        block->argument.self_size = sizeof(block->argument);
        block->argument.access_size = access_size(addresses[i], sizes[i]);
        block->argument.mem_type = MEM_TYPE_PA_TO_EL3;
        block->argument.addr = addresses[i];
        block->argument.size = sizes[i];
        offset += sizeof(*block);
    }

    int result = send_packet(&header->header, packet_size, NULL, 0);
    free(packet);
    if (result != 0)
        return -1;

    uint8_t raw[SDBGP_RESPONSE_SCAN];
    (void)kernel_copyout(kread64(g_buffer_slot), raw, sizeof(raw));
    for (uint32_t i = 0; i < 2; i++) {
        if (parse_read_response(raw, sizeof(raw), i + 2, addresses[i],
                                sizes[i], destinations[i]) != 0)
            return -1;
    }
    return 0;
}

static int callback_read(void *context, uint64_t address, void *destination,
                         uint32_t size) {
    (void)context;
    return read_memory(address, destination, size);
}

static int callback_write(void *context, uint64_t address, const void *source,
                          uint32_t size) {
    (void)context;
    return write_memory(address, source, size);
}

static void callback_log(void *context, const char *message) {
    (void)context;
    puts(message);
}

static uint64_t callback_transactions(void *context) {
    (void)context;
    return g_transactions;
}

static uint64_t callback_opens(void *context) {
    (void)context;
    return g_transport_opens;
}

static uint64_t callback_ticks(void *context) {
    (void)context;
    return g_elapsed_ticks;
}

int a53_transport_initialize(const struct a53_transport_options *options) {
    if (!options)
        return -1;
    g_persistent = options->persistent;
    g_batch = options->batch;
    g_mixed_io = options->mixed_io;
    if (find_mp4_device() != 0)
        return -1;
    return initialize_mailbox();
}

int a53_transport_get_version(char *out, uint32_t out_size) {
    struct {
        struct deci5s_cmd_hdr header;
        struct { uint32_t self, total, type, pad[4], args; } command;
    } packet;
    if (!out || out_size < 2)
        return -1;
    memset(&packet, 0, sizeof(packet));
    initialize_outer(&packet.header, sizeof(packet), 1);
    packet.command.self = sizeof(packet.command);
    packet.command.total = sizeof(packet.command);
    packet.command.type = SDBGP_GET_CONF;
    uint64_t buffer = kread64(g_buffer_slot);
    if (send_packet(&packet.header.header, sizeof(packet), NULL, 0) != 0)
        return -1;
    memset(out, 0, out_size);
    (void)kernel_copyout(buffer + 0x148, out, out_size - 1);
    return 0;
}

uint32_t a53_transport_parse_release(const char *version) {
    const char *release = strstr(version, "releases/");
    unsigned int major = 0;
    unsigned int minor = 0;
    if (!release || sscanf(release + 9, "%u.%u", &major, &minor) != 2 ||
        major > 99 || minor > 99)
        return 0;
    return ((major / 10) << 28) | ((major % 10) << 24) |
           ((minor / 10) << 20) | ((minor % 10) << 16);
}

int a53_transport_verify_and_enable_fast(
        const struct a53_transport_options *requested) {
    uint8_t baseline[8];
    uint32_t batch0 = 0;
    uint32_t batch1 = 0;
    uint8_t persistent0[8];
    uint8_t persistent1[8];
    int batch_ok = 0;
    int persistent_ok = 0;

    if (!requested || !g_initialized)
        return -1;

    /* Probe optimized reads before exposing them to the mutating patch state
     * machine. This also guards the dynamically discovered 7.61/9.60 layout. */
    a53_transport_shutdown();
    g_persistent = 0;
    g_batch = 0;
    g_mixed_io = 0;

    if (!requested->persistent && !requested->batch && !requested->mixed_io)
        return 0;

    if (read_memory(PPR_PATCH_LAYOUT_PA, baseline, sizeof(baseline)) < 0) {
        puts("[!] fast transport probe: scalar baseline read failed");
        goto done;
    }

    if (requested->batch || requested->mixed_io) {
        const uint64_t addresses[2] = {
            PPR_PATCH_LAYOUT_PA,
            PPR_PATCH_LAYOUT_PA + sizeof(uint32_t),
        };
        const uint32_t sizes[2] = {
            sizeof(batch0), sizeof(batch1),
        };
        void *destinations[2] = {&batch0, &batch1};

        g_batch = 1;
        if (read_many(NULL, addresses, sizes, destinations, 2) == 0 &&
            memcmp(&batch0, baseline, sizeof(batch0)) == 0 &&
            memcmp(&batch1, baseline + sizeof(batch0), sizeof(batch1)) == 0) {
            batch_ok = 1;
        } else {
            puts("[!] fast transport probe: batch read mismatch; disabling batch/mixed I/O");
        }
        g_batch = 0;
    }

    if (requested->persistent) {
        g_persistent = 1;
        if (read_memory(PPR_PATCH_LAYOUT_PA, persistent0,
                        sizeof(persistent0)) >= 0 &&
            read_memory(PPR_PATCH_LAYOUT_PA, persistent1,
                        sizeof(persistent1)) >= 0 &&
            memcmp(persistent0, baseline, sizeof(baseline)) == 0 &&
            memcmp(persistent1, baseline, sizeof(baseline)) == 0) {
            persistent_ok = 1;
        } else {
            puts("[!] fast transport probe: persistent reuse mismatch; disabling persistent transport");
        }
        g_persistent = 0;
        a53_transport_shutdown();
    }

    if (requested->persistent && requested->batch &&
        persistent_ok && batch_ok) {
        const uint64_t addresses[2] = {
            PPR_PATCH_LAYOUT_PA,
            PPR_PATCH_LAYOUT_PA + sizeof(uint32_t),
        };
        const uint32_t sizes[2] = {
            sizeof(batch0), sizeof(batch1),
        };
        void *destinations[2] = {&batch0, &batch1};

        batch0 = 0;
        batch1 = 0;
        g_persistent = 1;
        g_batch = 1;
        if (read_many(NULL, addresses, sizes, destinations, 2) != 0 ||
            memcmp(&batch0, baseline, sizeof(batch0)) != 0 ||
            memcmp(&batch1, baseline + sizeof(batch0), sizeof(batch1)) != 0) {
            puts("[!] fast transport probe: persistent batch mismatch; disabling batch/mixed I/O");
            batch_ok = 0;
        }
        g_persistent = 0;
        g_batch = 0;
        a53_transport_shutdown();
    }

done:
    g_batch = requested->batch && batch_ok;
    g_mixed_io = requested->mixed_io && batch_ok;
    g_persistent = requested->persistent && persistent_ok;
    printf("[+] verified transport: persistent=%s batch=%s mixed-io=%s\n",
           g_persistent ? "on" : "off",
           g_batch ? "on" : "off",
           g_mixed_io ? "on" : "off");

    /* The capability probe is not part of the patch operation statistics.
     * Its persistent descriptor was closed, so the next open is counted. */
    g_transactions = 0;
    g_transport_opens = 0;
    g_elapsed_ticks = 0;
    return ((requested->batch && !batch_ok) ||
            (requested->mixed_io && !batch_ok) ||
            (requested->persistent && !persistent_ok)) ? 1 : 0;
}

void a53_transport_make_ppr(struct ppr_patch_transport *out, int fast_mode) {
    memset(out, 0, sizeof(*out));
    out->read = callback_read;
    out->write = callback_write;
    out->read_many = g_batch ? read_many : NULL;
    out->write_pair_read_pair = g_mixed_io ? write_pair_read_pair : NULL;
    out->log = callback_log;
    out->transaction_count = callback_transactions;
    out->transport_open_count = callback_opens;
    out->elapsed_ticks = callback_ticks;
    out->fast_mode = fast_mode;
    out->batch_enabled = g_batch;
    out->mixed_io_enabled = g_mixed_io;
}
