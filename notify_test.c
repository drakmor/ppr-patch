#include "notify.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#define NOTIFICATION_CAPACITY 8U
#define NOTIFICATION_MESSAGE_SIZE 3075U

struct notification_request {
    char reserved[45];
    char message[NOTIFICATION_MESSAGE_SIZE];
};

_Static_assert(sizeof(struct notification_request) == 0xc30,
               "notification request ABI size");

static char g_messages[NOTIFICATION_CAPACITY][NOTIFICATION_MESSAGE_SIZE];
static unsigned g_message_count;

int sceKernelSendNotificationRequest(int device,
                                     struct notification_request *request,
                                     size_t size, int flags) {
    assert(device == 0);
    assert(size == sizeof(*request));
    assert(flags == 0);
    assert(g_message_count < NOTIFICATION_CAPACITY);
    memcpy(g_messages[g_message_count], request->message,
           sizeof(g_messages[g_message_count]));
    g_messages[g_message_count][NOTIFICATION_MESSAGE_SIZE - 1] = '\0';
    g_message_count++;
    return 0;
}

int main(void) {
    assert(ppr_printf("first") >= 0);
    assert(g_message_count == 0);

    assert(ppr_printf(" line\nsecond\n") >= 0);
    assert(g_message_count == 2);
    assert(strcmp(g_messages[0], "first line") == 0);
    assert(strcmp(g_messages[1], "second") == 0);

    assert(ppr_puts("third") >= 0);
    assert(g_message_count == 3);
    assert(strcmp(g_messages[2], "third") == 0);

    assert(ppr_printf("\n") >= 0);
    assert(g_message_count == 3);

    assert(ppr_printf("tail") >= 0);
    assert(g_message_count == 3);
    ppr_notify_flush();
    assert(g_message_count == 4);
    assert(strcmp(g_messages[3], "tail") == 0);

    assert(fputc('\n', stdout) != EOF);
    puts("notification per-line tests passed");
    return 0;
}
