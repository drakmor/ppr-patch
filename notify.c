#include "notify.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    char reserved[45];
    char message[3075];
} ppr_notify_request_t;

_Static_assert(sizeof(ppr_notify_request_t) == 0xc30,
               "notification request ABI size");

int sceKernelSendNotificationRequest(int, ppr_notify_request_t *, size_t,
                                     int);

static char g_line[sizeof(((ppr_notify_request_t *)0)->message)];
static size_t g_line_len;

void ppr_notify_flush(void) {
    if (g_line_len == 0)
        return;

    int saved_errno = errno;
    ppr_notify_request_t request;
    memset(&request, 0, sizeof(request));
    memcpy(request.message, g_line, g_line_len);
    request.message[g_line_len] = '\0';
    (void)sceKernelSendNotificationRequest(0, &request, sizeof(request), 0);
    g_line_len = 0;
    errno = saved_errno;
}

static void notify_feed(const char *text, size_t size) {
    if (!text)
        return;
    for (size_t i = 0; i < size; i++) {
        if (text[i] == '\n') {
            ppr_notify_flush();
        } else if (text[i] != '\r') {
            if (g_line_len == sizeof(g_line) - 1)
                ppr_notify_flush();
            g_line[g_line_len++] = text[i];
        }
    }
}

int ppr_printf(const char *format, ...) {
    char rendered[4096];
    va_list console_args, render_args;

    va_start(console_args, format);
    va_copy(render_args, console_args);
    int rc = vprintf(format, console_args);
    va_end(console_args);
    int saved_errno = errno;

    int n = vsnprintf(rendered, sizeof(rendered), format, render_args);
    va_end(render_args);
    if (n > 0) {
        size_t used = (size_t)n;
        if (used >= sizeof(rendered))
            used = sizeof(rendered) - 1;
        notify_feed(rendered, used);
    }
    errno = saved_errno;
    return rc;
}

int ppr_puts(const char *text) {
    int rc = fputs(text, stdout);
    if (rc != EOF)
        rc = fputc('\n', stdout);
    int saved_errno = errno;
    notify_feed(text, strlen(text));
    notify_feed("\n", 1);
    errno = saved_errno;
    return rc;
}

void ppr_perror(const char *prefix) {
    int saved_errno = errno;
    char rendered[512];

    errno = saved_errno;
    perror(prefix);
    int n = snprintf(rendered, sizeof(rendered), "%s%s%s\n",
                     prefix ? prefix : "",
                     prefix && prefix[0] ? ": " : "",
                     strerror(saved_errno));
    if (n > 0) {
        size_t used = (size_t)n;
        if (used >= sizeof(rendered))
            used = sizeof(rendered) - 1;
        notify_feed(rendered, used);
    }
    errno = saved_errno;
}
