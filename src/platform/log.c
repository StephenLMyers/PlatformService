#include "platform/log.h"

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>   /* strcasecmp */
#include <time.h>

#define PS_REQUEST_ID_MAX 64

static ps_log_level_t  g_min_level = PS_LOG_INFO;
static bool            g_use_color = false;
static pthread_mutex_t g_lock      = PTHREAD_MUTEX_INITIALIZER;

/*
 * Request id lives in thread-local storage rather than being threaded through
 * every call. Logging is cross-cutting; passing a context pointer into every
 * function that might log would distort every signature in the codebase.
 */
static __thread char g_request_id[PS_REQUEST_ID_MAX] = { 0 };

static const char *const LEVEL_NAMES[] = {
    "TRACE", "DEBUG", "INFO", "WARN", "ERROR"
};

/* ANSI colors, indexed by level. Only used on a tty. */
static const char *const LEVEL_COLORS[] = {
    "\033[90m", "\033[36m", "\033[32m", "\033[33m", "\033[31m"
};

#define COLOR_RESET "\033[0m"

void ps_log_init(ps_log_level_t min_level, bool use_color)
{
    g_min_level = min_level;
    g_use_color = use_color;
}

void ps_log_shutdown(void)
{
    (void)fflush(stderr);
}

void ps_log_set_level(ps_log_level_t min_level)
{
    g_min_level = min_level;
}

ps_log_level_t ps_log_get_level(void)
{
    return g_min_level;
}

const char *ps_log_level_name(ps_log_level_t level)
{
    if ((int)level < 0 || (size_t)level >= sizeof LEVEL_NAMES / sizeof LEVEL_NAMES[0]) {
        return "?";
    }
    return LEVEL_NAMES[level];
}

bool ps_log_level_from_string(const char *name, ps_log_level_t *out)
{
    if (name == NULL || out == NULL) {
        return false;
    }
    for (size_t i = 0; i < sizeof LEVEL_NAMES / sizeof LEVEL_NAMES[0]; i++) {
        if (strcasecmp(name, LEVEL_NAMES[i]) == 0) {
            *out = (ps_log_level_t)i;
            return true;
        }
    }
    return false;
}

void ps_log_set_request_id(const char *request_id)
{
    if (request_id == NULL) {
        g_request_id[0] = '\0';
        return;
    }
    /* Truncating is correct here: a request id is a label, not data. */
    size_t n = strlen(request_id);
    if (n >= sizeof g_request_id) {
        n = sizeof g_request_id - 1;
    }
    memcpy(g_request_id, request_id, n);
    g_request_id[n] = '\0';
}

/* ISO-8601 UTC with milliseconds. Buffer must hold at least 25 bytes. */
static void format_timestamp(char *buf, size_t buflen)
{
    struct timespec ts;
    struct tm       tm_utc;

    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        (void)snprintf(buf, buflen, "0000-00-00T00:00:00.000Z");
        return;
    }
    if (gmtime_r(&ts.tv_sec, &tm_utc) == NULL) {
        (void)snprintf(buf, buflen, "0000-00-00T00:00:00.000Z");
        return;
    }

    char base[20];
    (void)strftime(base, sizeof base, "%Y-%m-%dT%H:%M:%S", &tm_utc);

    /*
     * Clamped so the compiler can see the value is three digits. tv_nsec is
     * always 0..999999999 in practice, but nothing in the type says so, and
     * -Wformat-truncation is right to insist.
     */
    long ms = ts.tv_nsec / 1000000L;
    if (ms < 0) {
        ms = 0;
    } else if (ms > 999) {
        ms = 999;
    }
    (void)snprintf(buf, buflen, "%s.%03dZ", base, (int)ms);
}

/* Strip the directory prefix so lines read "log.c:42", not the full path. */
static const char *basename_of(const char *path)
{
    const char *slash = strrchr(path, '/');
    return (slash != NULL) ? slash + 1 : path;
}

void ps_log_write(ps_log_level_t level, const char *file, int line,
                  const char *fmt, ...)
{
    if (level < g_min_level) {
        return;
    }

    char timestamp[32];
    format_timestamp(timestamp, sizeof timestamp);

    char message[2048];
    va_list args;
    va_start(args, fmt);
    int written = vsnprintf(message, sizeof message, fmt, args);
    va_end(args);

    if (written < 0) {
        (void)snprintf(message, sizeof message, "<message formatting failed>");
    }

    const char *color = g_use_color ? LEVEL_COLORS[level] : "";
    const char *reset = g_use_color ? COLOR_RESET : "";

    (void)pthread_mutex_lock(&g_lock);

    if (g_request_id[0] != '\0') {
        (void)fprintf(stderr, "%s %s%-5s%s [%s] %s:%d  %s\n",
                      timestamp, color, ps_log_level_name(level), reset,
                      g_request_id, basename_of(file), line, message);
    } else {
        (void)fprintf(stderr, "%s %s%-5s%s %s:%d  %s\n",
                      timestamp, color, ps_log_level_name(level), reset,
                      basename_of(file), line, message);
    }
    (void)fflush(stderr);

    (void)pthread_mutex_unlock(&g_lock);
}
