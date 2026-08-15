#include "testutil.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "platform/log.h"

static const char *const CAPTURE_PATH = "build/test-scratch-log-capture.txt";

/*
 * Redirect the stderr file descriptor (not the FILE* stream itself) to a
 * scratch file. log.c writes via fprintf(stderr, ...) + fflush(stderr); the
 * stdio stream keeps writing to fd 2 exactly as before, it just no longer
 * points at the terminal.
 */
static int capture_start(void)
{
    (void)fflush(stderr);
    int saved = dup(STDERR_FILENO);
    PS_CHECK(saved >= 0);
    int fd = open(CAPTURE_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    PS_CHECK(fd >= 0);
    dup2(fd, STDERR_FILENO);
    (void)close(fd);
    return saved;
}

static void capture_stop(int saved, char *buf, size_t buflen)
{
    (void)fflush(stderr);
    dup2(saved, STDERR_FILENO);
    (void)close(saved);

    buf[0] = '\0';
    FILE *f = fopen(CAPTURE_PATH, "re");
    if (f != NULL) {
        size_t n = fread(buf, 1, buflen - 1, f);
        buf[n] = '\0';
        (void)fclose(f);
    }
    (void)remove(CAPTURE_PATH);
}

/* Length of the text between the first '[' and ']', or -1 if absent. */
static long bracket_len(const char *s)
{
    const char *open_b = strchr(s, '[');
    if (open_b == NULL) {
        return -1;
    }
    const char *close_b = strchr(open_b, ']');
    if (close_b == NULL) {
        return -1;
    }
    return (long)(close_b - open_b - 1);
}

/* ------------------------------------------------------------------------- */

static void test_level_name_roundtrip(void)
{
    static const ps_log_level_t levels[] = {
        PS_LOG_TRACE, PS_LOG_DEBUG, PS_LOG_INFO, PS_LOG_WARN, PS_LOG_ERROR
    };
    for (size_t i = 0; i < sizeof levels / sizeof levels[0]; i++) {
        const char     *name = ps_log_level_name(levels[i]);
        ps_log_level_t  back;
        PS_CHECK(ps_log_level_from_string(name, &back));
        PS_CHECK_EQ_INT(back, levels[i]);
    }
}

static void test_level_from_string_case_insensitive(void)
{
    ps_log_level_t out;
    PS_CHECK(ps_log_level_from_string("info", &out));
    PS_CHECK_EQ_INT(out, PS_LOG_INFO);
    PS_CHECK(ps_log_level_from_string("WARN", &out));
    PS_CHECK_EQ_INT(out, PS_LOG_WARN);
    PS_CHECK(ps_log_level_from_string("ErRoR", &out));
    PS_CHECK_EQ_INT(out, PS_LOG_ERROR);
}

static void test_level_from_string_unknown_rejected(void)
{
    ps_log_level_t out = PS_LOG_WARN; /* sentinel */
    PS_CHECK(!ps_log_level_from_string("VERBOSE", &out));
    PS_CHECK_EQ_INT(out, PS_LOG_WARN); /* untouched on failure */
    PS_CHECK(!ps_log_level_from_string("", &out));
}

static void test_level_from_string_null_safe(void)
{
    ps_log_level_t out;
    PS_CHECK(!ps_log_level_from_string(NULL, &out));
}

static void test_level_name_out_of_range(void)
{
    PS_CHECK_STR_EQ(ps_log_level_name((ps_log_level_t)99), "?");
}

static void test_set_get_level(void)
{
    ps_log_set_level(PS_LOG_ERROR);
    PS_CHECK_EQ_INT(ps_log_get_level(), PS_LOG_ERROR);
    ps_log_set_level(PS_LOG_TRACE);
    PS_CHECK_EQ_INT(ps_log_get_level(), PS_LOG_TRACE);
}

static void test_filtering_suppresses_below_min_level(void)
{
    ps_log_set_level(PS_LOG_WARN);

    int  saved = capture_start();
    PS_DEBUG("this must not appear");
    char below[4096];
    capture_stop(saved, below, sizeof below);
    PS_CHECK_EQ_INT(strlen(below), 0);

    saved = capture_start();
    PS_ERROR("this must appear");
    char above[4096];
    capture_stop(saved, above, sizeof above);
    PS_CHECK(strstr(above, "this must appear") != NULL);
    PS_CHECK(strstr(above, "ERROR") != NULL);

    ps_log_set_level(PS_LOG_TRACE);
}

static void test_output_contains_formatted_message(void)
{
    ps_log_set_level(PS_LOG_TRACE);

    int  saved = capture_start();
    PS_INFO("value is %d and %s", 42, "ok");
    char out[4096];
    capture_stop(saved, out, sizeof out);

    PS_CHECK(strstr(out, "INFO") != NULL);
    PS_CHECK(strstr(out, "value is 42 and ok") != NULL);
    PS_CHECK(strstr(out, "test_log.c") != NULL); /* basename, not full path */
}

static void test_request_id_appears_and_clears(void)
{
    ps_log_set_level(PS_LOG_TRACE);
    ps_log_set_request_id("req-abc-123");

    int  saved = capture_start();
    PS_INFO("with id");
    char with_id[4096];
    capture_stop(saved, with_id, sizeof with_id);
    PS_CHECK(strstr(with_id, "req-abc-123") != NULL);

    ps_log_set_request_id(NULL);

    saved = capture_start();
    PS_INFO("without id");
    char without_id[4096];
    capture_stop(saved, without_id, sizeof without_id);
    PS_CHECK(strstr(without_id, "req-abc-123") == NULL);
}

static void test_request_id_is_truncated_not_overflowed(void)
{
    ps_log_set_level(PS_LOG_TRACE);

    char long_id[256];
    memset(long_id, 'x', sizeof long_id - 1);
    long_id[sizeof long_id - 1] = '\0';
    ps_log_set_request_id(long_id);

    int  saved = capture_start();
    PS_INFO("checking truncation");
    char out[4096];
    capture_stop(saved, out, sizeof out);

    long len = bracket_len(out);
    PS_CHECK(len >= 0);
    PS_CHECK(len < (long)sizeof long_id - 1); /* shorter than the input */
    PS_CHECK(len <= 63);                      /* PS_REQUEST_ID_MAX - 1 */

    ps_log_set_request_id(NULL);
}

static void test_oversized_message_does_not_crash(void)
{
    ps_log_set_level(PS_LOG_TRACE);

    char huge[4096];
    memset(huge, 'a', sizeof huge - 1);
    huge[sizeof huge - 1] = '\0';

    int  saved = capture_start();
    PS_INFO("%s", huge);
    char out[8192];
    capture_stop(saved, out, sizeof out);

    /* Didn't crash to get here; output exists and is bounded, not garbage. */
    PS_CHECK(strlen(out) > 0);
    PS_CHECK(strlen(out) < sizeof out - 1);
}

int main(void)
{
    ps_log_init(PS_LOG_TRACE, false);

    PS_RUN_TEST(test_level_name_roundtrip);
    PS_RUN_TEST(test_level_from_string_case_insensitive);
    PS_RUN_TEST(test_level_from_string_unknown_rejected);
    PS_RUN_TEST(test_level_from_string_null_safe);
    PS_RUN_TEST(test_level_name_out_of_range);
    PS_RUN_TEST(test_set_get_level);
    PS_RUN_TEST(test_filtering_suppresses_below_min_level);
    PS_RUN_TEST(test_output_contains_formatted_message);
    PS_RUN_TEST(test_request_id_appears_and_clears);
    PS_RUN_TEST(test_request_id_is_truncated_not_overflowed);
    PS_RUN_TEST(test_oversized_message_does_not_crash);

    ps_log_shutdown();
    PS_TEST_EXIT();
}
