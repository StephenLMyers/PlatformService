/*
 * Leveled, thread-safe, structured logging.
 *
 * Deliberately offers no way to log a token, password, or hash. Anything
 * secret-shaped must be summarised by the caller (a jti prefix, a length,
 * a boolean) before it reaches this interface -- see plan 7.4.
 */
#ifndef PS_PLATFORM_LOG_H
#define PS_PLATFORM_LOG_H

#include <stdbool.h>

typedef enum {
    PS_LOG_TRACE = 0,
    PS_LOG_DEBUG = 1,
    PS_LOG_INFO  = 2,
    PS_LOG_WARN  = 3,
    PS_LOG_ERROR = 4
} ps_log_level_t;

/* Initialise before any other logging call. Safe to call once. */
void ps_log_init(ps_log_level_t min_level, bool use_color);

/* Release the logging mutex. Call once at shutdown, after all threads join. */
void ps_log_shutdown(void);

void ps_log_set_level(ps_log_level_t min_level);
ps_log_level_t ps_log_get_level(void);

/* Returns false when the name is not a known level; *out is then untouched. */
bool ps_log_level_from_string(const char *name, ps_log_level_t *out);
const char *ps_log_level_name(ps_log_level_t level);

/*
 * Bind a request identifier to the calling thread. Every subsequent log line
 * from this thread carries it until cleared. Pass NULL to clear.
 */
void ps_log_set_request_id(const char *request_id);

void ps_log_write(ps_log_level_t level, const char *file, int line,
                  const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));

#define PS_TRACE(...) ps_log_write(PS_LOG_TRACE, __FILE__, __LINE__, __VA_ARGS__)
#define PS_DEBUG(...) ps_log_write(PS_LOG_DEBUG, __FILE__, __LINE__, __VA_ARGS__)
#define PS_INFO(...)  ps_log_write(PS_LOG_INFO,  __FILE__, __LINE__, __VA_ARGS__)
#define PS_WARN(...)  ps_log_write(PS_LOG_WARN,  __FILE__, __LINE__, __VA_ARGS__)
#define PS_ERROR(...) ps_log_write(PS_LOG_ERROR, __FILE__, __LINE__, __VA_ARGS__)

#endif /* PS_PLATFORM_LOG_H */
