/*
 * JSON value type and recursive-descent parser.
 *
 * userId and other 64-bit integers are represented as JSON strings
 * throughout this service's API (plan 6.1), never as JSON numbers -- a
 * JSON number only round-trips exactly through IEEE 754 doubles, which
 * lose precision above 2^53. Every JSON number this parser produces or
 * accepts is therefore a plain `double`; nothing in this codebase needs
 * more.
 */
#ifndef PS_JSON_JSON_PARSE_H
#define PS_JSON_JSON_PARSE_H

#include <stdbool.h>
#include <stddef.h>

/* Depth includes the top-level value itself; a bare scalar is depth 1.
 * Caps recursion in both the parser and the writer against stack
 * exhaustion from adversarial nesting (plan 7.2). */
#define PS_JSON_MAX_DEPTH 32

typedef enum {
    PS_JSON_NULL,
    PS_JSON_BOOL,
    PS_JSON_NUMBER,
    PS_JSON_STRING,
    PS_JSON_ARRAY,
    PS_JSON_OBJECT,
} ps_json_type_t;

typedef struct ps_json_value ps_json_value_t;

/* ---- construction, for building response bodies ---- */

ps_json_value_t *ps_json_new_null(void);
ps_json_value_t *ps_json_new_bool(bool v);
ps_json_value_t *ps_json_new_number(double v);
ps_json_value_t *ps_json_new_string(const char *s);              /* NUL-terminated */
ps_json_value_t *ps_json_new_string_n(const char *s, size_t n);   /* may embed NUL */
ps_json_value_t *ps_json_new_array(void);
ps_json_value_t *ps_json_new_object(void);

/*
 * Every "new" call above may return NULL on allocation failure -- always
 * checked, never asserted (plan 7.2).
 */

/*
 * Takes ownership of `value` on success. On failure (allocation failure
 * only) returns false and value is left owned by the caller, who must
 * still free it.
 */
bool ps_json_array_append(ps_json_value_t *array, ps_json_value_t *value);
bool ps_json_object_set(ps_json_value_t *object, const char *key, ps_json_value_t *value);

/*
 * ---- inspection ----
 * Every function below is NULL-safe and type-safe: called on NULL or on a
 * value of the wrong type, it returns a safe default (NULL/0/false/
 * PS_JSON_NULL) instead of reading the wrong union member. This matters
 * because ps_json_object_get returns NULL for an absent key, and chaining
 * straight into a typed getter -- ps_json_get_string(ps_json_object_get(...))
 * -- is the normal way to read an optional field from a parsed, untrusted
 * request body.
 */

ps_json_type_t ps_json_type(const ps_json_value_t *v);
bool           ps_json_get_bool(const ps_json_value_t *v);
double         ps_json_get_number(const ps_json_value_t *v);
const char    *ps_json_get_string(const ps_json_value_t *v);   /* NUL-terminated */
size_t         ps_json_get_string_len(const ps_json_value_t *v);

size_t            ps_json_array_count(const ps_json_value_t *v);
ps_json_value_t  *ps_json_array_get(const ps_json_value_t *v, size_t index);

size_t            ps_json_object_count(const ps_json_value_t *v);
/* NULL if the key is absent -- absence and an explicit JSON null are
 * distinguishable this way. */
ps_json_value_t  *ps_json_object_get(const ps_json_value_t *v, const char *key);
const char       *ps_json_object_key_at(const ps_json_value_t *v, size_t index);
ps_json_value_t  *ps_json_object_value_at(const ps_json_value_t *v, size_t index);

/* Recursively frees v and everything it contains. Safe to call with NULL. */
void ps_json_free(ps_json_value_t *v);

/*
 * Parses exactly one JSON value from (data, len). Trailing non-whitespace
 * after the value is a parse error, not silently ignored. Returns NULL and
 * writes a reason into err on failure. The returned value is heap-owned;
 * free it with ps_json_free.
 */
ps_json_value_t *ps_json_parse(const char *data, size_t len, char *err, size_t errlen);

#endif /* PS_JSON_JSON_PARSE_H */
