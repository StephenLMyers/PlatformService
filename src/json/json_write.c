#include "json/json_write.h"

#include <math.h>
#include <stdio.h>
#include <string.h>

static bool write_value(const ps_json_value_t *v, ps_buf_t *buf, int depth);

static bool write_string(const char *s, size_t len, ps_buf_t *buf)
{
    if (!ps_buf_append_char(buf, '"')) {
        return false;
    }

    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        bool          ok;

        switch (c) {
        case '"':  ok = ps_buf_append_str(buf, "\\\""); break;
        case '\\': ok = ps_buf_append_str(buf, "\\\\"); break;
        case '\b': ok = ps_buf_append_str(buf, "\\b");  break;
        case '\f': ok = ps_buf_append_str(buf, "\\f");  break;
        case '\n': ok = ps_buf_append_str(buf, "\\n");  break;
        case '\r': ok = ps_buf_append_str(buf, "\\r");  break;
        case '\t': ok = ps_buf_append_str(buf, "\\t");  break;
        default:
            if (c < 0x20) {
                char esc[8];
                (void)snprintf(esc, sizeof esc, "\\u%04x", c);
                ok = ps_buf_append_str(buf, esc);
            } else {
                ok = ps_buf_append_char(buf, (char)c);
            }
        }

        if (!ok) {
            return false;
        }
    }

    return ps_buf_append_char(buf, '"');
}

static bool write_number(double n, ps_buf_t *buf)
{
    /* JSON has no representation for non-finite values. Our own number
     * sources are always well-defined (counts, config values), but a
     * hand-built value could in principle carry one -- refuse to ever
     * emit syntactically invalid JSON rather than trust the caller. */
    if (!isfinite(n)) {
        return ps_buf_append_str(buf, "null");
    }

    /* 17 significant digits round-trips any IEEE 754 double exactly, and
     * %g strips insignificant trailing digits/zeros for the common case of
     * whole numbers (counts, ports, TTLs). */
    char numbuf[32];
    int  len = snprintf(numbuf, sizeof numbuf, "%.17g", n);
    if (len < 0 || (size_t)len >= sizeof numbuf) {
        return false;
    }
    return ps_buf_append(buf, numbuf, (size_t)len);
}

static bool write_array(const ps_json_value_t *v, ps_buf_t *buf, int depth)
{
    if (!ps_buf_append_char(buf, '[')) {
        return false;
    }
    size_t n = ps_json_array_count(v);
    for (size_t i = 0; i < n; i++) {
        if (i > 0 && !ps_buf_append_char(buf, ',')) {
            return false;
        }
        if (!write_value(ps_json_array_get(v, i), buf, depth + 1)) {
            return false;
        }
    }
    return ps_buf_append_char(buf, ']');
}

static bool write_object(const ps_json_value_t *v, ps_buf_t *buf, int depth)
{
    if (!ps_buf_append_char(buf, '{')) {
        return false;
    }
    size_t n = ps_json_object_count(v);
    for (size_t i = 0; i < n; i++) {
        if (i > 0 && !ps_buf_append_char(buf, ',')) {
            return false;
        }
        const char *key = ps_json_object_key_at(v, i);
        if (!write_string(key, strlen(key), buf)) {
            return false;
        }
        if (!ps_buf_append_char(buf, ':')) {
            return false;
        }
        if (!write_value(ps_json_object_value_at(v, i), buf, depth + 1)) {
            return false;
        }
    }
    return ps_buf_append_char(buf, '}');
}

static bool write_value(const ps_json_value_t *v, ps_buf_t *buf, int depth)
{
    /* Defense in depth: our own parser can never hand back anything past
     * PS_JSON_MAX_DEPTH, but a hand-built value from trusted code could in
     * principle be constructed deeper. Refuse rather than blow the stack. */
    if (depth > PS_JSON_MAX_DEPTH) {
        return false;
    }

    switch (ps_json_type(v)) {
    case PS_JSON_NULL:
        return ps_buf_append_str(buf, "null");
    case PS_JSON_BOOL:
        return ps_buf_append_str(buf, ps_json_get_bool(v) ? "true" : "false");
    case PS_JSON_NUMBER:
        return write_number(ps_json_get_number(v), buf);
    case PS_JSON_STRING:
        return write_string(ps_json_get_string(v), ps_json_get_string_len(v), buf);
    case PS_JSON_ARRAY:
        return write_array(v, buf, depth);
    case PS_JSON_OBJECT:
        return write_object(v, buf, depth);
    }
    return false; /* unreachable: every ps_json_type_t is handled above */
}

bool ps_json_write(const ps_json_value_t *v, ps_buf_t *buf)
{
    return write_value(v, buf, 1);
}
