#include "json/json_parse.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "platform/buf.h"

struct ps_json_value {
    ps_json_type_t type;
    union {
        bool   boolean;
        double number;
        struct {
            char   *data; /* NUL-terminated */
            size_t  len;
        } string;
        struct {
            ps_json_value_t **items;
            size_t            count;
            size_t            capacity;
        } array;
        struct {
            char             **keys;
            ps_json_value_t **values;
            size_t             count;
            size_t             capacity;
        } object;
    } as;
};

/* ------------------------------------------------------------------------- */
/* Construction                                                              */
/* ------------------------------------------------------------------------- */

static ps_json_value_t *alloc_value(ps_json_type_t type)
{
    ps_json_value_t *v = calloc(1, sizeof *v);
    if (v != NULL) {
        v->type = type;
    }
    return v;
}

ps_json_value_t *ps_json_new_null(void) { return alloc_value(PS_JSON_NULL); }

ps_json_value_t *ps_json_new_bool(bool b)
{
    ps_json_value_t *v = alloc_value(PS_JSON_BOOL);
    if (v != NULL) {
        v->as.boolean = b;
    }
    return v;
}

ps_json_value_t *ps_json_new_number(double n)
{
    ps_json_value_t *v = alloc_value(PS_JSON_NUMBER);
    if (v != NULL) {
        v->as.number = n;
    }
    return v;
}

ps_json_value_t *ps_json_new_string_n(const char *s, size_t n)
{
    ps_json_value_t *v = alloc_value(PS_JSON_STRING);
    if (v == NULL) {
        return NULL;
    }
    char *copy = malloc(n + 1);
    if (copy == NULL) {
        free(v);
        return NULL;
    }
    if (n > 0) {
        memcpy(copy, s, n);
    }
    copy[n] = '\0';
    v->as.string.data = copy;
    v->as.string.len  = n;
    return v;
}

ps_json_value_t *ps_json_new_string(const char *s)
{
    return ps_json_new_string_n(s, strlen(s));
}

ps_json_value_t *ps_json_new_array(void) { return alloc_value(PS_JSON_ARRAY); }
ps_json_value_t *ps_json_new_object(void) { return alloc_value(PS_JSON_OBJECT); }

bool ps_json_array_append(ps_json_value_t *array, ps_json_value_t *value)
{
    if (array->as.array.count == array->as.array.capacity) {
        size_t new_cap = (array->as.array.capacity == 0) ? 4 : array->as.array.capacity * 2;
        ps_json_value_t **grown = realloc(array->as.array.items, new_cap * sizeof *grown);
        if (grown == NULL) {
            return false;
        }
        array->as.array.items    = grown;
        array->as.array.capacity = new_cap;
    }
    array->as.array.items[array->as.array.count++] = value;
    return true;
}

bool ps_json_object_set(ps_json_value_t *object, const char *key, ps_json_value_t *value)
{
    for (size_t i = 0; i < object->as.object.count; i++) {
        if (strcmp(object->as.object.keys[i], key) == 0) {
            ps_json_free(object->as.object.values[i]);
            object->as.object.values[i] = value;
            return true;
        }
    }

    if (object->as.object.count == object->as.object.capacity) {
        size_t new_cap = (object->as.object.capacity == 0) ? 4 : object->as.object.capacity * 2;

        char **new_keys = realloc(object->as.object.keys, new_cap * sizeof *new_keys);
        if (new_keys == NULL) {
            return false;
        }
        object->as.object.keys = new_keys;

        ps_json_value_t **new_values =
            realloc(object->as.object.values, new_cap * sizeof *new_values);
        if (new_values == NULL) {
            return false;
        }
        object->as.object.values   = new_values;
        object->as.object.capacity = new_cap;
    }

    size_t key_len  = strlen(key);
    char  *key_copy = malloc(key_len + 1);
    if (key_copy == NULL) {
        return false;
    }
    memcpy(key_copy, key, key_len + 1);

    object->as.object.keys[object->as.object.count]   = key_copy;
    object->as.object.values[object->as.object.count] = value;
    object->as.object.count++;
    return true;
}

/* ------------------------------------------------------------------------- */
/* Inspection -- NULL-safe and type-safe throughout, see header             */
/* ------------------------------------------------------------------------- */

ps_json_type_t ps_json_type(const ps_json_value_t *v)
{
    return (v != NULL) ? v->type : PS_JSON_NULL;
}

bool ps_json_get_bool(const ps_json_value_t *v)
{
    return (v != NULL && v->type == PS_JSON_BOOL) ? v->as.boolean : false;
}

double ps_json_get_number(const ps_json_value_t *v)
{
    return (v != NULL && v->type == PS_JSON_NUMBER) ? v->as.number : 0.0;
}

const char *ps_json_get_string(const ps_json_value_t *v)
{
    return (v != NULL && v->type == PS_JSON_STRING) ? v->as.string.data : NULL;
}

size_t ps_json_get_string_len(const ps_json_value_t *v)
{
    return (v != NULL && v->type == PS_JSON_STRING) ? v->as.string.len : 0;
}

size_t ps_json_array_count(const ps_json_value_t *v)
{
    return (v != NULL && v->type == PS_JSON_ARRAY) ? v->as.array.count : 0;
}

ps_json_value_t *ps_json_array_get(const ps_json_value_t *v, size_t index)
{
    if (v == NULL || v->type != PS_JSON_ARRAY || index >= v->as.array.count) {
        return NULL;
    }
    return v->as.array.items[index];
}

size_t ps_json_object_count(const ps_json_value_t *v)
{
    return (v != NULL && v->type == PS_JSON_OBJECT) ? v->as.object.count : 0;
}

ps_json_value_t *ps_json_object_get(const ps_json_value_t *v, const char *key)
{
    if (v == NULL || v->type != PS_JSON_OBJECT) {
        return NULL;
    }
    for (size_t i = 0; i < v->as.object.count; i++) {
        if (strcmp(v->as.object.keys[i], key) == 0) {
            return v->as.object.values[i];
        }
    }
    return NULL;
}

const char *ps_json_object_key_at(const ps_json_value_t *v, size_t index)
{
    if (v == NULL || v->type != PS_JSON_OBJECT || index >= v->as.object.count) {
        return NULL;
    }
    return v->as.object.keys[index];
}

ps_json_value_t *ps_json_object_value_at(const ps_json_value_t *v, size_t index)
{
    if (v == NULL || v->type != PS_JSON_OBJECT || index >= v->as.object.count) {
        return NULL;
    }
    return v->as.object.values[index];
}

void ps_json_free(ps_json_value_t *v)
{
    if (v == NULL) {
        return;
    }
    switch (v->type) {
    case PS_JSON_STRING:
        free(v->as.string.data);
        break;
    case PS_JSON_ARRAY:
        for (size_t i = 0; i < v->as.array.count; i++) {
            ps_json_free(v->as.array.items[i]);
        }
        free(v->as.array.items);
        break;
    case PS_JSON_OBJECT:
        for (size_t i = 0; i < v->as.object.count; i++) {
            free(v->as.object.keys[i]);
            ps_json_free(v->as.object.values[i]);
        }
        free(v->as.object.keys);
        free(v->as.object.values);
        break;
    case PS_JSON_NULL:
    case PS_JSON_BOOL:
    case PS_JSON_NUMBER:
        break;
    }
    free(v);
}

/* ------------------------------------------------------------------------- */
/* Recursive-descent parser                                                  */
/* ------------------------------------------------------------------------- */

typedef struct {
    const char *data;
    size_t      len;
    size_t      pos;
    char       *err;
    size_t      errlen;
    bool        failed;
} parser_t;

static bool fail(parser_t *p, const char *msg)
{
    if (!p->failed) {
        (void)snprintf(p->err, p->errlen, "%s at offset %zu", msg, p->pos);
        p->failed = true;
    }
    return false;
}

static int peek(const parser_t *p)
{
    return (p->pos < p->len) ? (unsigned char)p->data[p->pos] : -1;
}

static void skip_ws(parser_t *p)
{
    while (p->pos < p->len) {
        char c = p->data[p->pos];
        if (c != ' ' && c != '\t' && c != '\n' && c != '\r') {
            break;
        }
        p->pos++;
    }
}

static bool expect_literal(parser_t *p, const char *lit)
{
    size_t n = strlen(lit);
    if (p->pos + n > p->len || memcmp(p->data + p->pos, lit, n) != 0) {
        return false;
    }
    p->pos += n;
    return true;
}

static ps_json_value_t *parse_value(parser_t *p, int depth);

static ps_json_value_t *parse_number(parser_t *p)
{
    size_t start = p->pos;

    if (peek(p) == '-') {
        p->pos++;
    }

    if (peek(p) == '0') {
        p->pos++;
    } else if (isdigit(peek(p))) {
        while (isdigit(peek(p))) {
            p->pos++;
        }
    } else {
        fail(p, "invalid number");
        return NULL;
    }

    if (peek(p) == '.') {
        p->pos++;
        if (!isdigit(peek(p))) {
            fail(p, "invalid number (fraction)");
            return NULL;
        }
        while (isdigit(peek(p))) {
            p->pos++;
        }
    }

    if (peek(p) == 'e' || peek(p) == 'E') {
        p->pos++;
        if (peek(p) == '+' || peek(p) == '-') {
            p->pos++;
        }
        if (!isdigit(peek(p))) {
            fail(p, "invalid number (exponent)");
            return NULL;
        }
        while (isdigit(peek(p))) {
            p->pos++;
        }
    }

    size_t len = p->pos - start;
    char   numbuf[64];
    if (len >= sizeof numbuf) {
        fail(p, "number literal too long");
        return NULL;
    }
    memcpy(numbuf, p->data + start, len);
    numbuf[len] = '\0';

    char  *endptr = NULL;
    double val    = strtod(numbuf, &endptr);
    if (endptr != numbuf + len) {
        fail(p, "invalid number");
        return NULL;
    }

    ps_json_value_t *v = ps_json_new_number(val);
    if (v == NULL) {
        fail(p, "out of memory");
    }
    return v;
}

static bool parse_hex4(parser_t *p, unsigned *out)
{
    if (p->pos + 4 > p->len) {
        return false;
    }
    unsigned val = 0;
    for (int i = 0; i < 4; i++) {
        char c = p->data[p->pos + (size_t)i];
        val <<= 4;
        if (c >= '0' && c <= '9') {
            val |= (unsigned)(c - '0');
        } else if (c >= 'a' && c <= 'f') {
            val |= (unsigned)(c - 'a' + 10);
        } else if (c >= 'A' && c <= 'F') {
            val |= (unsigned)(c - 'A' + 10);
        } else {
            return false;
        }
    }
    p->pos += 4;
    *out = val;
    return true;
}

static bool append_utf8(ps_buf_t *out, unsigned cp)
{
    unsigned char bytes[4];
    size_t        n;

    if (cp <= 0x7Fu) {
        bytes[0] = (unsigned char)cp;
        n        = 1;
    } else if (cp <= 0x7FFu) {
        bytes[0] = (unsigned char)(0xC0u | (cp >> 6));
        bytes[1] = (unsigned char)(0x80u | (cp & 0x3Fu));
        n        = 2;
    } else if (cp <= 0xFFFFu) {
        bytes[0] = (unsigned char)(0xE0u | (cp >> 12));
        bytes[1] = (unsigned char)(0x80u | ((cp >> 6) & 0x3Fu));
        bytes[2] = (unsigned char)(0x80u | (cp & 0x3Fu));
        n        = 3;
    } else {
        bytes[0] = (unsigned char)(0xF0u | (cp >> 18));
        bytes[1] = (unsigned char)(0x80u | ((cp >> 12) & 0x3Fu));
        bytes[2] = (unsigned char)(0x80u | ((cp >> 6) & 0x3Fu));
        bytes[3] = (unsigned char)(0x80u | (cp & 0x3Fu));
        n        = 4;
    }
    return ps_buf_append(out, bytes, n);
}

/* Caller has already consumed the opening quote. */
static ps_json_value_t *parse_string(parser_t *p)
{
    ps_buf_t out;
    ps_buf_init(&out);

    for (;;) {
        if (p->pos >= p->len) {
            fail(p, "unterminated string");
            ps_buf_free(&out);
            return NULL;
        }
        unsigned char c = (unsigned char)p->data[p->pos];

        if (c == '"') {
            p->pos++;
            break;
        }
        if (c < 0x20) {
            fail(p, "control character in string");
            ps_buf_free(&out);
            return NULL;
        }
        if (c != '\\') {
            if (!ps_buf_append_char(&out, (char)c)) {
                fail(p, "out of memory");
                ps_buf_free(&out);
                return NULL;
            }
            p->pos++;
            continue;
        }

        /* Escape sequence. */
        p->pos++;
        if (p->pos >= p->len) {
            fail(p, "unterminated escape");
            ps_buf_free(&out);
            return NULL;
        }
        char esc = p->data[p->pos];
        p->pos++;

        bool ok = true;
        switch (esc) {
        case '"':  ok = ps_buf_append_char(&out, '"');  break;
        case '\\': ok = ps_buf_append_char(&out, '\\'); break;
        case '/':  ok = ps_buf_append_char(&out, '/');  break;
        case 'b':  ok = ps_buf_append_char(&out, '\b'); break;
        case 'f':  ok = ps_buf_append_char(&out, '\f'); break;
        case 'n':  ok = ps_buf_append_char(&out, '\n'); break;
        case 'r':  ok = ps_buf_append_char(&out, '\r'); break;
        case 't':  ok = ps_buf_append_char(&out, '\t'); break;
        case 'u': {
            unsigned cp;
            if (!parse_hex4(p, &cp)) {
                fail(p, "invalid \\u escape");
                ps_buf_free(&out);
                return NULL;
            }
            if (cp >= 0xD800u && cp <= 0xDBFFu) {
                if (p->pos + 2 > p->len || p->data[p->pos] != '\\' || p->data[p->pos + 1] != 'u') {
                    fail(p, "unpaired surrogate");
                    ps_buf_free(&out);
                    return NULL;
                }
                p->pos += 2;
                unsigned low;
                if (!parse_hex4(p, &low) || low < 0xDC00u || low > 0xDFFFu) {
                    fail(p, "invalid low surrogate");
                    ps_buf_free(&out);
                    return NULL;
                }
                cp = 0x10000u + ((cp - 0xD800u) << 10) + (low - 0xDC00u);
            } else if (cp >= 0xDC00u && cp <= 0xDFFFu) {
                fail(p, "unpaired low surrogate");
                ps_buf_free(&out);
                return NULL;
            }
            ok = append_utf8(&out, cp);
            break;
        }
        default:
            fail(p, "invalid escape character");
            ps_buf_free(&out);
            return NULL;
        }

        if (!ok) {
            fail(p, "out of memory");
            ps_buf_free(&out);
            return NULL;
        }
    }

    ps_json_value_t *v = ps_json_new_string_n(out.len > 0 ? out.data : "", out.len);
    ps_buf_free(&out);
    if (v == NULL) {
        fail(p, "out of memory");
    }
    return v;
}

static ps_json_value_t *parse_array(parser_t *p, int depth)
{
    ps_json_value_t *arr = ps_json_new_array();
    if (arr == NULL) {
        fail(p, "out of memory");
        return NULL;
    }

    skip_ws(p);
    if (peek(p) == ']') {
        p->pos++;
        return arr;
    }

    for (;;) {
        skip_ws(p);
        ps_json_value_t *item = parse_value(p, depth + 1);
        if (item == NULL) {
            ps_json_free(arr);
            return NULL;
        }
        if (!ps_json_array_append(arr, item)) {
            ps_json_free(item);
            ps_json_free(arr);
            fail(p, "out of memory");
            return NULL;
        }

        skip_ws(p);
        int c = peek(p);
        if (c == ',') {
            p->pos++;
            continue;
        }
        if (c == ']') {
            p->pos++;
            break;
        }
        fail(p, "expected ',' or ']'");
        ps_json_free(arr);
        return NULL;
    }
    return arr;
}

static ps_json_value_t *parse_object(parser_t *p, int depth)
{
    ps_json_value_t *obj = ps_json_new_object();
    if (obj == NULL) {
        fail(p, "out of memory");
        return NULL;
    }

    skip_ws(p);
    if (peek(p) == '}') {
        p->pos++;
        return obj;
    }

    for (;;) {
        skip_ws(p);
        if (peek(p) != '"') {
            fail(p, "expected string key");
            ps_json_free(obj);
            return NULL;
        }
        p->pos++;
        ps_json_value_t *key_val = parse_string(p);
        if (key_val == NULL) {
            ps_json_free(obj);
            return NULL;
        }

        skip_ws(p);
        if (peek(p) != ':') {
            fail(p, "expected ':'");
            ps_json_free(key_val);
            ps_json_free(obj);
            return NULL;
        }
        p->pos++;
        skip_ws(p);

        ps_json_value_t *val = parse_value(p, depth + 1);
        if (val == NULL) {
            ps_json_free(key_val);
            ps_json_free(obj);
            return NULL;
        }

        bool ok = ps_json_object_set(obj, ps_json_get_string(key_val), val);
        ps_json_free(key_val);
        if (!ok) {
            ps_json_free(val);
            ps_json_free(obj);
            fail(p, "out of memory");
            return NULL;
        }

        skip_ws(p);
        int c = peek(p);
        if (c == ',') {
            p->pos++;
            continue;
        }
        if (c == '}') {
            p->pos++;
            break;
        }
        fail(p, "expected ',' or '}'");
        ps_json_free(obj);
        return NULL;
    }
    return obj;
}

static ps_json_value_t *parse_value(parser_t *p, int depth)
{
    if (depth > PS_JSON_MAX_DEPTH) {
        fail(p, "maximum nesting depth exceeded");
        return NULL;
    }

    skip_ws(p);
    int c = peek(p);

    switch (c) {
    case '"':
        p->pos++;
        return parse_string(p);
    case '{':
        p->pos++;
        return parse_object(p, depth);
    case '[':
        p->pos++;
        return parse_array(p, depth);
    case 't': {
        if (!expect_literal(p, "true")) {
            fail(p, "invalid literal");
            return NULL;
        }
        ps_json_value_t *v = ps_json_new_bool(true);
        if (v == NULL) {
            fail(p, "out of memory");
        }
        return v;
    }
    case 'f': {
        if (!expect_literal(p, "false")) {
            fail(p, "invalid literal");
            return NULL;
        }
        ps_json_value_t *v = ps_json_new_bool(false);
        if (v == NULL) {
            fail(p, "out of memory");
        }
        return v;
    }
    case 'n': {
        if (!expect_literal(p, "null")) {
            fail(p, "invalid literal");
            return NULL;
        }
        ps_json_value_t *v = ps_json_new_null();
        if (v == NULL) {
            fail(p, "out of memory");
        }
        return v;
    }
    case '-':
        return parse_number(p);
    default:
        if (c >= '0' && c <= '9') {
            return parse_number(p);
        }
        fail(p, (c == -1) ? "unexpected end of input" : "unexpected character");
        return NULL;
    }
}

ps_json_value_t *ps_json_parse(const char *data, size_t len, char *err, size_t errlen)
{
    if (err == NULL || errlen == 0) {
        return NULL;
    }
    err[0] = '\0';

    parser_t p;
    p.data   = data;
    p.len    = len;
    p.pos    = 0;
    p.err    = err;
    p.errlen = errlen;
    p.failed = false;

    ps_json_value_t *v = parse_value(&p, 1);
    if (v == NULL) {
        return NULL;
    }

    skip_ws(&p);
    if (p.pos != p.len) {
        fail(&p, "trailing data after JSON value");
        ps_json_free(v);
        return NULL;
    }

    return v;
}
