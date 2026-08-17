#include "platform/buf.h"

#include <stdlib.h>
#include <string.h>

void ps_buf_init(ps_buf_t *b)
{
    b->data = NULL;
    b->len  = 0;
    b->cap  = 0;
}

static bool ensure_capacity(ps_buf_t *b, size_t additional)
{
    if (b->cap - b->len >= additional) {
        return true;
    }

    size_t need = b->len + additional;
    size_t cap  = (b->cap == 0) ? 256 : b->cap;
    while (cap < need) {
        cap *= 2;
    }

    char *grown = realloc(b->data, cap);
    if (grown == NULL) {
        return false;
    }
    b->data = grown;
    b->cap  = cap;
    return true;
}

bool ps_buf_append(ps_buf_t *b, const void *data, size_t n)
{
    if (n == 0) {
        return true;
    }
    if (!ensure_capacity(b, n)) {
        return false;
    }
    memcpy(b->data + b->len, data, n);
    b->len += n;
    return true;
}

bool ps_buf_append_str(ps_buf_t *b, const char *s)
{
    return ps_buf_append(b, s, strlen(s));
}

bool ps_buf_append_char(ps_buf_t *b, char c)
{
    return ps_buf_append(b, &c, 1);
}

void ps_buf_free(ps_buf_t *b)
{
    free(b->data);
    b->data = NULL;
    b->len  = 0;
    b->cap  = 0;
}
