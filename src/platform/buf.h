/*
 * Growable byte buffer. Shared by json/ and http/ (both need to build
 * variable-length output -- serialized JSON, HTTP response bytes) without
 * making either depend on the other (plan 3.1: json and http are peers).
 */
#ifndef PS_PLATFORM_BUF_H
#define PS_PLATFORM_BUF_H

#include <stdbool.h>
#include <stddef.h>

typedef struct {
    char   *data;
    size_t  len;
    size_t  cap;
} ps_buf_t;

/* Zeroes b. Safe to pass to ps_buf_free even if never appended to. */
void ps_buf_init(ps_buf_t *b);

/* Appends n bytes, growing as needed. Returns false only on allocation
 * failure, in which case b is left in its previous valid state. */
bool ps_buf_append(ps_buf_t *b, const void *data, size_t n);
bool ps_buf_append_str(ps_buf_t *b, const char *s);
bool ps_buf_append_char(ps_buf_t *b, char c);

void ps_buf_free(ps_buf_t *b);

#endif /* PS_PLATFORM_BUF_H */
