#include "crypto/base64url.h"

static const char ENCODE_TABLE[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

bool ps_base64url_encode(const unsigned char *data, size_t len, ps_buf_t *out)
{
    size_t i = 0;
    for (; i + 3 <= len; i += 3) {
        unsigned int n = ((unsigned int)data[i] << 16) |
                        ((unsigned int)data[i + 1] << 8) |
                        (unsigned int)data[i + 2];
        char chunk[4] = {
            ENCODE_TABLE[(n >> 18) & 0x3F], ENCODE_TABLE[(n >> 12) & 0x3F],
            ENCODE_TABLE[(n >> 6) & 0x3F],  ENCODE_TABLE[n & 0x3F],
        };
        if (!ps_buf_append(out, chunk, sizeof chunk)) {
            return false;
        }
    }

    size_t remaining = len - i;
    if (remaining == 1) {
        unsigned int n = (unsigned int)data[i] << 16;
        char chunk[2] = { ENCODE_TABLE[(n >> 18) & 0x3F], ENCODE_TABLE[(n >> 12) & 0x3F] };
        return ps_buf_append(out, chunk, sizeof chunk);
    }
    if (remaining == 2) {
        unsigned int n = ((unsigned int)data[i] << 16) | ((unsigned int)data[i + 1] << 8);
        char chunk[3] = {
            ENCODE_TABLE[(n >> 18) & 0x3F], ENCODE_TABLE[(n >> 12) & 0x3F], ENCODE_TABLE[(n >> 6) & 0x3F],
        };
        return ps_buf_append(out, chunk, sizeof chunk);
    }
    return true;
}

/* -1 for any byte outside the base64url alphabet -- '+', '/', and '='
 * included, deliberately, since this decoder never accepts them. */
static int decode_char(unsigned char c)
{
    if (c >= 'A' && c <= 'Z') return (int)(c - 'A');
    if (c >= 'a' && c <= 'z') return (int)(c - 'a') + 26;
    if (c >= '0' && c <= '9') return (int)(c - '0') + 52;
    if (c == '-') return 62;
    if (c == '_') return 63;
    return -1;
}

bool ps_base64url_decode(const char *text, size_t len, ps_buf_t *out)
{
    if (len % 4 == 1) {
        return false;
    }

    size_t i = 0;
    for (; i + 4 <= len; i += 4) {
        int c0 = decode_char((unsigned char)text[i]);
        int c1 = decode_char((unsigned char)text[i + 1]);
        int c2 = decode_char((unsigned char)text[i + 2]);
        int c3 = decode_char((unsigned char)text[i + 3]);
        if (c0 < 0 || c1 < 0 || c2 < 0 || c3 < 0) {
            return false;
        }
        unsigned int n = ((unsigned int)c0 << 18) | ((unsigned int)c1 << 12) |
                        ((unsigned int)c2 << 6) | (unsigned int)c3;
        char bytes[3] = { (char)(n >> 16), (char)(n >> 8), (char)n };
        if (!ps_buf_append(out, bytes, sizeof bytes)) {
            return false;
        }
    }

    size_t remaining = len - i;
    if (remaining == 2) {
        int c0 = decode_char((unsigned char)text[i]);
        int c1 = decode_char((unsigned char)text[i + 1]);
        if (c0 < 0 || c1 < 0 || (c1 & 0x0F) != 0) { /* nonzero padding bits: non-canonical */
            return false;
        }
        char byte = (char)(((unsigned int)c0 << 2) | ((unsigned int)c1 >> 4));
        return ps_buf_append(out, &byte, 1);
    }
    if (remaining == 3) {
        int c0 = decode_char((unsigned char)text[i]);
        int c1 = decode_char((unsigned char)text[i + 1]);
        int c2 = decode_char((unsigned char)text[i + 2]);
        if (c0 < 0 || c1 < 0 || c2 < 0 || (c2 & 0x03) != 0) { /* nonzero padding bits */
            return false;
        }
        unsigned int n = ((unsigned int)c0 << 18) | ((unsigned int)c1 << 12) | ((unsigned int)c2 << 6);
        char bytes[2] = { (char)(n >> 16), (char)(n >> 8) };
        return ps_buf_append(out, bytes, sizeof bytes);
    }
    return true;
}
