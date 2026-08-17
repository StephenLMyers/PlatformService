/*
 * RFC 7515 base64url: standard base64 with '-'/'_' in place of '+'/'/',
 * padding always omitted. Hand-rolled rather than adapted from OpenSSL's
 * EVP_EncodeBlock/EVP_DecodeBlock, which decode '=' as if it were data and
 * leave the caller to work out how many trailing bytes to discard -- since
 * decode is the first thing JWT verification does to attacker-controlled
 * bytes, this module owns every rejection path directly instead of
 * inheriting a general-purpose codec's padding quirks.
 */
#ifndef PS_CRYPTO_BASE64URL_H
#define PS_CRYPTO_BASE64URL_H

#include <stdbool.h>
#include <stddef.h>

#include "platform/buf.h"

/* Appends the base64url encoding of data[0..len) to out. out must already
 * be initialized (ps_buf_init); this only ever appends. */
bool ps_base64url_encode(const unsigned char *data, size_t len, ps_buf_t *out);

/*
 * Appends the decoded bytes of text[0..len) to out. Rejects, returning
 * false, on: any byte outside the base64url alphabet (including '+', '/',
 * and '=' -- this decoder never accepts padding), a length congruent to 1
 * mod 4 (not a valid base64 length), and a non-canonical final group whose
 * implied padding bits are nonzero. On failure, out may have been
 * partially appended to; callers must discard it rather than assume it is
 * untouched.
 */
bool ps_base64url_decode(const char *text, size_t len, ps_buf_t *out);

#endif /* PS_CRYPTO_BASE64URL_H */
