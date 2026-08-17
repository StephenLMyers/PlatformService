/*
 * Constant-time comparison, so verifying a MAC or signature never leaks
 * how many leading bytes matched through timing (plan 6.2).
 */
#ifndef PS_CRYPTO_CT_H
#define PS_CRYPTO_CT_H

#include <stdbool.h>
#include <stddef.h>

/* True if a[0..len) == b[0..len). Never use memcmp/strcmp in its place for
 * anything security-sensitive -- that's the whole point of this function. */
bool ps_ct_equal(const void *a, const void *b, size_t len);

#endif /* PS_CRYPTO_CT_H */
