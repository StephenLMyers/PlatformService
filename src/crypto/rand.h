/*
 * CSPRNG bytes (OpenSSL RAND_bytes), for salts and jti values.
 */
#ifndef PS_CRYPTO_RAND_H
#define PS_CRYPTO_RAND_H

#include <stdbool.h>
#include <stddef.h>

/* Fills buf[0..len) with cryptographically secure random bytes. Returns
 * false only if OpenSSL's CSPRNG itself reports failure -- treat that as
 * fatal; there is no weaker fallback to drop to. */
bool ps_rand_bytes(unsigned char *buf, size_t len);

#endif /* PS_CRYPTO_RAND_H */
