/*
 * Plain SHA-256 (OpenSSL EVP), for hashing verification tokens (plan 6.6).
 * Unlike a password, the token is already 256 bits of full-entropy CSPRNG
 * output, not a guessable human secret, so a plain digest -- no PBKDF2
 * stretching -- is sufficient and fast.
 */
#ifndef PS_CRYPTO_SHA256_H
#define PS_CRYPTO_SHA256_H

#include <stdbool.h>
#include <stddef.h>

#define PS_SHA256_LEN 32

bool ps_sha256(const void *data, size_t len, unsigned char out[PS_SHA256_LEN]);

#endif /* PS_CRYPTO_SHA256_H */
