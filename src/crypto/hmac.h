/*
 * HMAC-SHA256 (OpenSSL EVP), the primitive under both JWT signing (plan
 * 6.1) and constant-time comparisons elsewhere.
 */
#ifndef PS_CRYPTO_HMAC_H
#define PS_CRYPTO_HMAC_H

#include <stdbool.h>
#include <stddef.h>

#define PS_HMAC_SHA256_LEN 32

/* HMAC-SHA256(key, data) into out. Returns false only on an underlying
 * OpenSSL failure; a zero-length key or message is valid input, not an
 * error. */
bool ps_hmac_sha256(const void *key, size_t key_len,
                    const void *data, size_t data_len,
                    unsigned char out[PS_HMAC_SHA256_LEN]);

#endif /* PS_CRYPTO_HMAC_H */
