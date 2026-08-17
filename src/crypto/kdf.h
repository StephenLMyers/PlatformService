/*
 * PBKDF2-HMAC-SHA256 (plan 6.3) -- the password-hashing KDF. OpenSSL is
 * chosen under D1 over bcrypt/scrypt/Argon2, none of which OpenSSL
 * provides directly.
 */
#ifndef PS_CRYPTO_KDF_H
#define PS_CRYPTO_KDF_H

#include <stdbool.h>
#include <stddef.h>

#define PS_KDF_SALT_LEN   16
#define PS_KDF_OUTPUT_LEN 32

/* Derives out from password using salt and iterations. iterations is a
 * runtime parameter, not a compile-time constant: it's read from config
 * (so it can be raised later without a rebuild) and stored per password
 * row (so an existing hash stays verifiable after the configured default
 * changes -- plan 6.3). */
bool ps_kdf_derive(const char *password, size_t password_len,
                   const unsigned char salt[PS_KDF_SALT_LEN],
                   int iterations,
                   unsigned char out[PS_KDF_OUTPUT_LEN]);

#endif /* PS_CRYPTO_KDF_H */
