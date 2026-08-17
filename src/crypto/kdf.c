#include "crypto/kdf.h"

#include <openssl/evp.h>

bool ps_kdf_derive(const char *password, size_t password_len,
                   const unsigned char salt[PS_KDF_SALT_LEN],
                   int iterations,
                   unsigned char out[PS_KDF_OUTPUT_LEN])
{
    return PKCS5_PBKDF2_HMAC(password, (int)password_len, salt, PS_KDF_SALT_LEN,
                             iterations, EVP_sha256(), PS_KDF_OUTPUT_LEN, out) == 1;
}
