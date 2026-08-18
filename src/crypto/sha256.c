#include "crypto/sha256.h"

#include <openssl/evp.h>

bool ps_sha256(const void *data, size_t len, unsigned char out[PS_SHA256_LEN])
{
    unsigned int out_len = 0;
    bool ok = EVP_Digest(data, len, out, &out_len, EVP_sha256(), NULL) == 1;
    return ok && out_len == PS_SHA256_LEN;
}
