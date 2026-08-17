#include "crypto/hmac.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>

bool ps_hmac_sha256(const void *key, size_t key_len,
                    const void *data, size_t data_len,
                    unsigned char out[PS_HMAC_SHA256_LEN])
{
    unsigned int   out_len = 0;
    unsigned char *result  = HMAC(EVP_sha256(), key, (int)key_len,
                                  (const unsigned char *)data, data_len,
                                  out, &out_len);
    return result != NULL && out_len == PS_HMAC_SHA256_LEN;
}
