#include <openssl/evp.h>
#include "jssl.h"

EVP_PKEY *create_private_key(int type, byte* bytes, size_t length);
EVP_PKEY *create_public_key(byte* bytes, size_t length);

