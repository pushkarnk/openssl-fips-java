#include <openssl/evp.h>
#include <openssl/x509.h>

#include "jssl.h"

extern OSSL_LIB_CTX *global_libctx;

EVP_PKEY *create_private_key(int type, byte* bytes, size_t length) {
    return d2i_PrivateKey_ex(type, NULL, (const byte**)&bytes, length, global_libctx, NULL);
}

EVP_PKEY *create_public_key(byte* bytes, size_t length) {
    return d2i_PUBKEY_ex(NULL, (const byte**) &bytes, length, global_libctx, NULL);
}

