#include "jssl.h"
#include <openssl/evp.h>

typedef struct kem_keyspec {
    OSSL_LIB_CTX *libctx;
    EVP_PKEY *public_key;
    EVP_PKEY *private_key;
    byte *secret;
    size_t secret_length;
    byte *wrapped_key;
    size_t wrapped_key_length;
} kem_keyspec;

void free_kem_keyspec(kem_keyspec *spec);

kem_keyspec *init_kem_keyspec(OSSL_LIB_CTX *libctx);

kem_keyspec *init_kem_keyspec_with_key(EVP_PKEY *rsa_public_key, EVP_PKEY *rsa_private_key, OSSL_LIB_CTX *libctx);

int generate_and_wrap(kem_keyspec *spec);

int unwrap(kem_keyspec *spec);

void free_kem_keyspec(kem_keyspec *spec);

//util
int rsa_keygen(OSSL_LIB_CTX *libctx, int bits, EVP_PKEY **pub, EVP_PKEY **priv);
