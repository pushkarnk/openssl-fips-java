#include "keyencapsulation.h"
#include <openssl/pem.h>
#include <openssl/encoder.h>
#include <stdlib.h>

# define TEST_ptr(a)          (a)
# define TEST_true(a)         ((a) != 0)

int rsa_keygen(OSSL_LIB_CTX *libctx, int bits, EVP_PKEY **pub, EVP_PKEY **priv)
{
    int ret = 0;
    unsigned char *pub_der = NULL;
    const unsigned char *pp = NULL;
    size_t len = 0;
    OSSL_ENCODER_CTX *ectx = NULL;

    if (!TEST_ptr(*priv = EVP_PKEY_Q_keygen(libctx, NULL, "RSA", bits))
        || !TEST_ptr(ectx =
                     OSSL_ENCODER_CTX_new_for_pkey(*priv,
                                                   EVP_PKEY_PUBLIC_KEY,
                                                   "DER", "type-specific",
                                                   NULL))
        || !TEST_true(OSSL_ENCODER_to_data(ectx, &pub_der, &len)))
        goto err;
    pp = pub_der;
    if (NULL == (d2i_PublicKey(EVP_PKEY_RSA, pub, &pp, len)))
        goto err;
    ret = 1;
err:
    OSSL_ENCODER_CTX_free(ectx);
    OPENSSL_free(pub_der);
    return ret;
}


kem_keyspec *init_kem_keyspec(OSSL_LIB_CTX *libctx) {
    EVP_PKEY *public_key = NULL;
    EVP_PKEY *private_key = NULL;
    rsa_keygen(libctx, 4096, &public_key, &private_key);
    init_kem_keyspec_with_key(public_key, private_key, libctx);
}

kem_keyspec *init_kem_keyspec_with_key(EVP_PKEY *rsa_pub_key, EVP_PKEY *rsa_priv_key, OSSL_LIB_CTX *libctx) {
    kem_keyspec *spec = (kem_keyspec*)malloc(sizeof(kem_keyspec));
    spec->public_key = rsa_pub_key;
    spec->private_key = rsa_priv_key; 
    spec->libctx = libctx;
    spec->secret = NULL;
    spec->wrapped_key = NULL;
    spec->secret_length = 0;
    spec->wrapped_key_length =0;
    return spec;
}

void free_kem_keyspec(kem_keyspec *spec) {
    free(spec->wrapped_key);
    free(spec->secret);
    free(spec);
}

int generate_and_wrap(kem_keyspec *spec) {
    size_t wrapped_key_length = 0;
    size_t secret_length = 0;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(spec->libctx, spec->public_key, NULL);
    if (ctx == NULL) {
        return 1;
    }

    if (EVP_PKEY_encapsulate_init(ctx, NULL) <= 0) {
        return 1;
    }

    if (EVP_PKEY_CTX_set_kem_op(ctx, "RSASVE") <= 0) {
        return 1;
    }

    if (EVP_PKEY_encapsulate(ctx, NULL, &wrapped_key_length, NULL, &secret_length) <= 0) {
        return 1;
    }

    spec->secret = (byte *)malloc(secret_length);
    spec->wrapped_key = (byte *)malloc(wrapped_key_length);

    if (spec->secret == NULL || spec->wrapped_key == NULL) {
        return 1;
    }

    if (EVP_PKEY_encapsulate(ctx, spec->wrapped_key, &wrapped_key_length, spec->secret, &secret_length) <= 0) {
        return 1;
    }

    spec->wrapped_key_length = wrapped_key_length;
    spec->secret_length = secret_length;
    return 0;
}

int unwrap(kem_keyspec *spec) {
    size_t secret_length = 0;
    if (spec->wrapped_key == NULL || spec->wrapped_key_length <= 0) {
        return 1;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(spec->libctx, spec->private_key, NULL);
    if (ctx == NULL) {
        return 1;
    }

    if (EVP_PKEY_decapsulate_init(ctx, NULL) <= 0) {
        return 1;
    }

    if (EVP_PKEY_CTX_set_kem_op(ctx, "RSASVE") <= 0) {
        return 1;
    }

    if (EVP_PKEY_decapsulate(ctx, NULL, &secret_length, spec->wrapped_key, spec->wrapped_key_length) <= 0) {
        return 1;
    }

    byte *secret = OPENSSL_malloc(secret_length);
    if (secret == NULL) {
        return 1;
    }

    if (EVP_PKEY_decapsulate(ctx, secret, &secret_length, spec->wrapped_key, spec->wrapped_key_length) <= 0) {
        return 1;
    }

    spec->secret = secret;
    spec->secret_length = secret_length;
    return 0;
}
