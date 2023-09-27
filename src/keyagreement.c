#include "keyagreement.h"

key_agreement* init_key_agreement(key_agreement_algorithm algo, OSSL_LIB_CTX *libctx) {
    key_agreement agreement = {0};
    key_agreement *new_agreement = (key_agreement*)malloc(sizeof(key_agreement));
    *new_agreement = agreement;
    new_agreement->algorithm = algo;
    new_agreement->libctx = libctx;
}

void set_private_key(key_agreement *agreement, key_pair *private_key) {
    agreement->private_key = private_key->key; 
}

void set_peer_key(key_agreement *agreement, key_pair *peer_public_key) {
    agreement->peer_public_key = peer_public_key->key;
}

shared_secret *generate_shared_secret(key_agreement *agreement) {
    if (agreement->private_key == NULL || agreement->peer_public_key == NULL) {
        return NULL;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(agreement->libctx, agreement->private_key, NULL);
    if (ctx == NULL) {
        return NULL;
    }

    if (EVP_PKEY_derive_init(ctx) <= 0) {
        return NULL;
    }

    if (EVP_PKEY_derive_set_peer(ctx, agreement->peer_public_key) <= 0) {
        return NULL;
    }

    size_t secret_length = 0;
    if (EVP_PKEY_derive(ctx, NULL, &secret_length) <= 0) {
        return NULL;
    }

    byte *secret_bytes = OPENSSL_malloc(secret_length);

    if (secret_bytes == NULL) {
        return NULL;
    }

    if (EVP_PKEY_derive(ctx, secret_bytes, &secret_length) <= 0) {
        return NULL;
    }

    shared_secret *secret = (shared_secret*)malloc(sizeof(shared_secret));
    secret->bytes = secret_bytes;
    secret->length = secret_length;
    agreement->secret = secret;
    return secret;
}

int get_shared_secret(key_agreement *agreement, byte secret[]) {
    if (secret != NULL) {
        memcpy(secret, agreement->secret->bytes, agreement->secret->length);
    }
    return agreement->secret->length;
}

key_pair *generate_key(key_agreement_algorithm algo) {
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *key = NULL;
    OSSL_PARAM params[2];
    if (algo == DIFFIE_HELLMAN) {
        if(NULL == (pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL))) {
            return NULL;
        }
        params[0] = OSSL_PARAM_construct_utf8_string("group", "ffdhe2048", 0);
        params[1] = OSSL_PARAM_construct_end();
    } else {
        if(NULL == (pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL))) {
            return NULL;
        }
        params[0] = OSSL_PARAM_construct_utf8_string("group", "prime256v1", 0);
        params[1] = OSSL_PARAM_construct_end();
    }

    if(EVP_PKEY_keygen_init(pctx) <= 0) {
        return NULL;
    }

    EVP_PKEY_CTX_set_params(pctx, params);

    if(EVP_PKEY_keygen(pctx, &key) <= 0) {
        return NULL;
    }
    key_pair *new_key = (key_pair*) malloc(sizeof(key_pair));
    new_key->key = key;
    return new_key;
}

void free_shared_secret(shared_secret *this) {
    free(this->bytes);
    free(this);
}

void free_key_agreement(key_agreement *this) {
    EVP_PKEY_free(this->private_key);
    EVP_PKEY_free(this->peer_public_key);
    free_shared_secret(this->secret);
    free(this);
}

void free_key_pair(key_pair *this) {
    EVP_PKEY_free(this->key);
    free(this);
}


