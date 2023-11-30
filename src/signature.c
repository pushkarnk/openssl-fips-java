#include "signature.h"
#include "jssl.h"

sv_key *sv_init_key(OSSL_LIB_CTX *libctx, EVP_PKEY *pkey) {
    sv_key *key = (sv_key*)malloc(sizeof(sv_key));
    key->ctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, NULL);
    return key;
}

  
sv_params *sv_create_params(OSSL_LIB_CTX *libctx, int salt_length, sv_padding_mode padding, char *digest, char *mgf1_digest) {
    sv_params *params = (sv_params*) malloc(sizeof(sv_params));
    params->padding = padding;
    if (padding == PSS) {
        params->salt_length = salt_length;
    } else {
        params->salt_length = -1; //ignore
    }
    params->digest_type = digest;
    params->digest = EVP_MD_fetch(libctx, digest, NULL);

    if (padding == PSS) {
        params->mgf1_digest_type = mgf1_digest;
        params->mgf1_digest = EVP_MD_fetch(libctx, mgf1_digest, NULL);
    } else {
        params->mgf1_digest_type = NULL;
        params->mgf1_digest = NULL;
    }

    if (params->digest == NULL) {
        free(params);
        params = NULL;
    }
    return params;
}

sv_context *sv_init(OSSL_LIB_CTX *libctx, sv_key *key, sv_params *params, sv_state op) {
    if (NULL == key->ctx) {
        return NULL;
    }

    switch (op) {
        case SIGN:
            if (EVP_PKEY_sign_init(key->ctx) <= 0) return NULL; 
            break;
        case VERIFY:
            if (EVP_PKEY_verify_init(key->ctx) <= 0) return NULL;
            break;
    }

    if (EVP_PKEY_CTX_set_signature_md(key->ctx, params->digest) <= 0) {
        return NULL;
    }

    if (params->padding == PSS) {
        if (EVP_PKEY_CTX_set_rsa_padding(key->ctx, RSA_PKCS1_PSS_PADDING) <= 0) {
            return NULL;
        }

        if (params->salt_length > 0) {
            if (EVP_PKEY_CTX_set_rsa_pss_saltlen(key->ctx, params->salt_length) <= 0) {
                return NULL;
            }
        }

        if (params->mgf1_digest != NULL) {
            if (EVP_PKEY_CTX_set_rsa_mgf1_md(key->ctx, params->mgf1_digest) <= 0) {
                return NULL;
            }
        }
    }

    sv_context *new_context = (sv_context*) malloc(sizeof(sv_context));
    new_context->state = op;
    new_context->key = key; 
    new_context->data = NULL;
    new_context->length = 0;
    return new_context; 
}

int sv_update(sv_context *ctx, byte *data, size_t length) {
    if (ctx->length == 0) {
        ctx->data = data;
        ctx->length = length;
    } else {
        ctx->data = (byte *)realloc(data, ctx->length + length);
        ctx->length += length;
        memcpy(ctx->data + ctx->length, data, length);
    }
    return 1;
}

int sv_sign(sv_context *ctx, byte *signature, size_t *signature_length) {
    if (signature == NULL) {
        if (EVP_PKEY_sign(ctx->key->ctx, NULL, signature_length, ctx->data, ctx->length) <= 0) {
            return 0;
        }
        return 1;
    }

    if (EVP_PKEY_sign(ctx->key->ctx, signature, signature_length, ctx->data, ctx->length) <= 0) {
        return 0;
    } 

    return 1;
}

int sv_verify(sv_context *ctx, byte *digest, size_t digest_length, byte *signature, size_t sig_length) {
    return EVP_PKEY_verify(ctx->key->ctx, signature, sig_length, digest, digest_length);
}
