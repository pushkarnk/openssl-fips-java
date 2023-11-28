#include "jssl.h"
#include "mac.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/core_names.h>

static void set_params(EVP_MAC_CTX *ctx, mac_params *params) {
    OSSL_PARAM _params[8];
    int n_params = 0;
    if (params->cipher_name != NULL) {
        _params[n_params++] = OSSL_PARAM_construct_utf8_string("cipher", params->cipher_name, 0);
    }
    if (params->digest_name != NULL) {
        _params[n_params++] = OSSL_PARAM_construct_utf8_string("digest", params->digest_name, 0);
    }
    if (params->iv != NULL) {
        _params[n_params++] = OSSL_PARAM_construct_octet_string("iv", params->iv, params->iv_length);
    }
    _params[n_params] = OSSL_PARAM_construct_end();
    if (0 == EVP_MAC_CTX_set_params(ctx, _params)) {
        ERR_print_errors_fp(stdout);
    }
}

mac_context *mac_init(char *algorithm, byte *key, size_t key_length, mac_params *params) {
    mac_context *new_ctx = (mac_context *)malloc(sizeof(mac_context));
    new_ctx->algorithm = algorithm;
    EVP_MAC *mac = EVP_MAC_fetch(NULL, algorithm, NULL);
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
    EVP_MAC_free(mac);
    if (NULL == ctx) { 
        ERR_print_errors_fp(stdout);        
        free_mac_context(new_ctx);
        return NULL;
    }
    new_ctx->ctx = ctx;
    if (NULL != params) {
        set_params(new_ctx->ctx, params);
    }
    if (0 == EVP_MAC_init(new_ctx->ctx, (const unsigned char*)key, key_length, NULL)) {
        ERR_print_errors_fp(stdout);
        free_mac_context(new_ctx);
        return NULL;
    }   
    return new_ctx;
}

int mac_update(mac_context *ctx, byte *input, size_t input_size) {
    if (0 == EVP_MAC_update(ctx->ctx, input, input_size)) {
        free_mac_context(ctx);
        return 0;
    }
    return 1;
}

int mac_final(mac_context *ctx, byte *output, size_t *bytes_written, size_t output_size) {
    if (0 == EVP_MAC_final(ctx->ctx, output, bytes_written, output_size)) {
        free_mac_context(ctx);
        return 0;
    }
    return 1;
}

int mac_final_with_input(mac_context *ctx, byte *input, size_t input_size,
                     byte *output, size_t *bytes_written, size_t output_size) {
    if (0 == mac_update(ctx, input, input_size)) {
        free_mac_context(ctx);
        return 0;
    }
    if (0 == mac_final(ctx, output, bytes_written, output_size)) {
        free_mac_context(ctx);
        return 0;
    }
    return 1;
}

size_t get_mac_length(mac_context *mac) {
    return EVP_MAC_CTX_get_mac_size(mac->ctx);    
}

void free_mac_context(mac_context *mac) {
    EVP_MAC_CTX_free(mac->ctx);
    free(mac);
}
