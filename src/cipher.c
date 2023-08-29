#include "cipher.h"
#include <openssl/err.h>

int get_padding_code(const char *name) {
    if (IS_NULL(name) || STR_EQUAL(name, "NONE")) {
        return 0;
    } else if (STR_EQUAL(name, "PKCS7") || STR_EQUAL(name, "PKCS5")) {
        return EVP_PADDING_PKCS7;
    } else if (STR_EQUAL(name, "ISO10126-2")) {
        return EVP_PADDING_ISO10126;
    } else if (STR_EQUAL(name, "X9.23")) {
        return EVP_PADDING_ANSI923;
    } else if (STR_EQUAL(name, "ISO7816-4")) {
        return EVP_PADDING_ISO7816_4;
    } else {
        // TODO: handle an supported padding scheme
        // TEMP: disable padding :-(
        return 0;
    }
}

static EVP_CIPHER* get_cipherbyname(const char *name) {
    EVP_CIPHER *cipher = EVP_get_cipherbyname(name);
    if (!IS_NULL(cipher)) return cipher;

    /// return query_name_table(name);
    return NULL;
}
   
// The caller must ensure name is a valid cipher name
// aes-cbc, aes-128-ebc
cipher_context* create_cipher_context(const char *name, const char *padding_name) {
    cipher_context *new_context = (cipher_context*)malloc(sizeof(cipher_context));
    EVP_CIPHER_CTX *new_ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(new_ctx);
    new_context->name = name;
    new_context->context = new_ctx;
    new_context->cipher = get_cipherbyname(name); 
    if (IS_NULL(new_context->cipher) || IS_NULL(new_context->context)) {
        return NULL;
    }
    new_context->padding = get_padding_code(padding_name);
    return new_context;
}

void cipher_init(cipher_context * ctx, int mode, unsigned char *key, unsigned char *iv) {
    // TODO: assert mode lies in {-1, 0, 1 }
    EVP_CipherInit_ex(ctx->context, ctx->cipher, NULL, key, iv, mode);
    EVP_CIPHER_CTX_set_padding(ctx->context, ctx->padding);
}

void cipher_update(cipher_context *ctx, byte in_buf[], int in_offset, int in_len,
            byte out_buf[], int out_offset, int *out_len) {
    // TODO: examine return value
    EVP_CipherUpdate(ctx->context, out_buf + out_offset, out_len, in_buf + in_offset, in_len); 
}

void cipher_do_final(cipher_context *ctx, byte *out_buf, int *out_len) {
    // TODO: examine return value
    EVP_CipherFinal_ex(ctx->context, out_buf, out_len); 
}

void cipher_cleanup(cipher_context *ctx) {
    EVP_CIPHER_CTX_cleanup(ctx->context);
}

void cipher_destroy(cipher_context *ctx) {
    // TODO: handle errors
    EVP_CIPHER_CTX_cleanup(ctx->context);
    free(ctx);
}
