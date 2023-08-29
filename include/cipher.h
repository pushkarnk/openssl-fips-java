#include <openssl/evp.h>
#include <openssl/types.h>
#include <jssl.h>

#define DECRYPT 0
#define ENCRYPT 1 

typedef struct cipher_context {
    const char *name;
    EVP_CIPHER_CTX *context;
    const EVP_CIPHER* cipher;
    int mode;
    int padding;
} cipher_context;

cipher_context* create_cipher_context(const char *name, const char *padding_name);

void cipher_init(cipher_context * ctx, int mode, unsigned char *key, unsigned char *iv);

void cipher_update(cipher_context *ctx, byte in[], int in_offset, int in_len,
            byte out[], int out_offset, int *out_len);

void cipher_do_final(cipher_context *ctx, byte *out, int *out_len);

void cipher_cleanup(cipher_context *ctx);

void cipher_destroy(cipher_context *ctx);
