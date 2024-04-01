#include <openssl/evp.h>
#include "jssl.h"

typedef struct md_context {
    EVP_MD_CTX *ossl_ctx;
    OSSL_LIB_CTX *libctx;
} md_context;

md_context *md_init(OSSL_LIB_CTX *libctx, const char *algorithm);
int md_update(md_context *ctx, byte *input, size_t input_length);
int md_digest(md_context *ctx, byte *output, int *output_length);
void free_md_context(md_context *ctx);
