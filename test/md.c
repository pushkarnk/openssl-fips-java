#include "md.h"
#include <openssl/evp.h>

char *message1 = "Namaste, World!";
char *message2 = "How are you all?";
char *message3 = "How are you all!";

int equal(byte *out1, int len1, byte *out2, int len2) {
    if (len1 != len2) return 0;
    for (int i = 0; i < len1; i++) {
        if (out1[i] != out2[i]) return 0;
    }
    return 1;
}

void test_digest(const char *algo, OSSL_LIB_CTX *libctx) {
    byte output1[EVP_MAX_MD_SIZE] = {0};
    byte output2[EVP_MAX_MD_SIZE] = {0};
    int len1 = 0, len2 = 0;

    printf("Test MessageDigest of type %s: ", algo); 
    md_context *ctx = md_init(libctx, algo);

    if (ctx == NULL) {
        md_context_free(ctx);
        printf("FAILED (init)\n");
    }

    if (!(md_update(ctx, message1, strlen(message1)) &&
        md_update(ctx, message2, strlen(message2)))) {
        md_context_free(ctx);
        printf("FAILED (update)\n");
        return;
    }

    if (!md_digest(ctx, output1, &len1)) {
        md_context_free(ctx);
        printf("FAILED (digest)\n");
        return;
    }
    md_context_free(ctx);

    md_context *ctx1 = md_init(libctx, algo);
    if (!(md_update(ctx1, message1, strlen(message1)) &&
        md_update(ctx1, message3, strlen(message3)))) {
        md_context_free(ctx1);
        printf("FAILED (update)\n");
        return;   
    }

    if (!md_digest(ctx1, output2, &len2)) {
        md_context_free(ctx1);
        printf("FAILED (digest)\n");
        return;
    }

    if(equal(output1, len1, output2, len2)) {
       printf("FAILED (digests match)\n");
       return;
    }

    md_context_free(ctx1);
    printf("PASSED\n"); 
}

int main(int argc, char ** argv) {
    OSSL_LIB_CTX *libctx = load_openssl_fips_provider("/usr/local/ssl/openssl.cnf");
    test_digest("SHA1", libctx);
    test_digest("SHA224", libctx);
    test_digest("SHA256", libctx);
    test_digest("SHA384", libctx);
    test_digest("SHA512", libctx);
    test_digest("SHA2-224", libctx);
    test_digest("SHA2-256", libctx);
    test_digest("SHA2-384", libctx);
    test_digest("SHA2-512", libctx);
    test_digest("SHA3-224", libctx);
    test_digest("SHA3-256", libctx);
    test_digest("SHA3-384", libctx);
    test_digest("SHA3-512", libctx);
    test_digest("KECCAK-KMAC-128", libctx);
    test_digest("KECCAK-KMAC-256", libctx);
}
