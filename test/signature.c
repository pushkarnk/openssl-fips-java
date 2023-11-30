#include "jssl.h"
#include "signature.h"
#include "md.h"
#include "keyencapsulation.h"
#include <openssl/pem.h>
#include <openssl/encoder.h>
#include <stdlib.h>

char* message = "Into the valley of death, rode the six hundred!";
 
void test_rsa_sign_and_verify(OSSL_LIB_CTX *libctx) {
    printf("Testing RSA sign and verify: ");
    // create public and private RSA keys
    EVP_PKEY *public_key = NULL, *private_key = NULL;
    rsa_keygen(libctx, 4096, &public_key, &private_key);

    // create a SHA-256 MD
    byte output[EVP_MAX_MD_SIZE] = {0};
    int len = 0;
    md_context *ctx = md_init(libctx, "SHA-256");

    if (ctx == NULL) {
        md_context_free(ctx);
        printf("FAILED (MD)\n");
    }

    if (!(md_update(ctx, message, strlen(message)))) {
        md_context_free(ctx);
        printf("FAILED (MD)\n");
        return;
    }

    if (!md_digest(ctx, output, &len)) {
        md_context_free(ctx);
        printf("FAILED (MD)\n");
        return;
    }
    md_context_free(ctx);

    // sign the MD with the private key
    sv_params *p = sv_create_params(libctx, -1, PSS, "SHA-256", NULL);
    sv_key *key = sv_init_key(libctx, private_key);
    sv_context *svc = sv_init(libctx, key, p, SIGN);
    if (NULL == svc) {
        printf("FAILED (sign init)\n");
        return;
    }

    sv_update(svc, output, len);

    size_t length = 0;
    if (sv_sign(svc, NULL, &length) < 0) {
        printf("FAILED (signing)\n");
        return;
    }

    byte *signature = (byte *)malloc(length);
    if (sv_sign(svc, signature, &length) < 0) {
        printf("FAILED (signing)\n");
        return;
    }
    // verify with the public key
    sv_key *pubkey = sv_init_key(libctx, public_key);
    sv_context *svc1 = sv_init(libctx, pubkey, p, VERIFY);
    if (NULL == svc1) {
        printf("FAILED (verify init)\n");
        return;
    }

    if (sv_verify(svc1, output, len, signature, length) <= 0) {
        printf("FAILED (verify)\n");
        return;
    }
    printf("PASSED\n");
}

int main(int argc, char ** argv) {
    OSSL_LIB_CTX *libctx = load_openssl_fips_provider("/usr/local/ssl/openssl.cnf"); 
    test_rsa_sign_and_verify(libctx);
}
