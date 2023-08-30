#include "jssl.h" 
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <stdio.h>

OSSL_LIB_CTX* load_openssl_fips_provider(const char* conf_file_path) {
    OSSL_LIB_CTX *fips_libctx = OSSL_LIB_CTX_new();
    if (!OSSL_LIB_CTX_load_config(fips_libctx, conf_file_path)) {
        ERR_print_errors_fp(stderr);
    }

    OSSL_PROVIDER *fips = OSSL_PROVIDER_load(NULL, "fips");
    if (NULL == fips) {
        fprintf(stderr, "Failed to load the FIPS provider:\n");
        ERR_print_errors_fp(stderr);
    }
    
    return fips_libctx;
}
