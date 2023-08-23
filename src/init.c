#include "jssl.h" 
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <stdio.h>

OSSL_PROVIDER* load_openssl_fips_provider(const char* conf_file_path) {
    if (!OSSL_LIB_CTX_load_config(NULL, conf_file_path)) {
        ERR_print_errors_fp(stderr);
    }

    OSSL_PROVIDER *fips = OSSL_PROVIDER_load(NULL, "fips");
    if (NULL == fips) {
        fprintf(stderr, "Failed to load the FIPS provider:\n");
        ERR_print_errors_fp(stderr);
    }
    
    return fips;
}
