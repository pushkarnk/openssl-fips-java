#include <drbg.h>

/* Created the necessary params for the given algorithm 
 * Return the number of parameters added to `params`
 */
static int create_params(const char *name, OSSL_PARAM params[]) {
    if (STR_EQUAL(name, "HASH-DRBG")) {
        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_DIGEST, SN_sha512, 0);
        params[1] = OSSL_PARAM_construct_end();
        return 2;
    } else if (STR_EQUAL(name, "HMAC-DRBG")) {
        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_MAC, SN_hmac, 0);
        params[1] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_DIGEST, SN_sha256, 0);
        params[2] = OSSL_PARAM_construct_end();
        return 3;
    } else if (STR_EQUAL(name, "CTR-DRBG")) {
        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_CIPHER, SN_aes_256_ctr, 0);
        params[1] = OSSL_PARAM_construct_end();
        return 2;
    } else if (STR_EQUAL(name, "SEED-SRC")) {
	// TODO: We don't come here in the FIPS mode
        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_CIPHER, SN_aes_256_ctr, 0);
        params[1] = OSSL_PARAM_construct_end();
        return 2;
    } else if (STR_EQUAL(name, "TEST-RAND")) {
	// TODO: We don't come here in the FIPS mode
        return 0;
    } else {
        // We should never come here!
        return 0;
    }
}

DRBG* create_DRBG(const char* name) {
    EVP_RAND *rand = EVP_RAND_fetch(NULL, name, NULL);
    if (NULL == rand) {
        fprintf(stderr, "Couldn't allocate EVP_RAND\n");
        return NULL;
    }
    
    EVP_RAND_CTX * context = EVP_RAND_CTX_new(rand, NULL);
    EVP_RAND_free(rand);
    if (NULL == context) {
        fprintf(stderr, "Couldn't allocate EVP_RAND_CTX\n");
        return NULL;
    }

    OSSL_PARAM params[4];
    int n_params = create_params(name, params);
    if (n_params < 2) {
         fprintf(stderr, "Couldn't create params");
         return NULL;
    }

    EVP_RAND_instantiate(context, 128, 0, NULL, 0, params);

    const OSSL_PROVIDER *prov = EVP_RAND_get0_provider(EVP_RAND_CTX_get0_rand(context));
    DRBG *newDRBG = (DRBG*) malloc(sizeof(DRBG));
    newDRBG->context = context;
    newDRBG->seed = NULL;
    return newDRBG;
}
 
int next_rand(DRBG *drbg, byte output[], int n_bytes) {
    return EVP_RAND_generate(drbg->context, output, n_bytes, 128, 0, NULL, 0); 
}
