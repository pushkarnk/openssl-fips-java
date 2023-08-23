#include "jssl.h"
#include <drbg.h>

void test_xxx_drbg(const char *test, const char *algo) {
    DRBG *drbg = create_DRBG(algo);
    byte output1[10] = {0}, output2[10] = {0};
    next_rand(drbg, output1, 10);
    next_rand(drbg, output2, 10);
    for (int i = 0; i < 10; i++) {
        if(output1[i] == output2[i]) {
            printf("drbg_test/%s: FAIL\n", test); 
            return;
        }
    }
    printf("drbg_test/%s: PASS\n", test);
}

void test_basic_hmac_drbg() {
    test_xxx_drbg("test_basic_hmac_drbg", "HMAC-DRBG");
}

void test_basic_hash_drbg() {
    test_xxx_drbg("test_basic_hash_drbg", "HASH-DRBG");
}

void test_basic_ctr_drbg() {
    test_xxx_drbg("test_basic_hash_drbg", "CTR-DRBG");
}

void test_xxx_drbg_fails(const char *test, const char *algo) {
    if (NULL == create_DRBG(algo)) {
        printf("drbg_test/%s: PASS\n", test);
    } else {
        printf("drbg_test/%s: FAIL\n", test);
    }
}

void test_seed_src_drbg_fails() {
    test_xxx_drbg_fails("test_seed_src_drbg_fails", "SEED-SRC");
}

void test_test_rand_drbg_fails() {
   test_xxx_drbg_fails("test_test_rand_drbg_fails", "TEST-RAND");
}

int main(int argc, char ** argv) {
    load_openssl_fips_provider("/usr/local/ssl/openssl.cnf");
    test_basic_hmac_drbg();
    test_basic_hash_drbg();
    test_basic_ctr_drbg();
    test_seed_src_drbg_fails();
    test_test_rand_drbg_fails();
    return 0;
}
 
