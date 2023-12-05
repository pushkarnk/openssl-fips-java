#include "jssl.h"
#include "keyagreement.h"

int compare(shared_secret *s1, shared_secret *s2) {
    if (s1 == NULL || s2 == NULL) return 0;

    if (s1->length != s2->length) return 0;

    for(int i = 0; i < s1->length; i++) {
        if (s1->bytes[i] != s2->bytes[i]) return 0;
    }

    return 1;
}

void test(key_agreement_algorithm algo, OSSL_LIB_CTX *libctx) {
    switch(algo) {
        case DIFFIE_HELLMAN: printf("Testing DIFFIE_HELLMAN key-agreement: "); break;
        case ELLIPTIC_CURVE: printf("Testing ELLIPTIC_CURVE key-agreement: "); break;
    }

    shared_secret *alice_secret, *bob_secret;

    key_pair *alice_key = generate_key(algo);
    key_pair *bob_key = generate_key(algo);

    key_agreement *alice = init_key_agreement(algo, libctx);
    set_private_key(alice, alice_key);
    set_peer_key(alice, bob_key);
    alice_secret = generate_shared_secret(alice);
    
    key_agreement *bob = init_key_agreement(algo, libctx);
    set_private_key(bob, bob_key);
    set_peer_key(bob, alice_key);
    bob_secret = generate_shared_secret(bob);

    if (compare(alice_secret, bob_secret)) {
        printf(" PASSED\n");
    }

    free_key_pair(alice_key);
    free_key_pair(bob_key);
    free_shared_secret(alice_secret);
    free_shared_secret(bob_secret);
    free_key_agreement(alice);
    //free_key_agreement(bob); // keys are shared, don't free twice
    free(bob);
}

int main(int argc, char *argv[]) {
    OSSL_LIB_CTX *libctx = load_openssl_fips_provider("/usr/local/ssl/openssl.cnf");
    test(DIFFIE_HELLMAN, libctx);
    test(ELLIPTIC_CURVE, libctx);
}

