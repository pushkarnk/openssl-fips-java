#include "jssl.h"
#include <openssl/evp.h>

typedef enum key_agreement_algorithm {
    DIFFIE_HELLMAN, // Diffie-Hellman
    ELLIPTIC_CURVE  // Elliptic-Curve
} key_agreement_algorithm;

typedef struct shared_secret {
    byte *bytes;
    int length;
} shared_secret;

typedef struct key_agreement {
    OSSL_LIB_CTX *libctx;
    key_agreement_algorithm algorithm;
    EVP_PKEY *private_key;
    EVP_PKEY *peer_public_key;
    shared_secret *secret;
} key_agreement;

typedef struct key_pair {
    EVP_PKEY *key;
    //EVP_PKEY_CTX *ctx;
} key_pair;

key_pair *generate_key(key_agreement_algorithm algo);

key_agreement* init_key_agreement(key_agreement_algorithm algo, OSSL_LIB_CTX *libctx);

void set_private_key(key_agreement *agreement, key_pair *private_key);

void set_peer_key(key_agreement *agreement, key_pair *peer_public_key);

shared_secret *generate_shared_secret(key_agreement *agreement);

int get_shared_secret_bytes(key_agreement *agreement, byte secret[]);

key_pair *generate_key(key_agreement_algorithm algo);

void free_key_agreement(key_agreement *this);

void free_shared_secret(shared_secret *this);

void free_key_pair(key_pair *this);
