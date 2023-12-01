#include "jssl.h"

typedef enum kdf_type { PBKDF2, HKDF } kdf_type;

typedef struct pbkdf_spec {
    byte *password;
    int password_length;
    byte *salt;
    int salt_length;
    unsigned int iterations;
} pbkdf_spec;

typedef struct {
    char *digest_algorithm;
} pbkdf_params;

typedef struct {
    char *digest_algorithm;
} hkdf_params;

typedef struct {
    byte *salt;
    int salt_length;
    byte *info;
    int info_length;
    byte *key;
    int key_length;
} hkdf_spec;

typedef union {
    pbkdf_spec *pbkdf;
    hkdf_spec *hkdf;
} kdf_spec;

typedef union {
    pbkdf_params *pbkdf;
    hkdf_params *hkdf;
} kdf_params;

kdf_params *create_hkdf_params(char *algorithm);
kdf_spec *create_hkdf_spec(byte *salt, int saltlen, byte *info, int infolen, byte *key, int keylen);

kdf_params *create_pbkdf_params(char *algorithm);
kdf_spec *create_pbkdf_spec(byte *password, int pass_len, byte *salt, int salt_len, unsigned int iter);

int kdf_derive(OSSL_LIB_CTX *ossl_lib_ctx, kdf_spec *spec, kdf_params *params, byte *keydata, int keysize, kdf_type kdf);
