#include <openssl/provider.h>
#include <string.h>

OSSL_PROVIDER* load_openssl_fips_provider(const char*);

#define STR_EQUAL(a, b) (0 == strcmp(a, b))

#define MIN(a, b) (a > b ? b : a)
#define IS_NULL(a) (NULL == (void *)a)

/* Lets use 'byte' instead of 'char' */
typedef char byte;
