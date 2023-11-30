#include <openssl/provider.h>
#include <string.h>

OSSL_LIB_CTX* load_openssl_fips_provider(const char*);

#define STR_EQUAL(a, b) (0 == strcmp(a, b))

#define MIN(a, b) (a > b ? b : a)
#define IS_NULL(a) (NULL == (void *)a)
#define RET_NULL_IF_NULL(a) { if(IS_NULL(a)) return NULL; }
#define RET_ZERO_IF_NULL(a) { if(IS_NULL(a)) return 0; }
#define RET_NULL_IF_NON_POSITIVE(a) { if (a <= 0) return NULL; }
#define RET_ZERO_IF_NON_POSITIVE(a) { if (a <= 0) return 0; }

/* Lets use 'byte' instead of 'unsigned char' */
typedef unsigned char byte;
