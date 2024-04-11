#include <jni.h>
#include "jssl.h"
#include <openssl/pem.h>
#include <openssl/encoder.h>
#include <stdlib.h>

/*
 * Class:     EdDSAPublicKey
 * Method:    readPubKeyFromPem0
 * Signature: (Ljava/lang/String;)J
 */
JNIEXPORT jlong JNICALL Java_EdDSAPublicKey_readPubKeyFromPem0
  (JNIEnv *env, jobject this, jstring filename) {
   OSSL_LIB_CTX *libctx = load_openssl_fips_provider("/usr/local/ssl/openssl.cnf");
   char *c_filename = (char*)(*env)->GetStringUTFChars(env, filename, 0);
   FILE *pemfile = fopen(c_filename, "r");
   return (jlong)PEM_read_PUBKEY_ex(pemfile, NULL, NULL, NULL, libctx, NULL);
}
