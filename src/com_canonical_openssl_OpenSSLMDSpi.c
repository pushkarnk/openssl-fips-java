#include "com_canononical_openssl_OpenSSLMDSpi.h"
#include "jssl.h"
#include "md.h"
#include "jni_utils.h"

extern OSSL_LIB_CTX *global_libctx;

/*
 * Class:     OpenSSLMDSpi
 * Method:    doInit0
 * Signature: (Ljava/lang/String;)J
 */
JNIEXPORT jlong JNICALL Java_OpenSSLMDSpi_doInit0
  (JNIEnv *env, jobject this, jstring algorithm) {
    return (jlong) md_init(global_libctx, (const char*)jstring_to_char_array(env, algorithm));
}

/*
 * Class:     OpenSSLMDSpi
 * Method:    doUpdate0
 * Signature: ([B)V
 */
JNIEXPORT void JNICALL Java_OpenSSLMDSpi_doUpdate0
  (JNIEnv *env, jobject this, jbyteArray data) {
    md_context *ctx = (md_context*) get_long_field(env, this, "nativeHandle");
    byte *data_array = jbyteArray_to_byte_array(env, data);
    int length = array_length(env, data);    
    md_update(ctx, data_array, length);
}

/*
 * Class:     OpenSSLMDSpi
 * Method:    doFinal0
 * Signature: ()[B
 */
JNIEXPORT jbyteArray JNICALL Java_OpenSSLMDSpi_doFinal0
  (JNIEnv *env, jobject this) {
    byte digest[1024];
    int digest_length = 0;
    md_context *ctx = (md_context*) get_long_field(env, this, "nativeHandle");
    md_digest(ctx, digest, &digest_length); 
    return byte_array_to_jbyteArray(env, digest, digest_length);
}

