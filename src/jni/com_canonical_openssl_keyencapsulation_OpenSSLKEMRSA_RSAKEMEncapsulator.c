#include <jni.h>
#include "jssl.h"
#include "keyencapsulation.h"
#include "com_canonical_openssl_keyencapsulation_OpenSSLKEMRSA_RSAKEMEncapsulator.h"
#include "evp_utils.h"
#include "jni_utils.h"

extern OSSL_LIB_CTX *global_libctx;

/*
 * Class:     OpenSSLKEMRSA_RSAKEMEncapsulator
 * Method:    encapsulatorInit0
 * Signature: ([B)J
 */
JNIEXPORT jlong JNICALL Java_com_canonical_openssl_keyencapsulation_OpenSSLKEMRSA_00024RSAKEMEncapsulator_encapsulatorInit0
  (JNIEnv *env, jobject this, jbyteArray key) {
    byte* bytes = jbyteArray_to_byte_array(env, key);
    int length = array_length(env, key);
    EVP_PKEY *public_key = create_public_key(bytes, length);
    kem_keyspec *spec = init_kem_keyspec_with_key(public_key, NULL, global_libctx); 
    return (jlong)spec;
}

/*
 * Class:     OpenSSLKEMRSA_RSAKEMEncapsulator
 * Method:    engineEncapsulate0
 * Signature: ([B[B)V;
 */
JNIEXPORT void JNICALL Java_com_canonical_openssl_keyencapsulation_OpenSSLKEMRSA_00024RSAKEMEncapsulator_engineEncapsulate0
  (JNIEnv *env, jobject this, jbyteArray secret_bytes, jbyteArray encapsulated_bytes) {
    kem_keyspec *spec = (kem_keyspec*)get_long_field(env, this, "nativeHandle");
    generate_and_wrap(spec);
    copy_byte_array(env, secret_bytes, spec->secret, spec->secret_length);
    copy_byte_array(env, encapsulated_bytes, spec->wrapped_key, spec->wrapped_key_length);
    return;
}

/*
 * Class:     OpenSSLKEMRSA_RSAKEMEncapsulator
 * Method:    engineSecretSize0
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_canonical_openssl_keyencapsulation_OpenSSLKEMRSA_00024RSAKEMEncapsulator_engineSecretSize0
  (JNIEnv *env, jobject this) {
    kem_keyspec *spec = (kem_keyspec*)get_long_field(env, this, "nativeHandle");
    return get_secret_size(spec, JNI_TRUE);
}

/*
 * Class:     OpenSSLKEMRSA_RSAKEMEncapsulator
 * Method:    engineEncapsulationSize0
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_canonical_openssl_keyencapsulation_OpenSSLKEMRSA_00024RSAKEMEncapsulator_engineEncapsulationSize0
  (JNIEnv *env, jobject this) {
    kem_keyspec *spec = (kem_keyspec*)get_long_field(env, this, "nativeHandle");
    return get_encapsulation_size(spec, JNI_TRUE);
}
