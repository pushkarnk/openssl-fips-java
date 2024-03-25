#include <jni.h>
#include "jssl.h"
#include "keyencapsulation.h"
#include "com_canonical_openssl_keyencapsulation_OpenSSLKEMRSA_RSAKEMDecapsulator.h"
#include "evp_utils.h"
#include "jni_utils.h"

extern OSSL_LIB_CTX *global_libctx;
/*
 * Class:     OpenSSLKEMRSA_RSAKEMDecapsulator
 * Method:    decapsulatorInit0
 * Signature: ([B)J
 */
JNIEXPORT jlong JNICALL Java_com_canonical_openssl_keyencapsulation_OpenSSLKEMRSA_00024RSAKEMDecapsulator_decapsulatorInit0
  (JNIEnv *env, jobject this, jbyteArray key) {
    byte* bytes = jbyteArray_to_byte_array(env, key);
    int length = array_length(env, key);
    EVP_PKEY *private_key = create_private_key(EVP_PKEY_RSA, bytes, length);
    kem_keyspec *spec = init_kem_keyspec_with_key(NULL, private_key, global_libctx);
    return (jlong)spec;
}

/*
 * Class:     OpenSSLKEMRSA_RSAKEMDecapsulator
 * Method:    engineDecapsulate0
 * Signature: ([B[B)V;
 */
JNIEXPORT jbyteArray JNICALL Java_com_canonical_openssl_keyencapsulation_OpenSSLKEMRSA_00024RSAKEMDecapsulator_engineDecapsulate0
  (JNIEnv *env, jobject this, jbyteArray encapsulated) {
    kem_keyspec *spec = (kem_keyspec*)get_long_field(env, this, "nativeHandle");
    byte* bytes = jbyteArray_to_byte_array(env, encapsulated);
    int length = array_length(env, encapsulated);
    set_wrapped_key(spec, bytes, length);
    unwrap(spec);
    return new_byteArray(env, spec->secret, spec->secret_length);
}

/*
 * Class:     OpenSSLKEMRSA_RSAKEMDecapsulator
 * Method:    engineSecretSize0
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_canonical_openssl_keyencapsulation_OpenSSLKEMRSA_00024RSAKEMDecapsulator_engineSecretSize0
  (JNIEnv *env, jobject this) {
    kem_keyspec *spec = (kem_keyspec*)get_long_field(env, this, "nativeHandle");
    return get_secret_size(spec, JNI_FALSE);

}

/*
 * Class:     OpenSSLKEMRSA_RSAKEMDecapsulator
 * Method:    engineEncapsulationSize0
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_canonical_openssl_keyencapsulation_OpenSSLKEMRSA_00024RSAKEMDecapsulator_engineEncapsulationSize0
  (JNIEnv *env, jobject this) {
    kem_keyspec *spec = (kem_keyspec*)get_long_field(env, this, "nativeHandle");
    return get_encapsulation_size(spec, JNI_FALSE);
}
