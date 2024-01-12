#include <jni.h>
#include "jssl.h"
#include "cipher.h"
#include "com_canonical_openssl_OpenSSLCipherSpi.h"

#define LARGE_SIZE 1024
extern OSSL_LIB_CTX *global_libctx;

JNIEXPORT jlong JNICALL Java_OpenSSLCipherSpi_createContext0
  (JNIEnv *env, jobject this, jstring name, jstring padding) {
     const char *namestr = (*env)->GetStringUTFChars(env, name, 0);
     const char *paddingstr = (*env)->GetStringUTFChars(env, padding, 0);
     return (jlong) create_cipher_context(global_libctx, namestr, paddingstr); 
}

JNIEXPORT jbyteArray JNICALL Java_OpenSSLCipherSpi_doInit0
  (JNIEnv *env, jobject this, jbyteArray input, jint offset, jint length, jbyteArray key, jbyteArray iv, jint opmode) {

    jclass clazz = (*env)->GetObjectClass(env, this);
    jfieldID ctx_id = (*env)->GetFieldID(env, clazz, "cipherContext", "J");
    jlong ctx_handle = (*env)->GetLongField(env, this, ctx_id);

    jbyte *input_bytes = (jbyte *)malloc(length);
    (*env)->GetByteArrayRegion(env, input, offset, length, input_bytes);

    unsigned char *key_bytes = (unsigned char *) (*env)->GetByteArrayElements(env, key, NULL);
    unsigned char *iv_bytes  = (unsigned char *) (*env)->GetByteArrayElements(env, iv, NULL);
    int iv_length = (*env)->GetArrayLength(env, iv);

    cipher_init((cipher_context*)ctx_handle, input_bytes, length, key_bytes, iv_bytes, iv_length, opmode);
    return Java_OpenSSLCipherSpi_doUpdate0(env, this, input, offset, length);

}

JNIEXPORT jbyteArray JNICALL Java_OpenSSLCipherSpi_doUpdate0
  (JNIEnv *env, jobject this, jbyteArray input, jint offset, jint length) {
    byte output_bytes[1024];
    int output_length = 0;

    jclass clazz = (*env)->GetObjectClass(env, this);
    jfieldID ctx_id = (*env)->GetFieldID(env, clazz, "cipherContext", "J");
    jlong ctx_handle = (*env)->GetLongField(env, this, ctx_id);

    jbyte *input_bytes = (jbyte *)malloc(length);
    (*env)->GetByteArrayRegion(env, input, offset, length, input_bytes);

    cipher_update((cipher_context*)ctx_handle, output_bytes, &output_length, input_bytes, length);

    jbyteArray ret_array = (*env)->NewByteArray(env, output_length);
    (*env)->SetBooleanArrayRegion(env, ret_array, 0, output_length, output_bytes);
    return ret_array;
}

JNIEXPORT jbyteArray JNICALL Java_OpenSSLCipherSpi_doFinal0
  (JNIEnv *env, jobject this, jbyteArray output, jint length) {
    int templen = 0;

    jclass clazz = (*env)->GetObjectClass(env, this);
    jfieldID ctx_id = (*env)->GetFieldID(env, clazz, "cipherContext", "J");
    jlong ctx_handle = (*env)->GetLongField(env, this, ctx_id);

    jbyte *out_bytes  = (*env)->GetByteArrayElements(env, output, NULL);
    cipher_do_final((cipher_context*)ctx_handle, out_bytes + length, &templen);

    jbyteArray ret_array = (*env)->NewByteArray(env, length + templen);
    (*env)->SetBooleanArrayRegion(env, ret_array, 0, length + templen, out_bytes);
    return ret_array;
}

