/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class OpenSSLMDSpi */

#ifndef _Included_OpenSSLMDSpi
#define _Included_OpenSSLMDSpi
#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     OpenSSLMDSpi
 * Method:    doInit0
 * Signature: (Ljava/lang/String;)J
 */
JNIEXPORT jlong JNICALL Java_OpenSSLMDSpi_doInit0
  (JNIEnv *, jobject, jstring);

/*
 * Class:     OpenSSLMDSpi
 * Method:    doUpdate0
 * Signature: ([B)V
 */
JNIEXPORT void JNICALL Java_OpenSSLMDSpi_doUpdate0
  (JNIEnv *, jobject, jbyteArray);

/*
 * Class:     OpenSSLMDSpi
 * Method:    doFinal0
 * Signature: ()[B
 */
JNIEXPORT jbyteArray JNICALL Java_OpenSSLMDSpi_doFinal0
  (JNIEnv *, jobject);

#ifdef __cplusplus
}
#endif
#endif