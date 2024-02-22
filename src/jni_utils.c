#include <jni.h>
#include "jssl.h"

byte *jbyteArray_to_byte_array(JNIEnv *env, jbyteArray keyBytes) {
    return (byte *) (*env)->GetByteArrayElements(env, keyBytes, NULL);
}

jbyteArray byte_array_to_jbyteArray(JNIEnv *env, byte *array, int length) {
    jbyteArray ret_array = (*env)->NewByteArray(env, length);
    (*env)->SetByteArrayRegion(env, ret_array, 0, length, array);
    return ret_array;
}

int array_length(JNIEnv *env, jbyteArray array) {
    return (*env)->GetArrayLength(env, array);
}

long get_long_field(JNIEnv *env, jobject this, const char *field_name) {
    jclass clazz = (*env)->GetObjectClass(env, this);
    jfieldID ctx_id = (*env)->GetFieldID(env, clazz, field_name, "J");
    jlong ctx_handle = (*env)->GetLongField(env, this, ctx_id);
}

void copy_byte_array(JNIEnv *env, jbyteArray destination, byte *source, int length) {
    (*env)->SetByteArrayRegion(env, destination, 0, length, source);
}

jbyteArray new_byteArray(JNIEnv *env, byte *source, int length) {
    jbyteArray retArray = (*env)->NewByteArray(env, length);
    (*env)->SetByteArrayRegion(env, retArray, 0, length, source);
    return retArray;
}
