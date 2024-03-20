#include <jni.h>
#include "jssl.h"

byte *jbyteArray_to_byte_array(JNIEnv *env, jbyteArray keyBytes);

jbyteArray byte_array_to_jbyteArray(JNIEnv *env, byte *array, int length);

int array_length(JNIEnv *env, jbyteArray array);

long get_long_field(JNIEnv *env, jobject this, const char *field_name);

int get_int_field(JNIEnv *env, jobject this, const char *field_name);

jstring get_string_field(JNIEnv *env, jobject this, const char *field_name);

void copy_byte_array_range(JNIEnv *env, jbyteArray source, int offset, int length, byte *destination);

void copy_byte_array(JNIEnv *env, jbyteArray destination, byte *source, int length);

jbyteArray new_byteArray(JNIEnv *env, byte *source, int length);

char* jstring_to_char_array(JNIEnv *env, jstring string);

char *jcharArray_to_char_array(JNIEnv *env, jcharArray chars);

jlong invokeLongMethod(JNIEnv *env, jobject this, const char *name, const char *signature);
