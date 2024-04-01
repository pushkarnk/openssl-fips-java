JAVA_HOME :=/usr/lib/jvm/java-21-openjdk-amd64/

JAVA_SRC := src/java/com/canonical/openssl
JAVA_SRC_DIRS := ${JAVA_SRC} ${JAVA_SRC}/drbg ${JAVA_SRC}/keyagreement ${JAVA_SRC}/keyencapsulation ${JAVA_SRC}/mac
JAVA_SRC_DIRS += ${JAVA_SRC}/kdf ${JAVA_SRC}/md

JAVA_FILES := $(wildcard $(addsuffix /*.java, $(JAVA_SRC_DIRS)))

NATIVE_FILES_PATH := src/native
JNI_FILES_PATH := src/jni

JSSL_HEADERS := -I${PWD}/src/include/jni -I${PWD}/src/include/native
JNI_HEADERS := -I${JAVA_HOME}/include/linux/ -I${JAVA_HOME}/include/
OPENSSL_HEADERS := -I/usr/local/include/openssl/
INCLUDE_HEADERS := ${JSSL_HEADERS} ${JNI_HEADERS} ${OPENSSL_HEADERS} 

CCFLAGS := ${INCLUDE_HEADERS} -c -fPIC

BIN := ${PWD}/build/bin
LIBPATH := ${BIN}:${PWD}/build/test

java-build: $(JAVA_FILES)
	@mkdir -p build/classes && ${JAVA_HOME}/bin/javac -d build/classes $^

build:	java-build
	@mkdir -p ${BIN} && \
	cc ${CCFLAGS} ${NATIVE_FILES_PATH}/evp_utils.c -o ${BIN}/evp_utils.o && \
	cc ${CCFLAGS} ${NATIVE_FILES_PATH}/drbg.c -o ${BIN}/drbg.o && \
	cc ${CCFLAGS} ${NATIVE_FILES_PATH}/init.c -o ${BIN}/init.o && \
	cc ${CCFLAGS} ${NATIVE_FILES_PATH}/cipher.c -o ${BIN}/cipher.o && \
	cc ${CCFLAGS} ${NATIVE_FILES_PATH}/keyagreement.c -o ${BIN}/keyagreement.o && \
	cc ${CCFLAGS} ${NATIVE_FILES_PATH}/keyencapsulation.c -o ${BIN}/keyencapsulation.o && \
	cc ${CCFLAGS} ${NATIVE_FILES_PATH}/mac.c -o ${BIN}/mac.o && \
	cc ${CCFLAGS} ${NATIVE_FILES_PATH}/md.c -o ${BIN}/md.o && \
	cc ${CCFLAGS} ${NATIVE_FILES_PATH}/signature.c -o ${BIN}/signature.o && \
	cc ${CCFLAGS} ${NATIVE_FILES_PATH}/kdf.c -o ${BIN}/kdf.o && \
	cc ${CCFLAGS} ${JNI_FILES_PATH}/jni_utils.c -o ${BIN}/jni_utils.o && \
	cc ${CCFLAGS} ${JNI_FILES_PATH}/com_canonical_openssl_OpenSSLDrbg.c \
		-o ${BIN}/com_canonical_openssl_OpenSSLDrbg.o && \
	cc ${CCFLAGS} ${JNI_FILES_PATH}/com_canonical_openssl_OpenSSLCipherSpi.c \
		-o ${BIN}/com_canonical_openssl_OpenSSLCipherSpi.o && \
	cc ${CCFLAGS} ${JNI_FILES_PATH}/com_canonical_openssl_keyagreement_OpenSSLKeyAgreement.c \
		-o ${BIN}/com_canonical_openssl_keyagreement_OpenSSLKeyAgreement.o && \
	cc ${CCFLAGS} ${JNI_FILES_PATH}/com_canonical_openssl_keyencapsulation_OpenSSLKEMRSA_RSAKEMDecapsulator.c \
		-o ${BIN}/com_canonical_openssl_keyencapsulation_OpenSSLKEMRSA_RSAKEMDecapsulator.o && \
	cc ${CCFLAGS} ${JNI_FILES_PATH}/com_canonical_openssl_keyencapsulation_OpenSSLKEMRSA_RSAKEMEncapsulator.c \
		-o ${BIN}/com_canonical_openssl_keyencapsulation_OpenSSLKEMRSA_RSAKEMEncapsulator.o && \
	cc ${CCFLAGS} ${JNI_FILES_PATH}/com_canonical_openssl_mac_OpenSSLMAC.c \
		-o ${BIN}/com_canonical_openssl_mac_OpenSSLMACSpi.o && \
	cc ${CCFLAGS} ${JNI_FILES_PATH}/com_canonical_openssl_OpenSSLMD.c \
		-o ${BIN}/com_canonical_openssl_OpenSSLMD.o && \
	cc ${CCFLAGS} ${JNI_FILES_PATH}/com_canonical_openssl_kdf_OpenSSLPBKDF2.c \
		-o ${BIN}/com_canonical_openssl_kdf_OpenSSLPBKDF2.o && \
	cc ${CCFLAGS} ${JNI_FILES_PATH}/com_canonical_openssl_OpenSSLSignatureSpi.c \
		-o ${BIN}/com_canonical_openssl_OpenSSLSignatureSpi.o && \
	cc -shared -fPIC -Wl,-soname,libjssl.so -o ${BIN}/libjssl.so \
		${BIN}/evp_utils.o \
		${BIN}/jni_utils.o \
		${BIN}/init.o   \
		${BIN}/drbg.o   \
		${BIN}/cipher.o \
		${BIN}/keyagreement.o \
		${BIN}/keyencapsulation.o \
		${BIN}/mac.o \
		${BIN}/md.o \
		${BIN}/signature.o \
		${BIN}/kdf.o \
		${BIN}/com_canonical_openssl_OpenSSLDrbg.o \
		${BIN}/com_canonical_openssl_OpenSSLCipherSpi.o \
		${BIN}/com_canonical_openssl_keyagreement_OpenSSLKeyAgreement.o \
		${BIN}/com_canonical_openssl_keyencapsulation_OpenSSLKEMRSA_RSAKEMEncapsulator.o \
		${BIN}/com_canonical_openssl_keyencapsulation_OpenSSLKEMRSA_RSAKEMDecapsulator.o \
		${BIN}/com_canonical_openssl_mac_OpenSSLMACSpi.o \
		${BIN}/com_canonical_openssl_OpenSSLMD.o \
		${BIN}/com_canonical_openssl_kdf_OpenSSLPBKDF2.o \
		${BIN}/com_canonical_openssl_OpenSSLSignatureSpi.o \
		-L/usr/local/lib64 -lcrypto -lssl

build-test-lib:
	@mkdir -p build/test && \
	cc ${CCFLAGS} test/RSAKeyPairGenerator.c -o build/test/RSAKeyPairGenerator.o && \
	cc ${CCFLAGS} test/EdDSAPrivateKey.c -o build/test/EdDSAPrivateKey.o && \
	cc ${CCFLAGS} test/EdDSAPublicKey.c  -o build/test/EdDSAPublicKey.o && \
	cc -shared -fPIC -Wl,-soname,libsigtest.so -o build/test/libsigtest.so \
		build/test/RSAKeyPairGenerator.o \
		build/test/EdDSAPrivateKey.o \
		build/test/EdDSAPublicKey.o \
		-L/usr/local/lib64 -L${BIN} -lcrypto -lssl -ljssl

test-java-sv: build build-test-lib
	@mkdir -p build/test/java && ${JAVA_HOME}/bin/javac -cp build/classes -d build/test/java test/java/SignatureTest.java && \
	LD_LIBRARY_PATH=${BIN}:./build/test ${JAVA_HOME}/bin/java -Djava.library.path=${LIBPATH} -cp build/classes:build/test/java SignatureTest

test-java-kdf: build
	@mkdir -p build/test/java && ${JAVA_HOME}/bin/javac -cp build/classes -d build/test/java test/java/PBKDFTest.java && \
	LD_LIBRARY_PATH=${BIN} ${JAVA_HOME}/bin/java -Djava.library.path=${LIBPATH} -cp build/classes:build/test/java PBKDFTest

test-java-md: build
	@mkdir -p build/test/java && ${JAVA_HOME}/bin/javac -cp build/classes -d build/test/java test/java/MDTest.java && \
	LD_LIBRARY_PATH=${BIN} ${JAVA_HOME}/bin/java -Djava.library.path=${LIBPATH} -cp build/classes:build/test/java MDTest

test-java-mac: build
	@mkdir -p build/test/java && ${JAVA_HOME}/bin/javac -cp build/classes -d build/test/java test/java/MacTest.java && \
	LD_LIBRARY_PATH=${BIN} ${JAVA_HOME}/bin/java -Djava.library.path=${LIBPATH} -cp build/classes:build/test/java MacTest

test-java-ke: build
	@mkdir -p build/test/java && ${JAVA_HOME}/bin/javac -cp build/classes -d build/test/java test/java/KeyEncapsulationTest.java && \
	LD_LIBRARY_PATH=${BIN} ${JAVA_HOME}/bin/java -Djava.library.path=${LIBPATH} -cp build/classes:build/test/java KeyEncapsulationTest

test-java-ka: build
	@mkdir -p build/test/java && ${JAVA_HOME}/bin/javac -cp build/classes -d build/test/java test/java/KeyAgreementTest.java && \
	LD_LIBRARY_PATH=${BIN} ${JAVA_HOME}/bin/java -Djava.library.path=${LIBPATH} -cp build/classes:build/test/java KeyAgreementTest

test-java-cipher: build
	@mkdir -p build/test/java && ${JAVA_HOME}/bin/javac -cp build/classes -d build/test/java test/java/CipherTest.java && \
	LD_LIBRARY_PATH=${BIN} ${JAVA_HOME}/bin/java -Djava.library.path=${LIBPATH} -cp build/classes:build/test/java CipherTest

test-java-drbg: build
	@mkdir -p build/test/java && ${JAVA_HOME}/bin/javac -cp build/classes -d build/test/java test/java/DrbgTest.java && \
	LD_LIBRARY_PATH=${BIN} ${JAVA_HOME}/bin/java -Djava.library.path=${LIBPATH} -cp build/classes:build/test/java DrbgTest 

test-drbg: build
	@mkdir -p build/test &&  cc ${INCLUDE_HEADERS} -L${BIN}/  -o build/test/drbg_test test/drbg_test.c -ljssl && \
	LD_LIBRARY_PATH=${BIN} build/test/drbg_test 2>/dev/null

test-cipher: build
	@mkdir -p build/test &&  cc ${INCLUDE_HEADERS} -L${BIN}/  -o build/test/cipher_test test/cipher_test.c -ljssl && \
        LD_LIBRARY_PATH=${BIN} build/test/cipher_test 2>/dev/null

test-ka: build
	@mkdir -p build/test &&  cc ${INCLUDE_HEADERS} -L${BIN}/  -o build/test/keyagreement test/keyagreement.c -ljssl && \
	LD_LIBRARY_PATH=${BIN} build/test/keyagreement 2>/dev/null

test-ke: build
	@mkdir -p build/test &&  cc ${INCLUDE_HEADERS} -L${BIN}/ -L/usr/local/lib64 -o build/test/keyencapsulation test/keyencapsulation.c -ljssl && \
	LD_LIBRARY_PATH=${BIN} ./build/test/keyencapsulation 2>/dev/null
test-mac: build
	@mkdir -p build/test &&  cc ${INCLUDE_HEADERS} -L${BIN}/ -L/usr/local/lib64 -o build/test/mac test/mac.c -ljssl && \
	LD_LIBRARY_PATH=${BIN} ./build/test/mac 2>/dev/null
test-md: build
	@mkdir -p build/test &&  cc ${INCLUDE_HEADERS} -L${BIN}/ -L/usr/local/lib64 -o build/test/md test/md.c -ljssl && \
	LD_LIBRARY_PATH=${BIN} ./build/test/md 2>/dev/null
test-sv: build
	@mkdir -p build/test &&  cc ${INCLUDE_HEADERS} -L${BIN}/ -L/usr/local/lib64 -o build/test/signature test/signature.c -ljssl -lcrypto && \
	LD_LIBRARY_PATH=${BIN} ./build/test/signature 2>/dev/null
test-kdf: build
	@mkdir -p build/test &&  cc ${INCLUDE_HEADERS} -L${BIN}/ -L/usr/local/lib64 -o build/test/kdf test/kdf.c -ljssl && \
	LD_LIBRARY_PATH=${BIN} ./build/test/kdf 2>/dev/null
clean:
	@rm -rf build
