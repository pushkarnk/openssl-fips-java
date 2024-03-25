JAVA_HOME :=/usr/lib/jvm/java-21-openjdk-amd64/
LIBPATH=${PWD}/build/bin/:${PWD}/build/test

JAVA_SRC := src/java/com/canonical/openssl
JAVA_SRC_DIRS := ${JAVA_SRC} ${JAVA_SRC}/drbg ${JAVA_SRC}/keyagreement ${JAVA_SRC}/keyencapsulation ${JAVA_SRC}/mac
JAVA_SRC_DIRS += ${JAVA_SRC}/kdf

JAVA_FILES := $(wildcard $(addsuffix /*.java, $(JAVA_SRC_DIRS)))

java-build: $(JAVA_FILES)
	@mkdir -p build/classes && ${JAVA_HOME}/bin/javac -d build/classes $^

build:	java-build
	@mkdir -p build/bin && \
	cc -I/usr/local/include/openssl/ -I./include -c -fPIC src/evp_utils.c -o build/bin/evp_utils.o && \
	cc -I/usr/local/include/openssl/ -I./include -c -fPIC src/drbg.c -o build/bin/drbg.o && \
	cc -I/usr/local/include/openssl/ -I./include -I${JAVA_HOME}/include/linux/ -I${JAVA_HOME}/include/ -c -fPIC src/init.c -o build/bin/init.o && \
	cc -I/usr/local/include/openssl/ -I./include -c -fPIC src/cipher.c -o build/bin/cipher.o && \
	cc -I/usr/local/include/openssl/ -I./include -c -fPIC src/keyagreement.c -o build/bin/keyagreement.o && \
	cc -I/usr/local/include/openssl/ -I./include -c -fPIC src/keyencapsulation.c -o build/bin/keyencapsulation.o && \
	cc -I/usr/local/include/openssl/ -I./include -c -fPIC src/mac.c -o build/bin/mac.o && \
	cc -I/usr/local/include/openssl/ -I./include -c -fPIC src/md.c -o build/bin/md.o && \
	cc -I/usr/local/include/openssl/ -I./include -c -fPIC src/signature.c -o build/bin/signature.o && \
	cc -I./include -I/usr/local/include/openssl/ -I./include -c -fPIC src/kdf.c -o build/bin/kdf.o && \
	cc -I./include -I${JAVA_HOME}/include/linux/ -I${JAVA_HOME}/include/ -c -fPIC \
		src/jni_utils.c -o build/bin/jni_utils.o && \
	cc -I./include -I${JAVA_HOME}/include/linux/ -I${JAVA_HOME}/include/ -c -fPIC \
		src/com_canonical_openssl_OpenSSLDrbg.c -o build/bin/com_canonical_openssl_OpenSSLDrbg.o && \
	cc -I./include -I${JAVA_HOME}/include/linux/ -I${JAVA_HOME}/include/ -c -fPIC \
		src/com_canonical_openssl_OpenSSLCipherSpi.c -o build/bin/com_canonical_openssl_OpenSSLCipherSpi.o && \
	cc -I./include -I${JAVA_HOME}/include/linux/ -I${JAVA_HOME}/include/ -c -fPIC \
		src/com_canonical_openssl_keyagreement_OpenSSLKeyAgreement.c -o build/bin/com_canonical_openssl_keyagreement_OpenSSLKeyAgreement.o && \
	cc -I./include -I${JAVA_HOME}/include/linux/ -I${JAVA_HOME}/include/ -c -fPIC \
		src/com_canonical_openssl_keyencapsulation_OpenSSLKEMRSA_RSAKEMDecapsulator.c -o build/bin/com_canonical_openssl_keyencapsulation_OpenSSLKEMRSA_RSAKEMDecapsulator.o && \
	cc -I./include -I${JAVA_HOME}/include/linux/ -I${JAVA_HOME}/include/ -c -fPIC \
		src/com_canonical_openssl_keyencapsulation_OpenSSLKEMRSA_RSAKEMEncapsulator.c -o build/bin/com_canonical_openssl_keyencapsulation_OpenSSLKEMRSA_RSAKEMEncapsulator.o && \
	cc -I./include -I${JAVA_HOME}/include/linux/ -I${JAVA_HOME}/include/ -c -fPIC \
		src/com_canonical_openssl_mac_OpenSSLMAC.c -o build/bin/com_canonical_openssl_mac_OpenSSLMACSpi.o && \
	cc -I./include -I${JAVA_HOME}/include/linux/ -I${JAVA_HOME}/include/ -c -fPIC \
		src/com_canonical_openssl_OpenSSLMDSpi.c -o build/bin/com_canonical_openssl_OpenSSLMDSpi.o && \
	cc -I./include -I${JAVA_HOME}/include/linux/ -I${JAVA_HOME}/include/ -c -fPIC \
		src/com_canonical_openssl_kdf_OpenSSLPBKDF2.c -o build/bin/com_canonical_openssl_kdf_OpenSSLPBKDF2.o && \
	cc -I./include -I${JAVA_HOME}/include/linux/ -I${JAVA_HOME}/include/ -c -fPIC \
		src/com_canonical_openssl_OpenSSLSignatureSpi.c -o build/bin/com_canonical_openssl_OpenSSLSignatureSpi.o && \
	cc -shared -fPIC -Wl,-soname,libjssl.so -o build/bin/libjssl.so \
		build/bin/evp_utils.o \
		build/bin/jni_utils.o \
		build/bin/init.o   \
		build/bin/drbg.o   \
		build/bin/cipher.o \
		build/bin/keyagreement.o \
		build/bin/keyencapsulation.o \
		build/bin/mac.o \
		build/bin/md.o \
		build/bin/signature.o \
		build/bin/kdf.o \
		build/bin/com_canonical_openssl_OpenSSLDrbg.o \
		build/bin/com_canonical_openssl_OpenSSLCipherSpi.o \
		build/bin/com_canonical_openssl_keyagreement_OpenSSLKeyAgreement.o \
		build/bin/com_canonical_openssl_keyencapsulation_OpenSSLKEMRSA_RSAKEMEncapsulator.o \
		build/bin/com_canonical_openssl_keyencapsulation_OpenSSLKEMRSA_RSAKEMDecapsulator.o \
		build/bin/com_canonical_openssl_mac_OpenSSLMACSpi.o \
		build/bin/com_canonical_openssl_OpenSSLMDSpi.o \
		build/bin/com_canonical_openssl_kdf_OpenSSLPBKDF2.o \
		build/bin/com_canonical_openssl_OpenSSLSignatureSpi.o \
		-L/usr/local/lib64 -lcrypto -lssl

build-test-lib:
	@mkdir -p build/test && \
	cc -I./include -I${JAVA_HOME}/include/linux/ -I${JAVA_HOME}/include/ -c -fPIC test/RSAKeyPairGenerator.c -o build/test/RSAKeyPairGenerator.o && \
	cc -I./include -I${JAVA_HOME}/include/linux/ -I${JAVA_HOME}/include/ -c -fPIC test/EdDSAPrivateKey.c -o build/test/EdDSAPrivateKey.o && \
	cc -I./include -I${JAVA_HOME}/include/linux/ -I${JAVA_HOME}/include/ -c -fPIC test/EdDSAPublicKey.c  -o build/test/EdDSAPublicKey.o && \
	cc -shared -fPIC -Wl,-soname,libsigtest.so -o build/test/libsigtest.so \
		build/test/RSAKeyPairGenerator.o \
		build/test/EdDSAPrivateKey.o \
		build/test/EdDSAPublicKey.o \
		-L/usr/local/lib64 -L./build/bin -lcrypto -lssl -ljssl

test-java-sv: build build-test-lib
	@mkdir -p build/test/java && ${JAVA_HOME}/bin/javac -cp build/classes -d build/test/java test/java/SignatureTest.java && \
	LD_LIBRARY_PATH=./build/bin:./build/test ${JAVA_HOME}/bin/java -Djava.library.path=${LIBPATH} -cp build/classes:build/test/java SignatureTest

test-java-kdf: build
	@mkdir -p build/test/java && ${JAVA_HOME}/bin/javac -cp build/classes -d build/test/java test/java/PBKDFTest.java && \
	LD_LIBRARY_PATH=./build/bin ${JAVA_HOME}/bin/java -Djava.library.path=${LIBPATH} -cp build/classes:build/test/java PBKDFTest

test-java-md: build
	@mkdir -p build/test/java && ${JAVA_HOME}/bin/javac -cp build/classes -d build/test/java test/java/MDTest.java && \
	LD_LIBRARY_PATH=./build/bin ${JAVA_HOME}/bin/java -Djava.library.path=${LIBPATH} -cp build/classes:build/test/java MDTest

test-java-mac: build
	@mkdir -p build/test/java && ${JAVA_HOME}/bin/javac -cp build/classes -d build/test/java test/java/MacTest.java && \
	LD_LIBRARY_PATH=./build/bin ${JAVA_HOME}/bin/java -Djava.library.path=${LIBPATH} -cp build/classes:build/test/java MacTest

test-java-ke: build
	@mkdir -p build/test/java && ${JAVA_HOME}/bin/javac -cp build/classes -d build/test/java test/java/KeyEncapsulationTest.java && \
	LD_LIBRARY_PATH=./build/bin ${JAVA_HOME}/bin/java -Djava.library.path=${LIBPATH} -cp build/classes:build/test/java KeyEncapsulationTest

test-java-ka: build
	@mkdir -p build/test/java && ${JAVA_HOME}/bin/javac -cp build/classes -d build/test/java test/java/KeyAgreementTest.java && \
	LD_LIBRARY_PATH=./build/bin ${JAVA_HOME}/bin/java -Djava.library.path=${LIBPATH} -cp build/classes:build/test/java KeyAgreementTest

test-java-cipher: build
	@mkdir -p build/test/java && ${JAVA_HOME}/bin/javac -cp build/classes -d build/test/java test/java/CipherTest.java && \
	LD_LIBRARY_PATH=./build/bin ${JAVA_HOME}/bin/java -Djava.library.path=${LIBPATH} -cp build/classes:build/test/java CipherTest

test-java-drbg: build
	@mkdir -p build/test/java && ${JAVA_HOME}/bin/javac -cp build/classes -d build/test/java test/java/DrbgTest.java && \
	LD_LIBRARY_PATH=./build/bin ${JAVA_HOME}/bin/java -Djava.library.path=${LIBPATH} -cp build/classes:build/test/java DrbgTest 

test-drbg: build
	@mkdir -p build/test &&  cc -I./include/ -L./build/bin/  -o build/test/drbg_test test/drbg_test.c -ljssl && \
	LD_LIBRARY_PATH=./build/bin build/test/drbg_test 2>/dev/null

test-cipher: build
	@mkdir -p build/test &&  cc -I./include/ -L./build/bin/  -o build/test/cipher_test test/cipher_test.c -ljssl && \
        LD_LIBRARY_PATH=./build/bin build/test/cipher_test 2>/dev/null

test-ka: build
	@mkdir -p build/test &&  cc -I./include/ -L./build/bin/  -o build/test/keyagreement test/keyagreement.c -ljssl && \
	LD_LIBRARY_PATH=./build/bin build/test/keyagreement 2>/dev/null

test-ke: build
	@mkdir -p build/test &&  cc -I./include/ -L./build/bin/ -L/usr/local/lib64 -o build/test/keyencapsulation test/keyencapsulation.c -ljssl && \
	LD_LIBRARY_PATH=./build/bin ./build/test/keyencapsulation 2>/dev/null
test-mac: build
	@mkdir -p build/test &&  cc -I./include/ -L./build/bin/ -L/usr/local/lib64 -o build/test/mac test/mac.c -ljssl && \
	LD_LIBRARY_PATH=./build/bin ./build/test/mac 2>/dev/null
test-md: build
	@mkdir -p build/test &&  cc -I./include/ -L./build/bin/ -L/usr/local/lib64 -o build/test/md test/md.c -ljssl && \
	LD_LIBRARY_PATH=./build/bin ./build/test/md 2>/dev/null
test-sv: build
	@mkdir -p build/test &&  cc -I./include/ -L./build/bin/ -L/usr/local/lib64 -o build/test/signature test/signature.c -ljssl -lcrypto && \
	LD_LIBRARY_PATH=./build/bin ./build/test/signature 2>/dev/null
test-kdf: build
	@mkdir -p build/test &&  cc -I./include/ -L./build/bin/ -L/usr/local/lib64 -o build/test/kdf test/kdf.c -ljssl && \
	LD_LIBRARY_PATH=./build/bin ./build/test/kdf 2>/dev/null
clean:
	@rm -rf build
