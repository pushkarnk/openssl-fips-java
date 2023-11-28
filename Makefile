build:
	@mkdir -p build/bin && cc -I/usr/local/include/openssl/ -I./include -c -fPIC src/drbg.c -o build/bin/drbg.o && \
	cc -I/usr/local/include/openssl/ -I./include -c -fPIC src/init.c -o build/bin/init.o && \
        cc -I/usr/local/include/openssl/ -I./include -c -fPIC src/cipher.c -o build/bin/cipher.o && \
        cc -I/usr/local/include/openssl/ -I./include -c -fPIC src/keyagreement.c -o build/bin/keyagreement.o && \
        cc -I/usr/local/include/openssl/ -I./include -c -fPIC src/keyencapsulation.c -o build/bin/keyencapsulation.o && \
        cc -I/usr/local/include/openssl/ -I./include -c -fPIC src/mac.c -o build/bin/mac.o && \
	cc -shared -fPIC -Wl,-soname,libjssl.so -o build/bin/libjssl.so \
		build/bin/init.o   \
		build/bin/drbg.o   \
		build/bin/cipher.o \
                build/bin/keyagreement.o \
                build/bin/keyencapsulation.o \
                build/bin/mac.o \
		-L/usr/local/lib64 -lcrypto -lssl

test-drbg: build
	@mkdir -p build/test &&  cc -I./include/ -L./build/bin/  -o build/test/drbg_test test/drbg_test.c -ljssl && \
	build/test/drbg_test 2>/dev/null

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
clean:
	@rm -rf build
