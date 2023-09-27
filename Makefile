build:
	@mkdir -p build/bin && cc -I/usr/local/include/openssl/ -I./include -c -fPIC src/drbg.c -o build/bin/drbg.o && \
	cc -I/usr/local/include/openssl/ -I./include -c -fPIC src/init.c -o build/bin/init.o && \
        cc -I/usr/local/include/openssl/ -I./include -c -fPIC src/cipher.c -o build/bin/cipher.o && \
        cc -I/usr/local/include/openssl/ -I./include -c -fPIC src/keyagreement.c -o build/bin/keyagreement.o && \
	cc -shared -fPIC -Wl,-soname,libjssl.so -o build/bin/libjssl.so \
		build/bin/init.o   \
		build/bin/drbg.o   \
		build/bin/cipher.o \
                build/bin/keyagreement.o \
		-L/usr/local/lib64 -lcrypto -lssl

test-drbg: build
	@mkdir -p build/test &&  cc -I./include/ -L./build/bin/  -o build/test/drbg_test test/drbg_test.c -ljssl && \
	build/test/drbg_test 2>/dev/null

test-cipher: build
	@mkdir -p build/test &&  cc -I./include/ -L./build/bin/  -o build/test/cipher_test test/cipher_test.c -ljssl && \
        build/test/cipher_test 2>/dev/null

test-ka: build
	@mkdir -p build/test &&  cc -I./include/ -L./build/bin/  -o build/test/keyagreement test/keyagreement.c -ljssl && \
	build/test/keyagreement 2>/dev/null
clean:
	@rm -rf build
