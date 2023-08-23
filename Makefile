build:
	@mkdir -p build/bin && cc -I/usr/local/include/openssl/ -I./include -c -fPIC src/drbg.c -o build/bin/drbg.o && \
	cc -I/usr/local/include/openssl/ -I./include -c -fPIC src/init.c -o build/bin/init.o && \
	cc -shared -fPIC -Wl,-soname,libjssl.so -o build/bin/libjssl.so build/bin/init.o build/bin/drbg.o -L/usr/local/lib64 -lcrypto -lssl

test:	build
	@mkdir -p build/test &&  cc -I./include/ -L./build/bin/  -o build/test/drbg_test test/drbg_test.c -ljssl && \
	build/test/drbg_test 2>/dev/null

clean:
	@rm -rf build
