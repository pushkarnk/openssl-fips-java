package com.canonical.openssl.drbg;

import java.security.SecureRandomParameters;

final public class DrbgHashSHA512 extends OpenSSLDrbg {
    public DrbgHashSHA512() {
        super("HASH-DRBG");
    }

    public DrbgHashSHA512(SecureRandomParameters params) {
        super("HASH-DRBG", params);
    }

    @Override
    public String toString() {
        return "HASH-DRBG-with-SHA512";
    }
}

