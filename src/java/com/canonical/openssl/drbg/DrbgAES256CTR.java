package com.canonical.openssl.drbg;

import java.security.SecureRandomParameters;

final public class DrbgAES256CTR extends OpenSSLDrbg {
    public DrbgAES256CTR() {
        super("CTR-DRBG");
    }

    public DrbgAES256CTR(SecureRandomParameters params) {
        super("CTR-DRBG", params);
    }

    @Override
    public String toString() {
        return "CTR-DRBG-with-AES-256";
    }
}
