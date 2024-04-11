package com.canonical.openssl.drbg;

import java.security.SecureRandomParameters;

final public class DrbgHMACSHA256 extends OpenSSLDrbg {
    public DrbgHMACSHA256() {
        super("HMAC-DRBG");
    }

    public DrbgHMACSHA256(SecureRandomParameters params) {
        super("HMAC-DRBG", params);
    }

    @Override
    public String toString() {
        return "HMAC-DRBG-with-SHA256";
    }
}

