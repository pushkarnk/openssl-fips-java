package com.canonical.openssl.drbg;

import java.security.SecureRandomParameters;

final public class DrbgHMACSHA256 extends OpenSSLDrbg {
    public DrbgHMACSHA256() {
        super("HMAC-DRBG");
    }

    @Override
    public String toString() {
        return "HMAC-DRBG-with-SHA256";
    }
}

