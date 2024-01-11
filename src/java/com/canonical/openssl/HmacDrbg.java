package com.canonical.openssl;

import java.security.SecureRandomParameters;

public class HmacDrbg extends OpenSSLDrbg {
    public HmacDrbg() {
        super("HMAC-DRBG");
    }

    public HmacDrbg(SecureRandomParameters params) {
        super("HMAC-DRBG", params);
    }

    @Override
    public String toString() {
        return "HMAC-DRBG [mac: HMAC, digest: sha256]";
    }
}

