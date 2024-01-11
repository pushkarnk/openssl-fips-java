package com.canonical.openssl;

import java.security.SecureRandomParameters;

public class HashDrbg extends OpenSSLDrbg {
    public HashDrbg() {
        super("HASH-DRBG");
    }

    public HashDrbg(SecureRandomParameters params) {
        super("HASH-DRBG", params);
    }

    @Override
    public String toString() {
        return "HASH-DRBG[digest: sha512]";
    }
}

