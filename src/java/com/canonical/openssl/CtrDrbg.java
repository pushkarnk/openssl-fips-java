package com.canonical.openssl;

import java.security.SecureRandomParameters;

public class CtrDrbg extends OpenSSLDrbg {
    public CtrDrbg() {
        super("CTR-DRBG");
    }

    public CtrDrbg(SecureRandomParameters params) {
        super("CTR-DRBG", params);
    }

    @Override
    public String toString() {
        return "CTR-DRBG[cipher: aes-256-ctr]";
    }
}
