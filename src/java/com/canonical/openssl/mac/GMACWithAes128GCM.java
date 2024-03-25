package com.canonical.openssl.mac;

public final class GMACWithAes128GCM extends OpenSSLMAC {
    protected String getAlgorithm() {
        return "GMAC";
    }

    protected String getCipherType() {
        return "AES-128-GCM";
    }

    protected String getDigestType() {
        return null;
    }

    // TODO: a random IV?
    protected byte[] getIV() {
        return new byte[] { (byte)0xe0, (byte)0xe0, (byte)0x0f, (byte)0x19,
                            (byte)0xfe, (byte)0xd7, (byte)0xba, (byte)0x01,
                            (byte)0x36, (byte)0xa7, (byte)0x97, (byte)0xf3 };
    }
}
