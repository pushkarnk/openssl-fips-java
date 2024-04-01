package com.canonical.openssl.cipher;

public abstract class CipherAes extends OpenSSLCipher {

    protected CipherAes(String nameKeySizeMode, String padding) {
        super(nameKeySizeMode, padding);
    }

    public String getCipherName() {
        return "AES";
    }

    public abstract int getKeySize();

    public abstract String getMode();

    public abstract String getPadding();

    @Override 
    protected int engineGetBlockSize() {
        return 16;
    }

    @Override
    protected int engineGetOutputSize(int inputSize) {
        return inputSize;
    }
}
