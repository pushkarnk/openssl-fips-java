package com.canonical.openssl.cipher;

final public class AES__KS__with__MODE__padding__PADC__ extends CipherAes {

    public AES__KS__with__MODE__padding__PADC__() {
        super("AES-__KS__-__MODE__", "__PAD__");
    }

    @Override
    public int getKeySize() {
        return __KS__;
    }

    @Override
    public String getMode() {
        return "__MODE__";
    }

    @Override
    public String getPadding() {
        return "__PAD__";
    }
}

 
    
