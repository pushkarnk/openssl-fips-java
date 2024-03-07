class OpenSSLHMACSHA1Spi extends OpenSSLMACSpi {
    protected String getAlgorithm() {
        return "HMAC";
    }

    protected String getCipherType() {
        return null;
    }

    protected String getDigestType() {
        return "SHA1";
    }

    protected byte[] getIV() {
        return null; 
    }
}

