class OpenSSLHMACSHA3512Spi extends OpenSSLMACSpi {
    protected String getAlgorithm() {
        return "HMAC";
    }

    protected String getCipherType() {
        return null; 
    }

    protected String getDigestType() {
        return "SHA3-512";
    }

    protected byte[] getIV() {
        return null;
    }
}

