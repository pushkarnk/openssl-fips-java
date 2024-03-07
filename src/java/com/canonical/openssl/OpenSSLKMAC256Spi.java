class OpenSSLKMAC256Spi extends OpenSSLMACSpi {
    protected String getAlgorithm() {
        return "KMAC-256";
    }

    protected String getCipherType() {
        return null;
    }

    protected String getDigestType() {
        return null;
    }

    protected byte[] getIV() {
        return null;
    }
}

