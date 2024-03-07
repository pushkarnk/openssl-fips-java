class OpenSSLCMACAesSpi extends OpenSSLMACSpi {
    protected String getAlgorithm() {
        return "CMAC";
    } 

    protected String getCipherType() {
        return "AES-256-CBC";
    }

    protected String getDigestType() {
        return null;
    }

    protected byte[] getIV() {
        return null;
    }
}
