public class Aes192OpenSSLCipherSpi extends OpenSSLCipherSpi {

    public Aes192OpenSSLCipherSpi(String mode, String padding) {
        super("AES-192", mode, padding);
    }

    @Override
    protected int engineGetBlockSize() {
        return 16;
    }

    @Override
    protected int engineGetOutputSize(int inputSize) {
        return inputSize;
    }
}
