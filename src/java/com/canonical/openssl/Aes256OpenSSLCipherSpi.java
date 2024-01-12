public class Aes256OpenSSLCipherSpi extends OpenSSLCipherSpi {

    public Aes256OpenSSLCipherSpi(String mode, String padding) {
        super("AES-256", mode, padding);
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
