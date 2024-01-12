public class Aes128OpenSSLCipherSpi extends OpenSSLCipherSpi {

    public Aes128OpenSSLCipherSpi(String mode, String padding) {
        super("AES-128", mode, padding);
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
