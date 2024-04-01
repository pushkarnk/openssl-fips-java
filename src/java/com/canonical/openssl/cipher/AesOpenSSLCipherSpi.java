public class AesOpenSSLCipherSpi extends OpenSSLCipherSpi {

    public AesOpenSSLCipherSpi(String nameKeySizeMode, String padding) {
        super(nameKeySizeMode, padding);
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
