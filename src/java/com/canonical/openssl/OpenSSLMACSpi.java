import java.nio.ByteBuffer;
import java.security.Key;
import java.util.Arrays;
import javax.crypto.MacSpi;
import java.security.spec.AlgorithmParameterSpec;
import javax.xml.crypto.dsig.spec.HMACParameterSpec;

public abstract class OpenSSLMACSpi extends MacSpi {

    static {
        System.loadLibrary("jssl");
    }

    long nativeHandle;
    String cipherType;
    String digestType;
    byte[] initVector;

    protected abstract String getAlgorithm();
    protected abstract String getCipherType();
    protected abstract String getDigestType();
    protected abstract byte[] getIV();

    @Override
    protected byte[] engineDoFinal() {
        return doFinal0();
    }

    @Override
    protected int engineGetMacLength() {
        return getMacLength();
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec spec) {
        var outputLength = -1;
        if (spec != null && isHMAC(this) && spec instanceof HMACParameterSpec hmacSpec) {
            outputLength = hmacSpec.getOutputLength();
        }
        nativeHandle = doInit0(getAlgorithm(), getCipherType(), getDigestType(), getIV(), outputLength, key.getEncoded());
    }

    @Override
    protected void engineReset() {
        // TODO
    }

    @Override
    protected void engineUpdate(byte input) {
        engineUpdate(new byte[] { input });
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int length) {
        engineUpdate(Arrays.copyOfRange(input, offset, length));
    }

    @Override
    protected void engineUpdate(ByteBuffer buffer) {
        engineUpdate(buffer.array());
    }

    private void engineUpdate(byte[] input) {
        doUpdate0(input);
    }

    private boolean isHMAC(OpenSSLMACSpi object) {
        return object instanceof OpenSSLHMACSHA1Spi
            || object instanceof OpenSSLHMACSHA3512Spi; 
    }

    native long doInit0(String algo, String cipher, String digest, byte[] iv, int outLen, byte[] key);
    native int getMacLength();
    native void doUpdate0(byte[] input);
    native byte[] doFinal0();
    
}
