import javax.crypto.CipherSpi;
import javax.crypto.Cipher;
import java.security.Key;
import java.security.AlgorithmParameters;
import java.security.spec.AlgorithmParameterSpec;
import java.security.SecureRandom;
import javax.crypto.ShortBufferException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.BadPaddingException;

abstract public class OpenSSLCipherSpi extends CipherSpi {

    private static int UNDECIDED = -1;
    private static int DECRYPT = 0;
    private static int ENCRYPT = 1;

    // TODO: We need an AESParameters (AlgorithmParametersSpi) implemented
    // TODO: As well as an AESParameterSpec implementation
    String name;
    String mode;
    String padding;
    long cipherContext;
    byte []keyBytes;
    byte []iv;
    int inputSize;
    int outputSize;
    int opmode = UNDECIDED;
    boolean firstUpdate = true;
 
    OpenSSLCipherSpi(String name, String mode, String padding) {
        this.inputSize = 0;
        this.outputSize = 0;
        this.name = name;
        this.mode = mode;
        this.padding = padding;
        this.cipherContext = createContext0(name + "-" + mode, padding);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random) {
        System.err.println("AlgorithmParameters will be ignored by the prototype");
        engineInit(opmode, key, random);
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) {
        if (opmode != Cipher.ENCRYPT_MODE && opmode != Cipher.DECRYPT_MODE) {
            throw new UnsupportedOperationException ("The prototype supports only symmetric-key encrypt/decrypt");
        }
        this.opmode = opmode == Cipher.ENCRYPT_MODE ? ENCRYPT : DECRYPT;
        this.keyBytes = key.getEncoded();
        this.iv = new byte[16];
        random.nextBytes(iv);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) {
        System.err.println("AlgorithmParameterSpec will be ignored by the prototype");
        engineInit(opmode, key, random);
    }

    @Override
    protected void engineSetMode(String mode) {
        this.mode = mode;
    }

    @Override
    protected void engineSetPadding(String padding) {
        this.padding = padding;
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        inputSize += inputLen;
        if (firstUpdate) {
            firstUpdate = false;
            return doInit0(input, inputOffset, inputLen, keyBytes, iv, opmode);
        } 
        byte[] ret = doUpdate0(input, inputOffset, inputLen);
        outputSize += ret.length;
        return ret;
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException {
        byte[] nativeOutput = engineUpdate(input, inputOffset, inputLen);
        if (nativeOutput.length > (output.length - outputOffset))
            throw new ShortBufferException(); 
        System.arraycopy(nativeOutput, 0, output, outputOffset, nativeOutput.length);
        return nativeOutput.length;
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        throw new UnsupportedOperationException("The prototype ignores AlgorithmParameters");
    }

    @Override
    protected byte[] engineGetIV() {
        return iv;
    }

    protected abstract int engineGetOutputSize(int inputLen);

    protected abstract int engineGetBlockSize();

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException, 
                                   IllegalBlockSizeException, BadPaddingException {
        byte[] nativeOutput = engineDoFinal(input, inputOffset, inputLen);
        if (nativeOutput.length > (output.length - outputOffset)) {
            throw new ShortBufferException();
        }
        System.arraycopy(nativeOutput, 0, output, outputOffset, nativeOutput.length);
        return nativeOutput.length;
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) throws IllegalBlockSizeException, BadPaddingException {
        inputSize += inputLen;
        if (inputSize % engineGetBlockSize() != 0) {
            throw new IllegalBlockSizeException();
        }

        byte[] ret = doUpdate0(input, inputOffset, inputLen);
        outputSize += ret.length;

        return doFinal0(ret, outputSize);  
    }

    native long createContext0(String nameAndMode, String padding);
    native byte[] doInit0(byte[] input, int offset, int length, byte[] key, byte[] iv, int opmode);
    native byte[] doUpdate0(byte[] input, int offset, int length);
    native byte[] doFinal0(byte[] output, int length);
}
