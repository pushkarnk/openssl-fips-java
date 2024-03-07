import java.nio.ByteBuffer;
import java.security.DigestException;
import java.security.MessageDigestSpi;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Set;

public class OpenSSLMDSpi extends MessageDigestSpi {

    static {
        System.loadLibrary("jssl");
    }

    private String mdName;
    private long nativeHandle;

    private enum MDAlgorithms {
        SHA1     (Set.of("SHA", "SHA1", "SHA-1"), 20),
        SHA224   (Set.of("SHA224", "SHA-224", "SHA2-224"), 28),
        SHA256   (Set.of("SHA256", "SHA-256", "SHA2-256"), 32),
        SHA384   (Set.of("SHA384", "SHA-384", "SHA2-384"), 48),
        SHA512   (Set.of("SHA512", "SHA-512", "SHA2-512"), 64),
        SHA3_224 (Set.of("SHA3-224"), 28),
        SHA3_256 (Set.of("SHA3-256"), 32),
        SHA3_384 (Set.of("SHA3-384"), 48),
        SHA3_512 (Set.of("SHA3-512"), 64),
        KECCAK_KEMAK_128 (Set.of("KECCAK-KEMAK-128", "KECCAK-KEMAK128"), 16),
        KECCAK_KEMAK_256 (Set.of("KECCAK-KEMAK-256", "KECCAK-KEMAK256"), 32);

        final Set<String> names;
        final int hashSize;

        MDAlgorithms (Set<String> names, int hashSize) {
            this.names = names;
            this.hashSize = hashSize;
        }

        Set<String> getNames() {
            return this.names;
        } 

        int getHashSize() {
            return hashSize;
        }
    }

    private boolean initialized = false;

    OpenSSLMDSpi(String algorithm) throws NoSuchAlgorithmException {
        boolean found = false;
        for (var algo : MDAlgorithms.values()) {
            if (algo.getNames().contains(algorithm)) {
                found = true;
            }
        }

        if (!found) {
            throw new NoSuchAlgorithmException(algorithm);
        }

        this.mdName = algorithm;
    }

    @Override
    protected byte[] engineDigest() {
       return doFinal0();
    }

    @Override
    protected int engineDigest(byte[] buf, int offset, int len) throws DigestException {
        byte[] digest = engineDigest();
        if (len < digest.length) {
            throw new DigestException("Digest length = " + digest.length  + " is greater than len = " + len);
        }
        System.arraycopy(digest, 0, buf, offset, len);
        return len;
    }

    @Override
    protected int engineGetDigestLength() {
        for (var algo : MDAlgorithms.values()) {
            if (algo.getNames().contains(mdName)) {
                return algo.getHashSize();
            }
        }
        // we should never come here
        System.out.println("[WARNING] Algo not supported");
        return 0;
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
    protected void engineUpdate(byte []input, int offset, int len) {
        engineUpdate(Arrays.copyOfRange(input, offset, len));
    }

    @Override
    protected void engineUpdate(ByteBuffer data) {
        engineUpdate(data.array());
    }

    private void engineUpdate(byte[] data) {
        synchronized(this) {
           if (!this.initialized) {
               nativeHandle = doInit0(mdName);
               this.initialized = true;
           }
        }
        doUpdate0(data);
    }

    private native long doInit0(String name);
    private native void doUpdate0(byte[] data);
    private native byte[] doFinal0();
}
