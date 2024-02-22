import javax.crypto.DecapsulateException;
import javax.crypto.KEM;
import javax.crypto.KEM.Encapsulated;
import javax.crypto.KEMSpi;
import javax.crypto.KEMSpi.EncapsulatorSpi;
import javax.crypto.KEMSpi.DecapsulatorSpi;
import javax.crypto.SecretKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import javax.crypto.spec.SecretKeySpec;

public class OpenSSLKEMRSA implements KEMSpi {

    static {
        System.loadLibrary("jssl");
    }

    public EncapsulatorSpi engineNewEncapsulator(PublicKey publicKey,
            AlgorithmParameterSpec spec, SecureRandom secureRandom)
                    throws InvalidAlgorithmParameterException, InvalidKeyException {
        // TODO: spec, secureRandom are ignored, we could use RSAKeyGenParameterSpec
        if (publicKey instanceof RSAPublicKey rsaPublicKey)
            return new RSAKEMEncapsulator(rsaPublicKey);
        else
            throw new InvalidKeyException("Public key is not an RSAPublicKey");
    }

    public DecapsulatorSpi engineNewDecapsulator(PrivateKey privateKey, AlgorithmParameterSpec spec)
            throws InvalidAlgorithmParameterException, InvalidKeyException {
        // TODO: spec, secureRandom are ignored, we could use RSAKeyGenParameterSpec
        if (privateKey instanceof RSAPrivateKey rsaPrivateKey)
            return new RSAKEMDecapsulator(rsaPrivateKey);
        else
            throw new InvalidKeyException("Private key is not an RSAPrivateKey"); 
    }

    class RSAKEMEncapsulator implements KEMSpi.EncapsulatorSpi {
        long nativeHandle = 0;
        public RSAKEMEncapsulator(PublicKey key) {
            nativeHandle = encapsulatorInit0(key.getEncoded());
            
        }

        public KEM.Encapsulated engineEncapsulate(int from, int to, String algorithm) {
            // TODO: ignoring from, to in the prototype
            int secretSize = engineSecretSize();
            byte[] secretBytes = new byte[secretSize];

            int encapsulationSize = engineEncapsulationSize();
            byte[] encapsulatedBytes = new byte[encapsulationSize];

            engineEncapsulate0(secretBytes, encapsulatedBytes);
            SecretKey secretKey = new SecretKeySpec(secretBytes, algorithm);
            return new KEM.Encapsulated(secretKey, encapsulatedBytes, null);
        }

        public int engineSecretSize() {
            return engineSecretSize0(); 
        }

        public int engineEncapsulationSize() {
            return engineEncapsulationSize0();
        }

        private native long encapsulatorInit0(byte[] publicKeyBytes);
        private native void engineEncapsulate0(byte[] secretBytes, byte[] encapsulatedBytes);
        private native int engineSecretSize0();
        private native int engineEncapsulationSize0();
    }

    class RSAKEMDecapsulator implements KEMSpi.DecapsulatorSpi {
        long nativeHandle = 0;

        public RSAKEMDecapsulator(PrivateKey key) {
            nativeHandle = decapsulatorInit0(key.getEncoded());
        }

        public SecretKey engineDecapsulate(byte[] encapsulation, int from, int to, String algorithm)
                throws DecapsulateException {
            byte[] secretBytes = engineDecapsulate0(encapsulation);
            return new SecretKeySpec(secretBytes, algorithm);
        }

        public int engineSecretSize() {
            return engineSecretSize0();
        }

        public int engineEncapsulationSize() {
            return engineEncapsulationSize0();
        }

        private native long decapsulatorInit0(byte[] key);
        private native byte[] engineDecapsulate0(byte[] encapsulateArray);
        private native int engineSecretSize0();
        private native int engineEncapsulationSize0();

    }
}
