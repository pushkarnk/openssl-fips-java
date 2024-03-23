import com.canonical.openssl.drbg.OpenSSLDrbg;
import java.util.Arrays;
import java.security.*;
import java.security.DrbgParameters;
import java.security.DrbgParameters.Instantiation;
import java.security.DrbgParameters.Capability;
import java.lang.Long;

class TestOpenSSLDrbg extends OpenSSLDrbg {

    public TestOpenSSLDrbg(String name) {
        super(name);
    }

    public TestOpenSSLDrbg(String name, SecureRandomParameters params) {
        super(name, params);
    }

    @Override
    public byte[] engineGenerateSeed(int numBytes) {
        return super.engineGenerateSeed(numBytes);
    }

    @Override
    public SecureRandomParameters engineGetParameters() {
        return super.engineGetParameters();
    }

    @Override
    public void engineNextBytes(byte[] bytes) {
        super.engineNextBytes(bytes);
    }

    @Override
    protected void engineNextBytes(byte[] bytes, SecureRandomParameters params) throws IllegalArgumentException {
        super.engineNextBytes(bytes, params);
    }

    @Override
    protected void engineReseed() {
        super.engineReseed();
    }

    @Override
    public void engineReseed(SecureRandomParameters params) {
        super.engineReseed(params);
    }

    @Override
    public void engineSetSeed(byte[] seed) {
        super.engineSetSeed(seed);
    }

    @Override
    public void engineSetSeed(long seed) {
        super.engineSetSeed(seed);
    }
}

class CtrDrbg extends TestOpenSSLDrbg {
    public CtrDrbg() {
        super("CTR-DRBG");
    }

    public CtrDrbg(SecureRandomParameters params) {
        super("CTR-DRBG", params);
    }
}

class HashDrbg extends TestOpenSSLDrbg {
    public HashDrbg() {
        super("HASH-DRBG");
    }

    public HashDrbg(SecureRandomParameters params) {
        super("HASH-DRBG", params);
    }
}

class HmacDrbg extends TestOpenSSLDrbg {
    public HmacDrbg() {
        super("HMAC-DRBG");
    }

    public HmacDrbg(SecureRandomParameters params) {
        super("HMAC-DRBG", params);
    }
}

/*
 * TODO: params have an impact on the random number generation, openssl crashes at times.
 * It is essential to understand this impact in totality to maintain a good DRBG API
 */ 
public class DrbgTest {
    private static void  _IN(String s)  { System.out.print(s + ": "); }
    private static void _OUT(String s)  { System.out.println(s); }


    private static boolean checkRandomness(byte [] array1, byte [] array2) {
        boolean allZeros1 = true, allZeros2 = true; 
        int numZeros1 = 0, numZeros2 = 0;
        int matchingBytes = 0;
        int size = array1.length;

        for (int i = 0; i < array1.length; i++) {
            if (array1[i] != 0) {
                allZeros1 = false;
            } else {
                numZeros1++;
            }

            if (array2[i] != 0) {
                allZeros2 = false;
            } else {
                numZeros2++;
            }

            if (array1[i] == array2[i]) {
                matchingBytes += 1;
            }
        }

        boolean tooManyZeros = (numZeros1 > 2 && numZeros1 > size % 32) || (numZeros2 > 2 && numZeros2 > size % 32);
        double matchPercentage = ((double)matchingBytes/size) * 100;
        if (tooManyZeros) {
            System.out.print("[too many zeros (" + numZeros1 + ", " + numZeros2 + ")]");
        }
        if (allZeros1 || allZeros2) {
            System.out.print("[allZeros]");
        }
        if (matchingBytes > 2 || matchPercentage > 10.0) {
            System.out.print("[number of matches = " + matchingBytes + "]");
        }
        return (!tooManyZeros) && (!allZeros1) && (!allZeros2) && (matchingBytes < 2  && matchPercentage <= 10.0);
    }

    private static void testDRBGCreation() {
        _IN("Test DRBG creation");
        TestOpenSSLDrbg ctr = new CtrDrbg();
        TestOpenSSLDrbg hmac = new HmacDrbg();
        TestOpenSSLDrbg hash = new HashDrbg();
        if (ctr.engineGenerateSeed(8).length == 8 &&
            hmac.engineGenerateSeed(8).length == 8 &&
            hash.engineGenerateSeed(8).length == 8) {
            _OUT("Passed");
        } else {
            _OUT("Failed");
        }
    }

    private static void testDRBGCreationWithParams() {
        _IN("Test DRBG creation with parameters");
        SecureRandomParameters params = DrbgParameters.instantiation(144, Capability.PR_AND_RESEED, "FIPSPROTOTYPE".getBytes()); 
        TestOpenSSLDrbg ctr = new CtrDrbg(params);
        TestOpenSSLDrbg hmac = new HmacDrbg(params);
        TestOpenSSLDrbg hash = new HashDrbg(params);
        if (ctr.engineGenerateSeed(8).length == 8 &&
            hmac.engineGenerateSeed(8).length == 8 &&
            hash.engineGenerateSeed(8).length == 8) {
            _OUT("Passed");
        } else {
            _OUT("Failed");
        }
    }

    private static void testDRBGCreationGenerateSeed() {
        _IN("Test DRBG creation and seed generation");
        TestOpenSSLDrbg ctr = new CtrDrbg();
        TestOpenSSLDrbg hmac = new HmacDrbg();
        TestOpenSSLDrbg hash = new HashDrbg();
        if (checkRandomness(ctr.engineGenerateSeed(8), ctr.engineGenerateSeed(8)) &&
            checkRandomness(hmac.engineGenerateSeed(16), hmac.engineGenerateSeed(16)) && 
            checkRandomness(hash.engineGenerateSeed(32), hash.engineGenerateSeed(32))) {
            _OUT("Passed");
        } else {
            _OUT("Failed");
        }
    }

    private static void testDRBGCreationWithParamsGenerateSeed() {
        _IN("Test DRBG creation with parameters and seed generation");
        SecureRandomParameters params = DrbgParameters.instantiation(144, Capability.PR_AND_RESEED, "FIPSPROTOTYPE".getBytes());
        TestOpenSSLDrbg ctr = new CtrDrbg(params);
        TestOpenSSLDrbg hmac = new HmacDrbg(params);
        TestOpenSSLDrbg hash = new HashDrbg(params);
        if (checkRandomness(ctr.engineGenerateSeed(8), ctr.engineGenerateSeed(8)) &&
            checkRandomness(hmac.engineGenerateSeed(16), hmac.engineGenerateSeed(16)) &&
            checkRandomness(hash.engineGenerateSeed(32), hash.engineGenerateSeed(32))) {
            _OUT("Passed");
        } else {
            _OUT("Failed");
        }
    }

    private static void testDRBGCreationNextBytes() {
        _IN("Test DRBG creation and next bytes");
        
        TestOpenSSLDrbg ctr = new CtrDrbg();
        TestOpenSSLDrbg hmac = new HmacDrbg();
        TestOpenSSLDrbg hash = new HashDrbg();

        byte [] ctr1 = new byte[32];
        byte [] ctr2 = new byte[32];
        ctr.engineNextBytes(ctr1);
        ctr.engineNextBytes(ctr2);

        byte [] hmac1 = new byte[64];
        byte [] hmac2 = new byte[64];
        hmac.engineNextBytes(hmac1);
        hmac.engineNextBytes(hmac2);

        byte [] hash1 = new byte[64];
        byte [] hash2 = new byte[64];
        hash.engineNextBytes(hash1);
        hash.engineNextBytes(hash2);
 
        if(checkRandomness(ctr1, ctr2)
           && checkRandomness(hmac1, hmac2)
           && checkRandomness(hash1, hash2)) {
            _OUT("Passed");
        } else {
            _OUT("Failed");
        }
    }

    private static void testDRBGCreationWithParamsNextBytes() {
        _IN("Test DRBG creation with params and next bytes");
        SecureRandomParameters params = DrbgParameters.instantiation(256, Capability.PR_AND_RESEED, "FIPSPROTOTYPE".getBytes());
        TestOpenSSLDrbg ctr = new CtrDrbg(params);
        TestOpenSSLDrbg hmac = new HmacDrbg(params);
        TestOpenSSLDrbg hash = new HashDrbg(params);

        // TODO: size > 92 fails at openssl level, sometimes malloc() fails
        byte [] ctr1 = new byte[32];
        byte [] ctr2 = new byte[32];
        ctr.engineNextBytes(ctr1);
        ctr.engineNextBytes(ctr2);

        byte [] hmac1 = new byte[64];
        byte [] hmac2 = new byte[64];
        hmac.engineNextBytes(hmac1);
        hmac.engineNextBytes(hmac2);

        byte [] hash1 = new byte[84];
        byte [] hash2 = new byte[84];
        hash.engineNextBytes(hash1);
        hash.engineNextBytes(hash2);
    
        if(checkRandomness(ctr1, ctr2)
           && checkRandomness(hmac1, hmac2)
           && checkRandomness(hash1, hash2)) {
            _OUT("Passed"); 
        } else {
            _OUT("Failed"); 
        }
    }

    private static void testDRBGCreationNextBytesWithParams() {
       _IN("Test DRBG creation and next bytes with params");
        SecureRandomParameters nbParams = DrbgParameters.nextBytes(256, false, "123456".getBytes());
        TestOpenSSLDrbg ctr = new CtrDrbg();
        TestOpenSSLDrbg hmac = new HmacDrbg();
        TestOpenSSLDrbg hash = new HashDrbg();

        // TODO: memory corruption for next byte array sizes >= 32
        byte [] ctr1 = new byte[8];
        byte [] ctr2 = new byte[8];
        ctr.engineNextBytes(ctr1, nbParams);
        ctr.engineNextBytes(ctr2, nbParams);

        byte [] hmac1 = new byte[16];
        byte [] hmac2 = new byte[16];
        hmac.engineNextBytes(hmac1, nbParams);
        hmac.engineNextBytes(hmac2, nbParams);

        byte [] hash1 = new byte[32];
        byte [] hash2 = new byte[32];
        hash.engineNextBytes(hash1, nbParams);
        hash.engineNextBytes(hash2, nbParams);

        if(checkRandomness(ctr1, ctr2)
           && checkRandomness(hmac1, hmac2)
           && checkRandomness(hash1, hash2)) {
            _OUT("Passed");
        } else {
            _OUT("Failed");
        }
    }

    private static void testDRBGCreationWithParamsNextBytesWithParams() {
        _IN("Test DRBG creation with params, next bytes with params");
        SecureRandomParameters params = DrbgParameters.instantiation(128, Capability.PR_AND_RESEED, "FIPSPROTOTYPE".getBytes());
        SecureRandomParameters nbParams = DrbgParameters.nextBytes(128, true, "ADDITIONALINPUT".getBytes());
        TestOpenSSLDrbg ctr = new CtrDrbg(params);
        TestOpenSSLDrbg hmac = new HmacDrbg(params);
        TestOpenSSLDrbg hash = new HashDrbg(params);

        byte [] ctr1 = new byte[32];
        byte [] ctr2 = new byte[32];
        ctr.engineNextBytes(ctr1, nbParams);
        ctr.engineNextBytes(ctr2, nbParams);

        byte [] hmac1 = new byte[32];
        byte [] hmac2 = new byte[32];
        hmac.engineNextBytes(hmac1, nbParams);
        hmac.engineNextBytes(hmac2, nbParams);

        byte [] hash1 = new byte[32];
        byte [] hash2 = new byte[32];
        hash.engineNextBytes(hash1, nbParams);
        hash.engineNextBytes(hash2, nbParams);

        if(checkRandomness(ctr1, ctr2)
           && checkRandomness(hmac1, hmac2)
           && checkRandomness(hash1, hash2)) {
            _OUT("Passed");
        } else {
            _OUT("Failed");
        }
    }

    private static void testDRBGCreationReseed() {
        _IN("Test DRBG creation and engineReseed");
        TestOpenSSLDrbg ctr = new CtrDrbg();
        TestOpenSSLDrbg hmac = new HmacDrbg();
        TestOpenSSLDrbg hash = new HashDrbg();

        byte [] ctr1 = new byte[16];
        byte [] ctr2 = new byte[32];
        ctr.engineNextBytes(ctr1);
        ctr.engineReseed();
        ctr.engineNextBytes(ctr2);

        byte [] hmac1 = new byte[16];
        byte [] hmac2 = new byte[16];
        hmac.engineNextBytes(hmac1);
        hmac.engineReseed();
        hmac.engineNextBytes(hmac2);

        byte [] hash1 = new byte[16];
        byte [] hash2 = new byte[16];
        hash.engineNextBytes(hash1);
        hash.engineReseed();
        hash.engineNextBytes(hash2);

        if(checkRandomness(ctr1, ctr2)
           && checkRandomness(hmac1, hmac2)
           && checkRandomness(hash1, hash2)) {
            _OUT("Passed");
        } else {
            _OUT("Failed");
        }
    }

    private static void testDRBGCreationWithParamsReseed() {
        _IN("Test DRBG creation with params and engineReseed");
        SecureRandomParameters params = DrbgParameters.instantiation(128, Capability.PR_AND_RESEED, "FIPSPROTOTYPE".getBytes());
        TestOpenSSLDrbg ctr = new CtrDrbg(params);
        TestOpenSSLDrbg hmac = new HmacDrbg(params);
        TestOpenSSLDrbg hash = new HashDrbg(params);

        byte [] ctr1 = new byte[16];
        byte [] ctr2 = new byte[16];
        ctr.engineNextBytes(ctr1);
        ctr.engineReseed();
        ctr.engineNextBytes(ctr2);

        byte [] hmac1 = new byte[16];
        byte [] hmac2 = new byte[16];
        hmac.engineNextBytes(hmac1);
        hmac.engineReseed();
        hmac.engineNextBytes(hmac2);

        byte [] hash1 = new byte[16];
        byte [] hash2 = new byte[16];
        hash.engineNextBytes(hash1);
        hash.engineReseed();
        hash.engineNextBytes(hash2);

        if(checkRandomness(ctr1, ctr2)
           && checkRandomness(hmac1, hmac2)
           && checkRandomness(hash1, hash2)) {
            _OUT("Passed");
        } else {
            _OUT("Failed");
        }
    }

    private static void testDRBGCreationReseedWithParams() {
        _IN("Test DRBG creation and engineReseed with params");
        TestOpenSSLDrbg ctr = new CtrDrbg();
        TestOpenSSLDrbg hmac = new HmacDrbg();
        TestOpenSSLDrbg hash = new HashDrbg();

        SecureRandomParameters rs = DrbgParameters.reseed(true, "ADDITIONALINPUT".getBytes());
        byte [] ctr1 = new byte[16];
        byte [] ctr2 = new byte[16];
        ctr.engineNextBytes(ctr1);
        ctr.engineReseed(rs);
        ctr.engineNextBytes(ctr2);

        byte [] hmac1 = new byte[16];
        byte [] hmac2 = new byte[16];
        hmac.engineNextBytes(hmac1);
        hmac.engineReseed(rs);
        hmac.engineNextBytes(hmac2);

        byte [] hash1 = new byte[16];
        byte [] hash2 = new byte[16];
        hash.engineNextBytes(hash1);
        hash.engineReseed(rs);
        hash.engineNextBytes(hash2);

        if(checkRandomness(ctr1, ctr2)
           && checkRandomness(hmac1, hmac2)
           && checkRandomness(hash1, hash2)) {
            _OUT("Passed");
        } else {
            _OUT("Failed");
        }
    }

    private static void testDRBGCreationWithParamsReseedWithParams() {
        _IN("Test DRBG creation with params, engineReseed with params");
        SecureRandomParameters params = DrbgParameters.instantiation(128, Capability.PR_AND_RESEED, "FIPSPROTOTYPE".getBytes());
        TestOpenSSLDrbg ctr = new CtrDrbg(params);
        TestOpenSSLDrbg hmac = new HmacDrbg(params);
        TestOpenSSLDrbg hash = new HashDrbg(params);

        SecureRandomParameters rs = DrbgParameters.reseed(true, "ADDITIONALINPUT".getBytes());
        byte [] ctr1 = new byte[16];
        byte [] ctr2 = new byte[16];
        ctr.engineNextBytes(ctr1);
        ctr.engineReseed(rs);
        ctr.engineNextBytes(ctr2);

        byte [] hmac1 = new byte[16];
        byte [] hmac2 = new byte[16];
        hmac.engineNextBytes(hmac1);
        hmac.engineReseed(rs);
        hmac.engineNextBytes(hmac2);

        byte [] hash1 = new byte[16];
        byte [] hash2 = new byte[16];
        hash.engineNextBytes(hash1);
        hash.engineReseed(rs);
        hash.engineNextBytes(hash2);

        if(checkRandomness(ctr1, ctr2)
           && checkRandomness(hmac1, hmac2)
           && checkRandomness(hash1, hash2)) {
            _OUT("Passed");
        } else {
            _OUT("Failed");
        }
    }

    private static void testDRBGCreationSetSeedBytes() {
        _IN("Test DRBG creation with params and engineReseed with bytes");
        SecureRandomParameters params = DrbgParameters.instantiation(128, Capability.PR_AND_RESEED, "FIPSPROTOTYPE".getBytes());
        TestOpenSSLDrbg ctr = new CtrDrbg();
        TestOpenSSLDrbg hmac = new HmacDrbg();
        TestOpenSSLDrbg hash = new HashDrbg();

        byte [] ctr1 = new byte[16];
        byte [] ctr2 = new byte[16];
        ctr.engineNextBytes(ctr1);
        ctr.engineSetSeed("NEWBYTES".getBytes());
        ctr.engineNextBytes(ctr2);

        byte [] hmac1 = new byte[16];
        byte [] hmac2 = new byte[16];
        hmac.engineNextBytes(hmac1);
        hmac.engineSetSeed("NEWBYTES".getBytes());
        hmac.engineNextBytes(hmac2);

        byte [] hash1 = new byte[16];
        byte [] hash2 = new byte[16];
        hash.engineNextBytes(hash1);
        hash.engineSetSeed("NEWBYTES".getBytes());
        hash.engineNextBytes(hash2);

        if(checkRandomness(ctr1, ctr2)
           && checkRandomness(hmac1, hmac2)
           && checkRandomness(hash1, hash2)) {
            _OUT("Passed");
        } else {
            _OUT("Failed");
        }
    }

    private static void testDRBGCreationWithParamsSetSeedBytes() {
        _IN("Test DRBG creation with params and engineReseed with bytes");
        SecureRandomParameters params = DrbgParameters.instantiation(128, Capability.PR_AND_RESEED, "FIPSPROTOTYPE".getBytes());
        TestOpenSSLDrbg ctr = new CtrDrbg(params);
        TestOpenSSLDrbg hmac = new HmacDrbg(params);
        TestOpenSSLDrbg hash = new HashDrbg(params);

        byte [] ctr1 = new byte[16];
        byte [] ctr2 = new byte[16];
        ctr.engineNextBytes(ctr1);
        ctr.engineSetSeed("NEWBYTES".getBytes());
        ctr.engineNextBytes(ctr2);

        byte [] hmac1 = new byte[16];
        byte [] hmac2 = new byte[16];
        hmac.engineNextBytes(hmac1);
        hmac.engineSetSeed("NEWBYTES".getBytes());
        hmac.engineNextBytes(hmac2);

        byte [] hash1 = new byte[16];
        byte [] hash2 = new byte[16];
        hash.engineNextBytes(hash1);
        hash.engineSetSeed("NEWBYTES".getBytes());
        hash.engineNextBytes(hash2);

        if(checkRandomness(ctr1, ctr2)
           && checkRandomness(hmac1, hmac2)
           && checkRandomness(hash1, hash2)) {
            _OUT("Passed");
        } else {
            _OUT("Failed");
        }
    } 

    private static void testDRBGCreationSetSeedLong() {
        _IN("Test DRBG creation with params and engineReseed with long");
        TestOpenSSLDrbg ctr = new CtrDrbg();
        TestOpenSSLDrbg hmac = new HmacDrbg();
        TestOpenSSLDrbg hash = new HashDrbg();

        byte [] ctr1 = new byte[16];
        byte [] ctr2 = new byte[16];
        ctr.engineNextBytes(ctr1);
        ctr.engineSetSeed(Long.MAX_VALUE);
        ctr.engineNextBytes(ctr2);

        byte [] hmac1 = new byte[16];
        byte [] hmac2 = new byte[16];
        hmac.engineNextBytes(hmac1);
        hmac.engineSetSeed(Long.MAX_VALUE);
        hmac.engineNextBytes(hmac2);

        byte [] hash1 = new byte[16];
        byte [] hash2 = new byte[16];
        hash.engineNextBytes(hash1);
        hash.engineSetSeed(Long.MAX_VALUE);
        hash.engineNextBytes(hash2);

        if(checkRandomness(ctr1, ctr2)
           && checkRandomness(hmac1, hmac2)
           && checkRandomness(hash1, hash2)) {
            _OUT("Passed");
        } else {
            _OUT("Failed");
        }
    }

    private static void testDRBGCreationWithParamsSetSeedLong() {
        _IN("Test DRBG creation with params and engineReseed with long");
        SecureRandomParameters params = DrbgParameters.instantiation(128, Capability.PR_AND_RESEED, "FIPSPROTOTYPE".getBytes());
        TestOpenSSLDrbg ctr = new CtrDrbg(params);
        TestOpenSSLDrbg hmac = new HmacDrbg(params);
        TestOpenSSLDrbg hash = new HashDrbg(params);

        byte [] ctr1 = new byte[16];
        byte [] ctr2 = new byte[16];
        ctr.engineNextBytes(ctr1);
        ctr.engineSetSeed(Long.MAX_VALUE);
        ctr.engineNextBytes(ctr2);

        byte [] hmac1 = new byte[16];
        byte [] hmac2 = new byte[16];
        hmac.engineNextBytes(hmac1);
        hmac.engineSetSeed(Long.MAX_VALUE);
        hmac.engineNextBytes(hmac2);

        byte [] hash1 = new byte[16];
        byte [] hash2 = new byte[16];
        hash.engineNextBytes(hash1);
        hash.engineSetSeed(Long.MAX_VALUE);
        hash.engineNextBytes(hash2);

        if(checkRandomness(ctr1, ctr2)
           && checkRandomness(hmac1, hmac2)
           && checkRandomness(hash1, hash2)) {
            _OUT("Passed");
        } else {
            _OUT("Failed");
        }
    }

    public static void main(String []args) {
        testDRBGCreation();	
        testDRBGCreationWithParams();
        testDRBGCreationGenerateSeed();
        testDRBGCreationWithParamsGenerateSeed();
        testDRBGCreationNextBytes();
        testDRBGCreationNextBytesWithParams();
        testDRBGCreationWithParamsNextBytes();
        testDRBGCreationWithParamsNextBytesWithParams();
        testDRBGCreationReseed();
        testDRBGCreationWithParamsReseed();
        testDRBGCreationReseedWithParams();
        testDRBGCreationWithParamsReseedWithParams();
        testDRBGCreationSetSeedBytes();
        testDRBGCreationWithParamsSetSeedBytes();
        testDRBGCreationSetSeedLong();
        testDRBGCreationWithParamsSetSeedLong();
    }
}
