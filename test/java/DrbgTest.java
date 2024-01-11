import com.canonical.openssl.*;
import java.util.Arrays;
import java.security.*;
import java.security.DrbgParameters;
import java.security.DrbgParameters.Instantiation;
import java.security.DrbgParameters.Capability;
import java.lang.Long;

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
        SecureRandom ctr = new CtrDrbg();
        SecureRandom hmac = new HmacDrbg();
        SecureRandom hash = new HashDrbg();
        if (ctr.generateSeed(8).length == 8 &&
            hmac.generateSeed(8).length == 8 &&
            hash.generateSeed(8).length == 8) {
            _OUT("Passed");
        } else {
            _OUT("Failed");
        }
    }

    private static void testDRBGCreationWithParams() {
        _IN("Test DRBG creation with parameters");
        SecureRandomParameters params = DrbgParameters.instantiation(144, Capability.PR_AND_RESEED, "FIPSPROTOTYPE".getBytes()); 
        SecureRandom ctr = new CtrDrbg(params);
        SecureRandom hmac = new HmacDrbg(params);
        SecureRandom hash = new HashDrbg(params);
        if (ctr.generateSeed(8).length == 8 &&
            hmac.generateSeed(8).length == 8 &&
            hash.generateSeed(8).length == 8) {
            _OUT("Passed");
        } else {
            _OUT("Failed");
        }
    }

    private static void testDRBGCreationGenerateSeed() {
        _IN("Test DRBG creation and seed generation");
        SecureRandom ctr = new CtrDrbg();
        SecureRandom hmac = new HmacDrbg();
        SecureRandom hash = new HashDrbg();
        if (checkRandomness(ctr.generateSeed(8), ctr.generateSeed(8)) &&
            checkRandomness(hmac.generateSeed(16), hmac.generateSeed(16)) && 
            checkRandomness(hash.generateSeed(32), hash.generateSeed(32))) {
            _OUT("Passed");
        } else {
            _OUT("Failed");
        }
    }

    private static void testDRBGCreationWithParamsGenerateSeed() {
        _IN("Test DRBG creation with parameters and seed generation");
        SecureRandomParameters params = DrbgParameters.instantiation(144, Capability.PR_AND_RESEED, "FIPSPROTOTYPE".getBytes());
        SecureRandom ctr = new CtrDrbg(params);
        SecureRandom hmac = new HmacDrbg(params);
        SecureRandom hash = new HashDrbg(params);
        if (checkRandomness(ctr.generateSeed(8), ctr.generateSeed(8)) &&
            checkRandomness(hmac.generateSeed(16), hmac.generateSeed(16)) &&
            checkRandomness(hash.generateSeed(32), hash.generateSeed(32))) {
            _OUT("Passed");
        } else {
            _OUT("Failed");
        }
    }

    private static void testDRBGCreationNextBytes() {
        _IN("Test DRBG creation and next bytes");
        
        SecureRandom ctr = new CtrDrbg();
        SecureRandom hmac = new HmacDrbg();
        SecureRandom hash = new HashDrbg();

        byte [] ctr1 = new byte[32];
        byte [] ctr2 = new byte[32];
        ctr.nextBytes(ctr1);
        ctr.nextBytes(ctr2);

        byte [] hmac1 = new byte[64];
        byte [] hmac2 = new byte[64];
        hmac.nextBytes(hmac1);
        hmac.nextBytes(hmac2);

        byte [] hash1 = new byte[64];
        byte [] hash2 = new byte[64];
        hash.nextBytes(hash1);
        hash.nextBytes(hash2);
 
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
        SecureRandom ctr = new CtrDrbg(params);
        SecureRandom hmac = new HmacDrbg(params);
        SecureRandom hash = new HashDrbg(params);

        // TODO: size > 92 fails at openssl level, sometimes malloc() fails
        byte [] ctr1 = new byte[32];
        byte [] ctr2 = new byte[32];
        ctr.nextBytes(ctr1);
        ctr.nextBytes(ctr2);

        byte [] hmac1 = new byte[64];
        byte [] hmac2 = new byte[64];
        hmac.nextBytes(hmac1);
        hmac.nextBytes(hmac2);

        byte [] hash1 = new byte[84];
        byte [] hash2 = new byte[84];
        hash.nextBytes(hash1);
        hash.nextBytes(hash2);
    
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
        SecureRandom ctr = new CtrDrbg();
        SecureRandom hmac = new HmacDrbg();
        SecureRandom hash = new HashDrbg();

        // TODO: memory corruption for next byte array sizes >= 32
        byte [] ctr1 = new byte[8];
        byte [] ctr2 = new byte[8];
        ctr.nextBytes(ctr1, nbParams);
        ctr.nextBytes(ctr2, nbParams);

        byte [] hmac1 = new byte[16];
        byte [] hmac2 = new byte[16];
        hmac.nextBytes(hmac1, nbParams);
        hmac.nextBytes(hmac2, nbParams);

        byte [] hash1 = new byte[32];
        byte [] hash2 = new byte[32];
        hash.nextBytes(hash1, nbParams);
        hash.nextBytes(hash2, nbParams);

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
        SecureRandom ctr = new CtrDrbg(params);
        SecureRandom hmac = new HmacDrbg(params);
        SecureRandom hash = new HashDrbg(params);

        byte [] ctr1 = new byte[32];
        byte [] ctr2 = new byte[32];
        ctr.nextBytes(ctr1, nbParams);
        ctr.nextBytes(ctr2, nbParams);

        byte [] hmac1 = new byte[32];
        byte [] hmac2 = new byte[32];
        hmac.nextBytes(hmac1, nbParams);
        hmac.nextBytes(hmac2, nbParams);

        byte [] hash1 = new byte[32];
        byte [] hash2 = new byte[32];
        hash.nextBytes(hash1, nbParams);
        hash.nextBytes(hash2, nbParams);

        if(checkRandomness(ctr1, ctr2)
           && checkRandomness(hmac1, hmac2)
           && checkRandomness(hash1, hash2)) {
            _OUT("Passed");
        } else {
            _OUT("Failed");
        }
    }

    private static void testDRBGCreationReseed() {
        _IN("Test DRBG creation and reseed");
        SecureRandom ctr = new CtrDrbg();
        SecureRandom hmac = new HmacDrbg();
        SecureRandom hash = new HashDrbg();

        byte [] ctr1 = new byte[16];
        byte [] ctr2 = new byte[32];
        ctr.nextBytes(ctr1);
        ctr.reseed();
        ctr.nextBytes(ctr2);

        byte [] hmac1 = new byte[16];
        byte [] hmac2 = new byte[16];
        hmac.nextBytes(hmac1);
        hmac.reseed();
        hmac.nextBytes(hmac2);

        byte [] hash1 = new byte[16];
        byte [] hash2 = new byte[16];
        hash.nextBytes(hash1);
        hash.reseed();
        hash.nextBytes(hash2);

        if(checkRandomness(ctr1, ctr2)
           && checkRandomness(hmac1, hmac2)
           && checkRandomness(hash1, hash2)) {
            _OUT("Passed");
        } else {
            _OUT("Failed");
        }
    }

    private static void testDRBGCreationWithParamsReseed() {
        _IN("Test DRBG creation with params and reseed");
        SecureRandomParameters params = DrbgParameters.instantiation(128, Capability.PR_AND_RESEED, "FIPSPROTOTYPE".getBytes());
        SecureRandom ctr = new CtrDrbg(params);
        SecureRandom hmac = new HmacDrbg(params);
        SecureRandom hash = new HashDrbg(params);

        byte [] ctr1 = new byte[16];
        byte [] ctr2 = new byte[16];
        ctr.nextBytes(ctr1);
        ctr.reseed();
        ctr.nextBytes(ctr2);

        byte [] hmac1 = new byte[16];
        byte [] hmac2 = new byte[16];
        hmac.nextBytes(hmac1);
        hmac.reseed();
        hmac.nextBytes(hmac2);

        byte [] hash1 = new byte[16];
        byte [] hash2 = new byte[16];
        hash.nextBytes(hash1);
        hash.reseed();
        hash.nextBytes(hash2);

        if(checkRandomness(ctr1, ctr2)
           && checkRandomness(hmac1, hmac2)
           && checkRandomness(hash1, hash2)) {
            _OUT("Passed");
        } else {
            _OUT("Failed");
        }
    }

    private static void testDRBGCreationReseedWithParams() {
        _IN("Test DRBG creation and reseed with params");
        SecureRandom ctr = new CtrDrbg();
        SecureRandom hmac = new HmacDrbg();
        SecureRandom hash = new HashDrbg();

        SecureRandomParameters rs = DrbgParameters.reseed(true, "ADDITIONALINPUT".getBytes());
        byte [] ctr1 = new byte[16];
        byte [] ctr2 = new byte[16];
        ctr.nextBytes(ctr1);
        ctr.reseed(rs);
        ctr.nextBytes(ctr2);

        byte [] hmac1 = new byte[16];
        byte [] hmac2 = new byte[16];
        hmac.nextBytes(hmac1);
        hmac.reseed(rs);
        hmac.nextBytes(hmac2);

        byte [] hash1 = new byte[16];
        byte [] hash2 = new byte[16];
        hash.nextBytes(hash1);
        hash.reseed(rs);
        hash.nextBytes(hash2);

        if(checkRandomness(ctr1, ctr2)
           && checkRandomness(hmac1, hmac2)
           && checkRandomness(hash1, hash2)) {
            _OUT("Passed");
        } else {
            _OUT("Failed");
        }
    }

    private static void testDRBGCreationWithParamsReseedWithParams() {
        _IN("Test DRBG creation with params, reseed with params");
        SecureRandomParameters params = DrbgParameters.instantiation(128, Capability.PR_AND_RESEED, "FIPSPROTOTYPE".getBytes());
        SecureRandom ctr = new CtrDrbg(params);
        SecureRandom hmac = new HmacDrbg(params);
        SecureRandom hash = new HashDrbg(params);

        SecureRandomParameters rs = DrbgParameters.reseed(true, "ADDITIONALINPUT".getBytes());
        byte [] ctr1 = new byte[16];
        byte [] ctr2 = new byte[16];
        ctr.nextBytes(ctr1);
        ctr.reseed(rs);
        ctr.nextBytes(ctr2);

        byte [] hmac1 = new byte[16];
        byte [] hmac2 = new byte[16];
        hmac.nextBytes(hmac1);
        hmac.reseed(rs);
        hmac.nextBytes(hmac2);

        byte [] hash1 = new byte[16];
        byte [] hash2 = new byte[16];
        hash.nextBytes(hash1);
        hash.reseed(rs);
        hash.nextBytes(hash2);

        if(checkRandomness(ctr1, ctr2)
           && checkRandomness(hmac1, hmac2)
           && checkRandomness(hash1, hash2)) {
            _OUT("Passed");
        } else {
            _OUT("Failed");
        }
    }

    private static void testDRBGCreationSetSeedBytes() {
        _IN("Test DRBG creation with params and reseed with bytes");
        SecureRandomParameters params = DrbgParameters.instantiation(128, Capability.PR_AND_RESEED, "FIPSPROTOTYPE".getBytes());
        SecureRandom ctr = new CtrDrbg();
        SecureRandom hmac = new HmacDrbg();
        SecureRandom hash = new HashDrbg();

        byte [] ctr1 = new byte[16];
        byte [] ctr2 = new byte[16];
        ctr.nextBytes(ctr1);
        ctr.setSeed("NEWBYTES".getBytes());
        ctr.nextBytes(ctr2);

        byte [] hmac1 = new byte[16];
        byte [] hmac2 = new byte[16];
        hmac.nextBytes(hmac1);
        hmac.setSeed("NEWBYTES".getBytes());
        hmac.nextBytes(hmac2);

        byte [] hash1 = new byte[16];
        byte [] hash2 = new byte[16];
        hash.nextBytes(hash1);
        hash.setSeed("NEWBYTES".getBytes());
        hash.nextBytes(hash2);

        if(checkRandomness(ctr1, ctr2)
           && checkRandomness(hmac1, hmac2)
           && checkRandomness(hash1, hash2)) {
            _OUT("Passed");
        } else {
            _OUT("Failed");
        }
    }

    private static void testDRBGCreationWithParamsSetSeedBytes() {
        _IN("Test DRBG creation with params and reseed with bytes");
        SecureRandomParameters params = DrbgParameters.instantiation(128, Capability.PR_AND_RESEED, "FIPSPROTOTYPE".getBytes());
        SecureRandom ctr = new CtrDrbg(params);
        SecureRandom hmac = new HmacDrbg(params);
        SecureRandom hash = new HashDrbg(params);

        byte [] ctr1 = new byte[16];
        byte [] ctr2 = new byte[16];
        ctr.nextBytes(ctr1);
        ctr.setSeed("NEWBYTES".getBytes());
        ctr.nextBytes(ctr2);

        byte [] hmac1 = new byte[16];
        byte [] hmac2 = new byte[16];
        hmac.nextBytes(hmac1);
        hmac.setSeed("NEWBYTES".getBytes());
        hmac.nextBytes(hmac2);

        byte [] hash1 = new byte[16];
        byte [] hash2 = new byte[16];
        hash.nextBytes(hash1);
        hash.setSeed("NEWBYTES".getBytes());
        hash.nextBytes(hash2);

        if(checkRandomness(ctr1, ctr2)
           && checkRandomness(hmac1, hmac2)
           && checkRandomness(hash1, hash2)) {
            _OUT("Passed");
        } else {
            _OUT("Failed");
        }
    } 

    private static void testDRBGCreationSetSeedLong() {
        _IN("Test DRBG creation with params and reseed with long");
        SecureRandom ctr = new CtrDrbg();
        SecureRandom hmac = new HmacDrbg();
        SecureRandom hash = new HashDrbg();

        byte [] ctr1 = new byte[16];
        byte [] ctr2 = new byte[16];
        ctr.nextBytes(ctr1);
        ctr.setSeed(Long.MAX_VALUE);
        ctr.nextBytes(ctr2);

        byte [] hmac1 = new byte[16];
        byte [] hmac2 = new byte[16];
        hmac.nextBytes(hmac1);
        hmac.setSeed(Long.MAX_VALUE);
        hmac.nextBytes(hmac2);

        byte [] hash1 = new byte[16];
        byte [] hash2 = new byte[16];
        hash.nextBytes(hash1);
        hash.setSeed(Long.MAX_VALUE);
        hash.nextBytes(hash2);

        if(checkRandomness(ctr1, ctr2)
           && checkRandomness(hmac1, hmac2)
           && checkRandomness(hash1, hash2)) {
            _OUT("Passed");
        } else {
            _OUT("Failed");
        }
    }

    private static void testDRBGCreationWithParamsSetSeedLong() {
        _IN("Test DRBG creation with params and reseed with long");
        SecureRandomParameters params = DrbgParameters.instantiation(128, Capability.PR_AND_RESEED, "FIPSPROTOTYPE".getBytes());
        SecureRandom ctr = new CtrDrbg(params);
        SecureRandom hmac = new HmacDrbg(params);
        SecureRandom hash = new HashDrbg(params);

        byte [] ctr1 = new byte[16];
        byte [] ctr2 = new byte[16];
        ctr.nextBytes(ctr1);
        ctr.setSeed(Long.MAX_VALUE);
        ctr.nextBytes(ctr2);

        byte [] hmac1 = new byte[16];
        byte [] hmac2 = new byte[16];
        hmac.nextBytes(hmac1);
        hmac.setSeed(Long.MAX_VALUE);
        hmac.nextBytes(hmac2);

        byte [] hash1 = new byte[16];
        byte [] hash2 = new byte[16];
        hash.nextBytes(hash1);
        hash.setSeed(Long.MAX_VALUE);
        hash.nextBytes(hash2);

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
