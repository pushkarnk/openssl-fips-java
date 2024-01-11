package com.canonical.openssl;

import java.security.SecureRandom;
import java.security.SecureRandomParameters;
import java.security.DrbgParameters;
import java.security.Provider;

class OpenSSLDrbg extends SecureRandom {

    public static int DEFAULT_STRENGTH = 128;
    static {
        System.loadLibrary("jssl");
    }

    long drbgContext;
    SecureRandomParameters params;

    public OpenSSLDrbg(String name) {
        drbgContext = init(name, DEFAULT_STRENGTH, false, false, null);
    }        

    public OpenSSLDrbg(String name, SecureRandomParameters params) throws IllegalArgumentException {
        if(!(params instanceof DrbgParameters.Instantiation)) {
            throw new IllegalArgumentException("Parameters of type DrbgParameters.Instantiation expected, passed " + params.getClass());
        }

        if (params != null) {
            this.params = params;
            DrbgParameters.Instantiation ins = (DrbgParameters.Instantiation)params; 
            this.drbgContext = init(name, ins.getStrength(), ins.getCapability().supportsPredictionResistance(),
                                 ins.getCapability().supportsReseeding(), ins.getPersonalizationString());
        } else {
            this.drbgContext = init(name, DEFAULT_STRENGTH, false, false, null);
        }
    }

    public boolean isInitialized() {
        return drbgContext != 0L;
    }
    
    @Override 
    public SecureRandomParameters getParameters() {
        return this.params;
    }

    @Override
    public byte[] generateSeed(int numBytes) {
        return generateSeed0(numBytes);
    }

    @Override
    public void nextBytes(byte[] bytes) {
        nextBytes0(bytes, DEFAULT_STRENGTH, false, null);
    }

    @Override
    public void nextBytes(byte[] bytes, SecureRandomParameters params) throws IllegalArgumentException {
        if (params == null) {
            nextBytes(bytes);
            return;
        }

        if (!(params instanceof DrbgParameters.NextBytes)) {
            throw new IllegalArgumentException("Parameters of type DrbgParameters.NextByte expected, passed " + params.getClass());
        }

        DrbgParameters.NextBytes nb = (DrbgParameters.NextBytes)params;
        nextBytes0(bytes, nb.getStrength(), nb.getPredictionResistance(), nb.getAdditionalInput());
    }

    @Override
    public void reseed() {
        reseed0(null, false, null);
    }

    @Override
    public void reseed(SecureRandomParameters params) throws IllegalArgumentException {
        if (params == null) {
            reseed();
            return;
        }
        
        if (!(params instanceof DrbgParameters.Reseed)) {
            throw new IllegalArgumentException("Parameters of type DrbgParameters.Reseed expected, passed " + params.getClass());    
        }
        DrbgParameters.Reseed rs = (DrbgParameters.Reseed)params;
        reseed0(null, rs.getPredictionResistance(), rs.getAdditionalInput());
    }

    @Override
    public void setSeed(byte[] seed) {
        reseed0(seed, false, null);
    }

    @Override
    public void setSeed(long seed) {
        if (drbgContext == 0) {
            super.setSeed(seed);
            return;
        }

        byte [] seedBytes = new byte[8];
        for (int i = 0; i < 8; i++) {
             seedBytes[i] = (byte)(seed & (long)0xff);
             seed = seed >> 8; 
        }

        setSeed(seedBytes);
    }

    private native long init(String name, int strength, boolean supportsPredictionResistance, boolean supportsReseeding, byte[] personalizationString);
    private native void nextBytes0(byte[] bytes, int strength, boolean supportsPredictionResistance, byte[] additionalInput);
    private native void reseed0(byte[] bytes, boolean supportsPredictionResistance, byte[] additionalInput);
    private native byte[] generateSeed0(int numBytes);
}
