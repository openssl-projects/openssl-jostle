/*
 *
 *   Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *   Licensed under the Apache License 2.0 (the "License"). You may not use
 *   this file except in compliance with the License.  You can obtain a copy
 *   in the file LICENSE in the source distribution or at
 *   https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.rand;

import org.openssl.jostle.jcajce.provider.NISelector;

import java.security.DrbgParameters;
import java.security.SecureRandomSpi;
import java.security.SecureRandomParameters;
import java.security.ProviderException;

/**
 * Java 9+ variant of RandServiceSPI that accepts SecureRandomParameters
 * (notably DrbgParameters.Instantiation) and translates requested strength
 * and prediction-resistance into native-side checks/instantiation.
 */
public final class RandServiceSPI extends SecureRandomSpi
{
    private static final long serialVersionUID = 5952625728129925027L;
    private static final RandServiceNI randServiceNI = NISelector.RandServiceNI;

    private final RandAlgorithm algorithm;
    private final int instanceStrength;
    private final DrbgParameters.Capability instanceCapability;

    public RandServiceSPI(RandAlgorithm algorithm)
    {
        this(algorithm, null);
    }

    public RandServiceSPI(RandAlgorithm algorithm, SecureRandomParameters params)
    {
        if (algorithm == null)
        {
            throw new NullPointerException("algorithm cannot be null");
        }

        this.algorithm = algorithm;

        int strength = algorithm.getStrength();
        DrbgParameters.Capability capability = DrbgParameters.Capability.RESEED_ONLY;

        if (params != null)
        {
            if (!(params instanceof DrbgParameters.Instantiation))
            {
                throw new UnsupportedOperationException("only DrbgParameters.Instantiation is supported");
            }

            DrbgParameters.Instantiation ins = (DrbgParameters.Instantiation) params;
            if (ins.getPersonalizationString() != null)
            {
                throw new UnsupportedOperationException("personalization string is not supported");
            }

            strength = normalizeStrength(ins.getStrength());
            capability = ins.getCapability();
            boolean predRes = capability.supportsPredictionResistance();

            try
            {
                // Ask native side to accept/validate requested instantiation.
                randServiceNI.instantiate(strength, predRes);
            }
            catch (Exception e)
            {
                throw new ProviderException("unable to instantiate OpenSSL DRBG: " + e.getMessage(), e);
            }
        }

        this.instanceStrength = strength;
        this.instanceCapability = capability;
    }

    @Override
    protected void engineSetSeed(byte[] seed)
    {
        // OpenSSL owns seeding and reseeding for this implementation — no-op.
    }

    @Override
    protected byte[] engineGenerateSeed(int numBytes)
    {
        if (numBytes < 0)
        {
            throw new IllegalArgumentException("numBytes cannot be negative");
        }

        byte[] bytes = new byte[numBytes];
        randServiceNI.randomBytes(bytes, bytes.length, instanceStrength);
        return bytes;
    }

    @Override
    protected void engineNextBytes(byte[] bytes)
    {
        if (bytes == null)
        {
            throw new NullPointerException("bytes cannot be null");
        }

        boolean predictionResistant = instanceCapability.supportsPredictionResistance();
        randServiceNI.instantiate(instanceStrength, predictionResistant);
        randServiceNI.randomBytes(bytes, bytes.length, instanceStrength);
    }

    @Override
    protected void engineNextBytes(byte[] bytes, SecureRandomParameters params)
    {
        if (bytes == null)
        {
            throw new NullPointerException("bytes cannot be null");
        }

        if (params == null)
        {
            engineNextBytes(bytes);
            return;
        }

        if (!(params instanceof DrbgParameters.NextBytes))
        {
            throw new UnsupportedOperationException("only DrbgParameters.NextBytes is supported");
        }

        DrbgParameters.NextBytes nextBytes = (DrbgParameters.NextBytes) params;
        if (nextBytes.getAdditionalInput() != null)
        {
            throw new UnsupportedOperationException("additional input is not supported");
        }

        int strength = normalizeStrength(nextBytes.getStrength(), instanceStrength);
        boolean predictionResistant = nextBytes.getPredictionResistance();

        checkStrength(strength);
        checkPredictionResistance(predictionResistant);
        randServiceNI.instantiate(strength, predictionResistant);
        randServiceNI.randomBytes(bytes, bytes.length, strength);
    }

    @Override
    protected void engineReseed(SecureRandomParameters params)
    {
        if (params == null)
        {
            checkReseeding();
            randServiceNI.reseed(instanceStrength, false);
            return;
        }

        if (!(params instanceof DrbgParameters.Reseed))
        {
            throw new UnsupportedOperationException("only DrbgParameters.Reseed is supported");
        }

        DrbgParameters.Reseed reseed = (DrbgParameters.Reseed) params;
        if (reseed.getAdditionalInput() != null)
        {
            throw new UnsupportedOperationException("additional input is not supported");
        }

        checkReseeding();
        checkPredictionResistance(reseed.getPredictionResistance());
        randServiceNI.reseed(instanceStrength, reseed.getPredictionResistance());
    }

    @Override
    protected SecureRandomParameters engineGetParameters()
    {
        return DrbgParameters.instantiation(instanceStrength, instanceCapability, null);
    }

    private Object readResolve()
    {
        return new RandServiceSPI(algorithm, engineGetParameters());
    }

    private int normalizeStrength(int strength)
    {
        return normalizeStrength(strength, algorithm.getStrength());
    }

    private int normalizeStrength(int strength, int defaultStrength)
    {
        if (strength == -1)
        {
            return defaultStrength;
        }

        if (strength < -1)
        {
            throw new IllegalArgumentException("strength cannot be less than -1");
        }

        return strength;
    }

    private void checkStrength(int strength)
    {
        if (strength > instanceStrength)
        {
            throw new IllegalArgumentException("requested strength exceeds instantiated strength");
        }
    }

    private void checkPredictionResistance(boolean predictionResistant)
    {
        if (predictionResistant && !instanceCapability.supportsPredictionResistance())
        {
            throw new IllegalArgumentException("prediction resistance is not supported");
        }
    }

    private void checkReseeding()
    {
        if (!instanceCapability.supportsReseeding())
        {
            throw new UnsupportedOperationException("reseeding is not supported");
        }
    }
}
