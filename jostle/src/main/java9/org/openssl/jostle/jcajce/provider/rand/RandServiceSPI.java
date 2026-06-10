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

import org.openssl.jostle.disposal.NativeDisposer;
import org.openssl.jostle.disposal.NativeReference;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.util.Arrays;

import java.lang.ref.Reference;
import java.security.DrbgParameters;
import java.security.SecureRandomSpi;
import java.security.SecureRandomParameters;
import java.security.ProviderException;

/**
 * Java 9+ variant of RandServiceSPI that accepts SecureRandomParameters
 * (notably DrbgParameters.Instantiation) and translates requested strength
 * and prediction-resistance into a native-side context.
 */
public final class RandServiceSPI extends SecureRandomSpi
{
    private static final long serialVersionUID = 5952625728129925027L;
    private static final RandServiceNI randServiceNI = NISelector.RandServiceNI;

    private final RandAlgorithm algorithm;
    private final int instanceStrength;
    private final DrbgParameters.Capability instanceCapability;
    private final byte[] personalizationString;
    private final transient RandReference ref;

    public RandServiceSPI(RandAlgorithm algorithm)
    {
        this(algorithm, null);
    }

    public RandServiceSPI(RandAlgorithm algorithm, Object params)
    {
        if (algorithm == null)
        {
            throw new NullPointerException("algorithm cannot be null");
        }

        this.algorithm = algorithm;

        int strength = algorithm.getStrength();
        DrbgParameters.Capability capability = DrbgParameters.Capability.RESEED_ONLY;
        byte[] pstr = null;

        if (params != null)
        {
            if (!(params instanceof DrbgParameters.Instantiation))
            {
                throw new UnsupportedOperationException("only DrbgParameters.Instantiation is supported");
            }

            DrbgParameters.Instantiation ins = (DrbgParameters.Instantiation) params;
            strength = normalizeStrength(ins.getStrength());
            capability = ins.getCapability();
            pstr = Arrays.clone(ins.getPersonalizationString());
        }

        checkInstantiationStrength(strength);
        boolean predRes = capability.supportsPredictionResistance();
        try
        {
            this.ref = new RandReference(randServiceNI.createContext(strength, predRes, pstr),
                    algorithm.getJcaName());
        }
        catch (Exception e)
        {
            throw new ProviderException("unable to instantiate OpenSSL DRBG: " + e.getMessage(), e);
        }

        this.personalizationString = pstr;

        this.instanceStrength = strength;
        this.instanceCapability = capability;
    }

    @Override
    protected void engineSetSeed(byte[] seed)
    {
        if (seed == null)
        {
            throw new NullPointerException("seed cannot be null");
        }

        if (seed.length > 0)
        {
            contextReseed(instanceStrength, false, seed);
        }
    }

    @Override
    protected byte[] engineGenerateSeed(int numBytes)
    {
        if (numBytes < 0)
        {
            throw new IllegalArgumentException("numBytes cannot be negative");
        }

        byte[] bytes = new byte[numBytes];
        contextRandomBytes(bytes, instanceStrength, false, null);
        return bytes;
    }

    @Override
    protected void engineNextBytes(byte[] bytes)
    {
        if (bytes == null)
        {
            throw new NullPointerException("bytes cannot be null");
        }

        contextRandomBytes(bytes, instanceStrength,
                instanceCapability.supportsPredictionResistance(), null);
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
            throw new IllegalArgumentException("params cannot be null");
        }

        if (!(params instanceof DrbgParameters.NextBytes))
        {
            throw new UnsupportedOperationException("only DrbgParameters.NextBytes is supported");
        }

        DrbgParameters.NextBytes nextBytes = (DrbgParameters.NextBytes) params;
        int strength = normalizeStrength(nextBytes.getStrength(), instanceStrength);
        boolean predictionResistant = nextBytes.getPredictionResistance();
        byte[] additionalInput = nextBytes.getAdditionalInput();

        checkStrength(strength);
        checkPredictionResistance(predictionResistant);
        contextRandomBytes(bytes, strength, predictionResistant, additionalInput);
    }

    @Override
    protected void engineReseed(SecureRandomParameters params)
    {
        if (params == null)
        {
            checkReseeding();
            contextReseed(instanceStrength,
                    instanceCapability.supportsPredictionResistance(), null);
            return;
        }

        if (!(params instanceof DrbgParameters.Reseed))
        {
            throw new UnsupportedOperationException("only DrbgParameters.Reseed is supported");
        }

        DrbgParameters.Reseed reseed = (DrbgParameters.Reseed) params;
        checkReseeding();
        checkPredictionResistance(reseed.getPredictionResistance());
        contextReseed(instanceStrength, reseed.getPredictionResistance(), reseed.getAdditionalInput());
    }

    @Override
    protected SecureRandomParameters engineGetParameters()
    {
        return DrbgParameters.instantiation(instanceStrength, instanceCapability,
                Arrays.clone(personalizationString));
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

    private void checkInstantiationStrength(int strength)
    {
        if (strength > algorithm.getStrength())
        {
            throw new IllegalArgumentException("requested strength exceeds algorithm strength");
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

    private synchronized void contextRandomBytes(byte[] bytes, int strength,
                                                boolean predictionResistant,
                                                byte[] additionalInput)
    {
        try
        {
            randServiceNI.contextRandomBytes(ref.getReference(), bytes, bytes.length,
                    strength, predictionResistant, additionalInput);
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
    }

    private synchronized void contextReseed(int strength, boolean predictionResistant,
                                            byte[] additionalInput)
    {
        try
        {
            randServiceNI.contextReseed(ref.getReference(), strength,
                    predictionResistant, additionalInput);
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
    }

    private static class Disposer extends NativeDisposer
    {
        Disposer(long reference)
        {
            super(reference);
        }

        @Override
        protected void dispose(long reference)
        {
            randServiceNI.disposeContext(reference);
        }
    }

    private static class RandReference extends NativeReference
    {
        RandReference(long reference, String name)
        {
            super(reference, name);
        }

        @Override
        protected Runnable createAction()
        {
            return new Disposer(reference);
        }
    }
}
