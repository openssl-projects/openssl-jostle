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

import java.io.IOException;
import java.io.ObjectStreamException;
import java.lang.ref.Reference;
import java.security.DrbgParameters;
import java.security.ProviderException;
import java.security.SecureRandomParameters;
import java.security.SecureRandomSpi;

/**
 * Java 9+ {@link SecureRandomSpi} backed by an OpenSSL RAND context.
 * <p>
 * This implementation supports the JDK DRBG parameter model for the
 * OpenSSL-backed {@code DRBG} service:
 * </p>
 * <ul>
 *     <li>{@link DrbgParameters.Instantiation} during construction</li>
 *     <li>{@link DrbgParameters.NextBytes} for per-call generation controls</li>
 *     <li>{@link DrbgParameters.Reseed} for explicit reseeding</li>
 * </ul>
 * <p>
 * Requested strength is capped at the instantiated strength and prediction
 * resistance must be enabled by the instance capability before it can be used
 * for generation or reseeding.
 * </p>
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

    /**
     * Constructs an OpenSSL-backed SecureRandom SPI using the algorithm's
     * default strength and {@link DrbgParameters.Capability#RESEED_ONLY}.
     *
     * @param algorithm the registered SecureRandom algorithm
     * @throws NullPointerException if {@code algorithm} is {@code null}
     */
    public RandServiceSPI(RandAlgorithm algorithm)
    {
        this(algorithm, null);
    }

    /**
     * Constructs an OpenSSL-backed SecureRandom SPI.
     * <p>
     * The only supported non-null parameter type is
     * {@link DrbgParameters.Instantiation}. A strength of {@code -1} selects
     * the algorithm default. Personalization bytes are copied before being
     * passed to the native context.
     * </p>
     *
     * @param algorithm the registered SecureRandom algorithm
     * @param params    construction parameters, or {@code null}
     * @throws NullPointerException          if {@code algorithm} is {@code null}
     * @throws IllegalArgumentException      if the requested strength is invalid
     *                                       or exceeds the algorithm strength
     * @throws UnsupportedOperationException if {@code params} is not
     *                                       {@link DrbgParameters.Instantiation}
     * @throws ProviderException             if the native DRBG context cannot be created
     */
    public RandServiceSPI(RandAlgorithm algorithm, Object params)
    {
        if (algorithm == null)
        {
            throw new NullPointerException("algorithm cannot be null");
        }

        this.algorithm = algorithm;

        int strength = algorithm.getMaxStrength();
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
        } catch (Exception e)
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

    /**
     * Generates bytes using per-call DRBG parameters.
     *
     * @param bytes  the destination buffer
     * @param params generation parameters; must be
     *               {@link DrbgParameters.NextBytes}
     * @throws NullPointerException          if {@code bytes} is {@code null}
     * @throws IllegalArgumentException      if {@code params} is {@code null}, the
     *                                       requested strength is invalid, the requested strength exceeds the
     *                                       instantiated strength, or prediction resistance is requested for
     *                                       an instance that does not support it
     * @throws UnsupportedOperationException if {@code params} is not
     *                                       {@link DrbgParameters.NextBytes}
     */
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

    /**
     * Reseeds this OpenSSL DRBG context.
     *
     * @param params reseed parameters; must be
     *               {@link DrbgParameters.Reseed}, or {@code null} to reseed with the
     *               instance defaults
     * @throws IllegalArgumentException      if prediction resistance is requested
     *                                       for an instance that does not support it
     * @throws UnsupportedOperationException if reseeding is disabled by the
     *                                       instance capability or {@code params} is not
     *                                       {@link DrbgParameters.Reseed}
     */
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

    /**
     * Returns the effective instantiation parameters for this SPI.
     *
     * @return a {@link DrbgParameters.Instantiation} describing strength,
     * capability, and a defensive copy of the personalization string
     */
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
        return normalizeStrength(strength, algorithm.getMaxStrength());
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
        if (strength > algorithm.getMaxStrength())
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
        } finally
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
        } finally
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

    private void writeObject(java.io.ObjectOutputStream out)
            throws IOException
    {

        throw new UnsupportedOperationException("writeObject not implemented on native rand");
    }

    private void readObject(java.io.ObjectInputStream in)
            throws IOException, ClassNotFoundException
    {
        throw new UnsupportedOperationException("writeObject not implemented on native rand");
    }

    private void readObjectNoData()
            throws ObjectStreamException
    {
        throw new UnsupportedOperationException("writeObject not implemented on native rand");
    }


}
