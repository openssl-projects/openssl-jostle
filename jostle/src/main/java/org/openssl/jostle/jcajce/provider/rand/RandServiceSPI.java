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

import java.io.IOException;
import java.io.ObjectStreamException;
import java.security.ProviderException;
import java.security.SecureRandomSpi;

/**
 * {@link SecureRandomSpi} backed by a per-instance OpenSSL RAND (DRBG) context.
 * <p>
 * Each SPI owns its own native {@code EVP_RAND_CTX} (a CTR-DRBG seeded from the
 * OpenSSL entropy source) rather than sharing the process-wide private DRBG, so
 * instances are self-contained. OpenSSL owns entropy collection; caller-supplied
 * seed bytes supplement the native DRBG state via reseed but are not treated as
 * deterministic input. The Java 8 baseline implementation accepts only
 * unparameterized construction; the Java 9+ multi-release implementation adds
 * support for {@code DrbgParameters}.
 * </p>
 * <p>
 * Instances are not serializable: the native context handle cannot be persisted,
 * so {@code writeObject}/{@code readObject} throw. The native call sites use
 * {@code synchronized(this)} (the Java 8 baseline idiom) to keep this instance
 * reachable for the duration of each native call, preventing the disposer from
 * freeing the context mid-call.
 * </p>
 */
public final class RandServiceSPI extends SecureRandomSpi
{
    private static final long serialVersionUID = 5952625728129925027L;
    private static final RandServiceNI randServiceNI = NISelector.RandServiceNI;

    private final RandAlgorithm algorithm;
    private final transient RandReference ref;

    /**
     * Constructs an OpenSSL-backed SecureRandom SPI for the supplied algorithm.
     *
     * @param algorithm the registered SecureRandom algorithm
     * @throws NullPointerException if {@code algorithm} is {@code null}
     * @throws ProviderException    if the native DRBG context cannot be created
     */
    public RandServiceSPI(RandAlgorithm algorithm)
    {
        this(algorithm, null);
    }

    /**
     * Constructs an OpenSSL-backed SecureRandom SPI.
     * <p>
     * The Java 8 baseline implementation rejects non-null parameters. The
     * Java 9+ multi-release implementation accepts
     * {@code DrbgParameters.Instantiation}.
     * </p>
     *
     * @param algorithm the registered SecureRandom algorithm
     * @param params    construction parameters, or {@code null}
     * @throws NullPointerException          if {@code algorithm} is {@code null}
     * @throws UnsupportedOperationException if {@code params} is non-null
     * @throws ProviderException             if the native DRBG context cannot be created
     */
    public RandServiceSPI(RandAlgorithm algorithm, Object params)
    {
        if (params != null)
        {
            throw new UnsupportedOperationException("SecureRandom parameters are not supported");
        }

        if (algorithm == null)
        {
            throw new NullPointerException("algorithm cannot be null");
        }

        this.algorithm = algorithm;

        try
        {
            this.ref = new RandReference(
                    randServiceNI.createContext(algorithm.getMaxStrength(), false, null),
                    algorithm.getJcaName());
        }
        catch (Exception e)
        {
            throw new ProviderException("unable to instantiate OpenSSL DRBG: " + e.getMessage(), e);
        }
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
            contextReseed(algorithm.getMaxStrength(), false, seed);
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
        contextRandomBytes(bytes, algorithm.getMaxStrength(), false, null);
        return bytes;
    }

    @Override
    protected void engineNextBytes(byte[] bytes)
    {
        if (bytes == null)
        {
            throw new NullPointerException("bytes cannot be null");
        }

        contextRandomBytes(bytes, algorithm.getMaxStrength(), false, null);
    }

    private synchronized void contextRandomBytes(byte[] bytes, int strength,
                                                 boolean predictionResistant,
                                                 byte[] additionalInput)
    {
        randServiceNI.contextRandomBytes(ref.getReference(), bytes, bytes.length,
                strength, predictionResistant, additionalInput);
    }

    private synchronized void contextReseed(int strength, boolean predictionResistant,
                                            byte[] additionalInput)
    {
        randServiceNI.contextReseed(ref.getReference(), strength,
                predictionResistant, additionalInput);
    }

    private Object readResolve()
    {
        return new RandServiceSPI(algorithm);
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
