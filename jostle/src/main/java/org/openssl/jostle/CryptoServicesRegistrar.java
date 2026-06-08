/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle;

import org.openssl.jostle.jcajce.provider.NISelector;

import java.security.SecureRandom;
import java.util.concurrent.atomic.AtomicReference;

public class CryptoServicesRegistrar
{

    private static final SecureRandomProvider defaultRandomProviderImpl = new ThreadLocalSecureRandomProvider();
    private static final AtomicReference<SecureRandomProvider> defaultSecureRandomProvider = new AtomicReference<SecureRandomProvider>();


    static
    {
        Loader.load();
    }

    public static boolean isNativeAvailable()
    {
        return Loader.isLoadSuccessful() && NISelector.NativeServiceNI.isNativeAvailable();
    }

    public static void assertNativeAvailable()
    {

        if (!isNativeAvailable())
        {
            throw new IllegalStateException("no access to native library");
        }
    }


    public String getOpenSSLVersion()
    {
        return NISelector.NativeServiceNI.getOpenSSLVersion();
    }

    /**
     * Return the default source of randomness.
     *
     * @return the default SecureRandom
     */
    public static SecureRandom getSecureRandom()
    {
        defaultSecureRandomProvider.compareAndSet(null, defaultRandomProviderImpl);
        return defaultSecureRandomProvider.get().get();
    }

    /**
     * Return either the passed-in SecureRandom, or if it is null, then the default source of randomness.
     *
     * @param secureRandom the SecureRandom to use if it is not null.
     * @return the SecureRandom parameter if it is not null, or else the default SecureRandom
     */
    public static SecureRandom getSecureRandom(SecureRandom secureRandom)
    {
        return null == secureRandom ? getSecureRandom() : secureRandom;
    }

    /**
     * Return a {@link SecureRandom} whose reported security strength is
     * at least {@code requiredStrengthBits}.
     *
     * <p>Delegates to the current {@link SecureRandomProvider}'s
     * {@link SecureRandomProvider#get(int)} — the default
     * {@link ThreadLocalSecureRandomProvider} has a Java 9+ override
     * that constructs a DRBG via {@code DrbgParameters.instantiation}.
     * The Java 8 baseline inherits the default {@code get(int)} which
     * returns the regular {@link #getSecureRandom()} default.
     *
     * <p>Used by the post-quantum SPIs (ML-KEM, ML-DSA, SLH-DSA) to
     * obtain a default RNG that satisfies the algorithm's required
     * security category — without this, ML-KEM-768 (192-bit strength)
     * and ML-KEM-1024 (256-bit strength) keygen / encap calls fail
     * against the JDK's default 128-bit DRBG (GH issue #34).
     *
     * @param requiredStrengthBits desired minimum strength in bits
     *                             (typically 128, 192, or 256).
     * @return a SecureRandom suitable for use as the default source
     *         of randomness for an operation requiring at least the
     *         given strength.
     */
    public static SecureRandom getSecureRandom(int requiredStrengthBits)
    {
        defaultSecureRandomProvider.compareAndSet(null, defaultRandomProviderImpl);
        return defaultSecureRandomProvider.get().get(requiredStrengthBits);
    }


    /**
     * Set a default secure random provider to be used where none is otherwise provided.
     *
     * @param secureRandomProvider a provider SecureRandom to use when a default SecureRandom is requested.
     */
    public static void setSecureRandomProvider(SecureRandomProvider secureRandomProvider)
    {
        defaultSecureRandomProvider.set(secureRandomProvider);
    }


    /**
     * Set a default secure random to be used where none is otherwise provided.
     *
     * @param secureRandom the SecureRandom to use as the default.
     */
    public static void setSecureRandom(final SecureRandom secureRandom)
    {

        if (secureRandom == null)
        {
            defaultSecureRandomProvider.set(defaultRandomProviderImpl);
        }
        else
        {
            defaultSecureRandomProvider.set(new SecureRandomProvider()
            {
                public SecureRandom get()
                {
                    return secureRandom;
                }
            });
        }
    }
}
