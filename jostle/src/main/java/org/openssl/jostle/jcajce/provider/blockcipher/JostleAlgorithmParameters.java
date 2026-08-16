/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.blockcipher;

import org.openssl.jostle.jcajce.provider.JostleProvider;

import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * Resolves an {@link AlgorithmParameters} instance from a named Jostle
 * provider, falling back to the other only when the named one is absent.
 *
 * <p>The AEAD cipher SPIs expose their session nonce and tag length through
 * {@code engineGetParameters()}. An unpinned
 * {@code AlgorithmParameters.getInstance(alg)} makes the returned object's
 * implementation depend on {@code java.security.Provider} search order — a
 * foreign provider registered ahead of Jostle silently supplies it, coupling a
 * Jostle cipher's parameter behaviour to whatever that provider does. This was
 * latent until BouncyCastle 1.85, whose CCM AlgorithmParameters rejects
 * RFC 5084-valid ICV lengths below 12 on the {@code getParameterSpec} path
 * (its CCM read-back reuses the GCM extractor, which 1.85 validates with
 * GCM's 12..16 range); with BC ahead of JSL in the search order, a JSL CCM
 * cipher's own default 8-byte tag became unreadable from its own parameters.</p>
 *
 * <p>The caller passes the provider its SPI belongs to (from
 * {@code DefaultServiceNI.providerName()}), so a JSLFIPS cipher's parameters
 * come from JSLFIPS even when JSL is registered alongside it. Both providers
 * register the same {@code CCM} and {@code GCM} codecs — pure-Java encoding
 * classes, no cryptography and no native binding — so the fallback is a
 * functional no-op; it exists so a single-provider deployment still resolves
 * if the SPI's own provider is somehow unregistered.</p>
 */
final class JostleAlgorithmParameters
{
    /**
     * Name of the FIPS provider. A string literal rather than a reference to
     * {@code JostleFIPSProvider.PROVIDER_NAME} would risk drift; the constant
     * reference is a compile-time String constant, so it does NOT trigger
     * that class's initialisation (which performs the native FIPS load).
     */
    private static final String FIPS_PROVIDER_NAME =
            org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider.PROVIDER_NAME;

    private JostleAlgorithmParameters()
    {
    }

    /**
     * @param algorithm    a parameters algorithm both Jostle providers register
     *                     (e.g. "CCM", "GCM").
     * @param providerName the provider the calling SPI belongs to.
     * @return an instance from {@code providerName}, or from the other Jostle
     * provider if that one is not registered.
     * @throws NoSuchAlgorithmException when neither Jostle provider is
     *                                  registered in this JVM (also covers the
     *                                  never-expected case of a registered
     *                                  Jostle provider lacking the algorithm).
     */
    static AlgorithmParameters getInstance(String algorithm, String providerName) throws NoSuchAlgorithmException
    {
        try
        {
            return AlgorithmParameters.getInstance(algorithm, providerName);
        }
        catch (NoSuchProviderException e)
        {
            // The SPI's own provider is not registered — fall through.
        }

        String other = JostleProvider.PROVIDER_NAME.equals(providerName)
                ? FIPS_PROVIDER_NAME : JostleProvider.PROVIDER_NAME;
        try
        {
            return AlgorithmParameters.getInstance(algorithm, other);
        }
        catch (NoSuchProviderException e)
        {
            throw new NoSuchAlgorithmException(
                    "no Jostle provider registered to supply AlgorithmParameters." + algorithm, e);
        }
    }
}
