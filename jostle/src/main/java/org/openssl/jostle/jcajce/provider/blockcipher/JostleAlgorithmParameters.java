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
 * Name-based resolution of an {@link AlgorithmParameters} from a Jostle
 * provider, for callers that have no provider INSTANCE to pin.
 *
 * <p>Since MT-18 the only such caller is a directly-constructed SPI (MT-14's
 * unbound realm). Everything reached through a provider resolves by instance
 * instead — see {@code BlockCipherSpi.resolveParameters}, which also records
 * why the pin matters.
 *
 * <p>The cross-Jostle fallback exists so a single-provider deployment still
 * resolves when the SPI's own provider is unregistered; both providers
 * register the same pure-Java codecs, so it is a functional no-op.
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
