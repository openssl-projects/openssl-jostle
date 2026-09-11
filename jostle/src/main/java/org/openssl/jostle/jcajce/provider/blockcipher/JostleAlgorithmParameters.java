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

import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * Name-based resolution of an {@link AlgorithmParameters} from the SPI's OWN
 * Jostle provider, for callers that have no provider INSTANCE to pin.
 *
 * <p>The only such caller is a directly-constructed SPI (MT-14's unbound
 * realm). Everything reached through a provider resolves by instance instead —
 * see {@code BlockCipherSpi.resolveParameters}, which records why the pin
 * matters.
 *
 * <p>Resolution is to the named provider or nowhere. The fallback to the other
 * Jostle provider was removed 2026-09-11 with zero measured reach (85
 * registered Cipher services, none unbound); a JSLFIPS-named SPI served by JSL
 * is the crossing MT-10 and MT-14 refuse.
 */
final class JostleAlgorithmParameters
{
    private JostleAlgorithmParameters()
    {
    }

    /**
     * @param algorithm    a parameters algorithm the named provider registers
     *                     (e.g. "CCM", "GCM").
     * @param providerName the provider the calling SPI belongs to.
     * @return an instance from {@code providerName}.
     * @throws NoSuchAlgorithmException when that provider is not registered in
     *                                  this JVM, or does not serve the
     *                                  algorithm.
     */
    static AlgorithmParameters getInstance(String algorithm, String providerName) throws NoSuchAlgorithmException
    {
        try
        {
            return AlgorithmParameters.getInstance(algorithm, providerName);
        }
        catch (NoSuchProviderException e)
        {
            throw new NoSuchAlgorithmException(
                    "provider " + providerName + " is not registered, so AlgorithmParameters."
                            + algorithm + " cannot come from the provider this cipher belongs to", e);
        }
    }
}
