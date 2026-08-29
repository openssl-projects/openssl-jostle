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

package org.openssl.jostle.jcajce.provider;

import org.openssl.jostle.jcajce.provider.rand.RandAlgorithm;
import org.openssl.jostle.jcajce.provider.rand.RandServiceSPI;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandomParameters;
import java.util.HashMap;
import java.util.Map;

class ProvRand
{

    public void configure(final JostleProvider provider)
    {
        final Map<String, String> attr = new HashMap<String, String>();
        attr.put("ThreadSafe", "true");

        for (RandAlgorithm algorithm : RandAlgorithm.values())
        {
            addRand(provider, algorithm, attr);
        }
        provider.addAlias("SecureRandom", RandAlgorithm.DRBG.getJcaName(), "DEFAULT");
    }

    private static void addRand(final JostleProvider provider, RandAlgorithm algorithm, Map<String, String> attr)
    {
        String name = algorithm.getJcaName();
        provider.addAlgorithmImplementation("SecureRandom", name,
                RandServiceSPI.class.getName(), attr,
                (arg) -> createInstance(algorithm, arg));
    }

    private static RandServiceSPI createInstance(RandAlgorithm algorithm, Object arg)
            throws NoSuchAlgorithmException
    {
        if (arg == null)
        {
            return new RandServiceSPI(algorithm);
        }

        if (arg instanceof SecureRandomParameters)
        {
            return new RandServiceSPI(algorithm, (SecureRandomParameters) arg);
        }

        throw new NoSuchAlgorithmException("SecureRandom parameters must implement SecureRandomParameters");
    }
}
