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
import java.util.HashMap;
import java.util.Map;

class ProvRand
{
    private static final String PREFIX = ProvRand.class.getPackage().getName() + ".rand.";

    public void configure(final JostleProvider provider)
    {
        final Map<String, String> attr = new HashMap<String, String>();
        attr.put("ThreadSafe", "true");

        addRand(provider, RandAlgorithm.DRBG, attr);
    }

    private static void addRand(final JostleProvider provider, RandAlgorithm algorithm, Map<String, String> attr)
    {
        String name = algorithm.getJcaName();
        String clName = name.replace("-", "_").replace("/", "_");
        provider.addAlgorithmImplementation("SecureRandom", name,
                PREFIX + "RandServiceSPI$" + clName, attr,
                (arg) -> createInstance(algorithm, arg));
    }

    private static RandServiceSPI createInstance(RandAlgorithm algorithm, Object arg)
            throws NoSuchAlgorithmException
    {
        if (arg != null)
        {
            throw new NoSuchAlgorithmException("SecureRandom parameters are not supported");
        }

        return new RandServiceSPI(algorithm);
    }
}
