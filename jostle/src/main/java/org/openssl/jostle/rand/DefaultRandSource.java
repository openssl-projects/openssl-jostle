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

package org.openssl.jostle.rand;

import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.jcajce.provider.ErrorCode;

import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;

public class DefaultRandSource implements RandSource
{
    Logger LOG = Logger.getLogger("DefaultEntropyProvider(Java 8)");
    private final SecureRandom random;

    public static DefaultRandSource wrap(SecureRandom random)
    {
        return new DefaultRandSource(random);
    }

    public DefaultRandSource(SecureRandom secureRandom)
    {
        this.random = secureRandom;

        if (LOG.isLoggable(Level.FINE))
        {
            LOG.fine("SecureRandom does not have DrbgParameters, DefaultEntropyProvider will not assert strength or prediction resistance");
        }
    }

    /**
     * Return this or a new instance if the passed-in SecureRandom is different from the one used by this instance.
     *
     * @param secureRandom the SecureRandom to use.
     * @return this or a new instance if the passed-in SecureRandom is different from the one used by this instance.
     */
    public static RandSource replaceWith(RandSource randSource, SecureRandom secureRandom)
    {
        //
        // Use default if secureRandom is null.
        //
        secureRandom = CryptoServicesRegistrar.getSecureRandom(secureRandom);

        if (randSource instanceof DefaultRandSource)
        {
            if (((DefaultRandSource) randSource).random == secureRandom)
            {
                // Unchanged
                return randSource;
            }
        }

        return new DefaultRandSource(secureRandom);

    }


    @Override
    public int getEntropy(byte[] out, int len, int strength, boolean predictionResistant)
    {

        try
        {
            if (out == null)
            {
                throw new IllegalArgumentException("out is null");
            }
            if (out.length != len)
            {
                throw new IllegalArgumentException("out.length != len");
            }

            random.nextBytes(out);
        }
        catch (Throwable e)
        {
            //
            // JVM may shut down ungracefully if anything is cased to throw during an upcall.
            // Catch and log but return error code to indicate failure and fail elsewhere.
            //
            LOG.log(Level.SEVERE, "getInfo INFO_TYPE_ENTROPY", e);
            return ErrorCode.JO_RAND_ERROR.getCode();
        }
        return len;
    }

    @Override
    public SecureRandom getRandom()
    {
        return random;
    }


}
