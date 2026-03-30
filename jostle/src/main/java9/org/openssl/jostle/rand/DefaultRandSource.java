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

import java.security.DrbgParameters;
import java.security.SecureRandom;
import java.security.SecureRandomParameters;
import java.util.logging.Level;
import java.util.logging.Logger;

public class DefaultRandSource implements RandSource
{
    Logger LOG = Logger.getLogger("DefaultEntropyProvider(Java 9+)");
    private final SecureRandom random;
    protected final boolean assertConditions;
    protected final int strength;
    protected final boolean rngSupportsPredictionResistant;
    protected final boolean rngSupportsReseed;

    public static DefaultRandSource wrap(SecureRandom random)
    {
        return new DefaultRandSource(random);
    }

    protected DefaultRandSource(SecureRandom secureRandom)
    {
        this(secureRandom, secureRandom.getParameters());
    }

    protected DefaultRandSource(SecureRandom secureRandom, SecureRandomParameters params)
    {
        if (params instanceof DrbgParameters.Instantiation)
        {
            DrbgParameters.Instantiation ins = (DrbgParameters.Instantiation) params;

            assertConditions = true;
            strength = ins.getStrength();
            rngSupportsPredictionResistant = ins.getCapability().supportsPredictionResistance();
            rngSupportsReseed = ins.getCapability().supportsReseeding();

            if (LOG.isLoggable(Level.FINE))
            {
                LOG.fine("DefaultEntropyProvider will assert strength of prediction resistance");
            }
        }
        else
        {
            assertConditions = false;
            this.strength = 0;
            this.rngSupportsPredictionResistant = false;
            this.rngSupportsReseed = false;
            if (LOG.isLoggable(Level.FINE))
            {
                LOG.fine("SecureRandom does not have DrbgParameters, DefaultEntropyProvider will not assert strength or prediction resistance");
            }
        }

        this.random = secureRandom;

    }


    protected DefaultRandSource(SecureRandom secureRandom, boolean assertConditions, int strength, boolean rngSupportsPredictionResistant, boolean rngSupportsReseed)
    {
        this.random = secureRandom;
        this.assertConditions = assertConditions;
        this.strength = strength;
        this.rngSupportsPredictionResistant = rngSupportsPredictionResistant;
        this.rngSupportsReseed = rngSupportsReseed;


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


    /**
     * Return this or a new instance if the passed-in SecureRandom is different from the one used by this instance.
     *
     * @param secureRandom the SecureRandom to use.
     * @return this or a new instance if the passed-in SecureRandom is different from the one used by this instance.
     */
    public DefaultRandSource replaceWith(SecureRandom secureRandom)
    {
        if (this.random != secureRandom)
        {
            return new DefaultRandSource(secureRandom);
        }
        return this;
    }

    @Override
    public int getRandomBytes(byte[] out, int len, int strength, boolean predictionResistant)
    {
        if (assertConditions)
        {
            if (strength > this.strength)
            {
                LOG.warning(String.format("Insufficient strength: required %d but source strength is %d", strength, this.strength));
                return ErrorCode.JO_RAND_INSUFFICIENT_STRENGTH.getCode();
            }

            if (predictionResistant) // OpenSSL requested prediction resistance
            {
                if (!this.rngSupportsPredictionResistant)
                {
                    // DRBG does not support prediction resistance
                    if (!this.rngSupportsReseed)
                    {
                        //
                        // DRBG does not support reseeding
                        // So fail
                        //
                        LOG.warning("OpenSSL requested prediction resistance but DRBG does not support it or reseeding");
                        return ErrorCode.JO_RAND_NO_RESEED.getCode();
                    }
                    random.reseed();
                }
            }

        }


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
