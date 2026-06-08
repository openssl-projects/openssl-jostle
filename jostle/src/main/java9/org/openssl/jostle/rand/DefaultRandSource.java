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
     * Strength-aware variant of {@link #replaceWith(RandSource, SecureRandom)}.
     *
     * <p>Reuses {@code current} when it already satisfies the request, to
     * avoid allocating a new {@link DefaultRandSource} on every call.
     * The decision matrix:
     *
     * <ol>
     * <li>If the caller supplied a non-null {@code userRand}, that is
     *     the source of truth — the returned RandSource wraps it
     *     as-is regardless of strength (the caller has taken
     *     responsibility for the RNG). {@code current} is reused if
     *     it's already wrapping the same SecureRandom instance.</li>
     * <li>If {@code userRand} is null and {@code current}'s reported
     *     strength is already at least {@code requiredStrengthBits},
     *     {@code current} is returned unchanged.</li>
     * <li>Otherwise a strength-appropriate default DRBG is fetched via
     *     {@link CryptoServicesRegistrar#getSecureRandom(int)} (which
     *     on Java 9+ constructs a DRBG via {@code DrbgParameters})
     *     and {@code current} is replaced.</li>
     * </ol>
     *
     * @param current the existing RandSource (may be {@code null}).
     * @param userRand the caller-supplied SecureRandom, or {@code null}
     *                 to use a strength-appropriate default.
     * @param requiredStrengthBits minimum strength required; consulted
     *                             only when {@code userRand} is null.
     * @return {@code current} (unchanged) or a fresh DefaultRandSource.
     */
    public static RandSource replaceWith(RandSource current, SecureRandom userRand, int requiredStrengthBits)
    {
        if (userRand != null)
        {
            // Caller-supplied source — wrap as-is.
            if (current instanceof DefaultRandSource && ((DefaultRandSource) current).random == userRand)
            {
                return current;
            }
            return new DefaultRandSource(userRand);
        }

        // No caller-supplied random. Reuse current if it already meets
        // the strength requirement.
        if (current instanceof DefaultRandSource && current.getStrength() >= requiredStrengthBits)
        {
            return current;
        }

        SecureRandom defaultRand = CryptoServicesRegistrar.getSecureRandom(requiredStrengthBits);
        if (current instanceof DefaultRandSource && ((DefaultRandSource) current).random == defaultRand)
        {
            return current;
        }
        return new DefaultRandSource(defaultRand);
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

    /**
     * Returns the strength (in bits) extracted from the underlying
     * SecureRandom's {@link DrbgParameters.Instantiation}, or {@code 0}
     * if the SecureRandom was not constructed with DrbgParameters.
     */
    @Override
    public int getStrength()
    {
        return strength;
    }


    /**
     * Inspect the reported security strength of an externally-supplied
     * {@link SecureRandom}.
     *
     * <p>Returns the {@code DrbgParameters.Instantiation.getStrength()}
     * value when {@code rand} was constructed via {@code DrbgParameters}
     * (which is the case for {@code SecureRandom.getInstance("DRBG", ...)});
     * returns {@code 0} for plain {@code new SecureRandom()}, legacy
     * SHA1PRNG instances, or any custom subclass that doesn't expose a
     * {@code DrbgParameters} configuration.
     *
     * <p>Used by SPIs to fail fast at {@code initialize} when a caller
     * passes a SecureRandom whose reported strength is insufficient
     * for the algorithm. Callers should treat {@code 0} as "unknown —
     * don't reject" rather than "insufficient": rejecting on unknown
     * would break legitimate uses of plain {@code new SecureRandom()}
     * or custom subclasses, and the C-side RAND gate remains the
     * safety net for those.
     *
     * @param rand the SecureRandom to inspect; {@code null} returns 0.
     * @return reported strength in bits, or {@code 0} if unknown.
     */
    public static int strengthOf(SecureRandom rand)
    {
        if (rand == null)
        {
            return 0;
        }
        SecureRandomParameters params = rand.getParameters();
        if (params instanceof DrbgParameters.Instantiation)
        {
            return ((DrbgParameters.Instantiation) params).getStrength();
        }
        return 0;
    }
}
