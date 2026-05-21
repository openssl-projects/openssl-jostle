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
     * <li>Otherwise a strength-appropriate default is fetched via
     *     {@link CryptoServicesRegistrar#getSecureRandom(int)} and
     *     {@code current} is replaced (reusing it if it happens to
     *     already wrap the same default).</li>
     * </ol>
     *
     * <p>Java 8 baseline note: {@link #getStrength()} always returns
     * {@code 0} here because the Java 8 API can't introspect a DRBG's
     * configured strength. The reuse path therefore only fires via
     * identity-equality of the underlying SecureRandom in branch 1
     * (caller-supplied) and branch 3 (cached default). The Java 9+
     * multi-release override of this class returns the actual DRBG
     * strength, which makes branch 2 effective and avoids the per-call
     * allocation.
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


    @Override
    public int getRandomBytes(byte[] out, int len, int strength, boolean predictionResistant)
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

    /**
     * Java 8 baseline returns {@code 0} (strength unknown) — the
     * {@code DrbgParameters} API needed to introspect a SecureRandom's
     * configured strength is Java 9+. The Java 9+ multi-release
     * override reports the actual DRBG strength.
     */
    @Override
    public int getStrength()
    {
        return 0;
    }


    /**
     * Inspect the reported security strength of an externally-supplied
     * {@link SecureRandom}. Returns {@code 0} when the strength cannot
     * be determined.
     *
     * <p>Used by SPIs to fail fast at {@code initialize} when a caller
     * passes a SecureRandom whose reported strength is insufficient
     * for the algorithm — surfacing an {@code InvalidAlgorithmParameterException}
     * with a useful message instead of letting the C-side RAND gate
     * surface a generic OpenSSL error at first {@code generate*} call.
     *
     * <p>Java 8 baseline always returns {@code 0}: the {@code DrbgParameters}
     * API needed to introspect a SecureRandom's configured strength is
     * Java 9+, and there is no other portable way to query it. Callers
     * should treat {@code 0} as "unknown — don't reject" rather than
     * "insufficient": rejecting on unknown would break legitimate uses
     * of custom or plain {@code new SecureRandom()} instances, and the
     * C-side RAND gate is still the safety net for genuinely-weak
     * sources passed through unchecked.
     *
     * @param rand the SecureRandom to inspect; {@code null} returns 0.
     * @return reported strength in bits, or {@code 0} if unknown.
     */
    public static int strengthOf(SecureRandom rand)
    {
        return 0;
    }


}
