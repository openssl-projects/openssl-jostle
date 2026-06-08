/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle;

import java.security.DrbgParameters;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Java 9+ multi-release override of {@link ThreadLocalSecureRandomProvider}.
 *
 * <p>Identical public surface to the Java 8 baseline (CLAUDE.md
 * multi-release ABI stability rule). The override implements
 * {@link #get(int)} via {@code SecureRandom.getInstance("DRBG", DrbgParameters.instantiation(...))}
 * so the post-quantum SPIs can satisfy their security-category
 * requirements without an explicit caller-supplied SecureRandom
 * (GH issue #34).
 */
class ThreadLocalSecureRandomProvider implements SecureRandomProvider
{
    private static final Logger LOG = Logger.getLogger(ThreadLocalSecureRandomProvider.class.getName());

    final ThreadLocal<SecureRandom> defaultRandoms = new ThreadLocal<SecureRandom>();

    @Override
    public SecureRandom get()
    {
        if (defaultRandoms.get() == null)
        {
            SecureRandom rand = new SecureRandom();
            defaultRandoms.set(rand);
        }

        return defaultRandoms.get();
    }

    /**
     * Construct a fresh DRBG-backed {@link SecureRandom} at the
     * requested strength via {@code DrbgParameters.instantiation}.
     *
     * <p>Tries {@code PR_AND_RESEED} first, falls back to {@code NONE}
     * if the platform DRBG doesn't expose prediction-resistance at
     * that strength, finally falls back to {@link #get()} if the
     * platform can't construct a strength-targeted DRBG at all — the
     * native RAND bridge surfaces an {@code JO_RAND_INSUFFICIENT_STRENGTH}
     * error at first use in that last case, rather than silently
     * producing weaker output.
     *
     * @param strengthBits desired minimum strength in bits.
     * @return a DRBG-backed SecureRandom at the requested strength,
     *         or the regular {@link #get()} default on platform
     *         failure.
     */
    @Override
    public SecureRandom get(int strengthBits)
    {
        try
        {
            return SecureRandom.getInstance("DRBG",
                    DrbgParameters.instantiation(
                            strengthBits,
                            DrbgParameters.Capability.PR_AND_RESEED,
                            null));
        }
        catch (NoSuchAlgorithmException e)
        {
            // First fallback: DRBG without prediction resistance.
            try
            {
                return SecureRandom.getInstance("DRBG",
                        DrbgParameters.instantiation(
                                strengthBits,
                                DrbgParameters.Capability.NONE,
                                null));
            }
            catch (NoSuchAlgorithmException e2)
            {
                // Platform doesn't expose a strength-targeted DRBG.
                // Log and return the regular default — the native
                // RAND bridge will surface the resulting strength gap.
                LOG.log(Level.WARNING,
                        "Platform DRBG does not accept requested strength "
                                + strengthBits
                                + " bits; falling back to default SecureRandom",
                        e2);
                return get();
            }
        }
    }
}
