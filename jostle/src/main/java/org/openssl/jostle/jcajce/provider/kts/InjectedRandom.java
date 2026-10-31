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

package org.openssl.jostle.jcajce.provider.kts;

import org.openssl.jostle.rand.DefaultRandSource;

import javax.crypto.KeyGenerator;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.Provider;
import java.security.SecureRandom;

/**
 * Tells the SecureRandom the JCE injects into a javax.crypto init (when the caller passes none) from one the caller
 * chose. The framework hands every such init one process-wide object, captured through this provider's own ML-KEM
 * KeyGenerator: init(int) reaches engineInit(int, SecureRandom) with that object while this thread's probe flag is
 * set, and only then is it recorded. The JDK replaces that object whenever the provider list changes, so a source
 * that is not the recorded one is judged only after a fresh capture. Shared by the ML-KEM and hybrid KEM SPIs; the
 * package is not exported.
 */
public final class InjectedRandom
{
    private static final Object LOCK = new Object();
    private static final ThreadLocal<Boolean> PROBING = new ThreadLocal<Boolean>();
    private static final ThreadLocal<Boolean> LAST_INIT_SAW_DEFAULT = new ThreadLocal<Boolean>();
    private static volatile SecureRandom injected;

    private InjectedRandom()
    {
    }

    /** True only while this thread runs the capture probe. */
    public static boolean probing()
    {
        return Boolean.TRUE.equals(PROBING.get());
    }

    /** Records the object the framework injected into the probe's init. */
    public static void record(SecureRandom random)
    {
        injected = random;
    }

    /**
     * Resolves the source an encapsulating init draws from. The injected default means none was supplied: null is
     * returned, so the provider's own DRBG at the required strength is used. A source reporting a strength below
     * {@code requiredBits} is refused; one reporting none or enough is returned as given.
     */
    public static SecureRandom resolve(SecureRandom random, Provider provider, String name, int requiredBits)
        throws InvalidAlgorithmParameterException
    {
        boolean sawDefault = random != null && isInjectedDefault(random, provider);
        LAST_INIT_SAW_DEFAULT.set(sawDefault);
        if (random == null || sawDefault)
        {
            return null;
        }
        int supplied = DefaultRandSource.strengthOf(random);
        if (supplied > 0 && supplied < requiredBits)
        {
            throw new InvalidAlgorithmParameterException("supplied SecureRandom reports " + supplied
                    + "-bit strength but " + name + " requires " + requiredBits + "; pass a SecureRandom of at least "
                    + requiredBits + " bits");
        }
        return random;
    }

    /** Whether this thread's last encapsulating init recognised the injected default. Read by tests. */
    public static boolean lastInitSawInjectedDefault()
    {
        return Boolean.TRUE.equals(LAST_INIT_SAW_DEFAULT.get());
    }

    private static boolean isInjectedDefault(SecureRandom random, Provider provider)
    {
        if (random == injected)
        {
            return true;
        }
        if (provider == null)
        {
            return false;
        }
        synchronized (LOCK)
        {
            if (random != injected)
            {
                PROBING.set(Boolean.TRUE);
                try
                {
                    KeyGenerator.getInstance("ML-KEM", provider).init(256);
                }
                catch (GeneralSecurityException e)
                {
                    // No ML-KEM KeyGenerator on this provider: nothing is recognised as injected.
                }
                finally
                {
                    PROBING.remove();
                }
            }
            return random == injected;
        }
    }
}
