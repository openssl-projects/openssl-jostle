/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle;

import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.util.Properties;

import java.security.SecureRandom;
import java.util.concurrent.atomic.AtomicReference;

public class CryptoServicesRegistrar
{

    private static final SecureRandomProvider defaultRandomProviderImpl = new ThreadLocalSecureRandomProvider();
    private static final AtomicReference<SecureRandomProvider> defaultSecureRandomProvider = new AtomicReference<SecureRandomProvider>();

    /**
     * System / {@code java.security} property that gates the provider-backed
     * SecureRandom check in {@link #resolveProviderRandom(SecureRandom, SecureRandom)}.
     * Defaults to {@code true}. Set to {@code false} to let a
     * provider-bound (e.g. FIPS) service honour a caller-supplied SecureRandom
     * verbatim even when it is not backed by that provider — needed if you
     * deliberately drive a JSLFIPS operation with a DRBG from a different
     * FIPS-validated provider (BCFIPS, SunPKCS11), which this check cannot
     * recognise (there is no portable "is this SecureRandom FIPS?" query).
     */
    public static final String ENFORCE_PROVIDER_RANDOM = "org.openssl.jostle.fips.enforce_provider_random";

    // Read once during static init; defaults to true when the property is unset.
    private static final boolean enforceProviderRandom = Properties.isOverrideSet(ENFORCE_PROVIDER_RANDOM, true);


    static
    {
        Loader.load();
    }

    public static boolean isNativeAvailable()
    {
        return Loader.isLoadSuccessful() && NISelector.NativeServiceNI.isNativeAvailable();
    }

    public static void assertNativeAvailable()
    {

        if (!isNativeAvailable())
        {
            throw new IllegalStateException("no access to native library");
        }
    }


    public String getOpenSSLVersion()
    {
        return NISelector.NativeServiceNI.getOpenSSLVersion();
    }

    /**
     * Return the default source of randomness.
     *
     * @return the default SecureRandom
     */
    public static SecureRandom getSecureRandom()
    {
        defaultSecureRandomProvider.compareAndSet(null, defaultRandomProviderImpl);
        return defaultSecureRandomProvider.get().get();
    }

    /**
     * Return either the passed-in SecureRandom, or if it is null, then the default source of randomness.
     *
     * @param secureRandom the SecureRandom to use if it is not null.
     * @return the SecureRandom parameter if it is not null, or else the default SecureRandom
     */
    public static SecureRandom getSecureRandom(SecureRandom secureRandom)
    {
        return null == secureRandom ? getSecureRandom() : secureRandom;
    }

    /**
     * Return a {@link SecureRandom} whose reported security strength is
     * at least {@code requiredStrengthBits}.
     *
     * <p>Delegates to the current {@link SecureRandomProvider}'s
     * {@link SecureRandomProvider#get(int)} — the default
     * {@link ThreadLocalSecureRandomProvider} has a Java 9+ override
     * that constructs a DRBG via {@code DrbgParameters.instantiation}.
     * The Java 8 baseline inherits the default {@code get(int)} which
     * returns the regular {@link #getSecureRandom()} default.
     *
     * <p>Used by the post-quantum SPIs (ML-KEM, ML-DSA, SLH-DSA) to
     * obtain a default RNG that satisfies the algorithm's required
     * security category — without this, ML-KEM-768 (192-bit strength)
     * and ML-KEM-1024 (256-bit strength) keygen / encap calls fail
     * against the JDK's default 128-bit DRBG (GH issue #34).
     *
     * @param requiredStrengthBits desired minimum strength in bits
     *                             (typically 128, 192, or 256).
     * @return a SecureRandom suitable for use as the default source
     *         of randomness for an operation requiring at least the
     *         given strength.
     */
    public static SecureRandom getSecureRandom(int requiredStrengthBits)
    {
        defaultSecureRandomProvider.compareAndSet(null, defaultRandomProviderImpl);
        return defaultSecureRandomProvider.get().get(requiredStrengthBits);
    }

    /**
     * Whether the provider-backed SecureRandom check is enforced (the default).
     * Controlled by the {@link #ENFORCE_PROVIDER_RANDOM} property, read once at
     * class initialisation.
     *
     * @return true unless the property was set to false at JVM start-up.
     */
    public static boolean isProviderRandomEnforced()
    {
        return enforceProviderRandom;
    }

    /**
     * Resolve the {@link SecureRandom} a provider-bound service should use for
     * key/IV bytes it draws in Java, keeping that entropy inside the provider's
     * boundary when the check is enforced.
     *
     * <p>{@code providerRandom} is the service's own provider-supplied default
     * (for JSLFIPS, the FIPS module's DRBG obtained via
     * {@code SecureRandom.getInstance("DEFAULT", jslfips)}). Resolution:
     * <ol>
     *   <li>{@code providerRandom == null} — the service is not provider-bound
     *       (e.g. the non-FIPS provider); standard JCE resolution via
     *       {@link #getSecureRandom(SecureRandom)}.</li>
     *   <li>{@code supplied == null} — no caller random; use {@code providerRandom}.</li>
     *   <li>check disabled ({@link #isProviderRandomEnforced()} false) — honour
     *       {@code supplied} verbatim.</li>
     *   <li>otherwise — honour {@code supplied} only when it is backed by the
     *       same {@link java.security.Provider} as {@code providerRandom}
     *       (via {@link SecureRandom#getProvider()}); else fall back to
     *       {@code providerRandom} so the bytes stay inside the boundary.</li>
     * </ol>
     * {@code getProvider()} is the only portable handle on a SecureRandom's
     * backing (the {@code SecureRandomSpi} is not exposed); it recognises this
     * provider's own DRBG but not an arbitrary third-party FIPS DRBG — which is
     * why {@link #ENFORCE_PROVIDER_RANDOM} exists as an escape hatch.
     *
     * @param supplied       the caller-supplied SecureRandom (may be null).
     * @param providerRandom the service's provider-supplied default (null if the
     *                       service is not provider-bound).
     * @return the SecureRandom to draw from.
     */
    public static SecureRandom resolveProviderRandom(SecureRandom supplied, SecureRandom providerRandom)
    {
        return resolveProviderRandom(supplied, providerRandom, enforceProviderRandom);
    }

    /**
     * Explicit-flag variant of {@link #resolveProviderRandom(SecureRandom, SecureRandom)}
     * so the resolution logic can be exercised independently of the
     * statically-read {@link #ENFORCE_PROVIDER_RANDOM} property.
     *
     * @param supplied       the caller-supplied SecureRandom (may be null).
     * @param providerRandom the service's provider-supplied default (may be null).
     * @param enforce        whether to require {@code supplied} to be
     *                       provider-backed.
     * @return the SecureRandom to draw from.
     */
    public static SecureRandom resolveProviderRandom(SecureRandom supplied, SecureRandom providerRandom, boolean enforce)
    {
        if (providerRandom == null)
        {
            // Not provider-bound (e.g. the non-FIPS provider): standard JCE resolution.
            return getSecureRandom(supplied);
        }
        if (supplied == null)
        {
            // No caller-supplied random: use the provider's own DRBG.
            return providerRandom;
        }
        if (!enforce)
        {
            // Check disabled: honour the caller's SecureRandom verbatim.
            return supplied;
        }
        if (supplied.getProvider() != null && supplied.getProvider() == providerRandom.getProvider())
        {
            // Caller's random is backed by the same provider — honour it.
            return supplied;
        }
        // Not provider-backed: keep the bytes inside the boundary.
        return providerRandom;
    }


    /**
     * Set a default secure random provider to be used where none is otherwise provided.
     *
     * @param secureRandomProvider a provider SecureRandom to use when a default SecureRandom is requested.
     */
    public static void setSecureRandomProvider(SecureRandomProvider secureRandomProvider)
    {
        defaultSecureRandomProvider.set(secureRandomProvider);
    }


    /**
     * Set a default secure random to be used where none is otherwise provided.
     *
     * @param secureRandom the SecureRandom to use as the default.
     */
    public static void setSecureRandom(final SecureRandom secureRandom)
    {

        if (secureRandom == null)
        {
            defaultSecureRandomProvider.set(defaultRandomProviderImpl);
        }
        else
        {
            defaultSecureRandomProvider.set(new SecureRandomProvider()
            {
                public SecureRandom get()
                {
                    return secureRandom;
                }
            });
        }
    }
}
