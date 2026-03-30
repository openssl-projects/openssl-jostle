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

import java.security.SecureRandom;
import java.util.concurrent.atomic.AtomicReference;

public class CryptoServicesRegistrar
{

    private static final SecureRandomProvider defaultRandomProviderImpl = new ThreadLocalSecureRandomProvider();
    private static final AtomicReference<SecureRandomProvider> defaultSecureRandomProvider = new AtomicReference<SecureRandomProvider>();


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


    private static class ThreadLocalSecureRandomProvider
            implements SecureRandomProvider
    {
        final ThreadLocal<SecureRandom> defaultRandoms = new ThreadLocal<SecureRandom>();

        public SecureRandom get()
        {
            if (defaultRandoms.get() == null)
            {
                SecureRandom rand = new SecureRandom();
                defaultRandoms.set(rand);
            }

            return defaultRandoms.get();
        }
    }
}
