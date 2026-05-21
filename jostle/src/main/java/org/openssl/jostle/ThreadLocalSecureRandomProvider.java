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

import java.security.SecureRandom;

/**
 * Default {@link SecureRandomProvider} backing
 * {@link CryptoServicesRegistrar#getSecureRandom()}. Caches a
 * {@code new SecureRandom()} per thread to amortise its seeding cost.
 *
 * <p>The Java 8 baseline cannot programmatically request a specific
 * DRBG strength via {@code DrbgParameters} (Java 9+ API), so
 * {@link #get(int)} inherits the default that delegates back to
 * {@link #get()}. The Java 9+ multi-release override in
 * {@code src/main/java9/} constructs a DRBG with the requested strength.
 */
class ThreadLocalSecureRandomProvider implements SecureRandomProvider
{
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
}
