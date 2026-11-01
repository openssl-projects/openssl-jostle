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

package org.openssl.jostle.test.cert;

import org.junit.jupiter.api.Assertions;

import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;

/**
 * The global provider registry as it was, put back exactly on close and the restoration asserted: a cell that
 * leaves the registry changed fails unrelated classes later in the same JVM, and forkEvery does not contain it.
 */
public final class ProviderRegistrySnapshot
    implements AutoCloseable
{
    private final Provider[] original = Security.getProviders();

    /** Empties the registry and asserts it is empty. */
    public static void empty()
    {
        for (Provider installed : Security.getProviders())
        {
            Security.removeProvider(installed.getName());
        }
        Assertions.assertEquals(0, Security.getProviders().length, "the registry was not emptied");
    }

    /** Puts {@code provider} at position 1, removing any provider of its name first, and asserts it is first. */
    public static void insertFirst(Provider provider)
    {
        insertAt(provider, 1);
    }

    /** Puts {@code provider} at the 1-based {@code position}, removing any provider of its name first. */
    public static void insertAt(Provider provider, int position)
    {
        Security.removeProvider(provider.getName());
        Assertions.assertEquals(position, Security.insertProviderAt(provider, position),
                provider.getName() + " did not land at position " + position);
        Assertions.assertSame(provider, Security.getProviders()[position - 1]);
    }

    /** Appends {@code provider}, removing any provider of its name first, and asserts it is installed. */
    public static void append(Provider provider)
    {
        Security.removeProvider(provider.getName());
        Security.addProvider(provider);
        Assertions.assertSame(provider, Security.getProvider(provider.getName()));
    }

    @Override
    public void close()
        throws Exception
    {
        for (Provider installed : Security.getProviders())
        {
            Security.removeProvider(installed.getName());
        }
        // insertProviderAt is 1-based and preserves precedence; addProvider appends.
        for (int i = 0; i < original.length; i++)
        {
            Security.insertProviderAt(original[i], i + 1);
        }

        Provider[] restored = Security.getProviders();
        Assertions.assertEquals(original.length, restored.length, "provider count not restored");
        for (int i = 0; i < original.length; i++)
        {
            Assertions.assertSame(original[i], restored[i], "provider at position " + i + " not restored");
        }
        Assertions.assertDoesNotThrow(() -> SecureRandom.getInstance("SHA1PRNG"),
                "SHA1PRNG is unavailable after the restore");
    }
}
