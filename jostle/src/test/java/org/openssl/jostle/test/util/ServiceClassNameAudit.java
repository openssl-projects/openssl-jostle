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

package org.openssl.jostle.test.util;

import org.junit.jupiter.api.Assertions;

import java.security.Provider;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

/**
 * {@code Provider.Service.getClassName()} must name the class {@code
 * newInstance} actually returns.
 *
 * <p>Two arms, and the second is the load-bearing one. Loadability alone
 * passes a name that resolves to a REAL class the service never constructs, so
 * the check is IDENTITY of the loaded class with the runtime class of the
 * constructed instance, not assignability: a superclass and a subclass both
 * satisfy assignability while misreporting what a caller gets.
 *
 * <p>{@code JoService} overrides {@code newInstance} and returns the creator's
 * object unwrapped, so identity is achievable everywhere; no service needs an
 * exemption. Should a future service wrap its instance, surface it here rather
 * than weakening the arm to assignability.
 *
 * <p>The class name is resolved through the PROVIDER's class loader, not the
 * test's — that is the loader JCA's own default {@code Service.newInstance}
 * would use, so a mismatch here is a mismatch a third-party enumerator sees.
 */
public final class ServiceClassNameAudit
{
    private ServiceClassNameAudit()
    {
    }

    /**
     * @param provider the provider to audit
     * @param floor    minimum service count; below it the sweep would pass
     *                 vacuously. Per-provider, never shared — JSL and JSLFIPS
     *                 register very different numbers, and a gated module
     *                 registers fewer still.
     */
    public static void assertEveryClassNameNamesItsOwnClass(Provider provider, int floor)
    {
        Assertions.assertNotNull(provider, "provider must be registered");

        Set<Provider.Service> services = provider.getServices();
        Assertions.assertTrue(services.size() >= floor,
                provider.getName() + ": only " + services.size() + " services registered, expected at least "
                        + floor + " — the sweep would pass vacuously");

        List<String> phantom = new ArrayList<String>();
        List<String> mismatched = new ArrayList<String>();
        List<String> unconstructible = new ArrayList<String>();

        ClassLoader loader = provider.getClass().getClassLoader();

        for (Provider.Service s : services)
        {
            String where = s.getType() + "." + s.getAlgorithm();
            String cn = s.getClassName();

            if (cn == null)
            {
                phantom.add(where + " -> <null class name>");
                continue;
            }

            Class<?> declared;
            try
            {
                declared = Class.forName(cn, false, loader);
            }
            catch (Throwable t)
            {
                phantom.add(where + " -> " + cn + " (" + t.getClass().getSimpleName() + ")");
                continue;
            }

            Object instance;
            try
            {
                instance = s.newInstance(null);
            }
            catch (Throwable t)
            {
                unconstructible.add(where + " -> " + t.getClass().getSimpleName() + ": " + t.getMessage());
                continue;
            }

            if (instance == null)
            {
                unconstructible.add(where + " -> newInstance returned null");
                continue;
            }

            if (instance.getClass() != declared)
            {
                mismatched.add(where + " -> registered " + cn + ", constructs " + instance.getClass().getName());
            }
        }

        List<String> failures = new ArrayList<String>();
        report(failures, "names no loadable class", phantom);
        report(failures, "could not be constructed", unconstructible);
        report(failures, "names a class it does not construct", mismatched);

        Assertions.assertTrue(failures.isEmpty(),
                provider.getName() + ": " + (phantom.size() + unconstructible.size() + mismatched.size())
                        + " of " + services.size() + " services have a class name that does not describe them:\n"
                        + String.join("\n", failures));
    }

    private static void report(List<String> into, String heading, List<String> entries)
    {
        if (entries.isEmpty())
        {
            return;
        }
        Collections.sort(entries);
        into.add("  " + entries.size() + " " + heading + ":");
        for (String e : entries)
        {
            into.add("    " + e);
        }
    }
}
