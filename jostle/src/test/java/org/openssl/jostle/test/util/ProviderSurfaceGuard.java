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
import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

/**
 * The completeness guard a family's agreement class carries: every service the
 * provider registers is actually driven. Without one, a newly registered
 * algorithm is exercised by nothing and nobody notices.
 *
 * <p>Discovery is by SPI class-name prefix, not algorithm name, so a
 * transformation registered later is picked up without this being taught its
 * name. The prefix is therefore the {@code Prov} class's fully-qualified name,
 * which is what {@code addAlgorithmImplementation} is called with.
 */
public final class ProviderSurfaceGuard
{
    private ProviderSurfaceGuard()
    {
    }

    /** Drives one discovered service. Must THROW for a name it does not know. */
    public interface ServiceDriver
    {
        void drive(String type, String algorithm) throws Exception;
    }

    /**
     * Every service a provider registers under {@code prefix} is DRIVEN, with
     * the surface discovered rather than listed.
     *
     * <p>There is deliberately no hand-written-list variant. A covered list
     * drifts, and deriving it from the provider would make both sides of the
     * comparison the same source — a guard that always passes. Discovery plus
     * a driver that THROWS on an unknown name has neither problem: a new
     * registration fails until someone teaches it an operation.
     *
     * <p>What discovery cannot see is a REMOVED registration. That belongs in
     * one provider-wide golden snapshot, not in a list per family — see
     * {@code FIPSServedSurfaceSnapshotTest} for the FIPS side.
     *
     * <p>Failures are collected and reported together.
     */
    public static void assertEveryServiceDriven(Provider provider, String prefix, String family,
                                                String[] types, ServiceDriver driver)
    {
        Assertions.assertNotNull(provider, family + ": provider must be registered");
        SortedSet<String> registered = registeredSurface(provider, prefix, types);

        Assertions.assertFalse(registered.isEmpty(),
                family + ": no " + Arrays.toString(types) + " services discovered under " + prefix
                        + " — the guard would pass vacuously; check the prefix still matches the registrar");

        List<String> failures = new ArrayList<String>();
        for (String entry : registered)
        {
            int dot = entry.indexOf('.');
            String type = entry.substring(0, dot);
            String alg = entry.substring(dot + 1);
            try
            {
                driver.drive(type, alg);
            }
            catch (Throwable t)
            {
                failures.add(entry + " -> " + t.getClass().getSimpleName() + ": " + t.getMessage());
            }
        }

        Assertions.assertTrue(failures.isEmpty(),
                family + ": registered services that could not be driven (" + failures.size()
                        + " of " + registered.size() + "):\n  " + String.join("\n  ", failures));
    }

    /**
     * The {@code "<Type>.<ALGORITHM>"} set registered under {@code prefix},
     * primaries AND aliases.
     *
     * <p>Aliases matter: {@code getServices()} omits them, so a guard over
     * primaries alone says nothing about a name a caller can resolve — and an
     * alias landing on the wrong primary is a real defect. Recovered from the
     * provider's {@code Alg.Alias.*} entries.
     */
    public static SortedSet<String> registeredSurface(Provider provider, String prefix, String[] types)
    {
        SortedSet<String> out = new TreeSet<String>();
        Set<String> primaries = new HashSet<String>();
        Set<String> wanted = new HashSet<String>(Arrays.asList(types));

        for (Provider.Service s : provider.getServices())
        {
            String cn = s.getClassName();
            if (cn != null && cn.startsWith(prefix) && wanted.contains(s.getType()))
            {
                String key = s.getType() + "." + s.getAlgorithm().toUpperCase(Locale.ROOT);
                out.add(key);
                primaries.add(key);
            }
        }

        for (Map.Entry<Object, Object> e : provider.entrySet())
        {
            String key = String.valueOf(e.getKey());
            if (!key.startsWith("Alg.Alias."))
            {
                continue;
            }
            String rest = key.substring("Alg.Alias.".length());
            int dot = rest.indexOf('.');
            if (dot < 0)
            {
                continue;
            }
            String type = rest.substring(0, dot);
            String alias = rest.substring(dot + 1).toUpperCase(Locale.ROOT);
            String target = String.valueOf(e.getValue()).toUpperCase(Locale.ROOT);
            if (wanted.contains(type) && primaries.contains(type + "." + target))
            {
                out.add(type + "." + alias);
            }
        }
        return out;
    }
}
