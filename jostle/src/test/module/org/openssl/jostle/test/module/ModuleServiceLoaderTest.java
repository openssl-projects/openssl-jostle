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

package org.openssl.jostle.test.module;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.Provider;
import java.util.ArrayList;
import java.util.List;
import java.util.ServiceLoader;

/**
 * {@code ServiceLoader} discovery of the two providers, by BOTH routes.
 *
 * <p>Under a module the route is module-info's {@code provides
 * java.security.Provider}; on a classpath the descriptor is ignored entirely —
 * the jar is in the unnamed module — and the route is
 * {@code META-INF/services/java.security.Provider}. The two are not
 * alternatives: each serves a resolution mode the other cannot reach, which is
 * why both ship.
 *
 * <p>The size check is the DOUBLE-DISCOVERY guard. An explicit module provides
 * from its descriptor and its {@code META-INF/services} entry is not also
 * consulted, so the count must stay at two; if that ever changed, the modular
 * legs fail here rather than silently yielding four.
 *
 * <p>This makes jostle DISCOVERABLE to code that asks. It installs nothing:
 * JCA takes its providers from {@code java.security} or an explicit
 * {@code Security.addProvider}, never from {@code ServiceLoader}.
 *
 * <p>{@code ServiceLoader} INSTANTIATES each provider it yields, and
 * constructing {@code JostleProvider} loads the native library — so a classpath
 * consumer enumerating {@code Provider} services now pays that cost, exactly as
 * a modular one has since the {@code provides} clause landed.
 */
public class ModuleServiceLoaderTest
{
    @Test
    public void bothProvidersAreDiscoverableByWhicheverRouteServesThisMode()
    {
        List<String> found = new ArrayList<String>();
        for (Provider p : ServiceLoader.load(Provider.class))
        {
            if (p.getClass().getName().startsWith("org.openssl.jostle"))
            {
                found.add(p.getClass().getName());
            }
        }

        ModuleCell cell = ModuleCell.current();
        String route = cell.jostleIsModular()
                ? "the module-info provides declaration"
                : "META-INF/services/java.security.Provider";
        String where = " [" + cell + ", via " + route + "] found=" + found;

        Assertions.assertTrue(
                found.contains("org.openssl.jostle.jcajce.provider.JostleProvider"),
                "JostleProvider was not discovered through " + route + where);
        Assertions.assertTrue(
                found.contains("org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider"),
                "JostleFIPSProvider was not discovered through " + route + where);
        Assertions.assertEquals(2, found.size(),
                "expected exactly two jostle providers; a third means the descriptor"
                        + " and the services file were BOTH consulted." + where);
    }
}
