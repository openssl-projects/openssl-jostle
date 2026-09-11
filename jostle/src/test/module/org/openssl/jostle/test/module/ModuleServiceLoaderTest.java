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
 * module-info's {@code provides java.security.Provider} declaration. The jar
 * carries no META-INF/services entry, so it is visible under a module and
 * invisible on a classpath; both halves are pinned because the difference is
 * the fact. Adding a services entry would change discovery for every
 * non-modular consumer, so the classpath half must fail if one appears.
 */
public class ModuleServiceLoaderTest
{
    @Test
    public void theProvidesDeclarationIsVisibleUnderAModuleAndNotOnAClasspath()
    {
        List<String> found = new ArrayList<String>();
        for (Provider p : ServiceLoader.load(Provider.class))
        {
            if (p.getClass().getName().startsWith("org.openssl.jostle"))
            {
                found.add(p.getClass().getName());
            }
        }

        if (!ModuleCell.current().jostleIsModular())
        {
            Assertions.assertTrue(found.isEmpty(),
                    "ServiceLoader found jostle providers on a CLASSPATH run: " + found);
            return;
        }

        Assertions.assertTrue(
                found.contains("org.openssl.jostle.jcajce.provider.JostleProvider"),
                "JostleProvider was not discovered through the provides declaration: " + found);
        Assertions.assertTrue(
                found.contains("org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider"),
                "JostleFIPSProvider was not discovered through the provides declaration: " + found);
        Assertions.assertEquals(2, found.size(), "unexpected jostle providers discovered: " + found);
    }
}
