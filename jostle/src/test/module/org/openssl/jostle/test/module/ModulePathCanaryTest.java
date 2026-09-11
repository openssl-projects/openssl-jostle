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

import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * The wiring canary. A leg misconfigured onto the classpath runs every other
 * test in this source set successfully and reports green, so each fact is
 * asserted by STATE against the DECLARED cell.
 */
public class ModulePathCanaryTest
{
    /** The jar the leg put on the module path, so its ABSENCE from the classpath can be checked. */
    private static final String JAR_PATH = System.getProperty("jostle.test.module.jar");

    @Test
    public void theCellDeclaresItsConfiguration()
    {
        Assertions.assertNotNull(ModuleCell.current());
        Assertions.assertNotNull(JAR_PATH, "jostle.test.module.jar is unset");
    }

    @Test
    public void jostleIsWhereTheCellSays()
    {
        ModuleCell cell = ModuleCell.current();
        Module m = JostleProvider.class.getModule();
        if (!cell.jostleIsModular())
        {
            Assertions.assertFalse(m.isNamed(), "the CONTROL cell must run jostle on the classpath");
            return;
        }
        Assertions.assertTrue(m.isNamed(),
                "jostle is in the UNNAMED module: this leg is running on the classpath, so it"
                        + " witnesses nothing about the module path");
        Assertions.assertEquals("org.openssl.jostle.prov", m.getName());
        Assertions.assertFalse(m.getDescriptor().isAutomatic(),
                "jostle resolved as an AUTOMATIC module, so module-info.java was ignored");
    }

    /** The tests model a CONSUMER, so they may reach only exported packages. */
    @Test
    public void theTestsThemselvesAreInTheUnnamedModule()
    {
        Assertions.assertFalse(ModulePathCanaryTest.class.getModule().isNamed(),
                "the test source set is inside a named module; it must run as an ordinary"
                        + " classpath consumer");
    }

    @Test
    public void bcprovIsWhereTheCellSays()
    {
        ModuleCell cell = ModuleCell.current();
        Module bc = KTSParameterSpec.class.getModule();
        if (!cell.bcprovIsModular())
        {
            Assertions.assertFalse(bc.isNamed(), "bcprov should be on the classpath in cell " + cell);
            return;
        }
        Assertions.assertTrue(bc.isNamed(), "bcprov should be on the module path in cell " + cell);
        Assertions.assertEquals(cell == ModuleCell.AUTOMATIC, bc.getDescriptor().isAutomatic(),
                "bcprov automatic-ness does not match cell " + cell + "; module=" + bc.getName());
    }

    /**
     * The jar on BOTH paths is the split-package failure, and it is silent:
     * the classpath copy can answer first while every module assertion above
     * still passes. Compare CANONICAL PATHS — a substring test on
     * {@code java.class.path} also matches any directory whose name contains
     * the artefact's.
     */
    @Test
    public void theJarIsNotAlsoOnTheClasspath() throws IOException
    {
        if (!ModuleCell.current().jostleIsModular())
        {
            return;   // CONTROL puts it there on purpose.
        }
        Path jar = Paths.get(JAR_PATH).toRealPath();
        for (String entry : System.getProperty("java.class.path").split(File.pathSeparator))
        {
            if (entry.isEmpty())
            {
                continue;
            }
            Path p = Paths.get(entry);
            if (!Files.exists(p))
            {
                continue;
            }
            Assertions.assertNotEquals(jar, p.toRealPath(),
                    "the jostle jar is on the classpath as well as the module path: the packages"
                            + " are split and the module boundary is not being tested");
        }
    }
}
