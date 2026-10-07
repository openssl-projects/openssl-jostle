/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.fips;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.jcajce.provider.fips.OpenSSLFIPSNI;
import org.openssl.jostle.test.TestUtil;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;

/**
 * A module file not named "fips" activates under its own file name, and the diagnostics ask the provider by
 * that name. Reached through a symlink, so the bytes are the configured module's and only the name differs.
 *
 * <p>Owns the one-shot FIPS initialisation of its JVM, so it cannot share a JVM with another FIPS class.
 */
public class FIPSRenamedModuleIntegrationTest
{
    private static final String NAME = "jostle-probe";

    private static Path dir;
    private static JostleFIPSProvider provider;

    @BeforeAll
    static void before() throws Exception
    {
        Assumptions.assumeFalse(TestUtil.skipFipsTests(),
                "TEST_FIPS_LIB not set (full path to the FIPS module library)");
        File module = FIPSTestUtil.fipsModuleFile();
        String file = module.getName();
        String ext = file.lastIndexOf('.') > 0 ? file.substring(file.lastIndexOf('.')) : "";

        dir = Files.createTempDirectory("jostle-renamed-module");
        Path link = dir.resolve(NAME + ext);
        try
        {
            Files.createSymbolicLink(link, module.toPath().toAbsolutePath());
        }
        catch (UnsupportedOperationException | java.io.IOException e)
        {
            Assumptions.assumeTrue(false, "cannot create a symbolic link here: " + e);
        }
        Files.copy(new File(module.getParentFile(), "fipsmodule.cnf").toPath(), dir.resolve("fipsmodule.cnf"),
                StandardCopyOption.REPLACE_EXISTING);

        provider = new JostleFIPSProvider("fips_module='" + link.toString().replace('\\', '/') + "'");
    }

    @AfterAll
    static void after() throws Exception
    {
        if (dir != null)
        {
            try (java.util.stream.Stream<Path> s = Files.list(dir))
            {
                for (Path p : (Iterable<Path>) s::iterator)
                {
                    Files.deleteIfExists(p);
                }
            }
            Files.deleteIfExists(dir);
        }
    }

    @Test
    public void moduleDescriptionNamesTheActivatedModule()
    {
        String d = JostleFIPSProvider.moduleDescription();
        System.out.println("[renamed-module] moduleDescription=" + d);
        Assertions.assertTrue(d.startsWith("OpenSSL FIPS Provider 3."), d);
    }

    @Test
    public void operationsRunInTheProviderActivatedUnderTheFileName() throws Exception
    {
        Assertions.assertEquals(NAME,
                FIPSNISelector.OpenSSLFIPSNI.implementingProvider(OpenSSLFIPSNI.OP_MD, "SHA2-256"));
        Assertions.assertEquals(32, MessageDigest.getInstance("SHA-256", provider).digest(new byte[1]).length);
    }
}
