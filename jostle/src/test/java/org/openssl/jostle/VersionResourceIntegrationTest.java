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

package org.openssl.jostle;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/**
 * The jar carries the version the build wrote, and Version reports it. The build passes its version in as
 * {@code jostle.test.project.version}, so the jar and the build are compared rather than either with a literal.
 * <p>
 * These legs also put the build's resource directory on the classpath, so the entry is read from the jar that
 * Version itself was loaded from, never through a classpath lookup that the directory copy would answer.
 */
public class VersionResourceIntegrationTest
{
    private static final String ENTRY = "org/openssl/jostle/" + Version.RESOURCE;

    private static String projectVersion()
    {
        String v = System.getProperty("jostle.test.project.version");
        Assertions.assertNotNull(v, "jostle.test.project.version is not set by the build");
        return v;
    }

    private static File versionJar()
            throws Exception
    {
        URL location = Version.class.getProtectionDomain().getCodeSource().getLocation();
        File jar = new File(location.toURI());
        Assertions.assertTrue(jar.isFile() && jar.getName().endsWith(".jar"),
                "Version was not loaded from a jar on this leg: " + location);
        return jar;
    }

    @Test
    public void theJarCarriesTheBuildVersion()
            throws Exception
    {
        try (JarFile jar = new JarFile(versionJar()))
        {
            JarEntry entry = jar.getJarEntry(ENTRY);
            Assertions.assertNotNull(entry, ENTRY + " is missing from " + jar.getName());
            try (InputStream in = jar.getInputStream(entry))
            {
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                byte[] buf = new byte[256];
                int n;
                while ((n = in.read(buf)) >= 0)
                {
                    out.write(buf, 0, n);
                }
                Assertions.assertEquals("version=" + projectVersion() + "\n",
                        new String(out.toByteArray(), StandardCharsets.ISO_8859_1));
            }
        }
    }

    @Test
    public void versionReportsTheBuildVersionFromTheResource()
            throws Exception
    {
        Assertions.assertTrue(Version.fromResource(), "Version fell back instead of reading the resource");
        // Version.class may resolve to a META-INF/versions entry; the resource is unversioned. Only the jar
        // they come from is compared.
        URL found = Version.class.getResource(Version.RESOURCE);
        Assertions.assertNotNull(found, "no " + Version.RESOURCE + " visible to Version");
        String prefix = "jar:" + versionJar().toURI() + "!/";
        Assertions.assertTrue(found.toString().startsWith(prefix),
                "Version read a resource from outside its own jar: " + found);
        Assertions.assertEquals("v" + projectVersion(), Version.getVersionString());
        Assertions.assertEquals(Version.toDouble(projectVersion()), Version.getVersionDouble(), 0.0);
    }
}
