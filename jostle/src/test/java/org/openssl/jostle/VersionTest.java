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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;

/**
 * The version conversion rules, and the fallback when the resource is missing or unreadable. The fallback cells
 * load Version into an isolated class loader that controls what the resource lookup returns, so they do not
 * depend on the project version the build wrote.
 */
public class VersionTest
{
    @Test
    public void toDoubleFollowsThePaddingRule()
    {
        Object[][] rows = {
                {"v1.2.3", 1.0203},
                {"1.2.302", 1.02302},
                {"v0.1-SNAPSHOT", 0.01},
                {"v1.0.0-SNAPSHOT", 1.0},
                {"v0.0.0-SNAPSHOT", 0.0},
                {"v3", 3.0},
                {"v1.2.3.4", 1.020304},
                {"v10.11.12", 10.1112},
                {"v2.5-rc1", 2.05},
        };
        for (Object[] row : rows)
        {
            Assertions.assertEquals((Double) row[1], Version.toDouble((String) row[0]), 0.0, (String) row[0]);
        }
    }

    @Test
    public void toDoubleNeverTruncatesAComponentLongerThanTwoDigits()
    {
        Assertions.assertEquals(Version.toDouble("1.2.302"), Version.toDouble("1.02.302"), 0.0);
    }

    @Test
    public void toDoubleRefusesANonNumericComponent()
    {
        String[][] rows = {
                {"v1.x.3", "version component 'x' is not numeric in 'v1.x.3'"},
                {"v1..3", "version component '' is not numeric in 'v1..3'"},
                {"v", "version component '' is not numeric in 'v'"},
                {"", "version component '' is not numeric in ''"},
        };
        for (String[] row : rows)
        {
            IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                    () -> Version.toDouble(row[0]), row[0]);
            Assertions.assertEquals(row[1], e.getMessage());
        }
        IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                () -> Version.toDouble(null));
        Assertions.assertEquals("version is null", e.getMessage());
    }

    @Test
    public void normaliseAddsTheLeadingVOnce()
    {
        Assertions.assertEquals("v1.2.3", Version.normalise("1.2.3"));
        Assertions.assertEquals("v1.2.3", Version.normalise("v1.2.3"));
        Assertions.assertEquals("v0.1-SNAPSHOT", Version.normalise(" 0.1-SNAPSHOT "));
        for (String bad : new String[]{null, "", "  "})
        {
            IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                    () -> Version.normalise(bad));
            Assertions.assertEquals("version is null or empty", e.getMessage());
        }
    }

    @Test
    public void theDefaultIsTheFallback()
    {
        Assertions.assertEquals("v0.1-SNAPSHOT", Version.DEFAULT);
        Assertions.assertEquals(0.01, Version.toDouble(Version.DEFAULT), 0.0);
    }

    @Test
    public void aServedResourceIsRead()
            throws Exception
    {
        IsolatedLoader loader = new IsolatedLoader("version=9.8.7\n");
        Class<?> c = loader.loadClass(Version.class.getName());
        Assertions.assertNotSame(Version.class, c);
        Assertions.assertEquals("v9.8.7", call(c, "getVersionString"));
        Assertions.assertEquals(9.0807, (Double) call(c, "getVersionDouble"), 0.0);
        Assertions.assertEquals(Boolean.TRUE, call(c, "fromResource"));
        Assertions.assertTrue(loader.lookups >= 1, "the resource lookup never reached the loader");
    }

    @Test
    public void aMissingResourceFallsBackToTheDefault()
            throws Exception
    {
        IsolatedLoader loader = new IsolatedLoader(null);
        Class<?> c = loader.loadClass(Version.class.getName());
        Assertions.assertEquals("v0.1-SNAPSHOT", call(c, "getVersionString"));
        Assertions.assertEquals(0.01, (Double) call(c, "getVersionDouble"), 0.0);
        Assertions.assertEquals(Boolean.FALSE, call(c, "fromResource"));
        Assertions.assertTrue(loader.lookups >= 1, "the resource lookup never reached the loader");
    }

    @Test
    public void anUnparseableResourceFallsBackToTheDefault()
            throws Exception
    {
        for (String served : new String[]{"version=1.x\n", "other=1.2.3\n", "version=\n"})
        {
            IsolatedLoader loader = new IsolatedLoader(served);
            Class<?> c = loader.loadClass(Version.class.getName());
            Assertions.assertEquals("v0.1-SNAPSHOT", call(c, "getVersionString"), served);
            Assertions.assertEquals(0.01, (Double) call(c, "getVersionDouble"), 0.0, served);
            Assertions.assertEquals(Boolean.FALSE, call(c, "fromResource"), served);
            Assertions.assertTrue(loader.lookups >= 1, "the resource lookup never reached the loader");
        }
    }

    private static Object call(Class<?> c, String name)
            throws Exception
    {
        Method m = c.getDeclaredMethod(name);
        m.setAccessible(true);
        return m.invoke(null);
    }

    /**
     * Defines Version from its own class bytes, with only the bootstrap loader as parent, and answers the
     * version resource with the given content, or with nothing when it is null.
     */
    private static final class IsolatedLoader
            extends ClassLoader
    {
        private final String served;
        private Class<?> version;
        int lookups;

        IsolatedLoader(String served)
        {
            super(null);
            this.served = served;
        }

        @Override
        protected synchronized Class<?> loadClass(String name, boolean resolve)
                throws ClassNotFoundException
        {
            if (!Version.class.getName().equals(name))
            {
                return super.loadClass(name, resolve);
            }
            if (version == null)
            {
                byte[] bytes = classBytes();
                version = defineClass(name, bytes, 0, bytes.length);
            }
            return version;
        }

        @Override
        public InputStream getResourceAsStream(String name)
        {
            if (name.endsWith(Version.RESOURCE))
            {
                lookups++;
                if (served == null)
                {
                    return null;
                }
                return new ByteArrayInputStream(served.getBytes(StandardCharsets.ISO_8859_1));
            }
            return null;
        }

        private static byte[] classBytes()
                throws ClassNotFoundException
        {
            try (InputStream in = Version.class.getResourceAsStream("Version.class"))
            {
                if (in == null)
                {
                    throw new ClassNotFoundException("Version.class not found");
                }
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                byte[] buf = new byte[4096];
                int n;
                while ((n = in.read(buf)) >= 0)
                {
                    out.write(buf, 0, n);
                }
                return out.toByteArray();
            }
            catch (java.io.IOException e)
            {
                throw new ClassNotFoundException("Version.class unreadable", e);
            }
        }
    }
}
