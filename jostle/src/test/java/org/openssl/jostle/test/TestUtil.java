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

package org.openssl.jostle.test;

import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.rand.RandSource;

import java.security.SecureRandom;
import java.security.Security;

public class TestUtil
{

    public static final TestRandSource RNDSrc = new TestRandSource();

    /**
     * Environment variable naming the OpenSSL FIPS provider module for tests:
     * a full path to the module library (e.g.
     * {@code /opt/openssl-fips/lib/ossl-modules/fips.so}). This is exactly the
     * {@code fips_module} value {@link JostleFIPSProvider} expects; the
     * fipsinstall-generated {@code fipsmodule.cnf} is assumed to sit beside it.
     */
    public static final String FIPS_LIB_ENV = "TEST_FIPS_LIB";

    /**
     * Whether FIPS tests should be skipped: {@code true} when the
     * {@link #FIPS_LIB_ENV} environment variable is unset or empty, i.e. no
     * OpenSSL FIPS module is available to test against. Use as the negative
     * of a JUnit assumption:
     * {@code Assumptions.assumeFalse(TestUtil.skipFipsTests(), "TEST_FIPS_LIB not set")}.
     *
     * @return {@code true} if FIPS tests cannot run and should be skipped
     */
    public static boolean skipFipsTests()
    {
        return fipsLib() == null;
    }

    /**
     * Install and return the JSLFIPS provider using the module named by the
     * {@link #FIPS_LIB_ENV} environment variable, or return {@code null} when
     * that variable is unset or empty (so a caller can skip a FIPS test with
     * {@code Assumptions.assumeTrue(TestUtil.addFipsProvider() != null)}).
     *
     * <p>Idempotent: if a JSLFIPS provider is already registered it is
     * returned unchanged, matching the module's one-shot native
     * initialisation. A set-but-invalid path is NOT swallowed — the
     * {@link JostleFIPSProvider} constructor surfaces the failure so a
     * misconfigured path fails loudly rather than silently skipping.
     *
     * @return the registered {@link JostleFIPSProvider}, or {@code null} if
     *         {@link #FIPS_LIB_ENV} is not set
     */
    public static synchronized JostleFIPSProvider addFipsProvider()
    {
        String lib = fipsLib();
        if (lib == null)
        {
            return null;
        }

        JostleFIPSProvider existing =
                (JostleFIPSProvider) Security.getProvider(JostleFIPSProvider.PROVIDER_NAME);
        if (existing != null)
        {
            return existing;
        }

        JostleFIPSProvider provider = new JostleFIPSProvider("fips_module='" + lib + "'");
        Security.addProvider(provider);
        return provider;
    }

    /**
     * The trimmed {@link #FIPS_LIB_ENV} value (full path to the FIPS module
     * library), or {@code null} when unset or empty. Single source of truth
     * for {@link #skipFipsTests()}, {@link #addFipsProvider()}, and callers
     * that need the module path directly (e.g. to derive the module directory
     * or its {@code fipsmodule.cnf}).
     */
    public static String fipsLibPath()
    {
        return fipsLib();
    }

    private static String fipsLib()
    {
        String lib = System.getenv(FIPS_LIB_ENV);
        if (lib == null || lib.trim().isEmpty())
        {
            return null;
        }
        return lib.trim();
    }

    public static int jvmVersion()
    {
        String env = System.getProperty("java.version");
        if (env.startsWith("1.8"))
        {
            return 8;
        }
        else
        {
            if (env.startsWith("9"))
            {
                return 9;
            }
            else
            {
                if (env.startsWith("17"))
                {
                    return 17;
                }
                else
                {
                    if (env.startsWith("21"))
                    {
                        return 21;
                    }
                    else
                    {
                        if (env.startsWith("22"))
                        {
                            return 22;
                        }
                        else
                        {
                            if (env.startsWith("23"))
                            {
                                return 23;
                            }
                            else
                            {
                                if (env.startsWith("24"))
                                {
                                    return 24;
                                }
                                else
                                {
                                    if (env.startsWith("25"))
                                    {
                                        return 25;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        throw new RuntimeException("Unknown Java version: " + env);
    }

    public static boolean versionIn(int... versions)
    {
        int v = jvmVersion();
        for (int i = 0; i < versions.length; i++)
        {
            if (versions[i] == v)
            {
                return true;
            }
        }
        return false;
    }

    public static boolean versionIs(int notBefore, int notAfter)
    {
        int v = jvmVersion();
        return v >= notBefore && v <= notAfter;
    }



    public static class TestRandSource implements RandSource
    {



        private SecureRandom random = new SecureRandom();

        @Override
        public int getRandomBytes(byte[] out, int len, int strength, boolean predictionResistant)
        {
            random.nextBytes(out);
            return len;
        }

        @Override
        public SecureRandom getRandom()
        {
            return random;
        }

        @Override
        public int getStrength()
        {
            return 0;
        }
    }


}
