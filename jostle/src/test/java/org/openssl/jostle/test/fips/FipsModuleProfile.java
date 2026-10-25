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

import org.junit.jupiter.api.Assertions;
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;
import org.openssl.jostle.test.TestUtil;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * The loaded FIPS module as the refusal pins need it: its version and the options its fipsinstall wrote into the
 * {@code fipsmodule.cnf} beside the module {@link TestUtil#fipsLibPath()} names. Most refusals are options, not
 * properties of the version: the same 3.5.8 module installed with {@code -pedantic} refuses SHA-1 signing, DSA
 * signing and long PSS salts, and installed at the defaults serves all three.
 * <p>
 * Each rule below was measured on three installs: 3.5.8 pedantic, 3.5.8 at the fipsinstall defaults, and 3.1.2. A
 * module of any other version, or an option a rule reads missing from the file, fails the cell. All three installs
 * have security-checks = 1, so the rules that read it fail the cell when it is 0 rather than guess an answer no
 * install measured.
 */
final class FipsModuleProfile
{
    static final String MODULE_3_1_2 = "OpenSSL FIPS Provider 3.1.2";
    static final String MODULE_3_5_8 = "OpenSSL FIPS Provider 3.5.8";

    private static final String SECTION = "[fips_sect]";

    private static FipsModuleProfile loaded;

    private final String version;
    private final Map<String, String> options;
    private final String source;

    private FipsModuleProfile(String version, Map<String, String> options, String source)
    {
        this.version = version;
        this.options = options;
        this.source = source;
    }

    /** The profile of the module the tests load, read once. */
    static synchronized FipsModuleProfile get()
    {
        if (loaded == null)
        {
            String v = FIPSNISelector.OpenSSLFIPSNI.moduleVersion();
            Assertions.assertTrue(MODULE_3_1_2.equals(v) || MODULE_3_5_8.equals(v), "unmeasured module: " + v);
            File cnf = new File(new File(TestUtil.fipsLibPath()).getParentFile(), "fipsmodule.cnf");
            loaded = new FipsModuleProfile(v, read(cnf), cnf.getPath());
        }
        return loaded;
    }

    private static Map<String, String> read(File cnf)
    {
        Map<String, String> out = new HashMap<String, String>();
        try (BufferedReader r = new BufferedReader(new FileReader(cnf)))
        {
            boolean inSection = false;
            String line;
            while ((line = r.readLine()) != null)
            {
                String t = line.trim();
                if (t.startsWith("["))
                {
                    inSection = SECTION.equals(t);
                    continue;
                }
                int eq = t.indexOf('=');
                if (inSection && eq > 0 && !t.startsWith("#"))
                {
                    out.put(t.substring(0, eq).trim(), t.substring(eq + 1).trim());
                }
            }
        }
        catch (IOException e)
        {
            Assertions.fail("cannot read " + cnf + ": " + e.getMessage());
        }
        Assertions.assertFalse(out.isEmpty(), "no " + SECTION + " options in " + cnf);
        return Collections.unmodifiableMap(out);
    }

    /** The module's version, one of the two measured. */
    String version()
    {
        return version;
    }

    boolean isVersion312()
    {
        return MODULE_3_1_2.equals(version);
    }

    /** Whether an option the cnf must carry is on: "1" on, "0" off, anything else or absent fails the cell. */
    boolean option(String name)
    {
        String v = options.get(name);
        Assertions.assertNotNull(v, name + " is not in " + source);
        Assertions.assertTrue("1".equals(v) || "0".equals(v), name + " = " + v + " in " + source);
        return "1".equals(v);
    }

    /** security-checks, which is 1 on every install measured; 0 fails the cell, since no rule was measured there. */
    private boolean securityChecks()
    {
        Assertions.assertTrue(option("security-checks"), "unmeasured install: security-checks = 0 in " + source);
        return true;
    }

    /** SHA-1 signature generation (RSA, DSA, ECDSA): 3.1.2 refuses under security-checks (0 fails the cell), 3.5.8
     * under signature-digest-check. */
    boolean sha1SigningRefused()
    {
        return isVersion312() ? securityChecks() : option("signature-digest-check");
    }

    /** Every DSA signature and every DSA key and parameter generation: 3.5.8 under dsa-sign-disabled; 3.1.2 never. */
    boolean dsaSigningDisabled()
    {
        return !isVersion312() && option("dsa-sign-disabled");
    }

    /** Signing with a 1024-bit DSA key: 3.1.2 under security-checks (0 fails the cell); 3.5.8 signs it at the
     * defaults. */
    boolean dsaSmallKeySigningRefused()
    {
        return isVersion312() && securityChecks();
    }

    /** A PSS salt longer than the digest (2048-bit key, SHA-256): 3.5.8 under rsa-pss-saltlen-check; 3.1.2 never. */
    boolean pssSaltLengthChecked()
    {
        return !isVersion312() && option("rsa-pss-saltlen-check");
    }

    /** Signing with a 1024-bit RSA key: refused on every install measured, all with security-checks = 1; 0 fails
     * the cell. */
    boolean rsaSmallKeySigningRefused()
    {
        return securityChecks();
    }
}
