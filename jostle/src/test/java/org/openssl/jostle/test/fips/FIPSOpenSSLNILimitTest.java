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
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;
import org.openssl.jostle.jcajce.provider.fips.OpenSSLFIPSNI;
import org.openssl.jostle.test.TestUtil;

/**
 * setOSSLFIPSModule refuses a control character in any of its three strings, which are written into OpenSSL
 * config text. U+0000 gets the same code on both bridges: JNI sees the UTF-16 unit, FFM a 0x00 byte inside the
 * length it is passed. Every cell refuses at the bridge, so no native state changes.
 */
public class FIPSOpenSSLNILimitTest
{
    private static final String[] CONTROL = {"\u0000", "\u0000x", "x\u0000", "x\ny", "x\r", "x\ty", "x\u001fy",
            "x\u007fy"};

    private static OpenSSLFIPSNI ni;
    private static String dir;
    private static String cnf;

    @BeforeAll
    static void before()
    {
        Assumptions.assumeFalse(TestUtil.skipFipsTests(),
                "TEST_FIPS_LIB not set (full path to the FIPS module library)");
        ni = FIPSNISelector.OpenSSLFIPSNI;
        dir = FIPSTestUtil.fipsModuleDir().replace('\\', '/');
        cnf = dir + "/fipsmodule.cnf";
    }

    @Test
    public void controlCharacterInModuleDirRefused()
    {
        for (String c : CONTROL)
        {
            Assertions.assertEquals(ErrorCode.JO_FIPS_MODULE_PATH_INVALID.getCode(),
                    ni.setOSSLFIPSModule(dir + c, "fips", cnf), escape(c));
        }
    }

    @Test
    public void controlCharacterInProviderNameRefused()
    {
        for (String c : CONTROL)
        {
            Assertions.assertEquals(ErrorCode.JO_PROV_NAME_INVALID.getCode(),
                    ni.setOSSLFIPSModule(dir, "fips" + c, cnf), escape(c));
        }
        Assertions.assertEquals(ErrorCode.JO_PROV_NAME_INVALID.getCode(),
                ni.setOSSLFIPSModule(dir, "\u0000", cnf));
    }

    @Test
    public void controlCharacterInConfigPathRefused()
    {
        for (String c : CONTROL)
        {
            Assertions.assertEquals(ErrorCode.JO_FIPS_CONFIG_PATH_INVALID.getCode(),
                    ni.setOSSLFIPSModule(dir, "fips", cnf + c), escape(c));
        }
    }

    @Test
    public void earlierArgumentIsCheckedFirst()
    {
        // Each string is checked whole before the next, so a later bad string never masks an earlier one.
        Assertions.assertEquals(ErrorCode.JO_FIPS_MODULE_PATH_INVALID.getCode(),
                ni.setOSSLFIPSModule(dir + "\n", "fips\n", cnf + "\n"));
        Assertions.assertEquals(ErrorCode.JO_PROV_NAME_INVALID.getCode(),
                ni.setOSSLFIPSModule(dir, "fips\n", cnf + "\n"));
    }

    @Test
    public void justOutsideTheRefusedSetReachesActivation()
    {
        // 0x20 and 0x80 pass the bridge and fail later, at config load or activation, which roll back.
        assertReachedActivation(ni.setOSSLFIPSModule(dir + " ", "fips", cnf), "module dir 0x20");
        assertReachedActivation(ni.setOSSLFIPSModule(dir, "no\u0080such", cnf), "provider name 0x80");
        assertReachedActivation(ni.setOSSLFIPSModule(dir, "no such", cnf), "provider name 0x20");
        assertReachedActivation(ni.setOSSLFIPSModule(dir, "fips", cnf + " missing"), "config path 0x20");
    }

    private static void assertReachedActivation(int rc, String what)
    {
        Assertions.assertTrue(rc == ErrorCode.JO_FIPS_CONFIG_LOAD_FAILED.getCode()
                || rc == ErrorCode.JO_FIPS_PROVIDER_UNAVAILABLE.getCode(), what + ": " + rc);
    }

    private static String escape(String s)
    {
        StringBuilder b = new StringBuilder();
        for (char c : s.toCharArray())
        {
            if (c < 0x20 || c >= 0x7F)
            {
                b.append(String.format("\\u%04x", (int) c));
            }
            else
            {
                b.append(c);
            }
        }
        return b.toString();
    }
}
