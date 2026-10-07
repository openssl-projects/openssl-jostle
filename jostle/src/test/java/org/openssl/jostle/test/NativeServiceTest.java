/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.NativeServiceNI;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.test.crypto.TestNISelector;

import java.security.Security;

/**
 * The native-info entry points, called directly on whichever bridge the run selected.
 */
public class NativeServiceTest
{
    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    @Test
    public void nativeIsAvailable()
    {
        Assertions.assertTrue(TestNISelector.getNativeServiceNI().isNativeAvailable());
    }

    @Test
    public void bothVersionsAreOpenSSL3Strings()
    {
        NativeServiceNI ni = TestNISelector.getNativeServiceNI();
        String runtime = ni.getOpenSSLVersion();
        String build = ni.getOpenSSLBuildVersion();
        System.out.println("[native-info] runtime=" + runtime + " build=" + build);

        // A failed lookup answers with a sentence, so a digit-led "3." proves the native string arrived whole.
        Assertions.assertTrue(runtime.matches("3\\.\\d+\\.\\d+.*"), "runtime version " + runtime);
        Assertions.assertTrue(build.matches("3\\.\\d+\\.\\d+.*"), "build version " + build);
    }
}
