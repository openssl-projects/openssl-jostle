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
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.Loader;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import java.security.MessageDigest;
import java.security.Security;

/**
 * A named module calling a restricted method, with and without
 * {@code --enable-native-access}. Today the flag changes nothing but a
 * warning the JVM prints outside this process's reach, so these cells assert
 * the ABSENCE OF FAILURE, not the warning text. When a JDK starts blocking,
 * the {@code default} legs turn red and name this class. A named module has
 * no manifest route to enable itself, so the flag is the consumer's to pass.
 * MT-96 in reviews/misc-tasks-plan.md carries the measurement.
 */
public class ModuleNativeAccessTest
{
    /** "enabled" when the leg passed --enable-native-access, "default" when it did not. */
    private static final String NATIVE_ACCESS = System.getProperty("jostle.test.module.nativeaccess");

    /** "jni" or "ffi" — the bridge the leg forced, so a silent fall-back is visible. */
    private static final String INTERFACE = System.getProperty("jostle.test.module.interface");

    @BeforeAll
    public static void setUp()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    @Test
    public void theCellDeclaresItsNativeConfiguration()
    {
        Assertions.assertNotNull(NATIVE_ACCESS, "jostle.test.module.nativeaccess is unset");
        Assertions.assertTrue(NATIVE_ACCESS.equals("enabled") || NATIVE_ACCESS.equals("default"),
                "unknown native-access state '" + NATIVE_ACCESS + "'");
        Assertions.assertNotNull(INTERFACE, "jostle.test.module.interface is unset");
    }

    @Test
    public void theNativeLayerLoadsAndTheDeclaredBridgeIsTheOneInUse()
    {
        Assertions.assertTrue(Loader.isLoadSuccessful(),
                "the native layer did not load: " + Loader.getMessage());
        Assertions.assertEquals(INTERFACE.toUpperCase(), Loader.getInterfaceTypeName(),
                "the leg forced " + INTERFACE + " but the loader resolved "
                        + Loader.getInterfaceTypeName() + "; a silent fall-back to the other"
                        + " bridge would make this cell measure the wrong one");
        Assertions.assertEquals(INTERFACE.equals("ffi"), Loader.isFFI());
    }

    /**
     * The operation, not the loader's opinion of itself: restricted-method
     * enforcement would surface at the first downcall, not at load. Runs in
     * both native-access states — the point is that neither fails.
     */
    @Test
    public void aNativeOperationRunsInThisCellsNativeAccessState() throws Exception
    {
        MessageDigest md = MessageDigest.getInstance("SHA-256", JostleProvider.PROVIDER_NAME);
        byte[] one = md.digest(new byte[]{1, 2, 3});
        byte[] two = md.digest(new byte[]{1, 2, 4});

        Assertions.assertEquals(32, one.length);
        Assertions.assertFalse(java.util.Arrays.equals(one, two),
                "two different inputs digested identically");
    }
}
