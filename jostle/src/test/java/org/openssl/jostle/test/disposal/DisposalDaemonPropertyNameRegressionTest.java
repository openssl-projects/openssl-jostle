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

package org.openssl.jostle.test.disposal;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.disposal.DisposalDaemon;
import org.openssl.jostle.util.Properties;

import java.lang.reflect.Field;

/**
 * D50/C47: the cleanup-delay system property moved to the Jostle namespace,
 * and the unused {@code Properties.EMULATE_ORACLE} constant is gone.
 * Reflection in test code is fine — it is production reflecting on a spec
 * that C43-C47 removed, not test code inspecting a private field.
 */
public class DisposalDaemonPropertyNameRegressionTest
{
    @Test
    public void cleanupDelayPropertyIsInTheJostleNamespace() throws Exception
    {
        Field f = DisposalDaemon.class.getDeclaredField("CLEANUP_DELAY_PROP");
        f.setAccessible(true);
        Assertions.assertEquals("org.openssl.jostle.native.cleanup_delay", f.get(null),
                "the cleanup-delay property must live under the Jostle namespace, not BouncyCastle's");
    }

    @Test
    public void propertiesHasNoEmulateOracleField()
    {
        for (Field f : Properties.class.getDeclaredFields())
        {
            Assertions.assertNotEquals("EMULATE_ORACLE", f.getName(),
                    "Properties.EMULATE_ORACLE must be gone — it had no reader");
        }
    }
}
