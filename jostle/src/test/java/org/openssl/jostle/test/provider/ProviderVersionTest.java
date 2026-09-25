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

package org.openssl.jostle.test.provider;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.Version;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import java.security.Provider;
import java.security.Security;

/**
 * JSL reports the version and info Version gives it.
 */
public class ProviderVersionTest
{
    @Test
    @SuppressWarnings("deprecation")
    public void jslReportsVersionFromTheVersionClass()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        Provider p = Security.getProvider(JostleProvider.PROVIDER_NAME);
        Assertions.assertEquals(Version.getVersionDouble(), p.getVersion(), 0.0);
        Assertions.assertEquals("Jostle Provider for OpenSSL " + Version.getVersionString(), p.getInfo());
        Assertions.assertEquals(JostleProvider.INFO, p.getInfo());
    }
}
