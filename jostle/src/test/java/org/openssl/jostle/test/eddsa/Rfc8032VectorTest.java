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

package org.openssl.jostle.test.eddsa;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import java.security.Security;

/**
 * The RFC 8032 known answers through the base provider, on whichever bridge the leg loads.
 */
public class Rfc8032VectorTest
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
    public void everyVectorMatches() throws Exception
    {
        int run = Rfc8032VectorCells.checkAll(JostleProvider.PROVIDER_NAME, name -> true);
        Assertions.assertEquals(Rfc8032Vectors.ALL.length, run);
        Assertions.assertEquals(21, run);
    }
}
