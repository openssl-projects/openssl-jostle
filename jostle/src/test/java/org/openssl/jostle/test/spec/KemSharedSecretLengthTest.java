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
package org.openssl.jostle.test.spec;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.test.TestUtil;

import java.security.Provider;
import java.security.Security;

/**
 * The shared-secret length a size query reports is the length a real encapsulation produces and the length
 * the decapsulation size query reports, for every ML-KEM parameter set and every hybrid group JSL serves.
 * The two queries ask OpenSSL different questions of different keys, so this is what stops them disagreeing
 * silently. Runs on whichever bridge the leg loads.
 */
public class KemSharedSecretLengthTest
{
    @BeforeAll
    public static void installBase()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    @Test
    public void theEncapQueryAgreesWithDecapAndARealEncapsulation() throws Exception
    {
        Provider jsl = Security.getProvider(JostleProvider.PROVIDER_NAME);
        String table = KemSharedSecretLengths.check(jsl, KemSharedSecretLengths.ALL, TestUtil.RNDSrc);
        System.out.println("[kem-secret-length] JSL\n  " + table);
    }
}
