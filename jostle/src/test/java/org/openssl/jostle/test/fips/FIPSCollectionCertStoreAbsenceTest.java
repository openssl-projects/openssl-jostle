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

package org.openssl.jostle.test.fips;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.util.ArrayList;

import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * JSLFIPS serves no CertStore, following the policy of its CertPath services: it registers no CertPathValidator
 * or CertPathBuilder, so the Collection store is JSL's alone.
 */
public class FIPSCollectionCertStoreAbsenceTest
{
    private static Provider fips;

    @BeforeAll
    static void before()
    {
        fips = FIPSTestUtil.assumeFipsProvider();
    }

    @Test
    public void jslFipsServesNoCertStoreAsItServesNoCertPathService()
    {
        for (Provider.Service s : fips.getServices())
        {
            Assertions.assertNotEquals("CertStore", s.getType(), s.getAlgorithm());
            Assertions.assertNotEquals("CertPathValidator", s.getType(), s.getAlgorithm());
            Assertions.assertNotEquals("CertPathBuilder", s.getType(), s.getAlgorithm());
        }
        assertThrows(NoSuchAlgorithmException.class, () -> CertStore.getInstance("Collection",
                new CollectionCertStoreParameters(new ArrayList<Object>()), fips));
    }
}
