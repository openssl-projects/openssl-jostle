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
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import java.security.Provider;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.util.ArrayList;
import java.util.List;
import java.util.ServiceLoader;

/** The Collection CertStore is reachable through the provider in every module configuration. */
public class ModuleCertStoreTest
{
    @Test
    public void theCollectionStoreIsServedOnTheModulePath() throws Exception
    {
        Provider jsl = null;
        for (Provider p : ServiceLoader.load(Provider.class))
        {
            if (JostleProvider.class.getName().equals(p.getClass().getName()))
            {
                jsl = p;
            }
        }
        Assertions.assertNotNull(jsl, "JostleProvider was not discovered [" + ModuleCell.current() + "]");
        List<Object> coll = new ArrayList<Object>();
        coll.add("not a certificate");
        CertStore s = CertStore.getInstance("Collection", new CollectionCertStoreParameters(coll), jsl);
        Assertions.assertSame(jsl, s.getProvider());
        Assertions.assertEquals(0, s.getCertificates(null).size(), "[" + ModuleCell.current() + "]");
        Assertions.assertEquals(0, s.getCRLs(null).size(), "[" + ModuleCell.current() + "]");
    }
}
