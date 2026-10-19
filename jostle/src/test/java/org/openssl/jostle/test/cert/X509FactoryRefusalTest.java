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

package org.openssl.jostle.test.cert;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import java.security.Security;

/** The X.509 CertificateFactory's refusals on JSL; the cells are in {@link X509FactoryRefusalCells}. */
public class X509FactoryRefusalTest
{
    private final X509FactoryRefusalCells cells = new X509FactoryRefusalCells(JostleProvider.PROVIDER_NAME);

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    @Test
    public void ceilingRefusalsAreCheckedOnEveryPath() throws Exception
    {
        cells.ceilingRefusalsAreCheckedOnEveryPath();
    }

    @Test
    public void certPathFromAnEmptyStreamIsEmptyInput() throws Exception
    {
        cells.certPathFromAnEmptyStreamIsEmptyInput();
    }

    @Test
    public void nonNumericCeilingPropertyIsRefusedNamingIt() throws Exception
    {
        cells.nonNumericCeilingPropertyIsRefusedNamingIt();
    }

    @Test
    public void ceilingBoundsTheWholeEncoding() throws Exception
    {
        cells.ceilingBoundsTheWholeEncoding();
    }

    @Test
    public void pemBodyWithMoreThanOneObjectIsRefused() throws Exception
    {
        cells.pemBodyWithMoreThanOneObjectIsRefused();
    }

    @Test
    public void overlongOidTextIsAParseRefusal() throws Exception
    {
        cells.overlongOidTextIsAParseRefusal();
    }
}
