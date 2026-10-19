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

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.test.cert.X509FactoryRefusalCells;

/** The X.509 CertificateFactory's refusals on JSLFIPS; the cells are in {@link X509FactoryRefusalCells}. */
public class FIPSX509FactoryRefusalTest
{
    private final X509FactoryRefusalCells cells = new X509FactoryRefusalCells(JostleFIPSProvider.PROVIDER_NAME);

    @BeforeAll
    static void before()
    {
        FIPSTestUtil.assumeFipsProvider();
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
