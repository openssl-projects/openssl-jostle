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
import org.openssl.jostle.jcajce.provider.blockcipher.OSSLCipher;
import org.openssl.jostle.jcajce.provider.blockcipher.OSSLMode;
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;
import org.openssl.jostle.jcajce.provider.fips.OpenSSLFIPSNI;

import javax.crypto.Cipher;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;

import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * RFC 3217's Triple-DES key wrap is absent from JSLFIPS because neither supported module serves DES3-WRAP, asked of
 * the module rather than assumed. The 3.5.x module serves Triple-DES CBC and still not the wrap, which is what
 * makes the absence specific to the wrap.
 */
public class FIPSDESedeWrapAbsenceTest
{
    private static Provider fips;

    @BeforeAll
    static void before()
    {
        fips = FIPSTestUtil.assumeFipsProvider();
    }

    @Test
    public void theModuleServesNoTripleDesWrap()
    {
        for (String name : new String[]{"DES3-WRAP", "id-smime-alg-CMS3DESwrap", "1.2.840.113549.1.9.16.3.6"})
        {
            Assertions.assertEquals(0, FIPSNISelector.OpenSSLFIPSNI.canFetch(OpenSSLFIPSNI.OP_CIPHER, name), name);
        }
        Assertions.assertFalse(FIPSNISelector.BlockCipherNI.cipherFetchable(OSSLCipher.DES_EDE3.ordinal(),
                OSSLMode.WRAP.ordinal()), "the FIPS library's own DES_EDE3 WRAP fetch");

        boolean cbc = FIPSNISelector.OpenSSLFIPSNI.canFetch(OpenSSLFIPSNI.OP_CIPHER, "DES-EDE3-CBC") != 0;
        System.out.println("[desede-wrap] module serves DES-EDE3-CBC: " + cbc + "; DES3-WRAP: false");
        Assertions.assertEquals(cbc, FIPSNISelector.BlockCipherNI.cipherFetchable(OSSLCipher.DES_EDE3.ordinal(),
                OSSLMode.CBC.ordinal()), "the CBC control agrees with the module");
    }

    @Test
    public void jslFipsRegistersNoTripleDesWrapName()
    {
        for (String name : new String[]{"DESedeWrap", "1.2.840.113549.1.9.16.3.6", "DESedeRFC3217Wrap", "TDEAWrap"})
        {
            Assertions.assertNull(fips.getService("Cipher", name), name);
            assertThrows(NoSuchAlgorithmException.class, () -> Cipher.getInstance(name, fips), name);
        }
    }
}
