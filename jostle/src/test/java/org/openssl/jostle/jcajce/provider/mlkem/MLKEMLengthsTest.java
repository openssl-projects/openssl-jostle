/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.mlkem;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;

public class MLKEMLengthsTest
{
    @Test
    public void testKnownEncapsulationLengths()
    {
        Assertions.assertEquals(768, MLKEMLengths.getEncapsulationLength(OSSLKeyType.ML_KEM_512));
        Assertions.assertEquals(1088, MLKEMLengths.getEncapsulationLength(OSSLKeyType.ML_KEM_768));
        Assertions.assertEquals(1568, MLKEMLengths.getEncapsulationLength(OSSLKeyType.ML_KEM_1024));
    }

    @Test
    public void testUnknownEncapsulationLengthsUseNativeFallback()
    {
        Assertions.assertEquals(MLKEMLengths.UNKNOWN_ENCAPSULATION_LENGTH,
                MLKEMLengths.getEncapsulationLength(null));
        Assertions.assertEquals(MLKEMLengths.UNKNOWN_ENCAPSULATION_LENGTH,
                MLKEMLengths.getEncapsulationLength(OSSLKeyType.ML_DSA_44));
    }
}
