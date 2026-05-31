/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.mldsa;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;

public class MLDSALengthsTest
{
    @Test
    public void testKnownSignatureLengths()
    {
        Assertions.assertEquals(2420, MLDSALengths.getSignatureLength(OSSLKeyType.ML_DSA_44, false));
        Assertions.assertEquals(3309, MLDSALengths.getSignatureLength(OSSLKeyType.ML_DSA_65, false));
        Assertions.assertEquals(4627, MLDSALengths.getSignatureLength(OSSLKeyType.ML_DSA_87, false));
    }

    @Test
    public void testCalculateMuUsesNativeFallback()
    {
        Assertions.assertEquals(MLDSALengths.UNKNOWN_SIGNATURE_LENGTH,
                MLDSALengths.getSignatureLength(OSSLKeyType.ML_DSA_44, true));
        Assertions.assertEquals(MLDSALengths.UNKNOWN_SIGNATURE_LENGTH,
                MLDSALengths.getSignatureLength(OSSLKeyType.ML_DSA_65, true));
        Assertions.assertEquals(MLDSALengths.UNKNOWN_SIGNATURE_LENGTH,
                MLDSALengths.getSignatureLength(OSSLKeyType.ML_DSA_87, true));
    }

    @Test
    public void testUnknownSignatureLengthsUseNativeFallback()
    {
        Assertions.assertEquals(MLDSALengths.UNKNOWN_SIGNATURE_LENGTH,
                MLDSALengths.getSignatureLength(null, false));
        Assertions.assertEquals(MLDSALengths.UNKNOWN_SIGNATURE_LENGTH,
                MLDSALengths.getSignatureLength(OSSLKeyType.ML_KEM_512, false));
    }
}
