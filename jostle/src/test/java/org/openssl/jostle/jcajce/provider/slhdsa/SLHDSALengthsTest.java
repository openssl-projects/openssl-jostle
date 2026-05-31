/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.slhdsa;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;

public class SLHDSALengthsTest
{
    @Test
    public void testKnownSignatureLengths()
    {
        Assertions.assertEquals(7856, SLHDSALengths.getSignatureLength(OSSLKeyType.SLH_DSA_SHA2_128s));
        Assertions.assertEquals(7856, SLHDSALengths.getSignatureLength(OSSLKeyType.SLH_DSA_SHAKE_128s));
        Assertions.assertEquals(17088, SLHDSALengths.getSignatureLength(OSSLKeyType.SLH_DSA_SHA2_128f));
        Assertions.assertEquals(17088, SLHDSALengths.getSignatureLength(OSSLKeyType.SLH_DSA_SHAKE_128f));
        Assertions.assertEquals(16224, SLHDSALengths.getSignatureLength(OSSLKeyType.SLH_DSA_SHA2_192s));
        Assertions.assertEquals(16224, SLHDSALengths.getSignatureLength(OSSLKeyType.SLH_DSA_SHAKE_192s));
        Assertions.assertEquals(35664, SLHDSALengths.getSignatureLength(OSSLKeyType.SLH_DSA_SHA2_192f));
        Assertions.assertEquals(35664, SLHDSALengths.getSignatureLength(OSSLKeyType.SLH_DSA_SHAKE_192f));
        Assertions.assertEquals(29792, SLHDSALengths.getSignatureLength(OSSLKeyType.SLH_DSA_SHA2_256s));
        Assertions.assertEquals(29792, SLHDSALengths.getSignatureLength(OSSLKeyType.SLH_DSA_SHAKE_256s));
        Assertions.assertEquals(49856, SLHDSALengths.getSignatureLength(OSSLKeyType.SLH_DSA_SHA2_256f));
        Assertions.assertEquals(49856, SLHDSALengths.getSignatureLength(OSSLKeyType.SLH_DSA_SHAKE_256f));
    }

    @Test
    public void testUnknownSignatureLengthsUseNativeFallback()
    {
        Assertions.assertEquals(SLHDSALengths.UNKNOWN_SIGNATURE_LENGTH,
                SLHDSALengths.getSignatureLength(null));
        Assertions.assertEquals(SLHDSALengths.UNKNOWN_SIGNATURE_LENGTH,
                SLHDSALengths.getSignatureLength(OSSLKeyType.ML_KEM_512));
    }
}
