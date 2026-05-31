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

package org.openssl.jostle.jcajce.provider.ed;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;

public class EdDSALengthsTest
{
    @Test
    public void testKnownSignatureLengths()
    {
        Assertions.assertEquals(64, EdDSALengths.getSignatureLength(OSSLKeyType.ED25519));
        Assertions.assertEquals(64, EdDSALengths.getSignatureLength(OSSLKeyType.Ed25519ctx));
        Assertions.assertEquals(64, EdDSALengths.getSignatureLength(OSSLKeyType.Ed25519ph));
        Assertions.assertEquals(114, EdDSALengths.getSignatureLength(OSSLKeyType.ED448));
        Assertions.assertEquals(114, EdDSALengths.getSignatureLength(OSSLKeyType.ED448ph));
    }

    @Test
    public void testUnknownSignatureLengthsUseNativeFallback()
    {
        Assertions.assertEquals(EdDSALengths.UNKNOWN_SIGNATURE_LENGTH, EdDSALengths.getSignatureLength(null));
        Assertions.assertEquals(EdDSALengths.UNKNOWN_SIGNATURE_LENGTH,
                EdDSALengths.getSignatureLength(OSSLKeyType.ML_DSA_44));
    }
}
