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

package org.openssl.jostle.test.eddsa;

import org.junit.jupiter.api.Assertions;
import org.openssl.jostle.jcajce.spec.ContextParameterSpec;
import org.openssl.jostle.jcajce.spec.EdDSAParameterSpec;
import org.openssl.jostle.jcajce.spec.EdDSAPublicKeySpec;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

/**
 * JCE cells shared by the base and FIPS Ed tests, each taking the provider name under test.
 */
public final class EdKeyCells
{
    private EdKeyCells()
    {
    }

    /** A public key held by another provider: only its encoding is visible. */
    private static PublicKey foreign(String algorithm, byte[] encoding)
    {
        return new PublicKey()
        {
            @Override
            public String getAlgorithm()
            {
                return algorithm;
            }

            @Override
            public String getFormat()
            {
                return "X.509";
            }

            @Override
            public byte[] getEncoded()
            {
                return encoding.clone();
            }
        };
    }

    /**
     * A public y at or above the field prime is refused on every import path: X.509, the raw spec, translateKey
     * and initVerify of a foreign key.
     */
    public static void nonCanonicalPublicKeysAreRefused(String provider) throws Exception
    {
        for (byte[] raw : EdBridgeCells.nonCanonicalPoints())
        {
            boolean ed448 = raw.length == 57;
            String alg = ed448 ? "Ed448" : "Ed25519";
            String label = alg + " top " + (raw[raw.length - 1] & 0xff);
            KeyFactory kf = KeyFactory.getInstance(alg, provider);
            byte[] enc = EdBridgeCells.spki(raw);

            InvalidKeySpecException x509 = Assertions.assertThrows(InvalidKeySpecException.class,
                    () -> kf.generatePublic(new X509EncodedKeySpec(enc)), label);
            Assertions.assertEquals("EdDSA public key is not canonical", x509.getCause().getMessage(), label);

            EdDSAParameterSpec params = ed448 ? EdDSAParameterSpec.ED448 : EdDSAParameterSpec.ED25519;
            InvalidKeySpecException rawSpec = Assertions.assertThrows(InvalidKeySpecException.class,
                    () -> kf.generatePublic(new EdDSAPublicKeySpec(params, raw)), label);
            Assertions.assertEquals("EdDSA public key is not canonical", rawSpec.getCause().getMessage(), label);

            PublicKey foreign = foreign(alg, enc);
            InvalidKeyException translated = Assertions.assertThrows(InvalidKeyException.class,
                    () -> kf.translateKey(foreign), label);
            Assertions.assertEquals("EdDSA public key is not canonical", translated.getCause().getMessage(), label);

            Signature verifier = Signature.getInstance(alg, provider);
            Assertions.assertThrows(InvalidKeyException.class, () -> verifier.initVerify(foreign), label);
        }
        for (byte[] raw : EdBridgeCells.canonicalBoundaryPoints())
        {
            String alg = raw.length == 57 ? "Ed448" : "Ed25519";
            Assertions.assertEquals(alg, KeyFactory.getInstance(alg, provider)
                    .generatePublic(new X509EncodedKeySpec(EdBridgeCells.spki(raw))).getAlgorithm());
        }
    }

    /** A context longer than 255 bytes is refused when the spec is built, with the bound in the message. */
    public static void contextOfMoreThan255BytesIsRefused()
    {
        Assertions.assertEquals(255, new ContextParameterSpec(new byte[255]).getContext().length);
        IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                () -> new ContextParameterSpec(new byte[256]));
        Assertions.assertEquals("context too long, must be <= 255 bytes", e.getMessage());
    }
}
