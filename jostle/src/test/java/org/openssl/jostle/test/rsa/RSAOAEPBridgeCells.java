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

package org.openssl.jostle.test.rsa;

import org.junit.jupiter.api.Assertions;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.md.MDServiceNI;
import org.openssl.jostle.jcajce.provider.rsa.RSAOAEPCipherNI;
import org.openssl.jostle.jcajce.provider.rsa.RSAPKCS1CipherNI;
import org.openssl.jostle.jcajce.provider.rsa.RSAServiceNI;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.rand.RandSource;
import org.openssl.jostle.test.TestUtil;

/**
 * RSA-OAEP cipher bridge cells shared by the base and FIPS limit tests: each takes the NI set under test, so one
 * body pins both interface libraries on whichever bridge the leg loads.
 */
public final class RSAOAEPBridgeCells
{
    private static final RandSource RND = TestUtil.RNDSrc;
    private static final byte[] PUB_EXP_F4 = {0x01, 0x00, 0x01};
    private static final String DIGEST = "SHA-256";
    private static final int ENC = RSAOAEPCipherNI.OP_ENCRYPT;
    private static final int DEC = RSAOAEPCipherNI.OP_DECRYPT;

    private RSAOAEPBridgeCells()
    {
    }

    private static int code(ErrorCode c)
    {
        return c.getCode();
    }

    /**
     * A key spec, a PKCS#1 cipher context, an RSA signer context and a digest context as the OAEP context, and an
     * OAEP context as the key, are each refused with a typed code at both entries; a dispose of the wrong kind
     * frees nothing.
     */
    public static void wrongKindHandlesAreRefused(RSAOAEPCipherNI oaep, RSAPKCS1CipherNI pkcs1, RSAServiceNI rsa,
                                                  SpecNI spec, MDServiceNI md)
    {
        int ctxWrong = code(ErrorCode.JO_RSA_OAEP_CTX_WRONG_KIND);
        int specWrong = code(ErrorCode.JO_KEY_SPEC_WRONG_KIND);
        long keyRef = rsa.generateKeyPair(2048, PUB_EXP_F4, RND);
        long oaepRef = oaep.allocateCipher();
        long pkcs1Ref = pkcs1.allocateCipher();
        long sigRef = rsa.allocateSigner();
        long mdRef = md.allocateDigest("SHA256", 0);
        try
        {
            for (long bad : new long[]{keyRef, pkcs1Ref, sigRef, mdRef})
            {
                Assertions.assertEquals(ctxWrong, oaep.ni_init(bad, keyRef, ENC, DIGEST, null, null, RND));
                Assertions.assertEquals(ctxWrong, oaep.ni_doFinal(bad, new byte[16], 0, 16, null, 0, RND));
                Assertions.assertEquals(ctxWrong, oaep.ni_doFinal(bad, new byte[16], 0, 16, new byte[256], 0, RND));
            }
            Assertions.assertEquals(specWrong, oaep.ni_init(oaepRef, oaepRef, ENC, DIGEST, null, null, RND));
            Assertions.assertEquals(specWrong, oaep.ni_init(oaepRef, mdRef, ENC, DIGEST, null, null, RND));

            IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                    () -> oaep.doFinal(keyRef, new byte[16], 0, 16, null, 0, RND));
            Assertions.assertEquals("handle is not an RSA-OAEP cipher context", e.getMessage());

            // A dispose of the wrong kind frees nothing: the handles still work afterwards.
            oaep.disposeCipher(keyRef);
            oaep.disposeCipher(pkcs1Ref);
            oaep.disposeCipher(sigRef);
            oaep.disposeCipher(mdRef);
            Assertions.assertEquals(0, oaep.ni_init(oaepRef, keyRef, ENC, DIGEST, null, null, RND));
            Assertions.assertEquals(256, oaep.ni_doFinal(oaepRef, new byte[16], 0, 16, null, 0, RND));
            Assertions.assertEquals(32, md.ni_getDigestOutputLen(mdRef));
        }
        finally
        {
            md.dispose(mdRef);
            rsa.disposeSigner(sigRef);
            pkcs1.disposeCipher(pkcs1Ref);
            oaep.disposeCipher(oaepRef);
            spec.dispose(keyRef);
        }
    }

    /**
     * An empty name, one with an embedded NUL, and a name the library cannot fetch are refused with one code for
     * the digest and for MGF1, at encrypt and decrypt; a null digest keeps its own code; the JDK, BouncyCastle and
     * OpenSSL spellings of SHA-256 configure.
     */
    public static void unusableDigestNamesAreRefused(RSAOAEPCipherNI oaep, RSAServiceNI rsa, SpecNI spec)
    {
        int notServed = code(ErrorCode.JO_RSA_DIGEST_NOT_SUPPORTED);
        long keyRef = rsa.generateKeyPair(2048, PUB_EXP_F4, RND);
        long ref = oaep.allocateCipher();
        try
        {
            for (int op : new int[]{ENC, DEC})
            {
                for (String name : new String[]{"", DIGEST + "\u0000x", "NOPE"})
                {
                    String label = op + " " + name.replace("\u0000", "\\0");
                    Assertions.assertEquals(notServed, oaep.ni_init(ref, keyRef, op, name, null, null, RND), label);
                    Assertions.assertEquals(notServed, oaep.ni_init(ref, keyRef, op, DIGEST, name, null, RND), label);
                }
                for (String name : new String[]{"SHA-256", "SHA256", "SHA2-256"})
                {
                    Assertions.assertEquals(0, oaep.ni_init(ref, keyRef, op, name, name, null, RND), op + " " + name);
                }
                Assertions.assertEquals(code(ErrorCode.JO_NAME_IS_NULL),
                        oaep.ni_init(ref, keyRef, op, null, null, null, RND));
            }
            IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                    () -> oaep.init(ref, keyRef, ENC, "NOPE", null, null, RND));
            Assertions.assertEquals("the loaded provider does not serve RSA-OAEP with NOPE and MGF1 NOPE",
                    e.getMessage());
        }
        finally
        {
            oaep.disposeCipher(ref);
            spec.dispose(keyRef);
        }
    }

    /**
     * A re-init refused after the context check drops the previous session: doFinal then answers "not
     * initialised" rather than running the previous key and direction.
     */
    public static void aRefusedReinitLeavesNoSession(RSAOAEPCipherNI oaep, RSAServiceNI rsa, SpecNI spec)
    {
        int notInitialised = code(ErrorCode.JO_NOT_INITIALIZED);
        long keyRef = rsa.generateKeyPair(2048, PUB_EXP_F4, RND);
        long ref = oaep.allocateCipher();
        try
        {
            Assertions.assertEquals(0, oaep.ni_init(ref, keyRef, ENC, DIGEST, null, null, RND));
            Assertions.assertEquals(256, oaep.ni_doFinal(ref, new byte[16], 0, 16, null, 0, RND));
            Assertions.assertEquals(code(ErrorCode.JO_INVALID_OP_MODE),
                    oaep.ni_init(ref, keyRef, 3, DIGEST, null, null, RND));
            Assertions.assertEquals(notInitialised, oaep.ni_doFinal(ref, new byte[16], 0, 16, null, 0, RND));

            Assertions.assertEquals(0, oaep.ni_init(ref, keyRef, DEC, DIGEST, null, null, RND));
            Assertions.assertEquals(code(ErrorCode.JO_RSA_DIGEST_NOT_SUPPORTED),
                    oaep.ni_init(ref, keyRef, ENC, "NOPE", null, null, RND));
            Assertions.assertEquals(notInitialised, oaep.ni_doFinal(ref, new byte[256], 0, 256, null, 0, RND));
        }
        finally
        {
            oaep.disposeCipher(ref);
            spec.dispose(keyRef);
        }
    }

    /** The RandSource is checked at both bridge entries, after the context and the key. */
    public static void aNullRandSourceIsRefusedAtTheBridge(RSAOAEPCipherNI oaep, RSAServiceNI rsa, SpecNI spec)
    {
        int noRand = code(ErrorCode.JO_RAND_NO_RAND_UP_CALL);
        long keyRef = rsa.generateKeyPair(2048, PUB_EXP_F4, RND);
        long ref = oaep.allocateCipher();
        try
        {
            Assertions.assertEquals(noRand, oaep.ni_init(ref, keyRef, ENC, DIGEST, null, null, null));
            Assertions.assertEquals(code(ErrorCode.JO_KEY_SPEC_IS_NULL),
                    oaep.ni_init(ref, 0, ENC, DIGEST, null, null, null));
            Assertions.assertEquals(0, oaep.ni_init(ref, keyRef, ENC, DIGEST, null, null, RND));
            Assertions.assertEquals(noRand, oaep.ni_doFinal(ref, null, 0, 0, null, 0, null));
        }
        finally
        {
            oaep.disposeCipher(ref);
            spec.dispose(keyRef);
        }
    }
}
