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
 * RSA-PKCS1 cipher bridge cells shared by the base and FIPS limit tests: each takes the NI set under test, so one
 * body pins both interface libraries on whichever bridge the leg loads. Every cell inits for encrypt only, the one
 * direction both FIPS modules initialise.
 */
public final class RSAPKCS1BridgeCells
{
    private static final RandSource RND = TestUtil.RNDSrc;
    private static final byte[] PUB_EXP_F4 = {0x01, 0x00, 0x01};
    private static final int ENC = RSAPKCS1CipherNI.OP_ENCRYPT;

    private RSAPKCS1BridgeCells()
    {
    }

    private static int code(ErrorCode c)
    {
        return c.getCode();
    }

    /**
     * A key spec, an OAEP cipher context, an RSA signer context and a digest context as the PKCS1 context, and a
     * PKCS1 context as the key, are each refused with a typed code at both entries; a dispose of the wrong kind
     * frees nothing.
     */
    public static void wrongKindHandlesAreRefused(RSAPKCS1CipherNI pkcs1, RSAOAEPCipherNI oaep, RSAServiceNI rsa,
                                                  SpecNI spec, MDServiceNI md)
    {
        int ctxWrong = code(ErrorCode.JO_RSA_PKCS1_CTX_WRONG_KIND);
        int specWrong = code(ErrorCode.JO_KEY_SPEC_WRONG_KIND);
        long keyRef = rsa.generateKeyPair(2048, PUB_EXP_F4, RND);
        long pkcs1Ref = pkcs1.allocateCipher();
        long oaepRef = oaep.allocateCipher();
        long sigRef = rsa.allocateSigner();
        long mdRef = md.allocateDigest("SHA256", 0);
        try
        {
            for (long bad : new long[]{keyRef, oaepRef, sigRef, mdRef})
            {
                Assertions.assertEquals(ctxWrong, pkcs1.ni_init(bad, keyRef, ENC, RND));
                Assertions.assertEquals(ctxWrong, pkcs1.ni_doFinal(bad, new byte[16], 0, 16, null, 0, RND));
                Assertions.assertEquals(ctxWrong, pkcs1.ni_doFinal(bad, new byte[16], 0, 16, new byte[256], 0, RND));
            }
            Assertions.assertEquals(specWrong, pkcs1.ni_init(pkcs1Ref, pkcs1Ref, ENC, RND));
            Assertions.assertEquals(specWrong, pkcs1.ni_init(pkcs1Ref, mdRef, ENC, RND));

            IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                    () -> pkcs1.doFinal(keyRef, new byte[16], 0, 16, null, 0, RND));
            Assertions.assertEquals("handle is not an RSA-PKCS1 cipher context", e.getMessage());

            // A dispose of the wrong kind frees nothing: the handles still work afterwards.
            pkcs1.disposeCipher(keyRef);
            pkcs1.disposeCipher(oaepRef);
            pkcs1.disposeCipher(sigRef);
            pkcs1.disposeCipher(mdRef);
            Assertions.assertEquals(0, pkcs1.ni_init(pkcs1Ref, keyRef, ENC, RND));
            Assertions.assertEquals(0, oaep.ni_init(oaepRef, keyRef, RSAOAEPCipherNI.OP_ENCRYPT, "SHA-256", null,
                    null, RND));
            Assertions.assertEquals(32, md.ni_getDigestOutputLen(mdRef));
        }
        finally
        {
            md.dispose(mdRef);
            rsa.disposeSigner(sigRef);
            oaep.disposeCipher(oaepRef);
            pkcs1.disposeCipher(pkcs1Ref);
            spec.dispose(keyRef);
        }
    }

    /**
     * A re-init refused after the context, key and RandSource checks drops the previous session: doFinal then
     * answers "not initialised" rather than running the previous key and direction.
     */
    public static void aRefusedReinitLeavesNoSession(RSAPKCS1CipherNI pkcs1, RSAServiceNI rsa, SpecNI spec)
    {
        int notInitialised = code(ErrorCode.JO_NOT_INITIALIZED);
        int badMode = code(ErrorCode.JO_INVALID_OP_MODE);
        long keyRef = rsa.generateKeyPair(2048, PUB_EXP_F4, RND);
        long ref = pkcs1.allocateCipher();
        try
        {
            for (int mode : new int[]{0, 3})
            {
                Assertions.assertEquals(0, pkcs1.ni_init(ref, keyRef, ENC, RND));
                Assertions.assertEquals(badMode, pkcs1.ni_init(ref, keyRef, mode, RND), "op mode " + mode);
                Assertions.assertEquals(notInitialised, pkcs1.ni_doFinal(ref, new byte[16], 0, 16, null, 0, RND));
                Assertions.assertEquals(notInitialised,
                        pkcs1.ni_doFinal(ref, new byte[16], 0, 16, new byte[256], 0, RND));
            }
        }
        finally
        {
            pkcs1.disposeCipher(ref);
            spec.dispose(keyRef);
        }
    }

    /** The RandSource is checked at both bridge entries, after the context and the key. */
    public static void aNullRandSourceIsRefusedAtTheBridge(RSAPKCS1CipherNI pkcs1, RSAServiceNI rsa, SpecNI spec)
    {
        int noRand = code(ErrorCode.JO_RAND_NO_RAND_UP_CALL);
        long keyRef = rsa.generateKeyPair(2048, PUB_EXP_F4, RND);
        long ref = pkcs1.allocateCipher();
        try
        {
            Assertions.assertEquals(noRand, pkcs1.ni_init(ref, keyRef, ENC, null));
            Assertions.assertEquals(code(ErrorCode.JO_KEY_SPEC_IS_NULL), pkcs1.ni_init(ref, 0, ENC, null));
            Assertions.assertEquals(code(ErrorCode.JO_CIPHER_CTX_IS_NULL), pkcs1.ni_init(0, 0, ENC, null));
            Assertions.assertEquals(0, pkcs1.ni_init(ref, keyRef, ENC, RND));
            Assertions.assertEquals(noRand, pkcs1.ni_doFinal(ref, null, 0, 0, null, 0, null));
            Assertions.assertEquals(code(ErrorCode.JO_CIPHER_CTX_IS_NULL),
                    pkcs1.ni_doFinal(0, null, 0, 0, null, 0, null));
        }
        finally
        {
            pkcs1.disposeCipher(ref);
            spec.dispose(keyRef);
        }
    }
}
