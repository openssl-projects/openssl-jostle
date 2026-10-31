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

package org.openssl.jostle.test.mlxkem;

import org.junit.jupiter.api.Assertions;
import org.openssl.jostle.jcajce.interfaces.OSSLKey;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.md.MDServiceNI;
import org.openssl.jostle.jcajce.provider.mldsa.MLDSAServiceNI;
import org.openssl.jostle.jcajce.provider.mlxkem.MLXKEMServiceNI;
import org.openssl.jostle.jcajce.spec.MLXKEMParameterSpec;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.rand.RandSource;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.util.Arrays;

import java.security.PublicKey;

/**
 * Hybrid KEM bridge cells shared by the base and FIPS limit tests: each takes the NI set under test, so one body
 * pins both interface libraries on whichever bridge the leg loads. Only the foreign-key cell needs a key, and its
 * caller supplies one the module serves.
 */
public final class MLXKEMBridgeCells
{
    private static final RandSource RND = TestUtil.RNDSrc;
    private static final int KT_X25519 = OSSLKeyType.X25519MLKEM768.getKsType();
    // Above every group's share and private half.
    private static final int OUT_LEN = 4096;

    private MLXKEMBridgeCells()
    {
    }

    private static int code(ErrorCode c)
    {
        return c.getCode();
    }

    /**
     * An ML-DSA signer context and a digest context as the key spec are refused with a typed code at both getters and
     * both decoders, and nothing is written into them: each still answers as its own kind afterwards.
     */
    public static void wrongKindHandlesAreRefused(MLXKEMServiceNI mlxkem, MLDSAServiceNI mldsa, MDServiceNI md)
    {
        int specWrong = code(ErrorCode.JO_KEY_SPEC_WRONG_KIND);
        long mldsaRef = mldsa.allocateSigner();
        long mdRef = md.allocateDigest("SHA256", 0);
        try
        {
            for (long bad : new long[]{mldsaRef, mdRef})
            {
                Assertions.assertEquals(specWrong, mlxkem.ni_getPublicKey(bad, null));
                Assertions.assertEquals(specWrong, mlxkem.ni_getPublicKey(bad, new byte[OUT_LEN]));
                Assertions.assertEquals(specWrong, mlxkem.ni_getPrivateKey(bad, null));
                Assertions.assertEquals(specWrong, mlxkem.ni_getPrivateKey(bad, new byte[OUT_LEN]));
                Assertions.assertEquals(specWrong,
                        mlxkem.ni_decode_publicKey(bad, KT_X25519, new byte[OUT_LEN], 0, OUT_LEN));
                Assertions.assertEquals(specWrong,
                        mlxkem.ni_decode_privateKey(bad, KT_X25519, new byte[OUT_LEN], 0, OUT_LEN, RND));
            }

            IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                    () -> mlxkem.getPublicKey(mldsaRef, null));
            Assertions.assertEquals("handle is not a key spec", e.getMessage());

            // Nothing was written into the foreign objects: each still answers as its own kind.
            Assertions.assertEquals(32, md.ni_getDigestOutputLen(mdRef));
            Assertions.assertEquals(code(ErrorCode.JO_NOT_INITIALIZED), mldsa.ni_update(mldsaRef, new byte[8], 0, 8));
        }
        finally
        {
            md.dispose(mdRef);
            mldsa.disposeSigner(mldsaRef);
        }
    }

    /**
     * A key spec holding a key of another algorithm is refused typed at both getters, and a decode that fails leaves
     * it holding its own key: its encoding is unchanged afterwards. The decode targets {@code served}, a group the
     * library serves, and the import refuses the input; with no group served (null) it targets X25519MLKEM768 and
     * the library cannot start the import.
     */
    public static void aKeyOfAnotherAlgorithmIsRefusedAndKept(MLXKEMServiceNI mlxkem, MLXKEMParameterSpec served,
                                                             PublicKey... foreign)
    {
        int incorrect = code(ErrorCode.JO_INCORRECT_KEY_TYPE);
        int decodeType = served != null ? served.getKeyType().getKsType() : KT_X25519;
        int refused = code(served != null ? ErrorCode.JO_INVALID_KEY_TYPE : ErrorCode.JO_OPENSSL_ERROR);
        for (PublicKey key : foreign)
        {
            String alg = key.getAlgorithm();
            byte[] before = key.getEncoded();
            long ref = ((OSSLKey) key).getSpec().getReference();

            Assertions.assertEquals(incorrect, mlxkem.ni_getPublicKey(ref, null), alg);
            Assertions.assertEquals(incorrect, mlxkem.ni_getPublicKey(ref, new byte[OUT_LEN]), alg);
            Assertions.assertEquals(incorrect, mlxkem.ni_getPrivateKey(ref, null), alg);
            Assertions.assertEquals(incorrect, mlxkem.ni_getPrivateKey(ref, new byte[OUT_LEN]), alg);
            IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                    () -> mlxkem.getPublicKey(ref, null), alg);
            Assertions.assertEquals("invalid key type for a hybrid ML-KEM", e.getMessage(), alg);

            // One byte is no group's share or private half.
            Assertions.assertEquals(refused, mlxkem.ni_decode_publicKey(ref, decodeType, new byte[1], 0, 1), alg);
            Assertions.assertEquals(refused,
                    mlxkem.ni_decode_privateKey(ref, decodeType, new byte[1], 0, 1, RND), alg);

            Assertions.assertArrayEquals(before, key.getEncoded(), alg);
        }
    }

    /** Each decoder checks the key spec, then (private only) the RandSource, then the input; the getters the spec. */
    public static void theSpecThenTheRandSourceThenTheInputAreChecked(MLXKEMServiceNI mlxkem, SpecNI spec,
                                                                     MDServiceNI md)
    {
        int specWrong = code(ErrorCode.JO_KEY_SPEC_WRONG_KIND);
        int specNull = code(ErrorCode.JO_KEY_SPEC_IS_NULL);
        int noRand = code(ErrorCode.JO_RAND_NO_RAND_UP_CALL);
        int inputNull = code(ErrorCode.JO_INPUT_IS_NULL);
        long keyRef = spec.allocate();
        long mdRef = md.allocateDigest("SHA256", 0);
        try
        {
            Assertions.assertEquals(specNull, mlxkem.ni_getPublicKey(0, null));
            Assertions.assertEquals(specNull, mlxkem.ni_getPrivateKey(0, null));

            Assertions.assertEquals(specNull, mlxkem.ni_decode_publicKey(0, KT_X25519, null, -1, -1));
            Assertions.assertEquals(specWrong, mlxkem.ni_decode_publicKey(mdRef, KT_X25519, null, -1, -1));
            Assertions.assertEquals(inputNull, mlxkem.ni_decode_publicKey(keyRef, KT_X25519, null, -1, -1));

            Assertions.assertEquals(specNull, mlxkem.ni_decode_privateKey(0, KT_X25519, null, -1, -1, null));
            Assertions.assertEquals(specWrong, mlxkem.ni_decode_privateKey(mdRef, KT_X25519, null, -1, -1, null));
            Assertions.assertEquals(noRand, mlxkem.ni_decode_privateKey(keyRef, KT_X25519, null, -1, -1, null));
            Assertions.assertEquals(inputNull, mlxkem.ni_decode_privateKey(keyRef, KT_X25519, null, -1, -1, RND));

            IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                    () -> mlxkem.decode_privateKey(keyRef, KT_X25519, new byte[OUT_LEN], 0, OUT_LEN, null));
            Assertions.assertEquals("supplied random source was null", e.getMessage());
        }
        finally
        {
            md.dispose(mdRef);
            spec.dispose(keyRef);
        }
    }

    /**
     * An X group's exported private half re-imports through the private decoder, and the key it makes carries the
     * original share and decapsulates the original key's encapsulation to the same secret. The import runs the
     * ML-KEM half's pairwise test, which draws entropy through the RandSource.
     */
    public static void theExportedPrivateHalfReimports(MLXKEMServiceNI mlxkem, SpecNI spec,
                                                       Iterable<MLXKEMParameterSpec> groups)
    {
        for (MLXKEMParameterSpec group : groups)
        {
            String name = group.getName();
            int type = group.getKeyType().getKsType();
            long original = mlxkem.generateKeyPair(type, RND);
            long imported = spec.allocate();
            byte[] priv = null;
            try
            {
                priv = new byte[mlxkem.getPrivateKey(original, null)];
                Assertions.assertEquals(priv.length, mlxkem.getPrivateKey(original, priv), name);
                Assertions.assertEquals(0, mlxkem.decode_privateKey(imported, type, priv, 0, priv.length, RND), name);

                byte[] share = new byte[mlxkem.getPublicKey(original, null)];
                mlxkem.getPublicKey(original, share);
                byte[] again = new byte[mlxkem.getPublicKey(imported, null)];
                mlxkem.getPublicKey(imported, again);
                Assertions.assertArrayEquals(share, again, name + ": the share");

                int secretLen = spec.encapSecretLength(original, null, RND);
                int encLen = spec.encap(original, null, new byte[secretLen], 0, secretLen, null, 0, 0, RND);
                byte[] secret = new byte[secretLen];
                byte[] enc = new byte[encLen];
                spec.encap(original, null, secret, 0, secretLen, enc, 0, encLen, RND);
                byte[] opened = new byte[secretLen];
                spec.decap(imported, null, enc, 0, encLen, opened, 0, secretLen, RND);
                Assertions.assertArrayEquals(secret, opened, name + ": the secret");
            }
            finally
            {
                if (priv != null)
                {
                    Arrays.fill(priv, (byte) 0);
                }
                spec.dispose(imported);
                spec.dispose(original);
            }
        }
    }
}
