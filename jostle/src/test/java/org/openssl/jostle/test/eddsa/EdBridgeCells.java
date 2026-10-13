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
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.ed.EDServiceNI;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.rand.RandSource;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.util.asn1.ASN1Encoder;
import org.openssl.jostle.util.asn1.Asn1Ni;

import java.math.BigInteger;

/**
 * EdDSA bridge cells shared by the base and FIPS limit tests: each takes the NI set under test, so one body pins
 * both interface libraries on whichever bridge the leg loads. Freed handles are not driven here: reading a freed
 * handle is undefined, so those cells run only in a bounded child JVM.
 */
public final class EdBridgeCells
{
    private static final RandSource RND = TestUtil.RNDSrc;
    private static final int ED25519 = OSSLKeyType.ED25519.getKsType();
    private static final int ED448 = OSSLKeyType.ED448.getKsType();
    private static final String NAME = OSSLKeyType.ED25519.getTypeName();

    private static final BigInteger P25519 = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));
    private static final BigInteger P448 = BigInteger.ONE.shiftLeft(448).subtract(BigInteger.ONE.shiftLeft(224))
            .subtract(BigInteger.ONE);

    private EdBridgeCells()
    {
    }

    private static int code(ErrorCode c)
    {
        return c.getCode();
    }

    /** y little-endian over len bytes, with the x sign bit set when xOdd. */
    public static byte[] encodeY(BigInteger y, int len, boolean xOdd)
    {
        byte[] be = y.toByteArray();
        byte[] le = new byte[len];
        for (int i = 0; i < Math.min(be.length, len); i++)
        {
            le[i] = be[be.length - 1 - i];
        }
        if (xOdd)
        {
            le[len - 1] |= (byte) 0x80;
        }
        return le;
    }

    /** The SubjectPublicKeyInfo of a raw Ed25519 (32 bytes) or Ed448 (57 bytes) public key. */
    public static byte[] spki(byte[] raw)
    {
        byte[] hdr = raw.length == 32
                ? new byte[]{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00}
                : new byte[]{0x30, 0x43, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x71, 0x03, 0x3a, 0x00};
        byte[] out = new byte[hdr.length + raw.length];
        System.arraycopy(hdr, 0, out, 0, hdr.length);
        System.arraycopy(raw, 0, out, hdr.length, raw.length);
        return out;
    }

    /** Public keys whose y is not below the field prime, for both curves. */
    public static byte[][] nonCanonicalPoints()
    {
        return new byte[][]{
                encodeY(P25519, 32, false),
                encodeY(P25519.add(BigInteger.ONE), 32, false),
                encodeY(P25519, 32, true),
                encodeY(BigInteger.ONE.shiftLeft(255).subtract(BigInteger.ONE), 32, false),
                encodeY(P448, 57, false),
                encodeY(P448.add(BigInteger.ONE), 57, false),
                encodeY(BigInteger.ONE.add(BigInteger.ONE.shiftLeft(448)), 57, false)};
    }

    /** Public keys at the boundary that must still decode: y = p - 1 and y = 0 on both curves. */
    public static byte[][] canonicalBoundaryPoints()
    {
        return new byte[][]{
                encodeY(P25519.subtract(BigInteger.ONE), 32, false),
                new byte[32],
                encodeY(P448.subtract(BigInteger.ONE), 57, false),
                new byte[57]};
    }

    private static int decodePublic(EDServiceNI ed, SpecNI spec, int type, byte[] raw)
    {
        long ref = spec.allocate();
        try
        {
            return ed.ni_decode_publicKey(ref, type, raw, 0, raw.length);
        }
        finally
        {
            spec.dispose(ref);
        }
    }

    /** A signer handle given another kind of handle, and a key handle given a signer, are refused typed. */
    public static void wrongKindHandlesAreRefused(EDServiceNI ed, SpecNI spec)
    {
        int signerWrong = code(ErrorCode.JO_EDEC_CTX_WRONG_KIND);
        int specWrong = code(ErrorCode.JO_KEY_SPEC_WRONG_KIND);
        long keyRef = ed.generateKeyPair(ED25519, RND);
        long sigRef = ed.allocateSigner();
        try
        {
            Assertions.assertEquals(signerWrong, ed.ni_initSign(keyRef, keyRef, NAME, null, 0, RND));
            Assertions.assertEquals(signerWrong, ed.ni_initVerify(keyRef, keyRef, NAME, null, 0));
            Assertions.assertEquals(signerWrong, ed.ni_update(keyRef, new byte[8], 0, 8));
            Assertions.assertEquals(signerWrong, ed.ni_sign(keyRef, null, 0, RND));
            Assertions.assertEquals(signerWrong, ed.ni_verify(keyRef, new byte[64], 64));

            Assertions.assertEquals(specWrong, ed.ni_initSign(sigRef, sigRef, NAME, null, 0, RND));
            Assertions.assertEquals(specWrong, ed.ni_initVerify(sigRef, sigRef, NAME, null, 0));
            Assertions.assertEquals(specWrong, ed.ni_getPublicKey(sigRef, new byte[64]));
            Assertions.assertEquals(specWrong, ed.ni_getPrivateKey(sigRef, new byte[64]));
            Assertions.assertEquals(specWrong, ed.ni_decode_publicKey(sigRef, ED25519, new byte[32], 0, 32));
            Assertions.assertEquals(specWrong, ed.ni_decode_privateKey(sigRef, ED25519, new byte[32], 0, 32));

            IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                    () -> ed.update(keyRef, new byte[8], 0, 8));
            Assertions.assertEquals("handle is not an EdDSA signer context", e.getMessage());

            // A dispose of the wrong kind frees nothing: both handles still work afterwards.
            ed.disposeSigner(keyRef);
            Assertions.assertEquals(32, ed.ni_getPublicKey(keyRef, new byte[32]));
            Assertions.assertEquals(0, ed.ni_initSign(sigRef, keyRef, NAME, null, 0, RND));
            Assertions.assertEquals(64, ed.ni_sign(sigRef, null, 0, RND));
        }
        finally
        {
            ed.disposeSigner(sigRef);
            spec.dispose(keyRef);
        }
    }

    /** An instance name with an embedded NUL is refused before OpenSSL sees it; an empty one stays name-is-null. */
    public static void nulInstanceNamesAreRefused(EDServiceNI ed, SpecNI spec)
    {
        int refused = code(ErrorCode.JO_EDEC_INSTANCE_NOT_SUPPORTED);
        long keyRef = ed.generateKeyPair(ED25519, RND);
        long sigRef = ed.allocateSigner();
        try
        {
            for (String name : new String[]{"Ed25519\u0000x", "Ed25519\u0000", "\u0000Ed25519"})
            {
                Assertions.assertEquals(refused, ed.ni_initSign(sigRef, keyRef, name, null, 0, RND), name);
                Assertions.assertEquals(refused, ed.ni_initVerify(sigRef, keyRef, name, null, 0), name);
            }
            IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                    () -> ed.initSign(sigRef, keyRef, "Ed25519\u0000x", null, 0, RND));
            Assertions.assertEquals("EdDSA instance name is not supported", e.getMessage());
            Assertions.assertEquals(code(ErrorCode.JO_NAME_IS_NULL), ed.ni_initSign(sigRef, keyRef, "", null, 0, RND));
            Assertions.assertEquals(code(ErrorCode.JO_OPENSSL_ERROR),
                    ed.ni_initSign(sigRef, keyRef, "Foo", null, 0, RND));
            Assertions.assertEquals(0, ed.ni_initSign(sigRef, keyRef, NAME, null, 0, RND));
        }
        finally
        {
            ed.disposeSigner(sigRef);
            spec.dispose(keyRef);
        }
    }

    /** sign checks ctx, rnd, offset, then the output, and the sizing query refuses a negative offset. */
    public static void signArgumentOrder(EDServiceNI ed, SpecNI spec)
    {
        long keyRef = ed.generateKeyPair(ED25519, RND);
        long sigRef = ed.allocateSigner();
        try
        {
            Assertions.assertEquals(0, ed.ni_initSign(sigRef, keyRef, NAME, null, 0, RND));
            Assertions.assertEquals(code(ErrorCode.JO_OUTPUT_OFFSET_IS_NEGATIVE), ed.ni_sign(sigRef, null, -1, RND));
            Assertions.assertEquals(code(ErrorCode.JO_RAND_NO_RAND_UP_CALL),
                    ed.ni_sign(sigRef, new byte[64], -1, null));
            Assertions.assertEquals(code(ErrorCode.JO_RAND_NO_RAND_UP_CALL), ed.ni_sign(sigRef, null, -1, null));
            Assertions.assertEquals(code(ErrorCode.JO_OUTPUT_OUT_OF_RANGE), ed.ni_sign(sigRef, new byte[64], 65, RND));
            Assertions.assertEquals(64, ed.ni_sign(sigRef, null, 5, RND));
            Assertions.assertEquals(64, ed.ni_sign(sigRef, new byte[64], 0, RND));
        }
        finally
        {
            ed.disposeSigner(sigRef);
            spec.dispose(keyRef);
        }
    }

    /**
     * A public y at or above the field prime is refused at raw decode, and a spec that holds one by another path
     * (an SPKI decode) is refused at initVerify and initSign; y = p - 1 and y = 0 still decode.
     */
    public static void nonCanonicalPointsAreRefused(EDServiceNI ed, SpecNI spec, Asn1Ni asn1)
    {
        int refused = code(ErrorCode.JO_EDEC_POINT_NOT_CANONICAL);
        for (byte[] raw : nonCanonicalPoints())
        {
            int type = raw.length == 32 ? ED25519 : ED448;
            String label = raw.length + " bytes, top " + (raw[raw.length - 1] & 0xff);
            Assertions.assertEquals(refused, decodePublic(ed, spec, type, raw), label);
            Assertions.assertEquals(refused, decodePublic(ed, spec, OSSLKeyType.NONE.getKsType(), raw), label);

            byte[] enc = spki(raw);
            PKEYKeySpec ps = ASN1Encoder.fromSubjectPublicKeyInfo(asn1, spec, enc, 0, enc.length, null);
            String name = raw.length == 32 ? NAME : OSSLKeyType.ED448.getTypeName();
            long sigRef = ed.allocateSigner();
            try
            {
                Assertions.assertEquals(refused, ed.ni_initVerify(sigRef, ps.getReference(), name, null, 0), label);
                Assertions.assertEquals(refused, ed.ni_initSign(sigRef, ps.getReference(), name, null, 0, RND), label);
            }
            finally
            {
                ed.disposeSigner(sigRef);
            }
        }
        for (byte[] raw : canonicalBoundaryPoints())
        {
            int type = raw.length == 32 ? ED25519 : ED448;
            Assertions.assertEquals(0, decodePublic(ed, spec, type, raw), "" + raw.length);
        }
        IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class, () -> {
            long ref = spec.allocate();
            try
            {
                ed.decode_publicKey(ref, ED25519, nonCanonicalPoints()[0], 0, 32);
            }
            finally
            {
                spec.dispose(ref);
            }
        });
        Assertions.assertEquals("EdDSA public key is not canonical", e.getMessage());
    }

    /** A second decode into one spec replaces the key: the spec answers with the second public key. */
    public static void decodeTwiceReplacesTheKey(EDServiceNI ed, SpecNI spec)
    {
        long a = ed.generateKeyPair(ED25519, RND);
        long b = ed.generateKeyPair(ED25519, RND);
        long target = spec.allocate();
        try
        {
            byte[] pa = new byte[32];
            byte[] pb = new byte[32];
            ed.getPublicKey(a, pa);
            ed.getPublicKey(b, pb);
            Assertions.assertEquals(0, ed.ni_decode_publicKey(target, ED25519, pa, 0, 32));
            Assertions.assertEquals(0, ed.ni_decode_publicKey(target, ED25519, pb, 0, 32));
            byte[] now = new byte[32];
            ed.getPublicKey(target, now);
            Assertions.assertArrayEquals(pb, now);

            byte[] sa = new byte[32];
            ed.getPrivateKey(a, sa);
            Assertions.assertEquals(0, ed.ni_decode_privateKey(target, ED25519, sa, 0, 32));
            ed.getPublicKey(target, now);
            Assertions.assertArrayEquals(pa, now);
        }
        finally
        {
            spec.dispose(target);
            spec.dispose(a);
            spec.dispose(b);
        }
    }
}
