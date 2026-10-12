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

package org.openssl.jostle.test.ec;

import org.junit.jupiter.api.Assertions;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.ec.ECServiceNI;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.rand.RandSource;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.util.Arrays;

import java.math.BigInteger;

/**
 * EC bridge cells shared by the base and FIPS limit tests: each takes the NI pair under test, so one body pins
 * both interface libraries on whichever bridge the leg loads.
 */
public final class ECBridgeCells
{
    private static final RandSource RND = TestUtil.RNDSrc;
    private static final String CURVE = "P-256";
    private static final String DIGEST = "SHA256";

    private ECBridgeCells()
    {
    }

    private static int code(ErrorCode c)
    {
        return c.getCode();
    }

    private static byte[] curve(ECServiceNI ec, int component)
    {
        byte[] out = new byte[ec.getCurveComponent(CURVE, component, null)];
        ec.getCurveComponent(CURVE, component, out);
        return out;
    }

    private static byte[] generator(ECServiceNI ec)
    {
        byte[] gx = curve(ec, ECServiceNI.CURVE_COMP_GX);
        byte[] gy = curve(ec, ECServiceNI.CURVE_COMP_GY);
        byte[] point = new byte[65];
        point[0] = 4;
        System.arraycopy(gx, 0, point, 33 - gx.length, gx.length);
        System.arraycopy(gy, 0, point, 65 - gy.length, gy.length);
        return point;
    }

    private static int makePrivate(ECServiceNI ec, SpecNI spec, String name, byte[] scalar)
    {
        int[] err = new int[1];
        long ref = ec.ni_makePrivateFromComponents(name, scalar, err, RND);
        if (ref != 0)
        {
            spec.dispose(ref);
        }
        return err[0];
    }

    private static int makePublic(ECServiceNI ec, SpecNI spec, String name, byte[] point)
    {
        int[] err = new int[1];
        long ref = ec.ni_makePublicFromComponents(name, point, err, RND);
        if (ref != 0)
        {
            spec.dispose(ref);
        }
        return err[0];
    }

    /** An empty curve or digest name, or one with an embedded NUL, names nothing on either bridge. */
    public static void unusableNamesAreRefused(ECServiceNI ec, SpecNI spec)
    {
        int notSupported = code(ErrorCode.JO_CURVE_NOT_SUPPORTED);
        byte[] point = generator(ec);
        for (String name : new String[]{"P-256\u0000junk", ""})
        {
            Assertions.assertEquals(notSupported, ec.ni_curveSupported(name), name);
            int[] err = new int[1];
            Assertions.assertEquals(0L, ec.ni_generateKeyPair(name, err, RND), name);
            Assertions.assertEquals(notSupported, err[0], name);
            Assertions.assertEquals(notSupported, makePrivate(ec, spec, name, new byte[]{1}), name);
            Assertions.assertEquals(notSupported, makePublic(ec, spec, name, point), name);
            Assertions.assertEquals(notSupported,
                    ec.ni_getCurveComponent(name, ECServiceNI.CURVE_COMP_P, new byte[64]), name);
        }

        int digestRefused = code(ErrorCode.JO_EC_DIGEST_NOT_SUPPORTED);
        long keyRef = ec.generateKeyPair(CURVE, RND);
        long sigRef = ec.allocateSigner();
        try
        {
            for (String digest : new String[]{"SHA256\u0000junk", "", "NOPE"})
            {
                Assertions.assertEquals(digestRefused, ec.ni_initSign(sigRef, keyRef, digest, RND), digest);
                Assertions.assertEquals(digestRefused, ec.ni_initVerify(sigRef, keyRef, digest), digest);
            }
            IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                    () -> ec.initVerify(sigRef, keyRef, "NOPE"));
            Assertions.assertEquals("digest is not supported", e.getMessage());
            Assertions.assertEquals(0, ec.ni_initSign(sigRef, keyRef, DIGEST, RND));
        }
        finally
        {
            ec.disposeSigner(sigRef);
            spec.dispose(keyRef);
        }
    }

    /** A zero-length output is a size query on both bridges: the length comes back and nothing is written. */
    public static void zeroLengthOutputIsASizeQuery(ECServiceNI ec)
    {
        Assertions.assertEquals(32, ec.ni_getCurveComponent(CURVE, ECServiceNI.CURVE_COMP_P, new byte[0]));
        byte[][] in = new byte[7][];
        int[] comps = {ECServiceNI.CURVE_COMP_P, ECServiceNI.CURVE_COMP_A, ECServiceNI.CURVE_COMP_B,
                ECServiceNI.CURVE_COMP_GX, ECServiceNI.CURVE_COMP_GY, ECServiceNI.CURVE_COMP_ORDER,
                ECServiceNI.CURVE_COMP_COFACTOR};
        for (int i = 0; i < comps.length; i++)
        {
            in[i] = curve(ec, comps[i]);
        }
        int nameLen = ec.ni_findCurveName(ECServiceNI.FIELD_TYPE_PRIME, in[0], in[1], in[2], in[3], in[4], in[5],
                in[6], null);
        Assertions.assertTrue(nameLen > 0);
        Assertions.assertEquals(nameLen, ec.ni_findCurveName(ECServiceNI.FIELD_TYPE_PRIME, in[0], in[1], in[2],
                in[3], in[4], in[5], in[6], new byte[0]));
    }

    /** A handle of the wrong kind is refused with a typed code before it is used. */
    public static void wrongKindHandlesAreRefused(ECServiceNI ec, SpecNI spec)
    {
        int signerWrong = code(ErrorCode.JO_EC_CTX_WRONG_KIND);
        int kexWrong = code(ErrorCode.JO_EC_KEX_CTX_WRONG_KIND);
        int specWrong = code(ErrorCode.JO_KEY_SPEC_WRONG_KIND);
        long keyRef = ec.generateKeyPair(CURVE, RND);
        long peerRef = ec.generateKeyPair(CURVE, RND);
        long sigRef = ec.allocateSigner();
        long kexRef = ec.allocateKex();
        try
        {
            ec.initSign(sigRef, keyRef, DIGEST, RND);
            ec.kexInit(kexRef, keyRef, RND);
            ec.kexSetPeer(kexRef, peerRef, RND);

            Assertions.assertEquals(kexWrong, ec.ni_kexDerive(sigRef, new byte[32], 0, RND));
            Assertions.assertEquals(kexWrong, ec.ni_kexSetPeer(sigRef, peerRef, RND));
            Assertions.assertEquals(kexWrong, ec.ni_kexInit(sigRef, keyRef, RND));

            Assertions.assertEquals(signerWrong, ec.ni_update(kexRef, new byte[8], 0, 8));
            Assertions.assertEquals(signerWrong, ec.ni_sign(kexRef, null, 0, RND));
            Assertions.assertEquals(signerWrong, ec.ni_verify(kexRef, new byte[70], 70, RND));
            Assertions.assertEquals(signerWrong, ec.ni_initSign(kexRef, keyRef, DIGEST, RND));

            Assertions.assertEquals(signerWrong, ec.ni_initSign(keyRef, keyRef, DIGEST, RND));
            Assertions.assertEquals(kexWrong, ec.ni_kexDerive(keyRef, new byte[32], 0, RND));

            Assertions.assertEquals(specWrong, ec.ni_getComponent(sigRef, ECServiceNI.COMP_PUBLIC_X, new byte[64]));
            Assertions.assertEquals(specWrong, ec.ni_getComponent(kexRef, ECServiceNI.COMP_PUBLIC_X, new byte[64]));
            Assertions.assertEquals(specWrong, ec.ni_initSign(sigRef, kexRef, DIGEST, RND));
            Assertions.assertEquals(specWrong, ec.ni_kexSetPeer(kexRef, sigRef, RND));

            IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                    () -> ec.update(kexRef, new byte[8], 0, 8));
            Assertions.assertEquals("handle is not an EC signer context", e.getMessage());
            e = Assertions.assertThrows(IllegalArgumentException.class,
                    () -> ec.kexDerive(sigRef, new byte[32], 0, RND));
            Assertions.assertEquals("handle is not a key-agreement context", e.getMessage());

            // A dispose of the wrong kind frees nothing: the handles still work afterwards.
            ec.disposeSigner(kexRef);
            ec.disposeKex(sigRef);
            Assertions.assertEquals(32, ec.ni_kexDerive(kexRef, new byte[32], 0, RND));
            Assertions.assertTrue(ec.ni_sign(sigRef, null, 0, RND) > 0);
        }
        finally
        {
            ec.disposeKex(kexRef);
            ec.disposeSigner(sigRef);
            spec.dispose(keyRef);
            spec.dispose(peerRef);
        }
    }

    /** A private scalar of zero or at or above the order is refused; leading zero bytes are not. */
    public static void privateScalarRange(ECServiceNI ec, SpecNI spec)
    {
        int refused = code(ErrorCode.JO_EC_SCALAR_OUT_OF_RANGE);
        BigInteger n = new BigInteger(1, curve(ec, ECServiceNI.CURVE_COMP_ORDER));
        BigInteger nMinus1 = n.subtract(BigInteger.ONE);
        Assertions.assertEquals(refused, makePrivate(ec, spec, CURVE, new byte[1]));
        Assertions.assertEquals(refused, makePrivate(ec, spec, CURVE, new byte[32]));
        Assertions.assertEquals(0, makePrivate(ec, spec, CURVE, new byte[]{1}));
        Assertions.assertEquals(0, makePrivate(ec, spec, CURVE, magnitude(nMinus1, 32)));
        Assertions.assertEquals(refused, makePrivate(ec, spec, CURVE, magnitude(n, 32)));
        Assertions.assertEquals(refused, makePrivate(ec, spec, CURVE, magnitude(n.add(BigInteger.ONE), 32)));
        Assertions.assertEquals(refused, makePrivate(ec, spec, CURVE,
                magnitude(BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE), 32)));
        Assertions.assertEquals(0, makePrivate(ec, spec, CURVE, magnitude(nMinus1, 33)));

        IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                () -> ec.makePrivateFromComponents(CURVE, magnitude(n, 32), RND));
        Assertions.assertEquals("scalar is not in [1, n-1]", e.getMessage());
    }

    private static byte[] magnitude(BigInteger v, int len)
    {
        byte[] raw = v.toByteArray();
        byte[] out = new byte[len];
        int copy = Math.min(raw.length, len);
        System.arraycopy(raw, raw.length - copy, out, len - copy, copy);
        return out;
    }

    /** A derive that writes consumes the peer: the next derive needs a new set_peer, then agrees again. */
    public static void deriveConsumesThePeer(ECServiceNI ec, SpecNI spec)
    {
        int unexpected = code(ErrorCode.JO_UNEXPECTED_STATE);
        long keyRef = ec.generateKeyPair(CURVE, RND);
        long peerRef = ec.generateKeyPair(CURVE, RND);
        long kexRef = ec.allocateKex();
        try
        {
            ec.kexInit(kexRef, keyRef, RND);
            Assertions.assertEquals(0, ec.ni_kexSetPeer(kexRef, peerRef, RND));
            Assertions.assertEquals(32, ec.ni_kexDerive(kexRef, null, 0, RND));
            byte[] first = new byte[32];
            Assertions.assertEquals(32, ec.ni_kexDerive(kexRef, first, 0, RND));
            Assertions.assertEquals(unexpected, ec.ni_kexDerive(kexRef, new byte[32], 0, RND));
            Assertions.assertEquals(unexpected, ec.ni_kexDerive(kexRef, null, 0, RND));
            Assertions.assertEquals(0, ec.ni_kexSetPeer(kexRef, peerRef, RND));
            byte[] second = new byte[32];
            Assertions.assertEquals(32, ec.ni_kexDerive(kexRef, second, 0, RND));
            Assertions.assertTrue(Arrays.areEqual(first, second));
        }
        finally
        {
            ec.disposeKex(kexRef);
            spec.dispose(keyRef);
            spec.dispose(peerRef);
        }
    }

    /** An off-curve point and the point at infinity are refused at the NI with the OpenSSL error code. */
    public static void invalidPublicPointsAreRefused(ECServiceNI ec, SpecNI spec)
    {
        int openssl = code(ErrorCode.JO_OPENSSL_ERROR);
        byte[] g = generator(ec);
        Assertions.assertEquals(0, makePublic(ec, spec, CURVE, g));
        byte[] offCurve = g.clone();
        offCurve[64] ^= 1;
        Assertions.assertEquals(openssl, makePublic(ec, spec, CURVE, offCurve));
        Assertions.assertEquals(openssl, makePublic(ec, spec, CURVE, new byte[]{0}));
    }
}
