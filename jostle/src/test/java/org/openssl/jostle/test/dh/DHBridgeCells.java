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

package org.openssl.jostle.test.dh;

import org.junit.jupiter.api.Assertions;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.md.MDServiceNI;
import org.openssl.jostle.jcajce.provider.dh.DHServiceNI;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.rand.RandSource;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.util.Arrays;

import java.math.BigInteger;

/**
 * DH bridge cells shared by the base and FIPS limit tests: each takes the NI set under test, so one body pins
 * both interface libraries on whichever bridge the leg loads.
 */
public final class DHBridgeCells
{
    private static final RandSource RND = TestUtil.RNDSrc;
    private static final String GROUP = "ffdhe2048";

    private DHBridgeCells()
    {
    }

    private static int code(ErrorCode c)
    {
        return c.getCode();
    }

    private static byte[] component(DHServiceNI dh, long ref, int selector)
    {
        byte[] out = new byte[dh.getComponent(ref, selector, null)];
        dh.getComponent(ref, selector, out);
        return out;
    }

    private static byte[] magnitude(BigInteger v)
    {
        byte[] raw = v.toByteArray();
        if (raw.length > 1 && raw[0] == 0)
        {
            byte[] out = new byte[raw.length - 1];
            System.arraycopy(raw, 1, out, 0, out.length);
            return out;
        }
        return raw;
    }

    /**
     * A key spec or a digest context as the agreement context, and an agreement context as a key spec, are each
     * refused with a typed code at every entry that takes the handle; a dispose of the wrong kind frees nothing.
     */
    public static void wrongKindHandlesAreRefused(DHServiceNI dh, SpecNI spec, MDServiceNI md)
    {
        int ctxWrong = code(ErrorCode.JO_DH_KEX_CTX_WRONG_KIND);
        int specWrong = code(ErrorCode.JO_KEY_SPEC_WRONG_KIND);
        long keyRef = dh.generateKeyPairByGroup(GROUP, RND);
        long peerRef = dh.generateKeyPairByGroup(GROUP, RND);
        long kexRef = dh.allocateKex();
        long mdRef = md.allocateDigest("SHA256", 0);
        try
        {
            for (long bad : new long[]{keyRef, mdRef})
            {
                Assertions.assertEquals(ctxWrong, dh.ni_kexInit(bad, keyRef, RND));
                Assertions.assertEquals(ctxWrong, dh.ni_kexSetPeer(bad, peerRef, RND));
                Assertions.assertEquals(ctxWrong, dh.ni_kexDerive(bad, null, 0, RND));
                Assertions.assertEquals(ctxWrong, dh.ni_kexDerive(bad, new byte[256], 0, RND));
            }
            Assertions.assertEquals(specWrong, dh.ni_kexInit(kexRef, kexRef, RND));
            Assertions.assertEquals(specWrong, dh.ni_kexInit(kexRef, mdRef, RND));
            dh.kexInit(kexRef, keyRef, RND);
            Assertions.assertEquals(specWrong, dh.ni_kexSetPeer(kexRef, kexRef, RND));
            Assertions.assertEquals(specWrong, dh.ni_getComponent(kexRef, DHServiceNI.COMP_P, null));
            int[] err = new int[1];
            Assertions.assertEquals(0L, dh.ni_generateKeyPair(kexRef, 0, err, RND));
            Assertions.assertEquals(specWrong, err[0]);

            IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                    () -> dh.kexSetPeer(keyRef, peerRef, RND));
            Assertions.assertEquals("handle is not a DH key-agreement context", e.getMessage());

            // A dispose of the wrong kind frees nothing: the handles still work afterwards.
            dh.disposeKex(keyRef);
            dh.disposeKex(mdRef);
            Assertions.assertEquals(0, dh.ni_kexSetPeer(kexRef, peerRef, RND));
            Assertions.assertEquals(256, dh.ni_kexDerive(kexRef, null, 0, RND));
            Assertions.assertEquals(32, md.ni_getDigestOutputLen(mdRef));
        }
        finally
        {
            md.dispose(mdRef);
            dh.disposeKex(kexRef);
            spec.dispose(keyRef);
            spec.dispose(peerRef);
        }
    }

    /**
     * An empty group name, one with an embedded NUL, a long one and an unknown one answer the same "not served"
     * code on both group entries and both bridges.
     */
    public static void unusableGroupNamesAreRefused(DHServiceNI dh)
    {
        int notServed = code(ErrorCode.JO_CURVE_NOT_SUPPORTED);
        String longName = new String(new char[1000]).replace('\u0000', 'f');
        for (String name : new String[]{GROUP + "\u0000x", "", "nope", longName})
        {
            String label = name.length() > 20 ? name.substring(0, 20) : name;
            Assertions.assertEquals(notServed, dh.ni_groupSupported(name), label);
            int[] err = new int[1];
            Assertions.assertEquals(0L, dh.ni_generateKeyPairByGroup(name, err, RND), label);
            Assertions.assertEquals(notServed, err[0], label);
        }
        Assertions.assertEquals(code(ErrorCode.JO_NAME_IS_NULL), dh.ni_groupSupported(null));
        IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                () -> dh.generateKeyPairByGroup("nope", RND));
        Assertions.assertEquals("curve not supported by the loaded OpenSSL build", e.getMessage());
        Assertions.assertEquals(1, dh.ni_groupSupported(GROUP));
    }

    /**
     * A written derive consumes the peer: a second derive without a new set peer is refused, and a new set peer
     * derives the same secret again.
     */
    public static void deriveConsumesThePeer(DHServiceNI dh, SpecNI spec)
    {
        int unexpected = code(ErrorCode.JO_UNEXPECTED_STATE);
        long keyRef = dh.generateKeyPairByGroup(GROUP, RND);
        long peerRef = dh.generateKeyPairByGroup(GROUP, RND);
        long kexRef = dh.allocateKex();
        try
        {
            dh.kexInit(kexRef, keyRef, RND);
            dh.kexSetPeer(kexRef, peerRef, RND);
            Assertions.assertEquals(256, dh.ni_kexDerive(kexRef, null, 0, RND));
            byte[] first = new byte[256];
            Assertions.assertEquals(256, dh.ni_kexDerive(kexRef, first, 0, RND));
            Assertions.assertEquals(unexpected, dh.ni_kexDerive(kexRef, new byte[256], 0, RND));
            Assertions.assertEquals(unexpected, dh.ni_kexDerive(kexRef, null, 0, RND));
            dh.kexSetPeer(kexRef, peerRef, RND);
            byte[] second = new byte[256];
            Assertions.assertEquals(256, dh.ni_kexDerive(kexRef, second, 0, RND));
            Assertions.assertTrue(Arrays.areEqual(first, second));
        }
        finally
        {
            dh.disposeKex(kexRef);
            spec.dispose(keyRef);
            spec.dispose(peerRef);
        }
    }

    /**
     * The private-value length reaches key generation: 256 gives a key whose x has at most 256 bits and that
     * reports 256; a negative length is refused typed.
     */
    public static void privateLengthIsHonoured(DHServiceNI dh, SpecNI spec)
    {
        long groupKey = dh.generateKeyPairByGroup(GROUP, RND);
        long paramsRef = dh.makeParamsFromComponents(component(dh, groupKey, DHServiceNI.COMP_P), null,
                component(dh, groupKey, DHServiceNI.COMP_G));
        long keyRef = 0;
        try
        {
            keyRef = dh.generateKeyPair(paramsRef, 256, RND);
            Assertions.assertEquals(256, dh.getComponent(keyRef, DHServiceNI.COMP_PRIVATE_LENGTH, null));
            BigInteger x = new BigInteger(1, component(dh, keyRef, DHServiceNI.COMP_PRIVATE_VALUE));
            Assertions.assertTrue(x.bitLength() <= 256, "x has " + x.bitLength() + " bits");
            int[] err = new int[1];
            Assertions.assertEquals(0L, dh.ni_generateKeyPair(paramsRef, -1, err, RND));
            Assertions.assertEquals(code(ErrorCode.JO_INPUT_LEN_IS_NEGATIVE), err[0]);
        }
        finally
        {
            spec.dispose(keyRef);
            spec.dispose(paramsRef);
            spec.dispose(groupKey);
        }
    }

    /** The form selector answers the key's type: a named-group key is PKCS#3, a key imported with q is X9.42. */
    public static void formFollowsTheKeysType(DHServiceNI dh, SpecNI spec)
    {
        long groupKey = dh.generateKeyPairByGroup(GROUP, RND);
        byte[] p = component(dh, groupKey, DHServiceNI.COMP_P);
        byte[] g = component(dh, groupKey, DHServiceNI.COMP_G);
        byte[] q = magnitude(new BigInteger(1, p).subtract(BigInteger.ONE).shiftRight(1));
        long x942 = dh.makeParamsFromComponents(p, q, g);
        long pkcs3 = dh.makeParamsFromComponents(p, null, g);
        try
        {
            Assertions.assertEquals(DHServiceNI.FORM_PKCS3, dh.getComponent(groupKey, DHServiceNI.COMP_FORM, null));
            Assertions.assertEquals(DHServiceNI.FORM_PKCS3, dh.getComponent(pkcs3, DHServiceNI.COMP_FORM, null));
            Assertions.assertEquals(DHServiceNI.FORM_X942, dh.getComponent(x942, DHServiceNI.COMP_FORM, null));
        }
        finally
        {
            spec.dispose(x942);
            spec.dispose(pkcs3);
            spec.dispose(groupKey);
        }
    }

    /**
     * On a group with q, x must lie in [1, q-1]: q, q+1 and p are refused typed at import, 1 and q-1 import.
     * A public value outside [2, p-2] is refused at import with or without q.
     */
    public static void keyValuesAreRangeChecked(DHServiceNI dh, SpecNI spec)
    {
        long groupKey = dh.generateKeyPairByGroup(GROUP, RND);
        BigInteger p = new BigInteger(1, component(dh, groupKey, DHServiceNI.COMP_P));
        BigInteger q = p.subtract(BigInteger.ONE).shiftRight(1);
        byte[] pb = magnitude(p);
        byte[] qb = magnitude(q);
        byte[] g = component(dh, groupKey, DHServiceNI.COMP_G);
        try
        {
            int privateBad = code(ErrorCode.JO_DH_PRIVATE_VALUE_INVALID);
            for (BigInteger x : new BigInteger[]{BigInteger.ZERO, q, q.add(BigInteger.ONE), p})
            {
                int[] err = new int[1];
                Assertions.assertEquals(0L, dh.ni_makePrivateFromComponents(pb, qb, g, magnitude(x), err, RND));
                Assertions.assertEquals(privateBad, err[0], "x " + x.bitLength() + " bits");
            }
            for (BigInteger x : new BigInteger[]{BigInteger.ONE, q.subtract(BigInteger.ONE)})
            {
                spec.dispose(dh.makePrivateFromComponents(pb, qb, g, magnitude(x), RND));
            }
            IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                    () -> dh.makePrivateFromComponents(pb, qb, g, qb, RND));
            Assertions.assertEquals("DH x is outside its range: [1, q-1] with q, [1, p-2] without",
                    e.getMessage());

            int publicBad = code(ErrorCode.JO_DH_PEER_PUBKEY_INVALID);
            BigInteger[] bad = {BigInteger.ZERO, BigInteger.ONE, p.subtract(BigInteger.ONE), p, p.add(BigInteger.ONE)};
            for (BigInteger y : bad)
            {
                for (byte[] qOrNull : new byte[][]{null, qb})
                {
                    int[] err = new int[1];
                    Assertions.assertEquals(0L, dh.ni_makePublicFromComponents(pb, qOrNull, g, magnitude(y), err));
                    Assertions.assertEquals(publicBad, err[0], "y " + y.bitLength() + " bits");
                }
            }
            // 2 and 4 are residues mod an RFC 7919 prime, so they also pass the subgroup test OpenSSL's q enables.
            for (BigInteger y : new BigInteger[]{BigInteger.valueOf(2), BigInteger.valueOf(4)})
            {
                spec.dispose(dh.makePublicFromComponents(pb, null, g, magnitude(y)));
            }
        }
        finally
        {
            spec.dispose(groupKey);
        }
    }

    /**
     * Without q (and on no known group) x must lie in [1, p-2]: 0, p-1 and p are refused typed at import; 1 and
     * p-2 import. qLessP is a prime that is not a named group, so OpenSSL holds no q for it.
     */
    public static void qLessPrivateValueRangeIsChecked(DHServiceNI dh, SpecNI spec, byte[] qLessP)
    {
        BigInteger p = new BigInteger(1, qLessP);
        byte[] g = {2};
        int privateBad = code(ErrorCode.JO_DH_PRIVATE_VALUE_INVALID);
        for (BigInteger x : new BigInteger[]{BigInteger.ZERO, p.subtract(BigInteger.ONE), p})
        {
            int[] err = new int[1];
            Assertions.assertEquals(0L, dh.ni_makePrivateFromComponents(qLessP, null, g, magnitude(x), err, RND));
            Assertions.assertEquals(privateBad, err[0], "x " + x.bitLength() + " bits");
        }
        for (BigInteger x : new BigInteger[]{BigInteger.ONE, p.subtract(BigInteger.valueOf(2))})
        {
            spec.dispose(dh.makePrivateFromComponents(qLessP, null, g, magnitude(x), RND));
        }
    }

    /** Key generation over an even p fails with the generic error, never the q-required refusal. */
    public static void evenModulusIsNotReportedAsQRequired(DHServiceNI dh, SpecNI spec)
    {
        long groupKey = dh.generateKeyPairByGroup(GROUP, RND);
        byte[] even = magnitude(new BigInteger(1, component(dh, groupKey, DHServiceNI.COMP_P)).add(BigInteger.ONE));
        long params = dh.makeParamsFromComponents(even, null, new byte[]{2});
        try
        {
            int[] err = new int[1];
            Assertions.assertEquals(0L, dh.ni_generateKeyPair(params, 0, err, RND));
            Assertions.assertEquals(code(ErrorCode.JO_OPENSSL_ERROR), err[0]);
        }
        finally
        {
            spec.dispose(params);
            spec.dispose(groupKey);
        }
    }
}
