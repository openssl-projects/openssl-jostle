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

package org.openssl.jostle.test.xec;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Assertions;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.ec.ECServiceNI;
import org.openssl.jostle.jcajce.provider.xec.XECServiceNI;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.rand.RandSource;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.util.asn1.ASN1Encoder;
import org.openssl.jostle.util.asn1.Asn1Ni;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.function.Predicate;

/**
 * XDH bridge cells shared by the base and FIPS limit tests: key generation through the XEC NI and the agreement
 * through the EC kex NI, on whichever bridge the leg loads.
 */
public final class XdhBridgeCells
{
    private static final RandSource RND = TestUtil.RNDSrc;
    private static final BigInteger P25519 = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));
    private static final BigInteger P448 = BigInteger.ONE.shiftLeft(448).subtract(BigInteger.ONE.shiftLeft(224))
            .subtract(BigInteger.ONE);
    private static final byte[] P8_X25519 = Hex.decode("302e020100300506032b656e04220420");
    private static final byte[] P8_X448 = Hex.decode("3046020100300506032b656f043a0438");
    private static final byte[] SPKI_X25519 = Hex.decode("302a300506032b656e032100");
    private static final byte[] SPKI_X448 = Hex.decode("3042300506032b656f033900");

    private final XECServiceNI xec;
    private final ECServiceNI ec;
    private final SpecNI spec;
    private final Asn1Ni asn1;
    private final Predicate<String> keyTypeServed;

    /**
     * @param keyTypeServed whether the library under test generates a key of the named type at all; a name it
     *                      cannot generate is refused by OpenSSL before any key exists.
     */
    public XdhBridgeCells(XECServiceNI xec, ECServiceNI ec, SpecNI spec, Asn1Ni asn1, Predicate<String> keyTypeServed)
    {
        this.xec = xec;
        this.ec = ec;
        this.spec = spec;
        this.asn1 = asn1;
        this.keyTypeServed = keyTypeServed;
    }

    private static int code(ErrorCode c)
    {
        return c.getCode();
    }

    private static byte[] cat(byte[] a, byte[] b)
    {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    /** v little-endian over len bytes. */
    public static byte[] le(BigInteger v, int len)
    {
        byte[] be = v.toByteArray();
        byte[] out = new byte[len];
        for (int i = 0; i < Math.min(be.length, len); i++)
        {
            out[i] = be[be.length - 1 - i];
        }
        return out;
    }

    private PKEYKeySpec privateKey(byte[] raw)
    {
        byte[] p8 = cat(raw.length == 32 ? P8_X25519 : P8_X448, raw);
        return ASN1Encoder.fromPrivateKeyInfo(asn1, spec, p8, 0, p8.length, null);
    }

    private PKEYKeySpec publicKey(byte[] raw)
    {
        byte[] enc = cat(raw.length == 32 ? SPKI_X25519 : SPKI_X448, raw);
        return ASN1Encoder.fromSubjectPublicKeyInfo(asn1, spec, enc, 0, enc.length, null);
    }

    private byte[] rawPublic(PKEYKeySpec key)
    {
        byte[] enc = ASN1Encoder.asSubjectPublicKeyInfo(asn1, key);
        int n = enc.length == SPKI_X25519.length + 32 ? 32 : 56;
        byte[] raw = new byte[n];
        System.arraycopy(enc, enc.length - n, raw, 0, n);
        return raw;
    }

    /** The shared value for a local key and a peer key, or the refusal code from the kex NI. */
    private int derive(long local, long peer, byte[] out)
    {
        long kex = ec.allocateKex();
        try
        {
            int rc = ec.ni_kexInit(kex, local, RND);
            if (rc < 0)
            {
                return rc;
            }
            rc = ec.ni_kexSetPeer(kex, peer, RND);
            if (rc < 0)
            {
                return rc;
            }
            return ec.ni_kexDerive(kex, out, 0, RND);
        }
        finally
        {
            ec.disposeKex(kex);
        }
    }

    /** X25519(k, u) or X448(k, u) through the kex NI. */
    private byte[] scalarMult(byte[] k, byte[] u)
    {
        byte[] out = new byte[k.length];
        int w = derive(privateKey(k).getReference(), publicKey(u).getReference(), out);
        Assertions.assertEquals(k.length, w);
        return out;
    }

    private int generate(String name)
    {
        int[] err = new int[1];
        long ref = xec.ni_generateKeyPair(name, err, RND);
        if (ref != 0)
        {
            spec.dispose(ref);
        }
        return err[0];
    }

    /**
     * An empty name, one with an embedded NUL, and a name of another key type are refused before or after keygen
     * with the curve code; an unknown name stays OpenSSL's refusal.
     */
    public void unusableNamesAreRefused()
    {
        int refused = code(ErrorCode.JO_CURVE_NOT_SUPPORTED);
        for (String name : new String[]{"X25519\u0000x", "X25519\u0000", "\u0000X25519", ""})
        {
            Assertions.assertEquals(refused, generate(name), name.replace("\u0000", "\\0"));
        }
        for (String name : new String[]{"Ed25519", "ED448", "X25519MLKEM768"})
        {
            int expected = keyTypeServed.test(name) ? refused : code(ErrorCode.JO_OPENSSL_ERROR);
            Assertions.assertEquals(expected, generate(name), name);
        }
        IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                () -> xec.generateKeyPair("X25519\u0000x", RND));
        Assertions.assertEquals("curve not supported by the loaded OpenSSL build", e.getMessage());
        Assertions.assertEquals(code(ErrorCode.JO_OPENSSL_ERROR), generate("Foo"));
        Assertions.assertEquals(0, generate("X25519"));
        Assertions.assertEquals(0, generate("x448"));
    }

    /** Low-order and non-canonical peers pass the peer step and are refused by OpenSSL when the value is derived. */
    public void lowOrderPeersAreRefusedAtDerive()
    {
        byte[][] peers = {
                le(BigInteger.ZERO, 32), le(BigInteger.ONE, 32),
                Hex.decode("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
                Hex.decode("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
                le(P25519.subtract(BigInteger.ONE), 32), le(P25519, 32), le(P25519.add(BigInteger.ONE), 32),
                le(BigInteger.ZERO, 56), le(BigInteger.ONE, 56),
                le(P448.subtract(BigInteger.ONE), 56), le(P448, 56), le(P448.add(BigInteger.ONE), 56)};
        long a25 = xec.generateKeyPair("X25519", RND);
        long a448 = xec.generateKeyPair("X448", RND);
        try
        {
            for (byte[] raw : peers)
            {
                PKEYKeySpec peer = publicKey(raw);
                long kex = ec.allocateKex();
                try
                {
                    Assertions.assertEquals(0, ec.ni_kexInit(kex, raw.length == 32 ? a25 : a448, RND));
                    Assertions.assertEquals(0, ec.ni_kexSetPeer(kex, peer.getReference(), RND));
                    Assertions.assertEquals(code(ErrorCode.JO_OPENSSL_ERROR),
                            ec.ni_kexDerive(kex, new byte[raw.length], 0, RND), Hex.toHexString(raw));
                }
                finally
                {
                    ec.disposeKex(kex);
                }
            }
        }
        finally
        {
            spec.dispose(a25);
            spec.dispose(a448);
        }
    }

    /**
     * The derived value is exactly 32 or 56 bytes: a larger buffer gets that many with the rest untouched, a smaller
     * one is refused, and both halves agree.
     */
    public void derivedValueSizes()
    {
        for (String curve : new String[]{"X25519", "X448"})
        {
            int n = curve.equals("X25519") ? 32 : 56;
            long a = xec.generateKeyPair(curve, RND);
            long b = xec.generateKeyPair(curve, RND);
            try
            {
                long kex = ec.allocateKex();
                try
                {
                    ec.kexInit(kex, a, RND);
                    ec.kexSetPeer(kex, b, RND);
                    Assertions.assertEquals(n, ec.ni_kexDerive(kex, null, 0, RND), curve);
                    Assertions.assertEquals(code(ErrorCode.JO_OUTPUT_TOO_SMALL),
                            ec.ni_kexDerive(kex, new byte[n - 1], 0, RND), curve);
                }
                finally
                {
                    ec.disposeKex(kex);
                }
                byte[] big = new byte[n + 8];
                Arrays.fill(big, (byte) 0x5a);
                Assertions.assertEquals(n, derive(a, b, big), curve);
                for (int i = n; i < big.length; i++)
                {
                    Assertions.assertEquals((byte) 0x5a, big[i], curve + " tail");
                }
                byte[] exact = new byte[n];
                Assertions.assertEquals(n, derive(b, a, exact), curve);
                Assertions.assertArrayEquals(Arrays.copyOf(big, n), exact, curve);
            }
            finally
            {
                spec.dispose(a);
                spec.dispose(b);
            }
        }
    }

    /** RFC 7748 5.2 and 6: scalar multiplication, the iteration results after 1 and 1,000, and both exchanges. */
    public void rfc7748Vectors()
    {
        for (String[] v : Rfc7748Vectors.SCALAR_MULT)
        {
            Assertions.assertEquals(v[3], Hex.toHexString(scalarMult(Hex.decode(v[1]), Hex.decode(v[2]))), v[0]);
        }
        for (String[] v : Rfc7748Vectors.ITERATIONS)
        {
            int n = v[0].equals("X25519") ? 32 : 56;
            byte[] k = new byte[n];
            k[0] = (byte) (n == 32 ? 9 : 5);
            byte[] u = k.clone();
            for (int i = 1; i <= 1000; i++)
            {
                byte[] r = scalarMult(k, u);
                u = k;
                k = r;
                if (i == 1)
                {
                    Assertions.assertEquals(v[1], Hex.toHexString(k), v[0] + " after one");
                }
            }
            Assertions.assertEquals(v[2], Hex.toHexString(k), v[0] + " after 1,000");
        }
        for (String[] v : Rfc7748Vectors.DIFFIE_HELLMAN)
        {
            PKEYKeySpec alice = privateKey(Hex.decode(v[1]));
            PKEYKeySpec bob = privateKey(Hex.decode(v[3]));
            Assertions.assertEquals(v[2], Hex.toHexString(rawPublic(alice)), v[0] + " Alice public");
            Assertions.assertEquals(v[4], Hex.toHexString(rawPublic(bob)), v[0] + " Bob public");
            byte[] k1 = new byte[v[5].length() / 2];
            byte[] k2 = new byte[k1.length];
            PKEYKeySpec bobPublic = publicKey(Hex.decode(v[4]));
            PKEYKeySpec alicePublic = publicKey(Hex.decode(v[2]));
            Assertions.assertEquals(k1.length, derive(alice.getReference(), bobPublic.getReference(), k1));
            Assertions.assertEquals(k2.length, derive(bob.getReference(), alicePublic.getReference(), k2));
            Assertions.assertEquals(v[5], Hex.toHexString(k1), v[0] + " Alice shared");
            Assertions.assertEquals(v[5], Hex.toHexString(k2), v[0] + " Bob shared");
        }
    }
}
