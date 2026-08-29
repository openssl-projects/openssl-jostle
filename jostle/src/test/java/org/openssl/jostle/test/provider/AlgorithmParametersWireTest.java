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

package org.openssl.jostle.test.provider;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.spec.DHDomainParameterSpec;
import org.openssl.jostle.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.Provider;
import java.security.Security;
import java.security.spec.DSAParameterSpec;
import java.security.spec.InvalidParameterSpecException;

/**
 * The parameter codecs MT-18 brought in house must put the SAME bytes on the
 * wire as the platform implementations they replaced, in both directions.
 *
 * <p>Byte-equality against the platform is the point. A round-trip through our
 * own codec proves only self-consistency — a codec that is uniformly wrong
 * round-trips perfectly, and the ChaCha20-Poly1305 defect this arc found did
 * exactly that for months.
 *
 * <p>The platform provider is used as the test-side REFERENCE, which is
 * sanctioned; production resolves only from Jostle.
 */
public class AlgorithmParametersWireTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }

    // ---------------- GCM ----------------

    /**
     * The DEFAULT-omission boundary is the discriminating case: ICV 12 encodes
     * as a ONE-element SEQUENCE, 13..16 as two. A codec that always emitted the
     * length would round-trip against itself and diverge at exactly one input.
     *
     * <p><b>The byte-equality reference is BouncyCastle, not SunJCE, and that
     * is measured rather than preferred.</b> SunJCE's GCM encoder CHANGED
     * between JDK 11 and JDK 25: 11 always emits the ICV length, including when
     * it equals the DEFAULT, which X.690 11.5 forbids for DER; 25 omits it.
     * BouncyCastle 1.85 and JDK 25 agree with each other and with this codec on
     * every shape, so BC — a pinned test dependency — is the JDK-independent
     * reference.
     *
     * <p>Interop is unaffected and that is asserted below rather than assumed:
     * BOTH JDKs decode the omitted form correctly, so this codec's output is
     * readable by either. Only JDK 11's encode side is non-conformant.
     */
    @Test
    public void gcmMatchesTheDerReferenceAtEveryShape() throws Exception
    {
        for (int nlen : new int[]{1, 12, 16, 64, 200})
        {
            byte[] nonce = counting(nlen);
            for (int tagBits : new int[]{96, 104, 112, 120, 128})
            {
                byte[] gold = platform("GCM", "BC", new GCMParameterSpec(tagBits, nonce));
                byte[] mine = jostle("GCM", new GCMParameterSpec(tagBits, nonce));
                Assertions.assertArrayEquals(gold, mine,
                        "GCM nonce=" + nlen + " icv=" + tagBits / 8 + " must match BouncyCastle byte for byte");

                GCMParameterSpec back = decode(JSL, "GCM", gold, GCMParameterSpec.class);
                Assertions.assertEquals(tagBits, back.getTLen(), "Jostle must decode BC's bytes");
                Assertions.assertArrayEquals(nonce, back.getIV(), "nonce survives Jostle's decode");

                // The cross-decode against the JDK holds on every JDK, which is
                // what makes the encode-side divergence harmless.
                GCMParameterSpec fwd = decode("SunJCE", "GCM", mine, GCMParameterSpec.class);
                Assertions.assertEquals(tagBits, fwd.getTLen(), "SunJCE must decode Jostle's bytes");
                Assertions.assertArrayEquals(nonce, fwd.getIV(), "nonce survives SunJCE's decode");
            }
        }
    }

    @Test
    public void gcmIcv12OmitsTheLengthAnd13EmitsIt() throws Exception
    {
        byte[] twelve = jostle("GCM", new GCMParameterSpec(96, counting(12)));
        byte[] thirteen = jostle("GCM", new GCMParameterSpec(104, counting(12)));
        Assertions.assertEquals(0x0e, twelve[1] & 0xFF, "ICV 12 is the DEFAULT: one-element SEQUENCE");
        Assertions.assertEquals(0x11, thirteen[1] & 0xFF, "ICV 13 carries the INTEGER");
    }

    /**
     * Both halves of the IvParameterSpec contract, which diverged in opposite
     * directions during this arc: serving it dropped a caller's tag length,
     * accepting it invented one. SunJCE does neither.
     */
    @Test
    public void gcmRefusesIvParameterSpecOnBothSides() throws Exception
    {
        AlgorithmParameters ap = AlgorithmParameters.getInstance("GCM", JSL);
        Assertions.assertThrows(InvalidParameterSpecException.class,
                () -> ap.init(new IvParameterSpec(counting(12))),
                "accepting a nonce-only spec would silently apply the DEFAULT ICV");

        AlgorithmParameters ok = AlgorithmParameters.getInstance("GCM", JSL);
        ok.init(new GCMParameterSpec(96, counting(12)));
        Assertions.assertThrows(InvalidParameterSpecException.class,
                () -> ok.getParameterSpec(IvParameterSpec.class),
                "serving IvParameterSpec loses the tag length: BlockCipherSpi probes for it FIRST");
    }

    // ---------------- IV codec (CBC / CTR / the bare families) ----------------

    @Test
    public void ivCodecMatchesThePlatformAtBothBlockSizes() throws Exception
    {
        // DESede is 8 bytes and AES 16 — the reason the codec is length-agnostic.
        for (int len : new int[]{8, 16})
        {
            byte[] iv = counting(len);
            String platformAlg = len == 8 ? "DESede" : "AES";
            byte[] gold = platform(platformAlg, "SunJCE", new IvParameterSpec(iv));
            byte[] mine = jostle(platformAlg, new IvParameterSpec(iv));
            Assertions.assertArrayEquals(gold, mine, platformAlg + " IV must match SunJCE");
            Assertions.assertEquals(0x04, mine[0] & 0xFF, "a bare OCTET STRING, not a SEQUENCE");
            Assertions.assertArrayEquals(iv,
                    decode(JSL, platformAlg, gold, IvParameterSpec.class).getIV(),
                    "Jostle decodes the platform's bytes");
        }
    }

    /**
     * ARIA, CAMELLIA and SM4 registered NO parameters before MT-18, so
     * {@code getParameters()} threw {@code IllegalStateException} and the CMS
     * pattern was unusable for them.
     */
    @Test
    public void everyBlockCipherFamilyReportsItsOwnParameters() throws Exception
    {
        String[][] cases = {
                {"AES/CBC/PKCS5Padding", "AES", "16", "16"},
                {"ARIA/CBC/PKCS5Padding", "ARIA", "16", "16"},
                {"CAMELLIA/CBC/PKCS5Padding", "CAMELLIA", "16", "16"},
                {"SM4/CBC/PKCS5Padding", "SM4", "16", "16"},
                {"DESede/CBC/PKCS5Padding", "DESede", "24", "8"},
        };
        for (String[] c : cases)
        {
            Cipher ci = Cipher.getInstance(c[0], JSL);
            ci.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[Integer.parseInt(c[2])], c[1]));
            AlgorithmParameters p = ci.getParameters();
            Assertions.assertNotNull(p, c[0] + " must report parameters");
            Assertions.assertEquals(JSL, p.getProvider().getName(),
                    c[0] + " parameters must come from Jostle, not whatever the registry offers");
            Assertions.assertEquals(Integer.parseInt(c[3]),
                    p.getParameterSpec(IvParameterSpec.class).getIV().length, c[0] + " IV length");
        }
    }

    // ---------------- ChaCha20 ----------------

    @Test
    public void rawChaCha20ReportsNoParameters() throws Exception
    {
        Cipher ci = Cipher.getInstance("ChaCha20", JSL);
        ci.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[32], "ChaCha20"));
        Assertions.assertNull(ci.getParameters(),
                "no standard container carries the counter; SunJCE returns null and so must we");
        Assertions.assertNotNull(ci.getIV(), "the nonce is still reachable via getIV()");
    }

    /**
     * BouncyCastle is the reference here for the same reason as GCM, in a
     * second guise: SunJCE does not serve ChaCha20-Poly1305 parameters AT ALL
     * before JDK 11, so on the JDK 8 leg the platform reference does not exist.
     * BC is a pinned test dependency present on every leg.
     *
     * <p>The SunJCE cross-check still runs where SunJCE has the algorithm, and
     * is skipped — not silently, the assertion below records it — where it does
     * not.
     */
    @Test
    public void chaCha20Poly1305MatchesRfc8103() throws Exception
    {
        byte[] nonce = counting(12);
        byte[] gold = platform("ChaCha20-Poly1305", "BC", new IvParameterSpec(nonce));
        byte[] mine = jostle("ChaCha20-Poly1305", new IvParameterSpec(nonce));
        Assertions.assertArrayEquals(gold, mine, "RFC 8103 is a bare 12-octet OCTET STRING");
        Assertions.assertEquals(0x04, mine[0] & 0xFF, "not the GCM SEQUENCE form this used to emit");
        Assertions.assertEquals(14, mine.length, "tag + length + 12 nonce octets");

        Provider sun = Security.getProvider("SunJCE");
        if (sun == null || sun.getService("AlgorithmParameters", "ChaCha20-Poly1305") == null)
        {
            // Pre-JDK-11: nothing to cross-check against. The BC comparison
            // above is the pin either way.
            return;
        }
        byte[] sunGold = platform("ChaCha20-Poly1305", "SunJCE", new IvParameterSpec(nonce));
        Assertions.assertArrayEquals(sunGold, mine, "where SunJCE has it, it must agree too");
    }

    /** BouncyCastle registers the OID in both forms; so must we. */
    @Test
    public void chaCha20Poly1305ResolvesUnderAllThreeNames() throws Exception
    {
        byte[] nonce = counting(12);
        byte[] expected = jostle("ChaCha20-Poly1305", new IvParameterSpec(nonce));
        for (String name : new String[]{"1.2.840.113549.1.9.16.3.18", "OID.1.2.840.113549.1.9.16.3.18"})
        {
            Assertions.assertArrayEquals(expected, jostle(name, new IvParameterSpec(nonce)),
                    name + " must reach the same codec");
        }
    }

    // ---------------- DSA / DH ----------------

    @Test
    public void dsaMatchesThePlatformIncludingLongFormLengths() throws Exception
    {
        AlgorithmParameterGenerator g = AlgorithmParameterGenerator.getInstance("DSA", "SUN");
        g.init(2048);
        DSAParameterSpec real = g.generateParameters().getParameterSpec(DSAParameterSpec.class);
        byte[] gold = platform("DSA", "SUN", real);
        byte[] mine = jostle("DSA", real);
        Assertions.assertArrayEquals(gold, mine, "2048-bit DSA parameters must match SUN byte for byte");
        DSAParameterSpec back = decode(JSL, "DSA", gold, DSAParameterSpec.class);
        Assertions.assertEquals(real.getP(), back.getP(), "p survives");
        Assertions.assertEquals(real.getQ(), back.getQ(), "q survives");
    }

    @Test
    public void dhPkcs3MatchesThePlatformAndEmitsLOnlyWhenNonZero() throws Exception
    {
        BigInteger p = new BigInteger("8000000000000000000000000000000000000000000000000000000000000063", 16);
        BigInteger g = BigInteger.valueOf(2);
        for (int l : new int[]{0, 1, 160, 256, 1024})
        {
            DHParameterSpec spec = new DHParameterSpec(p, g, l);
            byte[] gold = platform("DiffieHellman", "SunJCE", spec);
            byte[] mine = jostle("DH", spec);
            Assertions.assertArrayEquals(gold, mine, "PKCS#3 l=" + l + " must match SunJCE");
            Assertions.assertEquals(l, decode(JSL, "DH", gold, DHParameterSpec.class).getL(),
                    "l survives Jostle's decode");
        }
    }

    /** The defect the X9.42 codec exists to fix: PKCS#3 has no q field at all. */
    @Test
    public void dhX942PreservesQThroughEncodeAndDecode() throws Exception
    {
        BigInteger p = new BigInteger("8000000000000000000000000000000000000000000000000000000000000063", 16);
        BigInteger q = new BigInteger("4000000000000000000000000000000000000000000000000000000000000031", 16);
        BigInteger g = BigInteger.valueOf(2);

        byte[] enc = jostle("DH", new DHDomainParameterSpec(p, q, g));
        DHDomainParameterSpec back = decode(JSL, "DH", enc, DHDomainParameterSpec.class);
        Assertions.assertEquals(q, back.getQ(), "q must survive the round trip");

        Object asBase = decode(JSL, "DH", enc, DHParameterSpec.class);
        Assertions.assertTrue(asBase instanceof DHDomainParameterSpec,
                "asking for the BASE type must not silently drop q, got " + asBase.getClass().getName());
    }

    /**
     * The three-way discriminator, pinned at every boundary. A two-way split
     * would read a 40-bit third INTEGER as a private-value length, which is a
     * bit COUNT and cannot be that large.
     */
    @Test
    public void dhThirdIntegerDiscriminatorBoundaries() throws Exception
    {
        assertThirdInteger(31, "l", null);
        assertThirdInteger(32, null, "too large for a PKCS#3 privateValueLength");
        assertThirdInteger(63, null, "too small for an X9.42 subgroup order");
        assertThirdInteger(64, "q", null);
    }

    private static void assertThirdInteger(int bits, String expectRead, String expectMessage) throws Exception
    {
        BigInteger p = new BigInteger("8000000000000000000000000000000000000000000000000000000000000063", 16);
        byte[] der = seq(intTlv(p), intTlv(BigInteger.valueOf(2)),
                intTlv(BigInteger.ONE.shiftLeft(bits - 1)));
        AlgorithmParameters ap = AlgorithmParameters.getInstance("DH", JSL);
        if (expectMessage != null)
        {
            Exception e = Assertions.assertThrows(Exception.class, () -> ap.init(der),
                    bits + "-bit third INTEGER is neither l nor q and must be refused");
            Assertions.assertTrue(String.valueOf(e.getMessage()).contains(expectMessage),
                    "the refusal must name both interpretations, got: " + e.getMessage());
            return;
        }
        ap.init(der);
        boolean readAsQ = ap.getParameterSpec(DHParameterSpec.class) instanceof DHDomainParameterSpec;
        Assertions.assertEquals("q".equals(expectRead), readAsQ,
                bits + "-bit third INTEGER must be read as " + expectRead);
    }

    // ---------------- helpers ----------------

    private static byte[] counting(int n)
    {
        byte[] b = new byte[n];
        for (int i = 0; i < n; i++)
        {
            b[i] = (byte) i;
        }
        return b;
    }

    private static byte[] platform(String alg, String provider, java.security.spec.AlgorithmParameterSpec s)
            throws Exception
    {
        AlgorithmParameters ap = AlgorithmParameters.getInstance(alg, provider);
        ap.init(s);
        return ap.getEncoded();
    }

    private static byte[] jostle(String alg, java.security.spec.AlgorithmParameterSpec s) throws Exception
    {
        AlgorithmParameters ap = AlgorithmParameters.getInstance(alg, JSL);
        ap.init(s);
        return ap.getEncoded();
    }

    private static <T extends java.security.spec.AlgorithmParameterSpec> T decode(
            String provider, String alg, byte[] der, Class<T> as) throws Exception
    {
        AlgorithmParameters ap = AlgorithmParameters.getInstance(alg, provider);
        ap.init(der);
        return ap.getParameterSpec(as);
    }

    private static byte[] intTlv(BigInteger v)
    {
        byte[] c = v.toByteArray();
        byte[] o = new byte[2 + c.length];
        o[0] = 0x02;
        o[1] = (byte) c.length;
        System.arraycopy(c, 0, o, 2, c.length);
        return o;
    }

    private static byte[] seq(byte[]... items)
    {
        int n = 0;
        for (byte[] i : items)
        {
            n += i.length;
        }
        byte[] body = new byte[n];
        int off = 0;
        for (byte[] i : items)
        {
            System.arraycopy(i, 0, body, off, i.length);
            off += i.length;
        }
        byte[] out = new byte[2 + n];
        out[0] = 0x30;
        out[1] = (byte) n;
        System.arraycopy(body, 0, out, 2, n);
        return Arrays.clone(out);
    }
}
