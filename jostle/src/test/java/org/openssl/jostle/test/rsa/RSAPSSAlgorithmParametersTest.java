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
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.util.Arrays;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.Security;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.PSSParameterSpec;

/**
 * RFC 4055 {@code RSASSA-PSS-params} against two independent implementations.
 *
 * <p>GitHub issue 58: the provider registered no {@code AlgorithmParameters}
 * for RSASSA-PSS, so the lookup escaped to SunRsaSign and a caller pinned to
 * this provider — or running without the JDK providers — had none.
 *
 * <p>The encoding is compared against SunRsaSign AND BouncyCastle from a
 * SHARED spec. Comparing against one would leave the other free to disagree,
 * and comparing our encoder against our own decoder would be satisfied by an
 * implementation that is uniformly wrong.
 *
 * <p>The digest name in a {@code PSSParameterSpec} is provider-scoped and the
 * two domains are DISJOINT for the truncated SHA-512s — SunRsaSign takes
 * {@code SHA-512/256} and refuses {@code SHA512(256)}, BouncyCastle the exact
 * reverse — so the digest is translated at the BouncyCastle call site rather
 * than shared down the row.
 */
public class RSAPSSAlgorithmParametersTest
{
    private static final String BC = "BC";

    @BeforeAll
    public static void setUp()
    {
        Security.addProvider(new JostleProvider());
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    /** JCA digest name, BouncyCastle's spelling of it, salt length. */
    private static final String[][] CASES = {
            {"SHA-1", "SHA-1", "20"},
            {"SHA-224", "SHA-224", "28"},
            {"SHA-256", "SHA-256", "32"},
            {"SHA-384", "SHA-384", "48"},
            {"SHA-512", "SHA-512", "64"},
            // Salt lengths off the digest default: these are the rows that
            // prove the DEFAULT omission is per-field, not all-or-nothing.
            {"SHA-256", "SHA-256", "20"},
            {"SHA-1", "SHA-1", "32"},
            {"SHA3-224", "SHA3-224", "28"},
            {"SHA3-256", "SHA3-256", "32"},
            {"SHA3-384", "SHA3-384", "48"},
            {"SHA3-512", "SHA3-512", "64"},
            {"SHA-512/224", "SHA512(224)", "28"},
            {"SHA-512/256", "SHA512(256)", "32"},
    };

    private static PSSParameterSpec spec(String digest, int saltLength)
    {
        return new PSSParameterSpec(digest, "MGF1", new MGF1ParameterSpec(digest), saltLength, 1);
    }

    private static byte[] encode(String provider, String algorithm, PSSParameterSpec spec)
        throws Exception
    {
        AlgorithmParameters params = AlgorithmParameters.getInstance(algorithm, provider);
        params.init(spec);
        return params.getEncoded();
    }

    @Test
    public void encodingAgreesWithSunRsaSignAndBouncyCastle()
        throws Exception
    {
        Assertions.assertTrue(CASES.length >= 13, "vacuity: the case table lost rows");
        for (String[] row : CASES)
        {
            int saltLength = Integer.parseInt(row[2]);
            String what = row[0] + "/salt" + saltLength;

            byte[] ours = encode("JSL", "RSASSA-PSS", spec(row[0], saltLength));
            byte[] sun = encode("SunRsaSign", "RSASSA-PSS", spec(row[0], saltLength));
            byte[] bc = encode(BC, "PSS", spec(row[1], saltLength));

            Assertions.assertTrue(Arrays.areEqual(ours, sun), what + ": SunRsaSign disagrees");
            Assertions.assertTrue(Arrays.areEqual(ours, bc), what + ": BouncyCastle disagrees");
        }
    }

    /**
     * Every field at its DEFAULT is omitted, so the whole structure collapses
     * to an empty SEQUENCE. Pinned as a literal because it is the shortest
     * statement of the MUST in RFC 4055 and the one a partial implementation
     * gets wrong.
     */
    @Test
    public void allDefaultsEncodeToTheEmptySequence()
        throws Exception
    {
        byte[] ours = encode("JSL", "RSASSA-PSS", spec("SHA-1", 20));
        Assertions.assertArrayEquals(new byte[]{0x30, 0x00}, ours);
    }

    /**
     * A caller that sends the DEFAULTs explicitly is accepted, and the
     * re-encode NORMALISES them away. So the codec is deliberately NOT a
     * byte-preserving round trip, and a test asserting one would be wrong.
     * Both references behave identically, measured.
     */
    @Test
    public void explicitDefaultsAreAcceptedAndNormalisedAway()
        throws Exception
    {
        byte[] explicit = new byte[]{
                0x30, 0x31,
                (byte) 0xa0, 0x0b, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00,
                (byte) 0xa1, 0x18, 0x30, 0x16,
                0x06, 0x09, 0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7, 0x0d, 0x01, 0x01, 0x08,
                0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00,
                (byte) 0xa2, 0x03, 0x02, 0x01, 0x14,
                (byte) 0xa3, 0x03, 0x02, 0x01, 0x01};

        AlgorithmParameters ours = AlgorithmParameters.getInstance("RSASSA-PSS", "JSL");
        ours.init(explicit);
        PSSParameterSpec decoded = ours.getParameterSpec(PSSParameterSpec.class);
        Assertions.assertEquals("SHA-1", decoded.getDigestAlgorithm());
        Assertions.assertEquals("MGF1", decoded.getMGFAlgorithm());
        Assertions.assertEquals(20, decoded.getSaltLength());
        Assertions.assertEquals(1, decoded.getTrailerField());
        Assertions.assertArrayEquals(new byte[]{0x30, 0x00}, ours.getEncoded(),
                "explicit DEFAULTs must normalise away on re-encode");

        // Both references normalise the same way; if that ever moves, this is
        // where it surfaces rather than in a silent interop failure.
        AlgorithmParameters sun = AlgorithmParameters.getInstance("RSASSA-PSS", "SunRsaSign");
        sun.init(explicit);
        Assertions.assertArrayEquals(new byte[]{0x30, 0x00}, sun.getEncoded());
        AlgorithmParameters bc = AlgorithmParameters.getInstance("PSS", BC);
        bc.init(explicit);
        Assertions.assertArrayEquals(new byte[]{0x30, 0x00}, bc.getEncoded());
    }

    @Test
    public void specSurvivesAnEncodeDecodeRoundTrip()
        throws Exception
    {
        for (String[] row : CASES)
        {
            int saltLength = Integer.parseInt(row[2]);
            byte[] der = encode("JSL", "RSASSA-PSS", spec(row[0], saltLength));

            AlgorithmParameters back = AlgorithmParameters.getInstance("RSASSA-PSS", "JSL");
            back.init(der);
            PSSParameterSpec decoded = back.getParameterSpec(PSSParameterSpec.class);

            Assertions.assertEquals(row[0], decoded.getDigestAlgorithm(), row[0]);
            Assertions.assertEquals("MGF1", decoded.getMGFAlgorithm(), row[0]);
            Assertions.assertEquals(row[0],
                    ((MGF1ParameterSpec) decoded.getMGFParameters()).getDigestAlgorithm(), row[0]);
            Assertions.assertEquals(saltLength, decoded.getSaltLength(), row[0]);
            Assertions.assertEquals(1, decoded.getTrailerField(), row[0]);
        }
    }

    /**
     * BouncyCastle's spelling of the truncated SHA-512s is accepted on the way
     * in, and the JCA standard name is what comes back out. One domain in, one
     * domain out, so a caller written for either provider works.
     */
    @Test
    public void bothDigestSpellingsAreAcceptedAndTheJcaNameIsReturned()
        throws Exception
    {
        String[][] pairs = {{"SHA512(224)", "SHA-512/224"}, {"SHA512(256)", "SHA-512/256"},
                {"SHA1", "SHA-1"}, {"sha-256", "SHA-256"}};
        for (String[] pair : pairs)
        {
            AlgorithmParameters ours = AlgorithmParameters.getInstance("RSASSA-PSS", "JSL");
            ours.init(spec(pair[0], 32));
            Assertions.assertEquals(pair[1],
                    ours.getParameterSpec(PSSParameterSpec.class).getDigestAlgorithm(),
                    pair[0] + " must canonicalise to " + pair[1]);
        }
    }

    /** Every registered spelling resolves to this SPI on both providers. */
    @Test
    public void everySpellingResolves()
        throws Exception
    {
        for (String name : new String[]{"RSASSA-PSS", "PSS", "RSAPSS", "1.2.840.113549.1.1.10"})
        {
            AlgorithmParameters params = AlgorithmParameters.getInstance(name, "JSL");
            params.init(spec("SHA-256", 32));
            Assertions.assertEquals(54, params.getEncoded().length, name);
        }
    }

    //
    // Deliberate divergences. Both halves are pinned — ours AND the
    // reference's — so a later parity sweep has to delete a self-explaining
    // test before it can "fix" either.
    //

    /**
     * RFC 4055 line 481: the trailer field value MUST be 1. Both references
     * encode a 2 from a spec; BouncyCastle also accepts one off the wire. We
     * refuse both, because {@code RSAPSSSignatureSpi} refuses to sign under
     * one and emitting it would produce parameters this provider cannot use.
     */
    @Test
    public void trailerFieldOtherThanOneIsRefusedBothWays()
        throws Exception
    {
        PSSParameterSpec trailerTwo =
                new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 2);

        InvalidParameterSpecException fromSpec = Assertions.assertThrows(
                InvalidParameterSpecException.class,
                () -> encode("JSL", "RSASSA-PSS", trailerTwo));
        Assertions.assertEquals("trailer field must be 1 (got 2)", fromSpec.getMessage());

        // SHA-1 defaults with trailerField 2 explicitly present.
        byte[] wire = new byte[]{0x30, 0x05, (byte) 0xa3, 0x03, 0x02, 0x01, 0x02};
        AlgorithmParameters ours = AlgorithmParameters.getInstance("RSASSA-PSS", "JSL");
        IOException fromWire = Assertions.assertThrows(IOException.class, () -> ours.init(wire));
        Assertions.assertEquals("unsupported trailerField value 2", fromWire.getMessage());

        // The reference halves, measured live so a bcprov bump moves this
        // rather than leaving the divergence undocumented.
        Assertions.assertDoesNotThrow(() -> encode("SunRsaSign", "RSASSA-PSS", trailerTwo),
                "SunRsaSign encodes trailerField 2 from a spec");
        Assertions.assertDoesNotThrow(() -> encode(BC, "PSS", trailerTwo),
                "BouncyCastle encodes trailerField 2 from a spec");
        AlgorithmParameters bcWire = AlgorithmParameters.getInstance("PSS", BC);
        Assertions.assertDoesNotThrow(() -> bcWire.init(wire),
                "BouncyCastle accepts trailerField 2 off the wire");
        AlgorithmParameters sunWire = AlgorithmParameters.getInstance("RSASSA-PSS", "SunRsaSign");
        Assertions.assertThrows(IOException.class, () -> sunWire.init(wire),
                "SunRsaSign refuses trailerField 2 off the wire");
    }

    /**
     * Bytes after the SEQUENCE are refused — the project rule that a decoder
     * checks consumed length. BouncyCastle agrees; SunRsaSign accepts them.
     */
    @Test
    public void trailingBytesAreRefused()
        throws Exception
    {
        byte[] junk = new byte[]{0x30, 0x00, 0x01};

        AlgorithmParameters ours = AlgorithmParameters.getInstance("RSASSA-PSS", "JSL");
        IOException e = Assertions.assertThrows(IOException.class, () -> ours.init(junk));
        Assertions.assertEquals("trailing bytes after RSASSA-PSS-params", e.getMessage());

        AlgorithmParameters bc = AlgorithmParameters.getInstance("PSS", BC);
        Assertions.assertThrows(IOException.class, () -> bc.init(junk),
                "BouncyCastle refuses trailing bytes");
        AlgorithmParameters sun = AlgorithmParameters.getInstance("RSASSA-PSS", "SunRsaSign");
        Assertions.assertDoesNotThrow(() -> sun.init(junk),
                "SunRsaSign accepts trailing bytes");
    }

    @Test
    public void wrongSpecTypeAndUninitialisedUseAreRefusedTyped()
        throws Exception
    {
        AlgorithmParameters params = AlgorithmParameters.getInstance("RSASSA-PSS", "JSL");
        InvalidParameterSpecException wrong = Assertions.assertThrows(
                InvalidParameterSpecException.class,
                () -> params.init(new javax.crypto.spec.IvParameterSpec(new byte[8])));
        Assertions.assertTrue(wrong.getMessage().startsWith("RSASSA-PSS parameters require a PSSParameterSpec"),
                wrong.getMessage());

        AlgorithmParameters fresh = AlgorithmParameters.getInstance("RSASSA-PSS", "JSL");
        Assertions.assertThrows(IOException.class, fresh::getEncoded);
    }

    @Test
    public void unsupportedDigestAndMaskFunctionAreRefused()
        throws Exception
    {
        AlgorithmParameters params = AlgorithmParameters.getInstance("RSASSA-PSS", "JSL");
        Assertions.assertThrows(InvalidParameterSpecException.class,
                () -> params.init(spec("MD5", 16)));

        AlgorithmParameters mgf = AlgorithmParameters.getInstance("RSASSA-PSS", "JSL");
        Assertions.assertThrows(InvalidParameterSpecException.class,
                () -> mgf.init(new PSSParameterSpec("SHA-256", "MGF2",
                        MGF1ParameterSpec.SHA256, 32, 1)));
    }

    /**
     * Salt length is bounded on the wire in both directions. The negative side
     * is caught by the shared DER reader, which refuses a negative INTEGER
     * before this class sees it; the upper bound is this class's own, because
     * the value crosses to the native layer as a length.
     */
    @Test
    public void saltLengthIsBoundedOffTheWire()
        throws Exception
    {
        // saltLength [2] INTEGER -1.
        byte[] negative = new byte[]{0x30, 0x05, (byte) 0xa2, 0x03, 0x02, 0x01, (byte) 0xff};
        AlgorithmParameters lower = AlgorithmParameters.getInstance("RSASSA-PSS", "JSL");
        IOException low = Assertions.assertThrows(IOException.class, () -> lower.init(negative));
        Assertions.assertEquals("negative INTEGER in saltLength INTEGER", low.getMessage());

        // saltLength [2] INTEGER 65535, well past the stated ceiling.
        byte[] huge = new byte[]{0x30, 0x07, (byte) 0xa2, 0x05, 0x02, 0x03, 0x00, (byte) 0xff, (byte) 0xff};
        AlgorithmParameters upper = AlgorithmParameters.getInstance("RSASSA-PSS", "JSL");
        IOException high = Assertions.assertThrows(IOException.class, () -> upper.init(huge));
        Assertions.assertTrue(high.getMessage().contains("salt length out of range"), high.getMessage());

        // Positive control at a large but permitted length, so the bound is
        // not passing by refusing everything.
        byte[] permitted = new byte[]{0x30, 0x06, (byte) 0xa2, 0x04, 0x02, 0x02, 0x01, 0x00};
        AlgorithmParameters ok = AlgorithmParameters.getInstance("RSASSA-PSS", "JSL");
        ok.init(permitted);
        Assertions.assertEquals(256, ok.getParameterSpec(PSSParameterSpec.class).getSaltLength());
    }
}
