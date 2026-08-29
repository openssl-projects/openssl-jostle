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

import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.Security;

/**
 * {@code util.asn1.Der} parses attacker-reachable input, so it is held to DER
 * strictness rather than BER tolerance, and every rejection is pinned.
 *
 * <p>Driven through the IV and DH codecs rather than against {@code Der}
 * directly: the test tree compiles against the assembled jar, so a
 * package-private helper is not reachable, and the codecs are the surface an
 * attacker actually reaches anyway.
 *
 * <p>Where this is STRICTER than the platform implementations it replaced,
 * that is deliberate — a narrowed acceptance set on a parser is a gain, and it
 * is recorded rather than silently inherited.
 */
public class DerCodecStrictnessTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    /**
     * The former hang: {@code Der.tlv} counted length octets with an unbounded
     * {@code len >>> (8 * bytes)}, and Java's shift count is taken mod 32, so
     * from 2^24 up the counter cycled forever. A 16 MiB IV was a DoS primitive,
     * not an encoding.
     *
     * <p>Pinned by the ENCODED HEADER, not by a timeout: a timeout assertion is
     * flaky under load, while the header proves the four-octet long form was
     * computed correctly.
     */
    @Test
    public void lengthOctetsTerminatesAtTheTwoToTwentyFourBoundary() throws Exception
    {
        int[] sizes = {0x7F, 0x80, 0xFFFF + 1, 0x1000000};
        int[] expectedFirstLengthByte = {0x7F, 0x81, 0x83, 0x84};
        for (int i = 0; i < sizes.length; i++)
        {
            AlgorithmParameters ap = AlgorithmParameters.getInstance("AES", JSL);
            ap.init(new IvParameterSpec(new byte[sizes[i]]));
            byte[] enc = ap.getEncoded();
            Assertions.assertEquals(0x04, enc[0] & 0xFF, "tag");
            Assertions.assertEquals(expectedFirstLengthByte[i], enc[1] & 0xFF,
                    "length form for " + sizes[i] + " content octets");
            Assertions.assertEquals(sizes[i], enc.length - headerLen(enc),
                    "content length round-trips at " + sizes[i]);
        }
    }

    @Test
    public void nonMinimalLongFormLengthIsRejected()
    {
        // 82 00 90 encodes 0x90 in two octets with a leading zero — BER, not DER.
        assertRejected(new byte[]{0x04, (byte) 0x82, 0x00, (byte) 0x90}, "leading zero octet");
    }

    @Test
    public void longFormForAShortLengthIsRejected()
    {
        assertRejected(new byte[]{0x04, (byte) 0x81, 0x02, 0x01, 0x02}, "non-minimal length");
    }

    @Test
    public void indefiniteLengthIsRejected()
    {
        assertRejected(new byte[]{0x04, (byte) 0x80}, "indefinite length");
    }

    @Test
    public void lengthOverrunningTheBufferIsRejected()
    {
        assertRejected(new byte[]{0x04, 0x40, 0x01}, "truncated content");
    }

    @Test
    public void trailingGarbageIsRejected()
    {
        assertRejected(new byte[]{0x04, 0x02, 0x01, 0x02, (byte) 0xFF}, "trailing bytes");
    }

    /**
     * Non-minimal INTEGER: a leading {@code 0x00} is permitted ONLY to clear a
     * top bit that would otherwise read as negative.
     */
    @Test
    public void nonMinimalIntegerIsRejected()
    {
        byte[] p = {0x02, 0x02, 0x00, (byte) 0x83};   // legal: clears the top bit
        byte[] g = {0x02, 0x01, 0x02};
        byte[] bad = {0x02, 0x02, 0x00, 0x05};        // illegal: top bit already clear
        byte[] der = seq(p, g, bad);

        IOException e = Assertions.assertThrows(IOException.class,
                () -> AlgorithmParameters.getInstance("DH", JSL).init(der));
        Assertions.assertTrue(String.valueOf(e.getMessage()).contains("non-minimal INTEGER"),
                "expected a non-minimal INTEGER rejection, got: " + e.getMessage());
    }

    /** The positive control: the same shape with a MINIMAL INTEGER is accepted. */
    @Test
    public void minimalIntegerIsAccepted() throws Exception
    {
        byte[] p = {0x02, 0x02, 0x00, (byte) 0x83};
        byte[] g = {0x02, 0x01, 0x02};
        byte[] good = {0x02, 0x01, 0x05};
        AlgorithmParameters ap = AlgorithmParameters.getInstance("DH", JSL);
        ap.init(seq(p, g, good));
        Assertions.assertNotNull(ap.getEncoded(), "a minimal encoding of the same values must parse");
    }

    // ---- length-claim attacks: the class a security report flagged elsewhere ----

    /**
     * A claimed length must be checked against the bytes actually present.
     * Every one of these declares far more content than the buffer holds; none
     * may allocate on the claim, and all must be refused.
     */
    @Test
    public void shortFormLengthClaimingPastTheBufferIsRejected()
    {
        assertRejected(new byte[]{0x04, 0x7F, 0x01}, "truncated content");
    }

    @Test
    public void longFormLengthClaimingPastTheBufferIsRejectedAtEveryOctetCount()
    {
        // count = 1..4, each claiming far more than is present.
        assertRejected(new byte[]{0x04, (byte) 0x81, (byte) 0xFF, 0x01}, "truncated content");
        assertRejected(new byte[]{0x04, (byte) 0x82, 0x7F, (byte) 0xFF, 0x01}, "truncated content");
        assertRejected(new byte[]{0x04, (byte) 0x83, 0x7F, (byte) 0xFF, (byte) 0xFF, 0x01}, "truncated content");
        assertRejected(new byte[]{0x04, (byte) 0x84, 0x00, 0x7F, (byte) 0xFF, (byte) 0xFF, 0x01},
                "non-minimal length encoding (leading zero octet)");
    }

    /** 0x7FFFFFFF content octets claimed against a four-byte buffer. */
    @Test
    public void lengthOfIntegerMaxValueIsRejected()
    {
        assertRejected(new byte[]{0x04, (byte) 0x84, 0x7F, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF},
                "truncated content");
    }

    /** Top bit set across four octets — the value exceeds Integer.MAX_VALUE. */
    @Test
    public void lengthExceedingIntegerMaxValueIsRejectedHonestly()
    {
        assertRejected(new byte[]{0x04, (byte) 0x84, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF},
                "exceeds Integer.MAX_VALUE");
    }

    @Test
    public void truncatedHeadersAreRejected()
    {
        assertRejected(new byte[]{}, "truncated");
        assertRejected(new byte[]{0x04}, "truncated");
    }

    /** The length octets themselves running past the end. */
    @Test
    public void truncatedLengthOctetsAreRejected()
    {
        assertRejected(new byte[]{0x04, (byte) 0x85, 0x01}, "unsupported length form");
        assertRejected(new byte[]{0x04, (byte) 0x84, 0x00, 0x01}, "unsupported length form");
    }

    // -----------------------------------------------------------------
    // OBJECT IDENTIFIER (MT-21). Driven through the EC codec, which is the
    // only surface that parses one, for the same reason the rest of this
    // class drives through the IV and DH codecs.
    // -----------------------------------------------------------------

    /** X.690 8.19.2: a subidentifier's first octet may not be 0x80. */
    @Test
    public void nonMinimalOidSubidentifierIsRejected()
    {
        assertOidRejected(new byte[]{0x06, 0x02, (byte) 0x80, 0x01},
                "non-minimal subidentifier");
    }

    /** A final octet still carrying the continuation bit is truncated. */
    @Test
    public void truncatedOidSubidentifierIsRejected()
    {
        assertOidRejected(new byte[]{0x06, 0x02, 0x2A, (byte) 0x86},
                "truncated subidentifier");
    }

    /** Empty contents are not an OID. */
    @Test
    public void emptyOidIsRejected()
    {
        assertOidRejected(new byte[]{0x06, 0x00}, "empty OBJECT IDENTIFIER");
    }

    /**
     * An arc wider than a long is REFUSED rather than wrapped. A silently
     * wrapped arc would decode to a different, entirely valid-looking OID —
     * which is worse than a rejection, because it names a different curve.
     */
    @Test
    public void anOverWideOidArcIsRejectedRatherThanWrapped()
    {
        byte[] tenContinuationOctets = new byte[]{
                0x06, 0x0B, 0x2A,
                (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 0x7F};
        assertOidRejected(tenContinuationOctets, "wider than 63 bits");
    }

    /** Trailing bytes after the OID are refused, as everywhere else in Der. */
    @Test
    public void trailingDataAfterAnOidIsRejected()
    {
        assertOidRejected(new byte[]{0x06, 0x08, 0x2A, (byte) 0x86, 0x48, (byte) 0xCE,
                0x3D, 0x03, 0x01, 0x07, 0x00}, "trailing data");
    }

    /**
     * The exact-length positive control: the same bytes without the trailing
     * octet must be accepted, so the boundary is shown to sit at
     * consumed == length rather than one either side.
     */
    @Test
    public void anExactLengthOidIsAccepted() throws Exception
    {
        AlgorithmParameters ap = AlgorithmParameters.getInstance("EC", JSL);
        ap.init(new byte[]{0x06, 0x08, 0x2A, (byte) 0x86, 0x48, (byte) 0xCE,
                0x3D, 0x03, 0x01, 0x07});
        Assertions.assertEquals("prime256v1", ap.toString());
    }

    /**
     * SunEC refuses an explicit-parameters SEQUENCE with IOException and so do
     * we: {@code ECParameters} is a CHOICE and only the namedCurve arm is
     * served. Pinned because "accepts more than the platform" is a divergence
     * as much as "accepts less".
     */
    @Test
    public void anExplicitParametersSequenceIsRejectedLikeThePlatform()
    {
        assertOidRejected(new byte[]{0x30, 0x03, 0x02, 0x01, 0x01}, "expected EC parameters");
    }

    private static void assertOidRejected(byte[] der, String expectedFragment)
    {
        IOException e = Assertions.assertThrows(IOException.class,
                () -> AlgorithmParameters.getInstance("EC", JSL).init(der),
                "malformed EC parameters must be refused, not tolerated");
        Assertions.assertTrue(String.valueOf(e.getMessage()).contains(expectedFragment),
                "expected a message naming \"" + expectedFragment + "\", got: " + e.getMessage());
    }

    private static void assertRejected(byte[] der, String expectedFragment)
    {
        IOException e = Assertions.assertThrows(IOException.class,
                () -> AlgorithmParameters.getInstance("AES", JSL).init(der),
                "malformed DER must be refused, not tolerated");
        Assertions.assertTrue(String.valueOf(e.getMessage()).contains(expectedFragment),
                "expected a message naming \"" + expectedFragment + "\", got: " + e.getMessage());
    }

    private static int headerLen(byte[] enc)
    {
        int lenByte = enc[1] & 0xFF;
        return (lenByte & 0x80) == 0 ? 2 : 2 + (lenByte & 0x7F);
    }

    private static byte[] seq(byte[]... items)
    {
        int n = 0;
        for (byte[] i : items)
        {
            n += i.length;
        }
        byte[] out = new byte[2 + n];
        out[0] = 0x30;
        out[1] = (byte) n;
        int off = 2;
        for (byte[] i : items)
        {
            System.arraycopy(i, 0, out, off, i.length);
            off += i.length;
        }
        return out;
    }
}
