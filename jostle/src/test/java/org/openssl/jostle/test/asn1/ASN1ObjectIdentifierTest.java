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

package org.openssl.jostle.test.asn1;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.util.asn1.ASN1ObjectIdentifier;
import org.openssl.jostle.util.asn1.oids.NISTObjectIdentifiers;

/**
 * Gates and {@code intern()} behaviour of {@link ASN1ObjectIdentifier}, exercised
 * through its public surface ({@code fromContents}, {@code branch}, {@code intern}).
 * The package-private string constructor is reached transitively via those.
 */
public class ASN1ObjectIdentifierTest
{
    // DER contents octets (value bytes only — no tag/length) of the SHA-256 OID
    // 2.16.840.1.101.3.4.2.1, and SHA-384 2.16.840.1.101.3.4.2.2.
    private static final byte[] SHA256_CONTENTS =
            {0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01};
    private static final byte[] SHA384_CONTENTS =
            {0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02};

    @Test
    public void testFromContents_roundTripsKnownOids()
    {
        Assertions.assertEquals(NISTObjectIdentifiers.id_sha256.getId(),
                ASN1ObjectIdentifier.fromContents(SHA256_CONTENTS, 0, SHA256_CONTENTS.length).getId());
        Assertions.assertEquals("2.16.840.1.101.3.4.2.2",
                ASN1ObjectIdentifier.fromContents(SHA384_CONTENTS, 0, SHA384_CONTENTS.length).getId());

        // Decode honours a non-zero offset / partial length: embed the SHA-256
        // contents inside a larger buffer and decode just that window.
        byte[] framed = new byte[SHA256_CONTENTS.length + 4];
        System.arraycopy(SHA256_CONTENTS, 0, framed, 3, SHA256_CONTENTS.length);
        Assertions.assertEquals("2.16.840.1.101.3.4.2.1",
                ASN1ObjectIdentifier.fromContents(framed, 3, SHA256_CONTENTS.length).getId());
    }

    @Test
    public void testFromContents_rejectsBadRanges()
    {
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> ASN1ObjectIdentifier.fromContents(null, 0, 1));
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> ASN1ObjectIdentifier.fromContents(SHA256_CONTENTS, -1, 4));
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> ASN1ObjectIdentifier.fromContents(SHA256_CONTENTS, 0, 0));
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> ASN1ObjectIdentifier.fromContents(SHA256_CONTENTS, 0, SHA256_CONTENTS.length + 1));
    }

    @Test
    public void testFromContents_rejectsContentsLengthLimit()
    {
        // 4097 single-octet sub-identifiers: each octet is a valid, minimal
        // sub-identifier, so only the MAX_CONTENTS_LENGTH (4096) gate trips.
        byte[] tooLong = new byte[4097];
        java.util.Arrays.fill(tooLong, (byte) 0x01);
        IllegalArgumentException ex = Assertions.assertThrows(IllegalArgumentException.class,
                () -> ASN1ObjectIdentifier.fromContents(tooLong, 0, tooLong.length));
        Assertions.assertTrue(ex.getMessage().contains("length limit"), ex.getMessage());

        // Exactly at the limit is accepted.
        byte[] atLimit = new byte[4096];
        java.util.Arrays.fill(atLimit, (byte) 0x01);
        ASN1ObjectIdentifier.fromContents(atLimit, 0, atLimit.length);
    }

    @Test
    public void testFromContents_rejectsNonMinimalSubidentifier()
    {
        // A sub-identifier whose leading octet is 0x80 is a non-minimal (leading
        // zero) base-128 encoding and must be rejected.
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> ASN1ObjectIdentifier.fromContents(new byte[]{(byte) 0x80, 0x01}, 0, 2));
    }

    @Test
    public void testFromContents_rejectsTruncatedEncoding()
    {
        // Trailing octet still has its continuation bit set => truncated.
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> ASN1ObjectIdentifier.fromContents(new byte[]{0x60, (byte) 0x86}, 0, 2));
    }

    @Test
    public void testFromContents_multiOctetSubidentifier()
    {
        // A two-octet base-128 sub-identifier: 0x88,0x37 -> (0x08<<7)|0x37 = 1079,
        // which splits as first arc 2, second arc 1079-80 = 999.
        Assertions.assertEquals("2.999",
                ASN1ObjectIdentifier.fromContents(new byte[]{(byte) 0x88, 0x37}, 0, 2).getId());
    }

    @Test
    public void testFromContents_oversizeSubidentifierUsesBigInteger()
    {
        // Eleven 0xFF continuation octets + a terminating 0x7F encode a 7*12 = 84-bit
        // second sub-identifier, well past a long's range — the decoder must switch
        // to BigInteger. Expected value: the first octet group sets arc1=2 (value >=80)
        // so we just assert the result is well-formed "2.<bigdecimal>" and that the
        // arc is the BigInteger of the 84-bit big-endian base-128 number minus 80.
        byte[] contents = new byte[12];
        java.util.Arrays.fill(contents, (byte) 0xFF);
        contents[11] = 0x7F;

        java.math.BigInteger acc = java.math.BigInteger.ZERO;
        for (byte b : contents)
        {
            acc = acc.shiftLeft(7).or(java.math.BigInteger.valueOf(b & 0x7F));
        }
        String expected = "2." + acc.subtract(java.math.BigInteger.valueOf(80));

        Assertions.assertEquals(expected,
                ASN1ObjectIdentifier.fromContents(contents, 0, contents.length).getId());
    }

    @Test
    public void testBranch_validAndInvalid()
    {
        ASN1ObjectIdentifier base = NISTObjectIdentifiers.nistAlgorithm; // 2.16.840.1.101.3.4
        Assertions.assertEquals(base.getId() + ".2.1", base.branch("2.1").getId());
        Assertions.assertEquals(base.getId() + ".99", base.branch("99").getId());

        // Invalid relative identifiers are rejected.
        Assertions.assertThrows(NullPointerException.class, () -> base.branch(null));
        Assertions.assertThrows(IllegalArgumentException.class, () -> base.branch(""));
        Assertions.assertThrows(IllegalArgumentException.class, () -> base.branch("01"));     // leading zero
        Assertions.assertThrows(IllegalArgumentException.class, () -> base.branch("1.02"));   // leading zero in group
        Assertions.assertThrows(IllegalArgumentException.class, () -> base.branch("1..2"));   // empty group
        Assertions.assertThrows(IllegalArgumentException.class, () -> base.branch("1a"));     // non-digit
    }

    @Test
    public void testIntern_poolsEqualOids()
    {
        ASN1ObjectIdentifier a = ASN1ObjectIdentifier.fromContents(SHA256_CONTENTS, 0, SHA256_CONTENTS.length).intern();
        ASN1ObjectIdentifier b = ASN1ObjectIdentifier.fromContents(SHA256_CONTENTS, 0, SHA256_CONTENTS.length).intern();
        Assertions.assertSame(a, b, "intern must return the same reference for equal OIDs");

        ASN1ObjectIdentifier other = ASN1ObjectIdentifier.fromContents(SHA384_CONTENTS, 0, SHA384_CONTENTS.length).intern();
        Assertions.assertNotSame(a, other, "distinct OIDs must not intern to the same reference");
    }

    @Test
    public void testFromContents_returnsInternedInstanceOnHit()
    {
        // A distinct OID not interned elsewhere: decode it twice WITHOUT interning
        // first — fromContents must hand back a fresh (non-shared) instance, proving
        // a miss does not auto-populate the pool.
        byte[] contents = {0x2B, 0x65, 0x70}; // 1.3.101.112 (Ed25519)
        ASN1ObjectIdentifier miss1 = ASN1ObjectIdentifier.fromContents(contents, 0, contents.length);
        ASN1ObjectIdentifier miss2 = ASN1ObjectIdentifier.fromContents(contents, 0, contents.length);
        Assertions.assertEquals(miss1, miss2);
        Assertions.assertNotSame(miss1, miss2, "a pool miss must not be cached (no unbounded growth)");

        // After interning, fromContents must consult the pool and return the shared
        // interned instance.
        ASN1ObjectIdentifier interned = miss1.intern();
        ASN1ObjectIdentifier hit = ASN1ObjectIdentifier.fromContents(contents, 0, contents.length);
        Assertions.assertSame(interned, hit, "fromContents must return the interned instance on a pool hit");
    }

    @Test
    public void testRegistryConstantsAreInterned()
    {
        // The OID-registry constants intern themselves at class-init, so decoding a
        // known algorithm OID off the wire returns the very same shared instance —
        // the dedup payoff for the cert/KDF decode paths.
        Assertions.assertSame(NISTObjectIdentifiers.id_sha256,
                ASN1ObjectIdentifier.fromContents(SHA256_CONTENTS, 0, SHA256_CONTENTS.length));
        Assertions.assertSame(NISTObjectIdentifiers.id_alg_ml_kem_768,
                ASN1ObjectIdentifier.fromContents(
                        new byte[]{0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x02}, 0, 9));
    }

    @Test
    public void testEqualsAndHashCode_valueSemantics()
    {
        ASN1ObjectIdentifier a = ASN1ObjectIdentifier.fromContents(SHA256_CONTENTS, 0, SHA256_CONTENTS.length);
        ASN1ObjectIdentifier b = ASN1ObjectIdentifier.fromContents(SHA256_CONTENTS, 0, SHA256_CONTENTS.length);
        ASN1ObjectIdentifier c = ASN1ObjectIdentifier.fromContents(SHA384_CONTENTS, 0, SHA384_CONTENTS.length);

        Assertions.assertEquals(a, b);
        Assertions.assertEquals(a.hashCode(), b.hashCode());
        Assertions.assertNotEquals(a, c);
        Assertions.assertNotEquals(a, null);
        Assertions.assertNotEquals(a, "2.16.840.1.101.3.4.2.1");
    }
}
