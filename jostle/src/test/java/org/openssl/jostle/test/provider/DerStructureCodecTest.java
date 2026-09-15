/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.provider;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.util.asn1.Der;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Date;

/**
 * Round-trip and falsification coverage for the structure codecs {@link Der}
 * gained for BCFKS: BIT STRING, UTF8String, GeneralizedTime, {@code [n]
 * EXPLICIT} tagging, AlgorithmIdentifier, CCMParameters (RFC 5084),
 * EncryptedPrivateKeyInfo (RFC 5958), PBES2-params and PBKDF2-params
 * (RFC 8018 A.2/A.4), and scrypt-params (RFC 7914 s7).
 *
 * <p>Dotted OID literals per the project convention: tests keep the literal,
 * main source uses the {@code oids} constants.
 */
public class DerStructureCodecTest
{
    private static final SecureRandom RANDOM = new SecureRandom();

    private static byte[] randomBytes(int n)
    {
        byte[] b = new byte[n];
        RANDOM.nextBytes(b);
        return b;
    }

    // ---- BIT STRING ----------------------------------------------------

    @Test
    public void bitStringRoundTrips() throws Exception
    {
        for (int len : new int[]{0, 1, 15, 16, 200})
        {
            byte[] content = randomBytes(len);
            byte[] encoded = Der.bitString(content);
            byte[] decoded = new Der.Reader(encoded).readBitString("test");
            Assertions.assertArrayEquals(content, decoded, "length " + len);
        }
    }

    @Test
    public void bitStringWithNonzeroUnusedBitsIsRejected()
    {
        // Hand-build: tag 0x03, length 2, unused-bit octet 0x04 (nonzero), one content byte.
        byte[] malformed = {0x03, 0x02, 0x04, 0x7F};
        IOException e = Assertions.assertThrows(IOException.class,
                () -> new Der.Reader(malformed).readBitString("test"));
        Assertions.assertTrue(e.getMessage().contains("non-byte-aligned"), e.getMessage());
    }

    @Test
    public void emptyBitStringIsRejected()
    {
        byte[] malformed = {0x03, 0x00};
        Assertions.assertThrows(IOException.class,
                () -> new Der.Reader(malformed).readBitString("test"));
    }

    @Test
    public void bitStringReaderRejectsWrongTag()
    {
        byte[] octetString = Der.octetString(new byte[]{1, 2, 3});
        Assertions.assertThrows(IOException.class,
                () -> new Der.Reader(octetString).readBitString("test"));
    }

    // ---- UTF8String ------------------------------------------------------

    @Test
    public void utf8StringRoundTrips() throws Exception
    {
        String[] cases = {"", "hello", "café über", "😀 emoji"};
        for (String s : cases)
        {
            byte[] encoded = Der.utf8String(s);
            String decoded = new Der.Reader(encoded).readUTF8String("test");
            Assertions.assertEquals(s, decoded);
        }
    }

    @Test
    public void utf8StringTruncatedContentIsRejected()
    {
        // Declares 10 content bytes, supplies 2.
        byte[] malformed = {0x0C, 0x0A, 'h', 'i'};
        Assertions.assertThrows(IOException.class,
                () -> new Der.Reader(malformed).readUTF8String("test"));
    }

    // ---- GeneralizedTime ---------------------------------------------

    @Test
    public void generalizedTimeRoundTripsAtSecondPrecision() throws Exception
    {
        long[] epochSeconds = {0L, 1_000_000_000L, 4_102_444_800L /* 2100-01-01 */};
        for (long secs : epochSeconds)
        {
            Date original = new Date(secs * 1000L);
            byte[] encoded = Der.generalizedTime(original);
            Date decoded = new Der.Reader(encoded).readGeneralizedTime("test");
            Assertions.assertEquals(original, decoded, "epoch seconds " + secs);
        }
    }

    @Test
    public void generalizedTimeEncodesTheDerCanonicalForm() throws Exception
    {
        // Epoch zero: byte-exact against BouncyCastle's own format string,
        // ASN1GeneralizedTime(Date) at r1rv86 (SimpleDateFormat
        // "yyyyMMddHHmmss'Z'" under a fixed UTC zone).
        byte[] encoded = Der.generalizedTime(new Date(0L));
        byte[] content = new Der.Reader(encoded).readTLV(Der.GENERALIZED_TIME, "test").remaining();
        Assertions.assertEquals("19700101000000Z", new String(content, "US-ASCII"));
    }

    @Test
    public void generalizedTimeWrongLengthIsRejected()
    {
        // 14 octets, missing the trailing Z.
        byte[] malformed = Der.tlv(Der.GENERALIZED_TIME, "19700101000000".getBytes());
        Assertions.assertThrows(IOException.class,
                () -> new Der.Reader(malformed).readGeneralizedTime("test"));
    }

    @Test
    public void generalizedTimeMissingZSuffixIsRejected()
    {
        byte[] malformed = Der.tlv(Der.GENERALIZED_TIME, "19700101000000+".getBytes());
        Assertions.assertThrows(IOException.class,
                () -> new Der.Reader(malformed).readGeneralizedTime("test"));
    }

    @Test
    public void generalizedTimeNonDigitContentIsRejected()
    {
        byte[] malformed = Der.tlv(Der.GENERALIZED_TIME, "1970010100000AZ".getBytes());
        Assertions.assertThrows(IOException.class,
                () -> new Der.Reader(malformed).readGeneralizedTime("test"));
    }

    // ---- [n] EXPLICIT ---------------------------------------------------

    @Test
    public void explicitTaggingRoundTrips() throws Exception
    {
        byte[] inner = Der.sequence(Der.octetString(new byte[]{1, 2, 3}));
        byte[] wrapped = Der.explicit(0, inner);
        Assertions.assertEquals(0xA0, wrapped[0] & 0xFF, "constructed context tag [0]");
        Der.Reader innerReader = new Der.Reader(wrapped).readExplicit(0, "test");
        byte[] content = innerReader.readTLV(Der.SEQUENCE, "inner").readTLV(Der.OCTET_STRING, "field").remaining();
        Assertions.assertArrayEquals(new byte[]{1, 2, 3}, content);
    }

    @Test
    public void explicitTagOutOfRangeIsRejected()
    {
        Assertions.assertThrows(IllegalArgumentException.class, () -> Der.explicit(31, new byte[]{0x05, 0x00}));
        Assertions.assertThrows(IllegalArgumentException.class, () -> Der.explicit(-1, new byte[]{0x05, 0x00}));
    }

    @Test
    public void explicitTagMismatchIsRejected() throws Exception
    {
        byte[] wrapped = Der.explicit(0, Der.sequence());
        Assertions.assertThrows(IOException.class, () -> new Der.Reader(wrapped).readExplicit(1, "test"));
    }

    // ---- AlgorithmIdentifier ---------------------------------------------

    @Test
    public void algorithmIdentifierRoundTripsWithAndWithoutParameters() throws Exception
    {
        // With explicit NULL parameters, as RFC 8018's algid-hmacWithSHA1-style
        // identifiers carry (id-hmacWithSHA512, RFC 4231 line 134).
        byte[] nullParams = {0x05, 0x00};
        byte[] withParams = Der.algorithmIdentifier("1.2.840.113549.2.11", nullParams);
        Der.AlgorithmIdentifier decoded1 = new Der.Reader(withParams).readAlgorithmIdentifier("test");
        Assertions.assertEquals("1.2.840.113549.2.11", decoded1.oid);
        Assertions.assertArrayEquals(nullParams, decoded1.parameters);

        // Without parameters at all, as id-scrypt style identifiers carry.
        byte[] noParams = Der.algorithmIdentifier("1.3.6.1.4.1.11591.4.11", null);
        Der.AlgorithmIdentifier decoded2 = new Der.Reader(noParams).readAlgorithmIdentifier("test");
        Assertions.assertEquals("1.3.6.1.4.1.11591.4.11", decoded2.oid);
        Assertions.assertNull(decoded2.parameters);
    }

    @Test
    public void algorithmIdentifierTruncatedIsRejected()
    {
        // A bare SEQUENCE with no OID at all.
        byte[] malformed = Der.sequence();
        Assertions.assertThrows(IOException.class, () -> new Der.Reader(malformed).readAlgorithmIdentifier("test"));
    }

    @Test
    public void algorithmIdentifierTrailingFieldIsRejected()
    {
        byte[] oid = Der.objectIdentifier("1.2.840.113549.2.11");
        byte[] malformed = Der.sequence(oid, new byte[]{0x05, 0x00}, new byte[]{0x05, 0x00});
        Assertions.assertThrows(IOException.class, () -> new Der.Reader(malformed).readAlgorithmIdentifier("test"));
    }

    // ---- CCMParameters (RFC 5084) -----------------------------------------

    @Test
    public void ccmParametersRoundTripsDefaultIcvOmitted() throws Exception
    {
        byte[] nonce = randomBytes(12);
        byte[] encoded = Der.ccmParameters(nonce, 12);
        // Per DER, the DEFAULT (12) is omitted: SEQUENCE of one element.
        Der.Reader seq = new Der.Reader(encoded).readTLV(Der.SEQUENCE, "outer");
        seq.readTLV(Der.OCTET_STRING, "nonce");
        Assertions.assertTrue(seq.atEnd(), "ICV length must be omitted at the DEFAULT");

        Der.CcmParameters decoded = new Der.Reader(encoded).readCcmParameters("test");
        Assertions.assertArrayEquals(nonce, decoded.nonce);
        Assertions.assertEquals(12, decoded.icvBytes);
    }

    @Test
    public void ccmParametersRoundTripsNonDefaultIcv() throws Exception
    {
        byte[] nonce = randomBytes(7);
        byte[] encoded = Der.ccmParameters(nonce, 16);
        Der.CcmParameters decoded = new Der.Reader(encoded).readCcmParameters("test");
        Assertions.assertArrayEquals(nonce, decoded.nonce);
        Assertions.assertEquals(16, decoded.icvBytes);
    }

    @Test
    public void ccmParametersTrailingFieldIsRejected()
    {
        byte[] nonce = Der.octetString(randomBytes(12));
        byte[] icv = Der.integer(12);
        byte[] malformed = Der.sequence(nonce, icv, icv);
        Assertions.assertThrows(IOException.class, () -> new Der.Reader(malformed).readCcmParameters("test"));
    }

    // ---- EncryptedPrivateKeyInfo (RFC 5958) -------------------------------

    @Test
    public void encryptedPrivateKeyInfoRoundTrips() throws Exception
    {
        byte[] algId = Der.algorithmIdentifier("1.2.840.113549.1.5.13", Der.sequence());
        byte[] encryptedData = randomBytes(48);
        byte[] encoded = Der.encryptedPrivateKeyInfo(algId, encryptedData);

        Der.EncryptedPrivateKeyInfo decoded = new Der.Reader(encoded).readEncryptedPrivateKeyInfo("test");
        Assertions.assertEquals("1.2.840.113549.1.5.13", decoded.encryptionAlgorithm.oid);
        Assertions.assertArrayEquals(encryptedData, decoded.encryptedData);
    }

    @Test
    public void encryptedPrivateKeyInfoMissingEncryptedDataIsRejected()
    {
        byte[] algId = Der.algorithmIdentifier("1.2.840.113549.1.5.13", null);
        byte[] malformed = Der.sequence(algId);
        Assertions.assertThrows(IOException.class,
                () -> new Der.Reader(malformed).readEncryptedPrivateKeyInfo("test"));
    }

    // ---- PBES2-params (RFC 8018 A.4) --------------------------------------

    @Test
    public void pbes2ParamsRoundTrips() throws Exception
    {
        byte[] kdf = Der.algorithmIdentifier("1.2.840.113549.1.5.12", Der.sequence());
        byte[] enc = Der.algorithmIdentifier("2.16.840.1.101.3.4.1.47", Der.sequence());
        byte[] encoded = Der.pbes2Params(kdf, enc);

        Der.Pbes2Params decoded = new Der.Reader(encoded).readPbes2Params("test");
        Assertions.assertEquals("1.2.840.113549.1.5.12", decoded.keyDerivationFunc.oid);
        Assertions.assertEquals("2.16.840.1.101.3.4.1.47", decoded.encryptionScheme.oid);
    }

    @Test
    public void pbes2ParamsMissingEncryptionSchemeIsRejected()
    {
        byte[] kdf = Der.algorithmIdentifier("1.2.840.113549.1.5.12", null);
        byte[] malformed = Der.sequence(kdf);
        Assertions.assertThrows(IOException.class, () -> new Der.Reader(malformed).readPbes2Params("test"));
    }

    // ---- PBKDF2-params (RFC 8018 A.2) -------------------------------------

    @Test
    public void pbkdf2ParamsRoundTripsAllFieldCombinations() throws Exception
    {
        byte[] salt = randomBytes(64);
        byte[] prf = Der.algorithmIdentifier("1.2.840.113549.2.11", new byte[]{0x05, 0x00});

        // (a) salt + iterationCount only.
        Der.Pbkdf2Params a = new Der.Reader(Der.pbkdf2Params(salt, 51200, null, null))
                .readPbkdf2Params("test");
        Assertions.assertArrayEquals(salt, a.salt);
        Assertions.assertEquals(51200, a.iterationCount);
        Assertions.assertNull(a.keyLength);
        Assertions.assertNull(a.prf);

        // (b) + keyLength, no prf.
        Der.Pbkdf2Params b = new Der.Reader(Der.pbkdf2Params(salt, 51200, 32, null))
                .readPbkdf2Params("test");
        Assertions.assertEquals(Integer.valueOf(32), b.keyLength);
        Assertions.assertNull(b.prf);

        // (c) + keyLength + prf.
        Der.Pbkdf2Params c = new Der.Reader(Der.pbkdf2Params(salt, 51200, 32, prf))
                .readPbkdf2Params("test");
        Assertions.assertEquals(Integer.valueOf(32), c.keyLength);
        Assertions.assertEquals("1.2.840.113549.2.11", c.prf.oid);

        // (d) + prf, no keyLength -- proves the two OPTIONAL fields disambiguate by tag.
        Der.Pbkdf2Params d = new Der.Reader(Der.pbkdf2Params(salt, 51200, null, prf))
                .readPbkdf2Params("test");
        Assertions.assertNull(d.keyLength);
        Assertions.assertEquals("1.2.840.113549.2.11", d.prf.oid);
    }

    @Test
    public void pbkdf2ParamsOtherSourceSaltChoiceIsRejected()
    {
        // The otherSource AlgorithmIdentifier CHOICE has no writer here and is
        // refused as a salt-field tag mismatch, per the class javadoc.
        byte[] otherSource = Der.algorithmIdentifier("1.2.840.113549.2.11", null);
        byte[] malformed = Der.sequence(otherSource, Der.integer(1000));
        Assertions.assertThrows(IOException.class, () -> new Der.Reader(malformed).readPbkdf2Params("test"));
    }

    @Test
    public void pbkdf2ParamsTrailingFieldIsRejected()
    {
        byte[] salt = Der.octetString(randomBytes(8));
        byte[] iter = Der.integer(1000);
        byte[] malformed = Der.sequence(salt, iter, iter, iter, iter);
        Assertions.assertThrows(IOException.class, () -> new Der.Reader(malformed).readPbkdf2Params("test"));
    }

    // ---- scrypt-params (RFC 7914 s7) --------------------------------------

    @Test
    public void scryptParamsRoundTripsWithAndWithoutKeyLength() throws Exception
    {
        byte[] salt = randomBytes(32);

        Der.ScryptParams withLength = new Der.Reader(Der.scryptParams(salt, 16384L, 8, 1, 32))
                .readScryptParams("test");
        Assertions.assertArrayEquals(salt, withLength.salt);
        Assertions.assertEquals(16384L, withLength.costParameter);
        Assertions.assertEquals(8, withLength.blockSize);
        Assertions.assertEquals(1, withLength.parallelizationParameter);
        Assertions.assertEquals(Integer.valueOf(32), withLength.keyLength);

        Der.ScryptParams withoutLength = new Der.Reader(Der.scryptParams(salt, 1_048_576L, 8, 1, null))
                .readScryptParams("test");
        Assertions.assertEquals(1_048_576L, withoutLength.costParameter);
        Assertions.assertNull(withoutLength.keyLength);
    }

    @Test
    public void scryptParamsMissingRequiredFieldIsRejected()
    {
        // Only salt and costParameter -- blockSize and parallelizationParameter absent.
        byte[] malformed = Der.sequence(Der.octetString(randomBytes(16)), Der.integer(16384));
        Assertions.assertThrows(IOException.class, () -> new Der.Reader(malformed).readScryptParams("test"));
    }

    @Test
    public void scryptParamsCostParameterBeyondLongRangeIsRejected()
    {
        // A 9-octet positive INTEGER content (value 2^64): too wide for a signed long.
        byte[] hugeInt = {0x02, 0x09, 0x01, 0, 0, 0, 0, 0, 0, 0, 0};
        byte[] salt = Der.octetString(randomBytes(8));
        byte[] wrapped = Der.sequence(salt, hugeInt, Der.integer(8), Der.integer(1));
        Assertions.assertThrows(IOException.class, () -> new Der.Reader(wrapped).readScryptParams("test"));
    }
}
