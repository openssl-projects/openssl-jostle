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

package org.openssl.jostle.jcajce.provider.bcfks;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.util.asn1.Der;

import java.io.IOException;
import java.util.Date;

/**
 * Structural DER read of BCFKS's ObjectStore wrapper against files BouncyCastle
 * 1.86 itself wrote (BCFKSStoreTest.java, r1rv86, fixtures kwpKeyStore :83,
 * oldKeyStoreNoPW :119, oldKeyStore :142 -- byte-identical to that source).
 * The store CONTENT (entries) is encrypted, so only the ObjectStore wrapper
 * and the integrity-check fields are checked here; the entries are
 * BcFKSKeyStoreSpiTest's decrypt-and-read path.
 */
public class BcFKSFormatTest
{
    /**
     * Measured against BouncyCastle's own bytes: an HMAC-SHA512 outer
     * integrity check (id-hmacWithSHA512, 1.2.840.113549.2.11), PBKDF2 key
     * derivation (id-PBKDF2, 1.2.840.113549.1.5.12), a 64-byte MAC (the
     * SHA-512 digest size), and the CHOICE resolving to the encrypted branch,
     * for all three real stores. {@link BcFKSKeyStoreSpiTest} covers the
     * decrypted entries; this class is the outer-structure half.
     */
    @Test
    public void kwpKeyStoreOuterStructureMatchesBouncyCastle() throws Exception
    {
        BcFKSFormat.ObjectStore store = BcFKSFormat.parseObjectStore(BcFKSFixtures.KWP_KEY_STORE);
        Assertions.assertTrue(store.encrypted);
        Assertions.assertEquals("1.2.840.113549.2.11", store.integrityCheck.pbkdMac.macAlgorithm.oid);
        Assertions.assertEquals("1.2.840.113549.1.5.12", store.integrityCheck.pbkdMac.pbkdAlgorithm.oid);
        Assertions.assertEquals(64, store.integrityCheck.pbkdMac.mac.length);
        Assertions.assertEquals(2371, store.storeDataRaw.length);
    }

    @Test
    public void oldKeyStoreOuterStructureMatchesBouncyCastle() throws Exception
    {
        BcFKSFormat.ObjectStore store = BcFKSFormat.parseObjectStore(BcFKSFixtures.OLD_KEY_STORE);
        Assertions.assertTrue(store.encrypted);
        Assertions.assertEquals("1.2.840.113549.2.11", store.integrityCheck.pbkdMac.macAlgorithm.oid);
        Assertions.assertEquals("1.2.840.113549.1.5.12", store.integrityCheck.pbkdMac.pbkdAlgorithm.oid);
        Assertions.assertEquals(64, store.integrityCheck.pbkdMac.mac.length);
    }

    @Test
    public void oldKeyStoreNoPWOuterStructureMatchesBouncyCastle() throws Exception
    {
        BcFKSFormat.ObjectStore store = BcFKSFormat.parseObjectStore(BcFKSFixtures.OLD_KEY_STORE_NO_PW);
        Assertions.assertTrue(store.encrypted);
        Assertions.assertEquals("1.2.840.113549.2.11", store.integrityCheck.pbkdMac.macAlgorithm.oid);
        Assertions.assertEquals("1.2.840.113549.1.5.12", store.integrityCheck.pbkdMac.pbkdAlgorithm.oid);
        Assertions.assertEquals(64, store.integrityCheck.pbkdMac.mac.length);
    }

    @Test
    public void objectStoreDataRoundTripsThroughOurOwnDerWriters() throws Exception
    {
        // No BC writer exists at this layer yet, so this synthesises a
        // plain (unencrypted) ObjectStoreData with Der's own writers and
        // parses it back -- proving the READ side of the 5/6-field schema
        // independently of any real file.
        String macAlgOid = "1.2.840.113549.2.11";
        byte[] macAlgIdTlv = Der.algorithmIdentifier(macAlgOid, new byte[]{0x05, 0x00});
        byte[] creation = Der.generalizedTime(new Date(0L));
        byte[] modified = Der.generalizedTime(new Date(1_000_000_000_000L));

        byte[] entry1 = Der.sequence(
                Der.integer(BcFKSFormat.ObjectData.TYPE_CERTIFICATE),
                Der.utf8String("trusted"),
                creation, modified,
                Der.octetString(new byte[]{1, 2, 3}));
        byte[] entries = Der.sequence(entry1);

        byte[] storeDataNoComment = Der.sequence(
                Der.integer(1), macAlgIdTlv, creation, modified, entries);
        BcFKSFormat.ObjectStoreData parsed = BcFKSFormat.parseObjectStoreData(storeDataNoComment);
        Assertions.assertEquals(1, parsed.version);
        Assertions.assertEquals(macAlgOid, parsed.integrityAlgorithm.oid);
        Assertions.assertEquals(1, parsed.entries.length);
        Assertions.assertEquals("trusted", parsed.entries[0].identifier);
        Assertions.assertEquals(BcFKSFormat.ObjectData.TYPE_CERTIFICATE, parsed.entries[0].type);
        Assertions.assertArrayEquals(new byte[]{1, 2, 3}, parsed.entries[0].data);
        Assertions.assertNull(parsed.comment);

        byte[] storeDataWithComment = Der.sequence(
                Der.integer(1), macAlgIdTlv, creation, modified, entries,
                Der.utf8String("a comment"));
        BcFKSFormat.ObjectStoreData parsedWithComment = BcFKSFormat.parseObjectStoreData(storeDataWithComment);
        Assertions.assertEquals("a comment", parsedWithComment.comment);
    }

    @Test
    public void wrongVersionIsRejected() throws Exception
    {
        // BouncyCastle's own reader does not check this (ours does); the
        // fixture is otherwise well-formed.
        byte[] macAlgIdTlv = Der.algorithmIdentifier(
                "1.2.840.113549.2.11", new byte[]{0x05, 0x00});
        byte[] time = Der.generalizedTime(new Date(0L));
        byte[] entries = Der.sequence();
        byte[] storeData = Der.sequence(
                Der.integer(2), macAlgIdTlv, time, time, entries);
        Assertions.assertThrows(IOException.class, () -> BcFKSFormat.parseObjectStoreData(storeData));
    }

    @Test
    public void objectStoreChoiceFieldCountOutsideTwoOrFiveSixIsRejected() throws Exception
    {
        // A 3-field first element: neither EncryptedObjectStoreData (2) nor
        // ObjectStoreData (5..6) -- must not fall into either branch.
        byte[] threeFields = Der.sequence(
                Der.integer(1),
                Der.integer(2),
                Der.integer(3));
        byte[] macAlgIdTlv = Der.algorithmIdentifier(
                "1.2.840.113549.2.11", new byte[]{0x05, 0x00});
        byte[] pbkdAlgIdTlv = Der.algorithmIdentifier(
                "1.2.840.113549.1.5.12", new byte[]{0x05, 0x00});
        byte[] pbkdMac = Der.sequence(
                macAlgIdTlv, pbkdAlgIdTlv, Der.octetString(new byte[8]));
        byte[] objectStore = Der.sequence(threeFields, pbkdMac);

        IOException e = Assertions.assertThrows(IOException.class,
                () -> BcFKSFormat.parseObjectStore(objectStore));
        Assertions.assertTrue(e.getMessage().contains("3 fields"), e.getMessage());
    }

    @Test
    public void signatureIntegrityCheckIsRecognisedAndParsed() throws Exception
    {
        byte[] macAlgIdTlv = Der.algorithmIdentifier(
                "1.2.840.113549.2.11", new byte[]{0x05, 0x00});
        byte[] time = Der.generalizedTime(new Date(0L));
        byte[] storeData = Der.sequence(
                Der.integer(1), macAlgIdTlv, time, time,
                Der.sequence());
        // [0] EXPLICIT SignatureCheck -- a minimal but well-formed wrapper,
        // no certificates field.
        byte[] sigAlgIdTlv = macAlgIdTlv;
        byte[] signatureValue = new byte[]{1, 2, 3};
        byte[] signatureCheck = Der.sequence(sigAlgIdTlv, Der.bitString(signatureValue));
        byte[] tagged = Der.explicit(0, signatureCheck);
        byte[] objectStore = Der.sequence(storeData, tagged);

        BcFKSFormat.ObjectStore store = BcFKSFormat.parseObjectStore(objectStore);
        Assertions.assertNull(store.integrityCheck.pbkdMac);
        Assertions.assertNotNull(store.integrityCheck.signatureCheck);
        Assertions.assertEquals("1.2.840.113549.2.11", store.integrityCheck.signatureCheck.signatureAlgorithm.oid);
        Assertions.assertNull(store.integrityCheck.signatureCheck.certificates);
        Assertions.assertArrayEquals(signatureValue, store.integrityCheck.signatureCheck.signatureValue);
    }

    /** As above, but with the OPTIONAL certificates field present. */
    @Test
    public void signatureIntegrityCheckWithCertificatesIsRecognisedAndParsed() throws Exception
    {
        byte[] macAlgIdTlv = Der.algorithmIdentifier(
                "1.2.840.113549.2.11", new byte[]{0x05, 0x00});
        byte[] time = Der.generalizedTime(new Date(0L));
        byte[] storeData = Der.sequence(
                Der.integer(1), macAlgIdTlv, time, time,
                Der.sequence());
        byte[] sigAlgIdTlv = macAlgIdTlv;
        byte[] signatureValue = new byte[]{4, 5, 6};
        // Not a real certificate -- BcFKSFormat treats it as an opaque TLV.
        byte[] fakeCert = Der.sequence(Der.integer(7));
        byte[] certsTlv = Der.explicit(0, Der.sequence(fakeCert));
        byte[] signatureCheck = Der.sequence(sigAlgIdTlv, certsTlv, Der.bitString(signatureValue));
        byte[] tagged = Der.explicit(0, signatureCheck);
        byte[] objectStore = Der.sequence(storeData, tagged);

        BcFKSFormat.ObjectStore store = BcFKSFormat.parseObjectStore(objectStore);
        Assertions.assertNotNull(store.integrityCheck.signatureCheck.certificates);
        Assertions.assertEquals(1, store.integrityCheck.signatureCheck.certificates.length);
        Assertions.assertArrayEquals(fakeCert, store.integrityCheck.signatureCheck.certificates[0]);
    }
}
