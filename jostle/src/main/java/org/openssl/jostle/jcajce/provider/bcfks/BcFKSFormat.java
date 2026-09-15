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

import org.openssl.jostle.util.Properties;
import org.openssl.jostle.util.asn1.Der;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * DER read of the BCFKS keystore format, over {@link Der}. Cited to
 * {@code org.bouncycastle.asn1.bc.*} at r1rv86, one class per structure below
 * — read in full rather than from the class javadoc, since
 * {@code ObjectStoreData}'s own javadoc names a {@code dataSalt} field its
 * parser and writer do not carry.
 *
 * <pre>
 * ObjectStore ::= SEQUENCE {
 *     CHOICE { EncryptedObjectStoreData, ObjectStoreData },
 *     ObjectStoreIntegrityCheck }
 * </pre>
 *
 * <p>The CHOICE is untagged. BouncyCastle (ObjectStore.java:44-64) decides it
 * by the FIELD COUNT of the first element: 2 fields is
 * {@code EncryptedObjectStoreData}, anything else is {@code ObjectStoreData}.
 * This codec is stricter on the "anything else": only 5 or 6 fields (the
 * comment is OPTIONAL) is accepted as {@code ObjectStoreData}; any other
 * count is refused rather than falling into either branch by default.
 */
final class BcFKSFormat
{
    private BcFKSFormat()
    {
    }

    /**
     * Ceiling on the WHOLE store input, applied to the stream before any DER
     * {@code Reader} exists — BouncyCastle's own {@code engineLoad} has no
     * such bound. 64 MiB, matching the X.509 container ceiling
     * ({@code X509NI.DEFAULT_MAX_CONTAINER_BYTES}): a BCFKS store holding many
     * certificates and private keys is the same shape of container.
     */
    static final int DEFAULT_MAX_STORE_BYTES = 64 * 1024 * 1024;

    /** Property overriding {@link #DEFAULT_MAX_STORE_BYTES}. */
    static final String MAX_STORE_BYTES_PROPERTY = "org.openssl.jostle.bcfks.max_store_bytes";

    static int maxStoreBytes()
    {
        try
        {
            int configured = Properties.asInteger(MAX_STORE_BYTES_PROPERTY, DEFAULT_MAX_STORE_BYTES);
            return configured < 1 ? DEFAULT_MAX_STORE_BYTES : configured;
        }
        catch (NumberFormatException e)
        {
            // Fail-open toward the default rather than refusing every load on
            // an operator typo, same trade-off as Der.usableOr.
            return DEFAULT_MAX_STORE_BYTES;
        }
    }

    /**
     * Read the whole input stream into a byte[], refusing the moment the
     * running total exceeds {@link #maxStoreBytes()} — before any DER
     * {@code Reader} is constructed, and before reading any further from the
     * stream. Read incrementally rather than pre-allocating the ceiling: the
     * bound is still the CONFIGURED cap, never a length the input claims, but
     * a small store no longer costs a 64 MiB allocation to read.
     */
    static byte[] readWholeStore(InputStream in) throws IOException
    {
        int limit = maxStoreBytes();
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        byte[] chunk = new byte[8192];
        int total = 0;
        int n;
        while ((n = in.read(chunk)) != -1)
        {
            total += n;
            if (total > limit)
            {
                throw new IOException("BCFKS store exceeds the " + limit + "-byte ceiling");
            }
            buf.write(chunk, 0, n);
        }
        return buf.toByteArray();
    }

    // ---- ObjectStore -------------------------------------------------------

    static final class ObjectStore
    {
        /**
         * The complete raw TLV of the first ObjectStore element, exactly as
         * read — never a re-encoding. This is what the MAC and signature
         * checks cover (BcFKSKeyStoreSpi.engineLoad, r1rv86:1414), and it is
         * byte-identical to BouncyCastle's own re-encoding for any DER input.
         */
        final byte[] storeDataRaw;
        final boolean encrypted;
        final IntegrityCheck integrityCheck;

        ObjectStore(byte[] storeDataRaw, boolean encrypted, IntegrityCheck integrityCheck)
        {
            this.storeDataRaw = storeDataRaw;
            this.encrypted = encrypted;
            this.integrityCheck = integrityCheck;
        }
    }

    /**
     * {@code ObjectStoreIntegrityCheck ::= CHOICE { PbkdMacIntegrityCheck,
     * [0] EXPLICIT SignatureCheck }}. Only the MAC half is parsed — signature
     * checks are not implemented yet; a {@code [0]} tag here is recognised
     * and refused typed, not silently misread as something else.
     */
    static final class IntegrityCheck
    {
        final PbkdMac pbkdMac;

        IntegrityCheck(PbkdMac pbkdMac)
        {
            this.pbkdMac = pbkdMac;
        }
    }

    /**
     * {@code PbkdMacIntegrityCheck ::= SEQUENCE { macAlgorithm
     * AlgorithmIdentifier, pbkdAlgorithm KeyDerivationFunc, mac OCTET STRING }}.
     * {@code KeyDerivationFunc} is BouncyCastle's own TODO-flagged wrapper
     * that is {@code AlgorithmIdentifier} on the wire
     * (core/.../pkcs/KeyDerivationFunc.java:10), so {@code pbkdAlgorithm}
     * reads exactly as {@code macAlgorithm} does.
     */
    static final class PbkdMac
    {
        final Der.AlgorithmIdentifier macAlgorithm;
        final Der.AlgorithmIdentifier pbkdAlgorithm;
        final byte[] mac;

        PbkdMac(Der.AlgorithmIdentifier macAlgorithm, Der.AlgorithmIdentifier pbkdAlgorithm, byte[] mac)
        {
            this.macAlgorithm = macAlgorithm;
            this.pbkdAlgorithm = pbkdAlgorithm;
            this.mac = mac;
        }
    }

    /**
     * {@code EncryptedObjectStoreData ::= SEQUENCE { encryptionAlgorithm
     * AlgorithmIdentifier, encryptedContent OCTET STRING }}.
     */
    static final class EncryptedObjectStoreData
    {
        final Der.AlgorithmIdentifier encryptionAlgorithm;
        final byte[] encryptedContent;

        EncryptedObjectStoreData(Der.AlgorithmIdentifier encryptionAlgorithm, byte[] encryptedContent)
        {
            this.encryptionAlgorithm = encryptionAlgorithm;
            this.encryptedContent = encryptedContent;
        }
    }

    /**
     * {@code ObjectStoreData ::= SEQUENCE { version INTEGER, integrityAlgorithm
     * AlgorithmIdentifier, creationDate GeneralizedTime, lastModifiedDate
     * GeneralizedTime, objectDataSequence SEQUENCE OF ObjectData, comment
     * UTF8String OPTIONAL }}. NO {@code dataSalt} field — see the class
     * javadoc.
     */
    static final class ObjectStoreData
    {
        final int version;
        final Der.AlgorithmIdentifier integrityAlgorithm;
        final Date creationDate;
        final Date lastModifiedDate;
        final ObjectData[] entries;
        final String comment;

        ObjectStoreData(int version, Der.AlgorithmIdentifier integrityAlgorithm, Date creationDate,
                         Date lastModifiedDate, ObjectData[] entries, String comment)
        {
            this.version = version;
            this.integrityAlgorithm = integrityAlgorithm;
            this.creationDate = creationDate;
            this.lastModifiedDate = lastModifiedDate;
            this.entries = entries;
            this.comment = comment;
        }
    }

    /**
     * {@code ObjectData ::= SEQUENCE { type INTEGER, identifier UTF8String,
     * creationDate GeneralizedTime, lastModifiedDate GeneralizedTime, data
     * OCTET STRING, comment UTF8String OPTIONAL }}.
     */
    static final class ObjectData
    {
        static final int TYPE_CERTIFICATE = 0;
        static final int TYPE_PRIVATE_KEY = 1;
        static final int TYPE_SECRET_KEY = 2;
        static final int TYPE_PROTECTED_PRIVATE_KEY = 3;
        static final int TYPE_PROTECTED_SECRET_KEY = 4;
        static final int TYPE_PBKDF_KEY = 5;

        final int type;
        final String identifier;
        final Date creationDate;
        final Date lastModifiedDate;
        final byte[] data;
        final String comment;

        ObjectData(int type, String identifier, Date creationDate, Date lastModifiedDate,
                   byte[] data, String comment)
        {
            this.type = type;
            this.identifier = identifier;
            this.creationDate = creationDate;
            this.lastModifiedDate = lastModifiedDate;
            this.data = data;
            this.comment = comment;
        }
    }

    // ---- Parsing -------------------------------------------------------

    /** Top-level entry point: the whole store, over the bytes {@link #readWholeStore} produced. */
    static ObjectStore parseObjectStore(byte[] der) throws IOException
    {
        Der.Reader top = new Der.Reader(der);
        Der.Reader seq = top.readTLV(Der.SEQUENCE, "ObjectStore");
        top.requireEnd("trailing bytes after ObjectStore");

        byte[] storeDataRaw = seq.readEncodedTLV(Der.SEQUENCE, "ObjectStore storeData");
        int fieldCount = countTopLevelFields(storeDataRaw);
        boolean encrypted;
        if (fieldCount == 2)
        {
            encrypted = true;
        }
        else if (fieldCount == 5 || fieldCount == 6)
        {
            encrypted = false;
        }
        else
        {
            throw new IOException("ObjectStore storeData has " + fieldCount
                    + " fields; expected 2 (encrypted) or 5..6 (plain)");
        }

        IntegrityCheck integrityCheck = parseIntegrityCheck(seq);
        seq.requireEnd("trailing bytes in ObjectStore");

        return new ObjectStore(storeDataRaw, encrypted, integrityCheck);
    }

    /** The number of top-level TLVs inside one SEQUENCE's content, without interpreting any of them. */
    private static int countTopLevelFields(byte[] sequenceTlv) throws IOException
    {
        Der.Reader r = new Der.Reader(sequenceTlv).readTLV(Der.SEQUENCE, "storeData");
        int count = 0;
        while (!r.atEnd())
        {
            r.readEncodedTLV(r.peekTag(), "storeData field " + count);
            count++;
        }
        return count;
    }

    /** [0] EXPLICIT's first octet: a constructed context-specific tag numbered 0. */
    private static final int EXPLICIT_0_TAG = 0xA0;

    private static IntegrityCheck parseIntegrityCheck(Der.Reader outer) throws IOException
    {
        int tag = outer.peekTag();
        if (tag == Der.SEQUENCE)
        {
            Der.Reader mac = outer.readTLV(Der.SEQUENCE, "PbkdMacIntegrityCheck");
            Der.AlgorithmIdentifier macAlgorithm = mac.readAlgorithmIdentifier("macAlgorithm");
            Der.AlgorithmIdentifier pbkdAlgorithm = mac.readAlgorithmIdentifier("pbkdAlgorithm");
            byte[] macValue = mac.readTLV(Der.OCTET_STRING, "mac").remaining();
            mac.requireEnd("trailing bytes in PbkdMacIntegrityCheck");
            return new IntegrityCheck(new PbkdMac(macAlgorithm, pbkdAlgorithm, macValue));
        }
        if (tag == EXPLICIT_0_TAG)
        {
            // [0] EXPLICIT SignatureCheck -- a recognised CHOICE arm, not yet implemented.
            throw new IOException("BCFKS signature integrity checks are not implemented");
        }
        throw new IOException("BCFKS KeyStore: unrecognised integrity check");
    }

    static EncryptedObjectStoreData parseEncryptedObjectStoreData(byte[] der) throws IOException
    {
        Der.Reader seq = new Der.Reader(der).readTLV(Der.SEQUENCE, "EncryptedObjectStoreData");
        Der.AlgorithmIdentifier encryptionAlgorithm = seq.readAlgorithmIdentifier("encryptionAlgorithm");
        byte[] encryptedContent = seq.readTLV(Der.OCTET_STRING, "encryptedContent").remaining();
        seq.requireEnd("trailing bytes in EncryptedObjectStoreData");
        return new EncryptedObjectStoreData(encryptionAlgorithm, encryptedContent);
    }

    static ObjectStoreData parseObjectStoreData(byte[] der) throws IOException
    {
        Der.Reader seq = new Der.Reader(der).readTLV(Der.SEQUENCE, "ObjectStoreData");

        int version = seq.readSmallInteger("version");
        // BouncyCastle's own reader does not check this; ours does. BC always writes 1.
        if (version != 1)
        {
            throw new IOException("ObjectStoreData version " + version + " is not supported (expected 1)");
        }

        Der.AlgorithmIdentifier integrityAlgorithm = seq.readAlgorithmIdentifier("integrityAlgorithm");
        Date creationDate = seq.readGeneralizedTime("creationDate");
        Date lastModifiedDate = seq.readGeneralizedTime("lastModifiedDate");

        Der.Reader entriesSeq = seq.readTLV(Der.SEQUENCE, "objectDataSequence");
        List<ObjectData> entries = new ArrayList<ObjectData>();
        while (!entriesSeq.atEnd())
        {
            entries.add(parseObjectDataInner(
                    entriesSeq.readTLV(Der.SEQUENCE, "ObjectData")));
        }

        String comment = null;
        if (!seq.atEnd())
        {
            comment = seq.readUTF8String("comment");
        }
        seq.requireEnd("trailing bytes in ObjectStoreData");

        return new ObjectStoreData(version, integrityAlgorithm, creationDate, lastModifiedDate,
                entries.toArray(new ObjectData[0]), comment);
    }

    private static ObjectData parseObjectDataInner(Der.Reader seq) throws IOException
    {
        int type = seq.readSmallInteger("ObjectData.type");
        String identifier = seq.readUTF8String("ObjectData.identifier");
        Date creationDate = seq.readGeneralizedTime("ObjectData.creationDate");
        Date lastModifiedDate = seq.readGeneralizedTime("ObjectData.lastModifiedDate");
        byte[] data = seq.readTLV(Der.OCTET_STRING, "ObjectData.data").remaining();
        String comment = null;
        if (!seq.atEnd())
        {
            comment = seq.readUTF8String("ObjectData.comment");
        }
        seq.requireEnd("trailing bytes in ObjectData");
        return new ObjectData(type, identifier, creationDate, lastModifiedDate, data, comment);
    }

    // ---- Entry payloads (ObjectData.data, once decrypted) ------------------

    /**
     * {@code EncryptedPrivateKeyObjectData ::= SEQUENCE { encryptedPrivateKeyInfo
     * EncryptedPrivateKeyInfo, certificates SEQUENCE OF Certificate }}
     * (org.bouncycastle.asn1.bc.EncryptedPrivateKeyData, r1rv86). The wire
     * shape of {@code EncryptedPrivateKeyInfo} is {@code SEQUENCE {
     * AlgorithmIdentifier, OCTET STRING }} -- identical to {@link
     * Der.EncryptedPrivateKeyInfo}, so this codec reuses
     * {@link Der.Reader#readEncryptedPrivateKeyInfo} rather than a second
     * definition of the same two fields.
     */
    static final class EncryptedPrivateKeyData
    {
        final Der.EncryptedPrivateKeyInfo encryptedPrivateKeyInfo;
        /** Each element is one complete Certificate TLV, raw (unparsed). */
        final byte[][] certificateChain;

        EncryptedPrivateKeyData(Der.EncryptedPrivateKeyInfo encryptedPrivateKeyInfo, byte[][] certificateChain)
        {
            this.encryptedPrivateKeyInfo = encryptedPrivateKeyInfo;
            this.certificateChain = certificateChain;
        }
    }

    static EncryptedPrivateKeyData parseEncryptedPrivateKeyData(byte[] der) throws IOException
    {
        Der.Reader seq = new Der.Reader(der).readTLV(Der.SEQUENCE, "EncryptedPrivateKeyData");
        Der.EncryptedPrivateKeyInfo epki = seq.readEncryptedPrivateKeyInfo("encryptedPrivateKeyInfo");
        Der.Reader certSeq = seq.readTLV(Der.SEQUENCE, "certificates");
        List<byte[]> certs = new ArrayList<byte[]>();
        while (!certSeq.atEnd())
        {
            certs.add(certSeq.readEncodedTLV(certSeq.peekTag(), "certificate"));
        }
        seq.requireEnd("trailing bytes in EncryptedPrivateKeyData");
        return new EncryptedPrivateKeyData(epki, certs.toArray(new byte[0][]));
    }

    /**
     * {@code EncryptedSecretKeyData ::= SEQUENCE { keyEncryptionAlgorithm
     * AlgorithmIdentifier, encryptedKeyData OCTET STRING }}
     * (org.bouncycastle.asn1.bc.EncryptedSecretKeyData, r1rv86) -- the same
     * two-field shape as {@code EncryptedPrivateKeyInfo}; reuses the same
     * reader.
     */
    static Der.EncryptedPrivateKeyInfo parseEncryptedSecretKeyData(byte[] der) throws IOException
    {
        return new Der.Reader(der).readEncryptedPrivateKeyInfo("EncryptedSecretKeyData");
    }

    /**
     * {@code SecretKeyData ::= SEQUENCE { keyAlgorithm OBJECT IDENTIFIER,
     * keyBytes OCTET STRING }} (org.bouncycastle.asn1.bc.SecretKeyData, r1rv86).
     * The DECRYPTED payload inside an {@code EncryptedSecretKeyData}.
     */
    static final class SecretKeyData
    {
        final String keyAlgorithmOid;
        final byte[] keyBytes;

        SecretKeyData(String keyAlgorithmOid, byte[] keyBytes)
        {
            this.keyAlgorithmOid = keyAlgorithmOid;
            this.keyBytes = keyBytes;
        }
    }

    static SecretKeyData parseSecretKeyData(byte[] der) throws IOException
    {
        Der.Reader seq = new Der.Reader(der).readTLV(Der.SEQUENCE, "SecretKeyData");
        String oid = seq.readObjectIdentifier("keyAlgorithm");
        byte[] keyBytes = seq.readTLV(Der.OCTET_STRING, "keyBytes").remaining();
        seq.requireEnd("trailing bytes in SecretKeyData");
        return new SecretKeyData(oid, keyBytes);
    }
}
