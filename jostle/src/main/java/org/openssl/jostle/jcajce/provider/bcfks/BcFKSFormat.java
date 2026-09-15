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
     * [0] EXPLICIT SignatureCheck }}. Exactly one field is non-{@code null}.
     */
    static final class IntegrityCheck
    {
        /** {@code null} when the store uses a signature check instead. */
        final PbkdMac pbkdMac;
        /** {@code null} when the store uses a PBKD-MAC check instead. */
        final SignatureCheck signatureCheck;

        IntegrityCheck(PbkdMac pbkdMac, SignatureCheck signatureCheck)
        {
            this.pbkdMac = pbkdMac;
            this.signatureCheck = signatureCheck;
        }
    }

    /**
     * {@code SignatureCheck ::= SEQUENCE { signatureAlgorithm
     * AlgorithmIdentifier, certificates [0] EXPLICIT SEQUENCE OF Certificate
     * OPTIONAL, signatureValue BIT STRING }}
     * (org.bouncycastle.asn1.bc.SignatureCheck, r1rv86, whole file --
     * 97 lines, one CHOICE arm).
     */
    static final class SignatureCheck
    {
        final Der.AlgorithmIdentifier signatureAlgorithm;
        /** Each element is one complete Certificate TLV, raw (unparsed); {@code null} when absent. */
        final byte[][] certificates;
        final byte[] signatureValue;

        SignatureCheck(Der.AlgorithmIdentifier signatureAlgorithm, byte[][] certificates, byte[] signatureValue)
        {
            this.signatureAlgorithm = signatureAlgorithm;
            this.certificates = certificates;
            this.signatureValue = signatureValue;
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
            return new IntegrityCheck(new PbkdMac(macAlgorithm, pbkdAlgorithm, macValue), null);
        }
        if (tag == EXPLICIT_0_TAG)
        {
            Der.Reader scWrapper = outer.readExplicit(0, "SignatureCheck");
            Der.Reader sc = scWrapper.readTLV(Der.SEQUENCE, "SignatureCheck");
            scWrapper.requireEnd("trailing bytes in SignatureCheck wrapper");
            Der.AlgorithmIdentifier signatureAlgorithm = sc.readAlgorithmIdentifier("signatureAlgorithm");
            byte[][] certificates = null;
            if (!sc.atEnd() && sc.peekTag() == EXPLICIT_0_TAG)
            {
                Der.Reader certsWrapper = sc.readExplicit(0, "certificates");
                Der.Reader certSeq = certsWrapper.readTLV(Der.SEQUENCE, "certificates");
                certsWrapper.requireEnd("trailing bytes in certificates wrapper");
                List<byte[]> list = new ArrayList<byte[]>();
                while (!certSeq.atEnd())
                {
                    list.add(certSeq.readEncodedTLV(certSeq.peekTag(), "certificate"));
                }
                certificates = list.toArray(new byte[0][]);
            }
            byte[] signatureValue = sc.readBitString("signatureValue");
            sc.requireEnd("trailing bytes in SignatureCheck");
            return new IntegrityCheck(null, new SignatureCheck(signatureAlgorithm, certificates, signatureValue));
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

    /**
     * {@code PbkdKeyData ::= SEQUENCE { keyAlgorithm UTF8String, password
     * OCTET STRING, salt [0] IMPLICIT OCTET STRING OPTIONAL, iterationCount
     * [1] IMPLICIT INTEGER OPTIONAL, encoded [2] IMPLICIT OCTET STRING
     * OPTIONAL }} (org.bouncycastle.asn1.bc.PbkdKeyData, r1rv86, whole file
     * -- carries a {@code javax.crypto.interfaces.PBEKey}'s full identity,
     * not just its derived bytes: algorithm, the PBE key's OWN password
     * (distinct from the entry's protection password), salt, iteration
     * count and the derived key). The DECRYPTED payload inside an {@code
     * EncryptedSecretKeyData} for a type-5 (PBKDF_KEY) entry.
     */
    static final class PbkdKeyData
    {
        final String keyAlgorithm;
        final byte[] password;
        /** {@code null} when the OPTIONAL field was absent. */
        final byte[] salt;
        /** {@code 0} when the OPTIONAL field was absent, matching BC's own {@code getIterationCount()}. */
        final int iterationCount;
        /** {@code null} when the OPTIONAL field was absent. */
        final byte[] encoded;

        PbkdKeyData(String keyAlgorithm, byte[] password, byte[] salt, int iterationCount, byte[] encoded)
        {
            this.keyAlgorithm = keyAlgorithm;
            this.password = password;
            this.salt = salt;
            this.iterationCount = iterationCount;
            this.encoded = encoded;
        }
    }

    /** [0]/[1]/[2] IMPLICIT's first octets: primitive context-specific tags 0/1/2. */
    private static final int IMPLICIT_0_TAG = 0x80;
    private static final int IMPLICIT_1_TAG = 0x81;
    private static final int IMPLICIT_2_TAG = 0x82;

    static PbkdKeyData parsePbkdKeyData(byte[] der) throws IOException
    {
        Der.Reader seq = new Der.Reader(der).readTLV(Der.SEQUENCE, "PbkdKeyData");
        String keyAlgorithm = seq.readUTF8String("keyAlgorithm");
        byte[] password = seq.readTLV(Der.OCTET_STRING, "password").remaining();

        byte[] salt = null;
        int iterationCount = 0;
        byte[] encoded = null;
        while (!seq.atEnd())
        {
            int tag = seq.peekTag();
            if (tag == IMPLICIT_0_TAG)
            {
                salt = seq.readImplicitOctetString(0, "salt");
            }
            else if (tag == IMPLICIT_1_TAG)
            {
                iterationCount = seq.readImplicitSmallInteger(1, "iterationCount");
            }
            else if (tag == IMPLICIT_2_TAG)
            {
                encoded = seq.readImplicitOctetString(2, "encoded");
            }
            else
            {
                throw new IOException("PbkdKeyData: unrecognised field tag 0x" + Integer.toHexString(tag));
            }
        }
        seq.requireEnd("trailing bytes in PbkdKeyData");
        return new PbkdKeyData(keyAlgorithm, password, salt, iterationCount, encoded);
    }

    // ---- Writing ---------------------------------------------------------
    // Mirrors the parse methods above field for field; every structure here
    // has its reader immediately above it.

    /** {@code ObjectStore}: the CHOICE element's raw TLV, followed by the integrity check TLV. */
    static byte[] writeObjectStore(byte[] storeDataTlv, byte[] integrityCheckTlv)
    {
        return Der.sequence(storeDataTlv, integrityCheckTlv);
    }

    /** {@code PbkdMacIntegrityCheck}. */
    static byte[] writePbkdMacIntegrityCheck(byte[] macAlgorithmTlv, byte[] pbkdAlgorithmTlv, byte[] mac)
    {
        return Der.sequence(macAlgorithmTlv, pbkdAlgorithmTlv, Der.octetString(mac));
    }

    // EncryptedObjectStoreData has no writer of its own: its wire shape is
    // SEQUENCE { AlgorithmIdentifier, OCTET STRING }, identical to {@link
    // Der#encryptedPrivateKeyInfo} -- BcFKSKeyStoreSpi.encryptEntry builds it
    // directly, the same way parseEncryptedSecretKeyData reuses the reader.

    /**
     * {@code ObjectStoreData}. {@code entryTlvs} are complete {@link #writeObjectData}
     * encodings; {@code comment} may be {@code null} to omit the OPTIONAL field.
     */
    static byte[] writeObjectStoreData(byte[] integrityAlgorithmTlv, Date creationDate, Date lastModifiedDate,
                                        byte[][] entryTlvs, String comment)
    {
        byte[] version = Der.integer(1);
        byte[] entriesSeq = Der.sequence(entryTlvs);
        return comment == null
                ? Der.sequence(version, integrityAlgorithmTlv, Der.generalizedTime(creationDate),
                        Der.generalizedTime(lastModifiedDate), entriesSeq)
                : Der.sequence(version, integrityAlgorithmTlv, Der.generalizedTime(creationDate),
                        Der.generalizedTime(lastModifiedDate), entriesSeq, Der.utf8String(comment));
    }

    /** {@code ObjectData}. {@code comment} may be {@code null} to omit the OPTIONAL field. */
    static byte[] writeObjectData(int type, String identifier, Date creationDate, Date lastModifiedDate,
                                   byte[] data, String comment)
    {
        byte[] typeTlv = Der.integer(type);
        byte[] idTlv = Der.utf8String(identifier);
        byte[] dataTlv = Der.octetString(data);
        return comment == null
                ? Der.sequence(typeTlv, idTlv, Der.generalizedTime(creationDate),
                        Der.generalizedTime(lastModifiedDate), dataTlv)
                : Der.sequence(typeTlv, idTlv, Der.generalizedTime(creationDate),
                        Der.generalizedTime(lastModifiedDate), dataTlv, Der.utf8String(comment));
    }

    /**
     * {@code EncryptedPrivateKeyData}. {@code encryptedPrivateKeyInfoTlv} is a
     * complete {@link Der#encryptedPrivateKeyInfo} encoding;
     * {@code certificateChainTlvs} are raw, already-encoded X.509 TLVs.
     */
    static byte[] writeEncryptedPrivateKeyData(byte[] encryptedPrivateKeyInfoTlv, byte[][] certificateChainTlvs)
    {
        return Der.sequence(encryptedPrivateKeyInfoTlv, Der.sequence(certificateChainTlvs));
    }

    /** {@code SecretKeyData}. */
    static byte[] writeSecretKeyData(String keyAlgorithmOid, byte[] keyBytes)
    {
        return Der.sequence(Der.objectIdentifier(keyAlgorithmOid), Der.octetString(keyBytes));
    }

    /**
     * {@code SignatureCheck}. {@code certificateTlvs} may be {@code null} to
     * omit the OPTIONAL field.
     */
    static byte[] writeSignatureCheck(byte[] signatureAlgorithmTlv, byte[][] certificateTlvs, byte[] signatureValue)
    {
        byte[] sigBits = Der.bitString(signatureValue);
        return certificateTlvs == null
                ? Der.sequence(signatureAlgorithmTlv, sigBits)
                : Der.sequence(signatureAlgorithmTlv, Der.explicit(0, Der.sequence(certificateTlvs)), sigBits);
    }

    /**
     * {@code PbkdKeyData}. Any of {@code salt}, {@code iterationCount <= 0}
     * or {@code encoded} may be absent, matching {@link Der.Reader
     * #readImplicitSmallInteger}'s "0 means absent" reading of BC's own
     * {@code getIterationCount()} contract.
     */
    static byte[] writePbkdKeyData(String keyAlgorithm, byte[] password, byte[] salt, int iterationCount,
                                    byte[] encoded)
    {
        List<byte[]> parts = new ArrayList<byte[]>();
        parts.add(Der.utf8String(keyAlgorithm));
        parts.add(Der.octetString(password));
        if (salt != null)
        {
            parts.add(Der.implicitOctetString(0, salt));
        }
        if (iterationCount > 0)
        {
            parts.add(Der.implicitInteger(1, iterationCount));
        }
        if (encoded != null)
        {
            parts.add(Der.implicitOctetString(2, encoded));
        }
        return Der.sequence(parts.toArray(new byte[0][]));
    }
}
