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
import org.openssl.jostle.jcajce.provider.kdf.KdfNI;
import org.openssl.jostle.jcajce.provider.kdf.MemoryHardKdfNI;
import org.openssl.jostle.util.asn1.Der;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ByteArrayOutputStream;
import java.security.KeyStore;
import java.security.Provider;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Shared instrument for the BCFKS limit classes: it builds the hostile inputs
 * and reports what the store did with them, so the base and FIPS classes
 * differ only in which provider they drive.
 *
 * <p>Lives in the implementation package because the questions are about the
 * package-private surface: {@link BcFKSFormat}'s parsers, the
 * {@link BcFKSKeyStoreSpi} constructor that takes the NIs (so a derivation can
 * be counted), and {@code deriveKey} / {@code encryptEntry}.
 *
 * <p><b>Offsets are never written down.</b> Every mutation names its target by
 * STRUCTURAL PATH through the walk and fails loudly when the path does not
 * resolve to the expected tag, so a format change breaks the instrument rather
 * than silently mutating a different field.
 */
final class BcFKSLimitDriver
{
    private BcFKSLimitDriver()
    {
    }

    static final String HMAC_SHA512_OID = "1.2.840.113549.2.11";
    static final String PBKDF2_OID = "1.2.840.113549.1.5.12";
    static final String SCRYPT_OID = "1.3.6.1.4.1.11591.4.11";

    /** Fixed instant: the store's dates are not what any of these cells measure. */
    static final Date FIXED_DATE = new Date(1_600_000_000_000L);

    // ---- The walk ----------------------------------------------------------

    /** One definite-length TLV, located rather than tabulated. */
    static final class Tlv
    {
        final int depth;
        final int tag;
        final int start;
        final int contentOff;
        final int contentLen;
        final int end;
        final String path;

        private Tlv(int depth, int tag, int start, int contentOff, int contentLen, String path)
        {
            this.depth = depth;
            this.tag = tag;
            this.start = start;
            this.contentOff = contentOff;
            this.contentLen = contentLen;
            this.end = contentOff + contentLen;
            this.path = path;
        }
    }

    /**
     * Every TLV in {@code der}, outermost first, descending into constructed
     * tags. Definite lengths only, which is all a conformant store contains.
     */
    static List<Tlv> walk(byte[] der)
    {
        List<Tlv> out = new ArrayList<Tlv>();
        walkInto(der, 0, der.length, 0, "", out);
        return out;
    }

    private static void walkInto(byte[] b, int off, int end, int depth, String path, List<Tlv> out)
    {
        int i = off;
        int index = 0;
        while (i < end)
        {
            int start = i;
            int tag = b[i++] & 0xFF;
            Assertions.assertNotEquals(0x1F, tag & 0x1F,
                    "multi-byte tag at " + start + ": this walk handles the store's own shapes only");
            int len = b[i++] & 0xFF;
            if ((len & 0x80) != 0)
            {
                int count = len & 0x7F;
                Assertions.assertTrue(count > 0 && count <= 4,
                        "unsupported length form at " + start);
                len = 0;
                for (int k = 0; k < count; k++)
                {
                    len = (len << 8) | (b[i++] & 0xFF);
                }
            }
            String childPath = path + "/" + index;
            out.add(new Tlv(depth, tag, start, i, len, childPath));
            if ((tag & 0x20) != 0)
            {
                walkInto(b, i, i + len, depth + 1, childPath, out);
            }
            i += len;
            index++;
        }
    }

    /**
     * The TLV at a structural index path, required to carry {@code expectedTag}.
     * {@code locate(store, Der.SEQUENCE, 0, 1, 1)} is "the integrity check's
     * pbkdAlgorithm".
     */
    static Tlv locate(byte[] der, int expectedTag, int... indexPath)
    {
        StringBuilder wanted = new StringBuilder();
        for (int i : indexPath)
        {
            wanted.append('/').append(i);
        }
        String key = wanted.toString();
        for (Tlv t : walk(der))
        {
            if (t.path.equals(key))
            {
                Assertions.assertEquals(expectedTag, t.tag,
                        "the store's shape has changed: " + key + " is tag 0x"
                                + Integer.toHexString(t.tag) + ", not 0x"
                                + Integer.toHexString(expectedTag));
                return t;
            }
        }
        return Assertions.fail("the store's shape has changed: no TLV at " + key);
    }

    // ---- Structural paths, named once --------------------------------------

    /** {@code EncryptedObjectStoreData.encryptionAlgorithm}. */
    static Tlv encryptionAlgorithm(byte[] store)
    {
        return locate(store, Der.SEQUENCE, 0, 0, 0);
    }

    /** {@code EncryptedObjectStoreData.encryptedContent}. */
    static Tlv encryptedContent(byte[] store)
    {
        return locate(store, Der.OCTET_STRING, 0, 0, 1);
    }

    /** {@code PbkdMacIntegrityCheck.macAlgorithm}. */
    static Tlv macAlgorithm(byte[] store)
    {
        return locate(store, Der.SEQUENCE, 0, 1, 0);
    }

    /** {@code PbkdMacIntegrityCheck.pbkdAlgorithm}. */
    static Tlv pbkdAlgorithm(byte[] store)
    {
        return locate(store, Der.SEQUENCE, 0, 1, 1);
    }

    /** The integrity check's PBKDF2 salt. */
    static Tlv macSalt(byte[] store)
    {
        return locate(store, Der.OCTET_STRING, 0, 1, 1, 1, 0);
    }

    /** The integrity check's PBKDF2 iteration count. */
    static Tlv macIterationCount(byte[] store)
    {
        return locate(store, Der.INTEGER, 0, 1, 1, 1, 1);
    }

    /** The integrity check's PBKDF2 PRF AlgorithmIdentifier. */
    static Tlv macPrf(byte[] store)
    {
        return locate(store, Der.SEQUENCE, 0, 1, 1, 1, 3);
    }

    /** {@code PbkdMacIntegrityCheck.mac}. */
    static Tlv macValue(byte[] store)
    {
        return locate(store, Der.OCTET_STRING, 0, 1, 2);
    }

    // ---- Re-encoding: cuts and splices -------------------------------------

    /**
     * A DER length header. Long form up to four octets, because a splice can
     * grow an element past 64 KiB and a header that silently truncated the
     * length would make the cell measure a malformed outer length instead of
     * the field under test.
     */
    static byte[] header(int tag, int len)
    {
        if (len < 0x80)
        {
            return new byte[]{(byte) tag, (byte) len};
        }
        if (len < 0x100)
        {
            return new byte[]{(byte) tag, (byte) 0x81, (byte) len};
        }
        if (len < 0x10000)
        {
            return new byte[]{(byte) tag, (byte) 0x82, (byte) (len >> 8), (byte) len};
        }
        if (len < 0x1000000)
        {
            return new byte[]{(byte) tag, (byte) 0x83, (byte) (len >> 16), (byte) (len >> 8), (byte) len};
        }
        return new byte[]{(byte) tag, (byte) 0x84, (byte) (len >> 24), (byte) (len >> 16),
                (byte) (len >> 8), (byte) len};
    }

    /**
     * Every offset a cut can land on: each TLV's start, its content start and
     * its end, generated from the walk. The three overlap heavily, so anything
     * falsifying this set must drop content starts to change it.
     */
    static SortedSet<Integer> cutOffsets(byte[] store)
    {
        SortedSet<Integer> out = new TreeSet<Integer>();
        for (Tlv t : walk(store))
        {
            out.add(Integer.valueOf(t.start));
            out.add(Integer.valueOf(t.contentOff));
            out.add(Integer.valueOf(t.end));
        }
        return out;
    }

    /**
     * {@code store} with everything at or after {@code cut} removed AND every
     * enclosing length re-encoded, so the input stays length-consistent.
     *
     * <p>This is the family that reaches the inner decoders. A plain
     * {@code copyOf} truncation does not: it leaves the outer TLV claiming more
     * than remains, so the outer length check fires first at almost every
     * offset and nothing further is exercised.
     */
    static byte[] cutAt(byte[] store, int cut)
    {
        return rebuild(store, 0, store.length, cut);
    }

    private static byte[] rebuild(byte[] b, int off, int end, int cut)
    {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int i = off;
        while (i < end)
        {
            int start = i;
            int tag = b[i++] & 0xFF;
            int len = readLength(b, i);
            i = afterLength(b, i);
            int contentOff = i;
            int contentEnd = i + len;
            if (start >= cut)
            {
                return out.toByteArray();
            }
            if (contentEnd <= cut)
            {
                out.write(b, start, contentEnd - start);
            }
            else if ((tag & 0x20) != 0)
            {
                byte[] inner = rebuild(b, contentOff, contentEnd, cut);
                write(out, header(tag, inner.length));
                write(out, inner);
            }
            else
            {
                int keep = Math.max(0, cut - contentOff);
                write(out, header(tag, keep));
                out.write(b, contentOff, keep);
            }
            i = contentEnd;
        }
        return out.toByteArray();
    }

    /**
     * {@code store} with the TLV beginning at {@code targetStart} replaced by
     * {@code replacement}, every enclosing length re-encoded.
     */
    static byte[] spliceAt(byte[] store, int targetStart, byte[] replacement)
    {
        return spliceInto(store, 0, store.length, targetStart, replacement);
    }

    private static byte[] spliceInto(byte[] b, int off, int end, int targetStart, byte[] replacement)
    {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int i = off;
        while (i < end)
        {
            int start = i;
            int tag = b[i++] & 0xFF;
            int len = readLength(b, i);
            i = afterLength(b, i);
            int contentOff = i;
            int contentEnd = i + len;
            if (start == targetStart)
            {
                write(out, replacement);
            }
            else if ((tag & 0x20) != 0 && targetStart > start && targetStart < contentEnd)
            {
                byte[] inner = spliceInto(b, contentOff, contentEnd, targetStart, replacement);
                write(out, header(tag, inner.length));
                write(out, inner);
            }
            else
            {
                out.write(b, start, contentEnd - start);
            }
            i = contentEnd;
        }
        return out.toByteArray();
    }

    private static int readLength(byte[] b, int lenPos)
    {
        int len = b[lenPos] & 0xFF;
        if ((len & 0x80) == 0)
        {
            return len;
        }
        int count = len & 0x7F;
        int v = 0;
        for (int k = 1; k <= count; k++)
        {
            v = (v << 8) | (b[lenPos + k] & 0xFF);
        }
        return v;
    }

    private static int afterLength(byte[] b, int lenPos)
    {
        int len = b[lenPos] & 0xFF;
        return (len & 0x80) == 0 ? lenPos + 1 : lenPos + 1 + (len & 0x7F);
    }

    private static void write(ByteArrayOutputStream out, byte[] bytes)
    {
        out.write(bytes, 0, bytes.length);
    }

    // ---- Generated stores --------------------------------------------------

    /** An empty store written by {@code provider}, generated at test time. */
    static byte[] minimalStore(String provider, char[] password) throws Exception
    {
        KeyStore store = KeyStore.getInstance("BCFKS", provider);
        store.load(null, null);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        store.store(out, password);
        return out.toByteArray();
    }

    // ---- Outcome capture ---------------------------------------------------

    /** What a load did: the exception class and message, or the alias count. */
    static final class Outcome
    {
        final Class<?> type;
        final String message;
        final int aliases;

        private Outcome(Class<?> type, String message, int aliases)
        {
            this.type = type;
            this.message = message;
            this.aliases = aliases;
        }

        boolean accepted()
        {
            return type == null;
        }

        public String toString()
        {
            return type == null ? "accepted(" + aliases + ")" : type.getName() + ": " + message;
        }
    }

    static Outcome load(String provider, byte[] bytes, char[] password)
    {
        try
        {
            KeyStore store = KeyStore.getInstance("BCFKS", provider);
            store.load(new ByteArrayInputStream(bytes), password);
            return new Outcome(null, null, java.util.Collections.list(store.aliases()).size());
        }
        catch (Throwable t)
        {
            return new Outcome(t.getClass(), t.getMessage(), -1);
        }
    }

    // ---- The named-malformation table --------------------------------------

    /** One hostile input, built from a generated store. */
    static final class Malformation
    {
        final String name;
        final byte[] bytes;
        final char[] password;
        /** The message fragment the refusal must carry on the base provider. */
        final String expectedMessage;
        /**
         * The fragment expected on a provider without scrypt, where the
         * not-served check answers first. Null when the two agree.
         */
        final String fipsExpectedMessage;

        Malformation(String name, byte[] bytes, char[] password, String expectedMessage)
        {
            this(name, bytes, password, expectedMessage, null);
        }

        Malformation(String name, byte[] bytes, char[] password, String expectedMessage,
                     String fipsExpectedMessage)
        {
            this.name = name;
            this.bytes = bytes;
            this.password = password;
            this.expectedMessage = expectedMessage;
            this.fipsExpectedMessage = fipsExpectedMessage;
        }

        /** The fragment to require of {@code provider}. */
        String expectedFor(boolean scryptServed)
        {
            return scryptServed || fipsExpectedMessage == null
                    ? expectedMessage : fipsExpectedMessage;
        }
    }

    /**
     * Every named malformation, keyed by name so a row cannot be added twice
     * and the every-row-reached guard has something to compare against.
     */
    static Map<String, Malformation> namedMalformations(byte[] store, char[] password)
    {
        // Several builders below rewrite the outer length in place, so the
        // form they assume is asserted once here rather than per builder.
        Assertions.assertEquals((byte) 0x82, store[1],
                "the store's outer length is no longer a two-octet long form, so the builders in"
                        + " this table would edit the wrong bytes");

        Map<String, Malformation> t = new LinkedHashMap<String, Malformation>();

        byte[] trailingByte = java.util.Arrays.copyOf(store, store.length + 1);
        put(t, new Malformation("trailing zero byte after the outer SEQUENCE",
                trailingByte, password, "trailing bytes after ObjectStore"));

        byte[] trailingTlv = java.util.Arrays.copyOf(store, store.length + 2);
        trailingTlv[store.length] = (byte) Der.NULL;
        put(t, new Malformation("trailing NULL TLV after the outer SEQUENCE",
                trailingTlv, password, "trailing bytes after ObjectStore"));

        byte[] overLength = store.clone();
        bumpOuterLength(overLength, 1);
        put(t, new Malformation("outer length claims one byte more than remains",
                overLength, password, "truncated content in ObjectStore"));

        byte[] farOverLength = store.clone();
        farOverLength[2] = (byte) 0x7F;
        farOverLength[3] = (byte) 0xFF;
        put(t, new Malformation("outer length claims 32767",
                farOverLength, password, "truncated content in ObjectStore"));

        byte[] indefinite = new byte[store.length];
        indefinite[0] = (byte) Der.SEQUENCE;
        indefinite[1] = (byte) 0x80;
        System.arraycopy(store, 4, indefinite, 2, store.length - 4);
        put(t, new Malformation("indefinite length on the outer SEQUENCE",
                indefinite, password, "indefinite length not permitted in ObjectStore"));

        byte[] nonMinimal = new byte[store.length + 1];
        nonMinimal[0] = (byte) Der.SEQUENCE;
        nonMinimal[1] = (byte) 0x83;
        nonMinimal[2] = 0x00;
        nonMinimal[3] = store[2];
        nonMinimal[4] = store[3];
        System.arraycopy(store, 4, nonMinimal, 5, store.length - 4);
        put(t, new Malformation("non-minimal long-form outer length",
                nonMinimal, password, "non-minimal length encoding"));

        byte[] wrongOuterTag = store.clone();
        wrongOuterTag[0] = 0x31;
        put(t, new Malformation("outer tag is a SET, not a SEQUENCE",
                wrongOuterTag, password, "expected ObjectStore (tag 0x30), got tag 0x31"));

        put(t, new Malformation("zero-length input", new byte[0], password, "truncated ObjectStore"));
        put(t, new Malformation("a single SEQUENCE tag byte",
                new byte[]{(byte) Der.SEQUENCE}, password, "truncated ObjectStore"));
        put(t, new Malformation("an empty outer SEQUENCE",
                new byte[]{(byte) Der.SEQUENCE, 0x00}, password, "truncated ObjectStore storeData"));

        put(t, new Malformation("wrong password", store, "not the password".toCharArray(),
                "BCFKS KeyStore corrupted: MAC calculation failed"));
        put(t, new Malformation("null password on an encrypted store", store, null,
                "BCFKS KeyStore corrupted: MAC calculation failed"));
        put(t, new Malformation("empty password on an encrypted store", store, new char[0],
                "BCFKS KeyStore corrupted: MAC calculation failed"));

        byte[] macFirstFlipped = store.clone();
        Tlv mac = macValue(store);
        macFirstFlipped[mac.contentOff] ^= 0x01;
        put(t, new Malformation("first MAC byte flipped", macFirstFlipped, password,
                "BCFKS KeyStore corrupted: MAC calculation failed"));

        byte[] macLastFlipped = store.clone();
        macLastFlipped[mac.end - 1] ^= 0x01;
        put(t, new Malformation("last MAC byte flipped", macLastFlipped, password,
                "BCFKS KeyStore corrupted: MAC calculation failed"));

        byte[] ciphertextFlipped = store.clone();
        ciphertextFlipped[encryptedContent(store).contentOff] ^= 0x01;
        put(t, new Malformation("first ciphertext byte flipped", ciphertextFlipped, password,
                "BCFKS KeyStore corrupted: MAC calculation failed"));

        put(t, new Malformation("the encrypted content emptied",
                spliceAt(store, encryptedContent(store).start, Der.octetString(new byte[0])), password,
                "BCFKS KeyStore corrupted: MAC calculation failed"));

        put(t, new Malformation("the MAC emptied",
                spliceAt(store, mac.start, Der.octetString(new byte[0])), password,
                "BCFKS KeyStore corrupted: MAC calculation failed"));

        put(t, new Malformation("the MAC truncated to one byte",
                spliceAt(store, mac.start, Der.octetString(new byte[1])), password,
                "BCFKS KeyStore corrupted: MAC calculation failed"));

        put(t, new Malformation("the store encryption AlgorithmIdentifier replaced",
                spliceAt(store, encryptionAlgorithm(store).start,
                        Der.algorithmIdentifier("1.2.3.4", Der.nullValue())), password,
                "BCFKS KeyStore corrupted: MAC calculation failed"));

        put(t, new Malformation("an unrecognised MAC algorithm OID",
                spliceAt(store, macAlgorithm(store).start,
                        Der.algorithmIdentifier("1.2.3.4", Der.nullValue())), password,
                "BCFKS KeyStore: cannot set up MAC calculation"));

        put(t, new Malformation("an unrecognised integrity-check KDF OID",
                spliceAt(store, pbkdAlgorithm(store).start,
                        Der.algorithmIdentifier("1.2.3.4", Der.nullValue())), password,
                "BCFKS KeyStore: unrecognized MAC PBKD: 1.2.3.4"));

        put(t, new Malformation("an unrecognised integrity-check PRF OID",
                spliceAt(store, macPrf(store).start,
                        Der.algorithmIdentifier("1.2.3.4", Der.nullValue())), password,
                "BCFKS KeyStore: unrecognized MAC PBKD PRF: 1.2.3.4"));

        put(t, new Malformation("an integrity-check iteration count past the cap",
                spliceAt(store, macIterationCount(store).start,
                        Der.integer((int) (BcFKSKeyStoreSpi.DEFAULT_MAX_IT_COUNT + 1))), password,
                "greater than " + BcFKSKeyStoreSpi.DEFAULT_MAX_IT_COUNT));

        put(t, new Malformation("an integrity-check PBKDF2 salt past the octet-string ceiling",
                spliceAt(store, macSalt(store).start,
                        Der.octetString(new byte[Der.DEFAULT_MAX_OCTET_STRING_BYTES + 1])), password,
                "exceeds the " + Der.DEFAULT_MAX_OCTET_STRING_BYTES + "-byte ceiling"));

        put(t, new Malformation("an integrity-check iteration count of zero",
                spliceAt(store, macIterationCount(store).start, Der.integer(0)), password,
                "BCFKS KeyStore: invalid iteration count"));

        put(t, new Malformation("an empty integrity-check PBKDF2 salt",
                spliceAt(store, macSalt(store).start, Der.octetString(new byte[0])), password,
                "BCFKS KeyStore: empty salt"));

        put(t, new Malformation("an integrity-check scrypt cost past the memory cap",
                spliceAt(store, pbkdAlgorithm(store).start,
                        Der.algorithmIdentifier(SCRYPT_OID, Der.scryptParams(new byte[16],
                                BcFKSKeyStoreSpi.DEFAULT_MAX_SCRYPT_MEMORY / (128L * 8) + 1, 8, 1, null))),
                password, "scrypt cost parameters require more than",
                // Without scrypt the not-served check answers first, so the
                // cost bound is never reached. Both messages are correct; which
                // one is right depends on the provider.
                "BCFKS store uses scrypt, which this provider does not serve"));

        return t;
    }

    private static void put(Map<String, Malformation> t, Malformation m)
    {
        Assertions.assertNull(t.put(m.name, m), "duplicate malformation name: " + m.name);
    }

    /** Add {@code delta} to the outer SEQUENCE's two-octet long-form length. */
    private static void bumpOuterLength(byte[] store, int delta)
    {
        int claimed = ((store[2] & 0xFF) << 8) | (store[3] & 0xFF);
        int updated = claimed + delta;
        store[2] = (byte) (updated >> 8);
        store[3] = (byte) updated;
    }

    // ---- The trailing-bytes table ------------------------------------------

    /** One parse entry point, and a well-formed object for it. */
    static final class DecodeSite
    {
        final String name;
        final byte[] wellFormed;
        final Decoder decoder;
        /** The type name the refusal must carry. */
        final String objectName;

        DecodeSite(String name, byte[] wellFormed, String objectName, Decoder decoder)
        {
            this.name = name;
            this.wellFormed = wellFormed;
            this.objectName = objectName;
            this.decoder = decoder;
        }
    }

    interface Decoder
    {
        void decode(byte[] der) throws Exception;
    }

    /**
     * Every {@link BcFKSFormat} entry point that decodes a whole blob, each
     * with a fixture built here rather than recorded.
     *
     * <p>A blob decoder must consume its input exactly: an appended TLV is
     * trailing garbage, not a second object. The stream-reading contract is the
     * opposite one and does not apply to any of these.
     */
    static Map<String, DecodeSite> decodeSites(byte[] store)
    {
        byte[] algorithmIdentifier = Der.algorithmIdentifier(HMAC_SHA512_OID, Der.nullValue());
        byte[] encryptedPrivateKeyInfo = Der.encryptedPrivateKeyInfo(algorithmIdentifier, new byte[16]);

        Map<String, DecodeSite> t = new LinkedHashMap<String, DecodeSite>();
        t.put("ObjectStore", new DecodeSite("ObjectStore", store, "ObjectStore",
                new Decoder()
                {
                    public void decode(byte[] der) throws Exception
                    {
                        BcFKSFormat.parseObjectStore(der);
                    }
                }));
        t.put("EncryptedObjectStoreData", new DecodeSite("EncryptedObjectStoreData",
                Der.sequence(algorithmIdentifier, Der.octetString(new byte[8])),
                "EncryptedObjectStoreData", new Decoder()
                {
                    public void decode(byte[] der) throws Exception
                    {
                        BcFKSFormat.parseEncryptedObjectStoreData(der);
                    }
                }));
        t.put("ObjectStoreData", new DecodeSite("ObjectStoreData",
                BcFKSFormat.writeObjectStoreData(algorithmIdentifier, FIXED_DATE, FIXED_DATE,
                        new byte[][]{entry(BcFKSFormat.ObjectData.TYPE_CERTIFICATE, "a", new byte[]{1})},
                        null),
                "ObjectStoreData", new Decoder()
                {
                    public void decode(byte[] der) throws Exception
                    {
                        BcFKSFormat.parseObjectStoreData(der);
                    }
                }));
        t.put("EncryptedPrivateKeyData", new DecodeSite("EncryptedPrivateKeyData",
                BcFKSFormat.writeEncryptedPrivateKeyData(encryptedPrivateKeyInfo, new byte[0][]),
                "EncryptedPrivateKeyData", new Decoder()
                {
                    public void decode(byte[] der) throws Exception
                    {
                        BcFKSFormat.parseEncryptedPrivateKeyData(der);
                    }
                }));
        t.put("EncryptedSecretKeyData", new DecodeSite("EncryptedSecretKeyData",
                encryptedPrivateKeyInfo, "EncryptedSecretKeyData", new Decoder()
                {
                    public void decode(byte[] der) throws Exception
                    {
                        BcFKSFormat.parseEncryptedSecretKeyData(der);
                    }
                }));
        t.put("SecretKeyData", new DecodeSite("SecretKeyData",
                BcFKSFormat.writeSecretKeyData("2.16.840.1.101.3.4.1.42", new byte[32]),
                "SecretKeyData", new Decoder()
                {
                    public void decode(byte[] der) throws Exception
                    {
                        BcFKSFormat.parseSecretKeyData(der);
                    }
                }));
        t.put("PbkdKeyData", new DecodeSite("PbkdKeyData",
                BcFKSFormat.writePbkdKeyData("PBKDF2", "password".getBytes(java.nio.charset.StandardCharsets.UTF_8),
                        new byte[16], 2048, new byte[32]),
                "PbkdKeyData", new Decoder()
                {
                    public void decode(byte[] der) throws Exception
                    {
                        BcFKSFormat.parsePbkdKeyData(der);
                    }
                }));
        return t;
    }

    /** {@code der} with a NULL TLV appended: one object, then garbage. */
    static byte[] withTrailingTlv(byte[] der)
    {
        byte[] out = new byte[der.length + 2];
        System.arraycopy(der, 0, out, 0, der.length);
        out[der.length] = (byte) Der.NULL;
        return out;
    }

    // ---- Forging a MAC-valid store -----------------------------------------

    /**
     * A store whose MAC verifies, carrying entries this implementation would
     * never write, so the load-side dispatch is reached instead of the MAC
     * check turning every cell into the same refusal.
     */
    static byte[] forge(Provider provider, BcFKSKeyStoreSpi spi, char[] password, byte[]... entryTlvs)
        throws Exception
    {
        byte[] integrityAlgorithmTlv = Der.algorithmIdentifier(HMAC_SHA512_OID, Der.nullValue());
        byte[] storeData = BcFKSFormat.writeObjectStoreData(integrityAlgorithmTlv, FIXED_DATE,
                FIXED_DATE, entryTlvs, null);
        byte[] encrypted = spi.encryptEntry(storeData,
                org.openssl.jostle.jcajce.provider.kdf.BytePasswordKdf.PURPOSE_STORE_ENCRYPTION, password);

        byte[] kdfTlv = Der.algorithmIdentifier(PBKDF2_OID, Der.pbkdf2Params(new byte[64], 2048,
                Integer.valueOf(64), Der.algorithmIdentifier(HMAC_SHA512_OID, Der.nullValue())));
        Der.AlgorithmIdentifier kdfAlgorithm =
                new Der.Reader(kdfTlv).readAlgorithmIdentifier("forged integrity check");
        byte[] macKey = spi.deriveKey(kdfAlgorithm,
                org.openssl.jostle.jcajce.provider.kdf.BytePasswordKdf.PURPOSE_INTEGRITY_CHECK,
                password, Integer.valueOf(64), false);

        Mac mac = Mac.getInstance(HMAC_SHA512_OID, provider);
        mac.init(new SecretKeySpec(macKey, HMAC_SHA512_OID));
        byte[] macValue = mac.doFinal(encrypted);

        return BcFKSFormat.writeObjectStore(encrypted,
                BcFKSFormat.writePbkdMacIntegrityCheck(integrityAlgorithmTlv, kdfTlv, macValue));
    }

    /** One entry, as {@code forge} takes them. */
    static byte[] entry(int type, String alias, byte[] data)
    {
        return BcFKSFormat.writeObjectData(type, alias, FIXED_DATE, FIXED_DATE, data, null);
    }

    // ---- The shared assertions both limit classes drive ---------------------
    //
    // These live here rather than being written twice because the two classes
    // differ only in which provider they pass. The copy that existed before
    // had already lost one step of the trailing-bytes check.

    /** Every length-consistent cut is refused as a typed IOException. */
    static void assertEveryCutIsRefusedTyped(String provider, byte[] store, char[] password)
    {
        SortedSet<Integer> cuts = cutOffsets(store);
        Assertions.assertFalse(cuts.isEmpty(), "no cut offsets were generated");

        List<String> missing = new ArrayList<String>();
        for (Tlv tlv : walk(store))
        {
            if (!cuts.contains(Integer.valueOf(tlv.start))
                    || !cuts.contains(Integer.valueOf(tlv.contentOff))
                    || !cuts.contains(Integer.valueOf(tlv.end)))
            {
                missing.add(tlv.path);
            }
        }
        Assertions.assertTrue(missing.isEmpty(),
                "the cut set omits an offset for " + missing.size() + " TLVs, so those elements"
                        + " are never cut:\n  " + String.join("\n  ", missing));

        List<String> unexpected = new ArrayList<String>();
        for (int cut : cuts)
        {
            Outcome outcome = load(provider, cutAt(store, cut), password);
            if (cut == store.length)
            {
                if (!outcome.accepted())
                {
                    unexpected.add("cut " + cut + " removes nothing and must be accepted: " + outcome);
                }
            }
            else if (outcome.accepted() || outcome.type != IOException.class)
            {
                unexpected.add("cut " + cut + " -> " + outcome);
            }
        }
        Assertions.assertTrue(unexpected.isEmpty(),
                provider + ": cuts not refused as a typed IOException (" + unexpected.size()
                        + " of " + cuts.size() + "):\n  " + String.join("\n  ", unexpected));
    }

    /** Every named malformation is refused with the message its row declares. */
    static void assertEveryMalformationIsRefused(String provider, byte[] store, char[] password,
                                                 boolean scryptServed)
    {
        Map<String, Malformation> table = namedMalformations(store, password);
        Assertions.assertFalse(table.isEmpty(), "the malformation table is empty");

        List<String> failures = new ArrayList<String>();
        for (Malformation malformation : table.values())
        {
            Outcome outcome = load(provider, malformation.bytes, malformation.password);
            if (outcome.type != IOException.class)
            {
                failures.add(malformation.name + " -> " + outcome);
                continue;
            }
            String wanted = malformation.expectedFor(scryptServed);
            if (outcome.message == null || !outcome.message.contains(wanted))
            {
                failures.add(malformation.name + " -> message was \"" + outcome.message
                        + "\", expected it to contain \"" + wanted + "\"");
            }
        }
        Assertions.assertTrue(failures.isEmpty(),
                provider + ": malformations refused wrongly (" + failures.size() + " of "
                        + table.size() + "):\n  " + String.join("\n  ", failures));
    }

    /** No unchecked throwable escapes load over the whole hostile set. */
    static void assertNoUncheckedThrowableEscapesLoad(String provider, byte[] store, char[] password)
    {
        List<byte[]> inputs = new ArrayList<byte[]>();
        for (int cut : cutOffsets(store))
        {
            inputs.add(cutAt(store, cut));
        }
        for (Malformation malformation : namedMalformations(store, password).values())
        {
            inputs.add(malformation.bytes);
        }
        Assertions.assertFalse(inputs.isEmpty(), "no hostile inputs were generated");

        List<String> escaped = new ArrayList<String>();
        for (byte[] input : inputs)
        {
            Outcome outcome = load(provider, input, password);
            if (!outcome.accepted() && outcome.type != IOException.class)
            {
                escaped.add(outcome.toString());
            }
        }
        Assertions.assertTrue(escaped.isEmpty(),
                provider + ": unchecked throwables escaped load (" + escaped.size() + " of "
                        + inputs.size() + "):\n  " + String.join("\n  ", escaped));
    }

    /**
     * Every blob decoder refuses a TLV appended after its object. The fixture
     * is required to decode CLEAN first, or a broken fixture would satisfy the
     * refusal for the wrong reason.
     */
    static void assertEveryBlobDecoderRefusesTrailingBytes(byte[] store)
    {
        Map<String, DecodeSite> sites = decodeSites(store);
        Assertions.assertFalse(sites.isEmpty(), "no decode sites were declared");

        List<String> failures = new ArrayList<String>();
        for (DecodeSite site : sites.values())
        {
            try
            {
                site.decoder.decode(site.wellFormed);
            }
            catch (Throwable t)
            {
                failures.add(site.name + ": the fixture itself does not decode -- "
                        + t.getClass().getName() + ": " + t.getMessage());
                continue;
            }
            try
            {
                site.decoder.decode(withTrailingTlv(site.wellFormed));
                failures.add(site.name + ": accepted a TLV appended after the object");
            }
            catch (IOException e)
            {
                String wanted = "trailing bytes after " + site.objectName;
                if (e.getMessage() == null || !e.getMessage().contains(wanted))
                {
                    failures.add(site.name + ": refused with \"" + e.getMessage()
                            + "\", expected it to contain \"" + wanted + "\"");
                }
            }
            catch (Throwable t)
            {
                failures.add(site.name + ": refused with " + t.getClass().getName()
                        + " rather than a typed IOException");
            }
        }
        Assertions.assertTrue(failures.isEmpty(),
                "blob decoders mishandling trailing bytes (" + failures.size() + " of "
                        + sites.size() + "):\n  " + String.join("\n  ", failures));
    }

    // ---- Counting derivations ----------------------------------------------

    /**
     * Wraps the real KDF so a cell can assert a bound refused BEFORE any
     * derivation ran. A clock cannot answer that: a cheap derivation and no
     * derivation both take about no time.
     */
    static final class CountingKdfNI implements KdfNI
    {
        private final KdfNI delegate;
        final AtomicInteger pbkdf2Calls = new AtomicInteger();

        CountingKdfNI(KdfNI delegate)
        {
            this.delegate = delegate;
        }

        public int pbkdf2(byte[] password, byte[] salt, int iterations, String digest,
                          byte[] out, int outOffset, int outLen)
        {
            pbkdf2Calls.incrementAndGet();
            return delegate.pbkdf2(password, salt, iterations, digest, out, outOffset, outLen);
        }

        public int hkdf(byte[] ikm, byte[] salt, byte[] info, String digest,
                        byte[] out, int outOffset, int outLen)
        {
            return delegate.hkdf(ikm, salt, info, digest, out, outOffset, outLen);
        }

        public int kbkdf(String mode, String mac, String digest, String cipher, byte[] key,
                         byte[] label, byte[] context, byte[] seed, int r, int useL,
                         int useSeparator, byte[] out, int outOffset, int outLen)
        {
            return delegate.kbkdf(mode, mac, digest, cipher, key, label, context, seed, r, useL,
                    useSeparator, out, outOffset, outLen);
        }

        public int sskdf(String digest, byte[] secret, byte[] info, byte[] out, int outOffset, int outLen)
        {
            return delegate.sskdf(digest, secret, info, out, outOffset, outLen);
        }

        public int sshkdf(String digest, byte[] key, byte[] exchangeHash, byte[] sessionId, String type,
                          byte[] out, int outOffset, int outLen)
        {
            return delegate.sshkdf(digest, key, exchangeHash, sessionId, type, out, outOffset, outLen);
        }
    }

    /** The scrypt twin of {@link CountingKdfNI}; {@code null} under FIPS. */
    static final class CountingMemoryHardKdfNI implements MemoryHardKdfNI
    {
        private final MemoryHardKdfNI delegate;
        final AtomicInteger scryptCalls = new AtomicInteger();

        CountingMemoryHardKdfNI(MemoryHardKdfNI delegate)
        {
            this.delegate = delegate;
        }

        public int scrypt(byte[] password, byte[] salt, int n, int r, int p,
                          byte[] out, int outOffset, int outLen)
        {
            scryptCalls.incrementAndGet();
            return delegate.scrypt(password, salt, n, r, p, out, outOffset, outLen);
        }

        public int argon2(byte[] password, byte[] salt, int type, int version, int iterations,
                          int memoryKiB, int lanes, byte[] out, int outOffset, int outLen)
        {
            return delegate.argon2(password, salt, type, version, iterations, memoryKiB, lanes,
                    out, outOffset, outLen);
        }
    }

    // ---- Building KDF AlgorithmIdentifiers for the bound cells --------------

    static Der.AlgorithmIdentifier algorithmIdentifier(String oid, byte[] params) throws Exception
    {
        return new Der.Reader(Der.algorithmIdentifier(oid, params)).readAlgorithmIdentifier("bound probe");
    }

    static Der.AlgorithmIdentifier pbkdf2(int iterationCount, Integer keyLength) throws Exception
    {
        return algorithmIdentifier(PBKDF2_OID, Der.pbkdf2Params(new byte[16], iterationCount, keyLength,
                Der.algorithmIdentifier(HMAC_SHA512_OID, Der.nullValue())));
    }

    static Der.AlgorithmIdentifier scrypt(long cost, int blockSize, int parallelization,
                                            Integer keyLength) throws Exception
    {
        return algorithmIdentifier(SCRYPT_OID,
                Der.scryptParams(new byte[16], cost, blockSize, parallelization, keyLength));
    }
}
