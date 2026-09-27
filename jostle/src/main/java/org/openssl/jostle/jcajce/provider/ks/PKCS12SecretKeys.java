/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.ks;

import org.openssl.jostle.util.Strings;
import org.openssl.jostle.util.asn1.ASN1ObjectIdentifier;
import org.openssl.jostle.util.asn1.oids.NISTObjectIdentifiers;
import org.openssl.jostle.util.asn1.oids.NSRIObjectIdentifiers;
import org.openssl.jostle.util.asn1.oids.NTTObjectIdentifiers;
import org.openssl.jostle.util.asn1.oids.OIWObjectIdentifiers;
import org.openssl.jostle.util.asn1.oids.PKCSObjectIdentifiers;

import java.util.HashMap;
import java.util.Map;

/**
 * The algorithm OIDs a PKCS#12 secret-key entry carries. The RFC 7292 form names the key by the OID BouncyCastle
 * writes (a key-size-specific CBC OID for a block cipher); the SunJCE form by the one SunJCE writes (one OID per
 * algorithm). These are published identifiers, not facts OpenSSL reports. The set written is the algorithms both
 * forms can name; reading maps either form's OID back to its JCA name, and leaves an unknown OID as its dotted form.
 */
final class PKCS12SecretKeys
{
    /** The OID written under each form. */
    static final class Oids
    {
        final String rfc;
        final String sun;

        Oids(ASN1ObjectIdentifier rfc, ASN1ObjectIdentifier sun)
        {
            this.rfc = rfc.getId();
            this.sun = sun.getId();
        }
    }

    private static final Map<String, String> NAMES = new HashMap<String, String>();

    static
    {
        name("AES", NISTObjectIdentifiers.id_aes128_CBC, NISTObjectIdentifiers.id_aes192_CBC,
                NISTObjectIdentifiers.id_aes256_CBC, NISTObjectIdentifiers.aes);
        // JDK 8's SunJCE writes ARIA under id-aria256-ofb (measured); read it as ARIA too.
        name("ARIA", NSRIObjectIdentifiers.id_aria128_cbc, NSRIObjectIdentifiers.id_aria192_cbc,
                NSRIObjectIdentifiers.id_aria256_cbc, NSRIObjectIdentifiers.id_aria256_ofb);
        name("Camellia", NTTObjectIdentifiers.id_camellia128_cbc, NTTObjectIdentifiers.id_camellia192_cbc,
                NTTObjectIdentifiers.id_camellia256_cbc);
        name("DESede", PKCSObjectIdentifiers.des_EDE3_CBC, OIWObjectIdentifiers.desEDE);
        name("HmacSHA1", PKCSObjectIdentifiers.id_hmacWithSHA1);
        name("HmacSHA224", PKCSObjectIdentifiers.id_hmacWithSHA224);
        name("HmacSHA256", PKCSObjectIdentifiers.id_hmacWithSHA256);
        name("HmacSHA384", PKCSObjectIdentifiers.id_hmacWithSHA384);
        name("HmacSHA512", PKCSObjectIdentifiers.id_hmacWithSHA512);
        name("HmacSHA3-224", NISTObjectIdentifiers.id_hmacWithSHA3_224);
        name("HmacSHA3-256", NISTObjectIdentifiers.id_hmacWithSHA3_256);
        name("HmacSHA3-384", NISTObjectIdentifiers.id_hmacWithSHA3_384);
        name("HmacSHA3-512", NISTObjectIdentifiers.id_hmacWithSHA3_512);
    }

    private static void name(String jcaName, ASN1ObjectIdentifier... oids)
    {
        for (ASN1ObjectIdentifier oid : oids)
        {
            NAMES.put(oid.getId(), jcaName);
        }
    }

    private PKCS12SecretKeys()
    {
    }

    /**
     * The OIDs for a key of {@code algorithm} and {@code keyLen} bytes, or null when the two forms cannot both
     * name it. A block cipher needs a 16, 24 or 32 byte key, as its RFC 7292 OID is size-specific.
     */
    static Oids oidsFor(String algorithm, int keyLen)
    {
        if (algorithm == null)
        {
            return null;
        }
        String alg = Strings.toUpperCase(algorithm);
        if (alg.equals("AES"))
        {
            return blockCipher(keyLen, NISTObjectIdentifiers.id_aes128_CBC, NISTObjectIdentifiers.id_aes192_CBC,
                    NISTObjectIdentifiers.id_aes256_CBC, NISTObjectIdentifiers.aes);
        }
        if (alg.equals("ARIA"))
        {
            return blockCipher(keyLen, NSRIObjectIdentifiers.id_aria128_cbc, NSRIObjectIdentifiers.id_aria192_cbc,
                    NSRIObjectIdentifiers.id_aria256_cbc, NSRIObjectIdentifiers.id_aria256_cbc);
        }
        if (alg.equals("CAMELLIA"))
        {
            return blockCipher(keyLen, NTTObjectIdentifiers.id_camellia128_cbc,
                    NTTObjectIdentifiers.id_camellia192_cbc, NTTObjectIdentifiers.id_camellia256_cbc,
                    NTTObjectIdentifiers.id_camellia256_cbc);
        }
        if (alg.equals("DESEDE") || alg.equals("TRIPLEDES"))
        {
            return new Oids(PKCSObjectIdentifiers.des_EDE3_CBC, OIWObjectIdentifiers.desEDE);
        }
        ASN1ObjectIdentifier hmac = hmacOid(alg);
        return hmac == null ? null : new Oids(hmac, hmac);
    }

    private static Oids blockCipher(int keyLen, ASN1ObjectIdentifier k16, ASN1ObjectIdentifier k24,
                                    ASN1ObjectIdentifier k32, ASN1ObjectIdentifier sun)
    {
        switch (keyLen)
        {
        case 16:
            return new Oids(k16, sun);
        case 24:
            return new Oids(k24, sun);
        case 32:
            return new Oids(k32, sun);
        default:
            return null;
        }
    }

    private static ASN1ObjectIdentifier hmacOid(String alg)
    {
        switch (alg)
        {
        case "HMACSHA1":
            return PKCSObjectIdentifiers.id_hmacWithSHA1;
        case "HMACSHA224":
            return PKCSObjectIdentifiers.id_hmacWithSHA224;
        case "HMACSHA256":
            return PKCSObjectIdentifiers.id_hmacWithSHA256;
        case "HMACSHA384":
            return PKCSObjectIdentifiers.id_hmacWithSHA384;
        case "HMACSHA512":
            return PKCSObjectIdentifiers.id_hmacWithSHA512;
        case "HMACSHA3-224":
            return NISTObjectIdentifiers.id_hmacWithSHA3_224;
        case "HMACSHA3-256":
            return NISTObjectIdentifiers.id_hmacWithSHA3_256;
        case "HMACSHA3-384":
            return NISTObjectIdentifiers.id_hmacWithSHA3_384;
        case "HMACSHA3-512":
            return NISTObjectIdentifiers.id_hmacWithSHA3_512;
        default:
            return null;
        }
    }

    /** The JCA name for an OID read from either form, or the dotted OID itself when neither table names it. */
    static String nameFor(String oid)
    {
        String name = NAMES.get(oid);
        return name != null ? name : oid;
    }

    /**
     * Decode the native SEQUENCE { OBJECT IDENTIFIER, OCTET STRING } into the OID and the key. Every length read
     * is bounded by the buffer, the key by KSServiceNI.SECRET_MAX_LEN, and the whole input must be consumed.
     *
     * @return {oid, key}, the key a fresh array the caller clears
     */
    static Object[] decode(byte[] der)
    {
        int[] pos = {0};
        int seqLen = expect(der, pos, 0x30);
        if (pos[0] + seqLen != der.length)
        {
            throw new IllegalStateException("malformed secret key entry");
        }
        int oidLen = expect(der, pos, 0x06);
        String oid = ASN1ObjectIdentifier.fromContents(der, pos[0], oidLen).getId();
        pos[0] += oidLen;
        int keyLen = expect(der, pos, 0x04);
        if (keyLen <= 0 || keyLen > KSServiceNI.SECRET_MAX_LEN || pos[0] + keyLen != der.length)
        {
            throw new IllegalStateException("malformed secret key entry");
        }
        byte[] key = new byte[keyLen];
        System.arraycopy(der, pos[0], key, 0, keyLen);
        return new Object[]{oid, key};
    }

    /** Read a tag and a definite length of at most three octets, and return the length within the buffer. */
    private static int expect(byte[] der, int[] pos, int tag)
    {
        int p = pos[0];
        if (der == null || p + 2 > der.length || (der[p] & 0xff) != tag)
        {
            throw new IllegalStateException("malformed secret key entry");
        }
        int len = der[p + 1] & 0xff;
        p += 2;
        if (len > 0x80)
        {
            int n = len - 0x80;
            if (n > 2 || p + n > der.length)
            {
                throw new IllegalStateException("malformed secret key entry");
            }
            len = 0;
            for (int i = 0; i < n; i++)
            {
                len = (len << 8) | (der[p++] & 0xff);
            }
        }
        else if (len == 0x80)
        {
            throw new IllegalStateException("malformed secret key entry");
        }
        if (len > der.length - p)
        {
            throw new IllegalStateException("malformed secret key entry");
        }
        pos[0] = p;
        return len;
    }
}
