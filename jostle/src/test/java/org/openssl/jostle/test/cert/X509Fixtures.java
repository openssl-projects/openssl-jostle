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

package org.openssl.jostle.test.cert;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTCTime;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Structurally valid certificates and CRLs with a chosen OID in one place, for
 * the parser's bounds. The signature is random bytes: these inputs are parsed,
 * never verified.
 */
public final class X509Fixtures
{
    /** id-ecdsa-with-SHA256. */
    public static final String ECDSA_SHA256 = "1.2.840.10045.4.3.2";

    private static final String EC_PUBLIC_KEY = "1.2.840.10045.2.1";
    private static final String PRIME256V1 = "1.2.840.10045.3.1.7";

    /** The P-256 base point, uncompressed: a valid public key no test depends on. */
    private static final byte[] P256_G = hex(
            "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
                    + "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");

    private static final SecureRandom RANDOM = new SecureRandom();

    private X509Fixtures()
    {
    }

    /** A dotted OID of exactly {@code length} characters, starting "1.2". */
    public static String oidOfLength(int length)
    {
        StringBuilder sb = new StringBuilder("1.2");
        while (sb.length() + 2 <= length)
        {
            sb.append(".1");
        }
        if (sb.length() < length)
        {
            sb.append('1');
        }
        if (sb.length() != length)
        {
            throw new IllegalStateException("no OID of length " + length);
        }
        return sb.toString();
    }

    /**
     * A v3 certificate. Any argument may be null for the default: no extension,
     * ECDSA with SHA-256, an EC public key.
     */
    public static byte[] certificate(String extensionOid, String signatureOid, String spkiOid)
        throws Exception
    {
        AlgorithmIdentifier sig = new AlgorithmIdentifier(
                new ASN1ObjectIdentifier(signatureOid == null ? ECDSA_SHA256 : signatureOid));
        AlgorithmIdentifier keyAlg = spkiOid == null
                ? new AlgorithmIdentifier(new ASN1ObjectIdentifier(EC_PUBLIC_KEY),
                new ASN1ObjectIdentifier(PRIME256V1))
                : new AlgorithmIdentifier(new ASN1ObjectIdentifier(spkiOid));

        ASN1EncodableVector tbs = new ASN1EncodableVector();
        tbs.add(new DERTaggedObject(true, 0, new ASN1Integer(2)));
        tbs.add(new ASN1Integer(1 + RANDOM.nextInt(1 << 20)));
        tbs.add(sig);
        tbs.add(new X500Name("CN=fixture,O=jostle"));
        tbs.add(new DERSequence(new ASN1Encodable[]{
                new DERUTCTime("250101000000Z"), new DERUTCTime("350101000000Z")}));
        tbs.add(new X500Name("CN=fixture,O=jostle"));
        tbs.add(new DERSequence(new ASN1Encodable[]{keyAlg, new DERBitString(P256_G)}));
        if (extensionOid != null)
        {
            ASN1EncodableVector ext = new ASN1EncodableVector();
            ext.add(new ASN1ObjectIdentifier(extensionOid));
            ext.add(new DEROctetString(new byte[]{0x05, 0x00}));
            tbs.add(new DERTaggedObject(true, 3, new DERSequence(new DERSequence(ext))));
        }
        return signed(new DERSequence(tbs), sig);
    }

    /** A v2 CRL with one revoked entry, signed (structurally) under {@code signatureOid}. */
    public static byte[] crl(String signatureOid)
        throws Exception
    {
        AlgorithmIdentifier sig = new AlgorithmIdentifier(
                new ASN1ObjectIdentifier(signatureOid == null ? ECDSA_SHA256 : signatureOid));
        ASN1EncodableVector entry = new ASN1EncodableVector();
        entry.add(new ASN1Integer(1 + RANDOM.nextInt(1 << 20)));
        entry.add(new DERUTCTime("250601000000Z"));

        ASN1EncodableVector tbs = new ASN1EncodableVector();
        tbs.add(new ASN1Integer(1));
        tbs.add(sig);
        tbs.add(new X500Name("CN=fixture,O=jostle"));
        tbs.add(new DERUTCTime("250101000000Z"));
        tbs.add(new DERUTCTime("350101000000Z"));
        tbs.add(new DERSequence(new DERSequence(entry)));
        return signed(new DERSequence(tbs), sig);
    }

    public static String pem(String label, byte[] der)
    {
        String body = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(der);
        return "-----BEGIN " + label + "-----\n" + body + "\n-----END " + label + "-----\n";
    }

    public static byte[] ascii(String s)
    {
        return s.getBytes(StandardCharsets.US_ASCII);
    }

    public static byte[] concat(byte[] a, byte[] b)
    {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static byte[] signed(DERSequence tbs, AlgorithmIdentifier sig)
        throws Exception
    {
        byte[] signature = new byte[64];
        RANDOM.nextBytes(signature);
        return new DERSequence(new ASN1Encodable[]{tbs, sig, new DERBitString(signature)})
                .getEncoded(ASN1Encoding.DER);
    }

    private static byte[] hex(String s)
    {
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++)
        {
            b[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        }
        return b;
    }
}
