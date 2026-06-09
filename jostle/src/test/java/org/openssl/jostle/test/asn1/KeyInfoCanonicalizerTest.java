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
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.util.asn1.KeyInfoCanonicalizer;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * The JSL KeyFactory must canonicalise an ML-DSA / SLH-DSA / ML-KEM key whose
 * AlgorithmIdentifier carries an explicit NULL {@code parameters} element (as
 * emitted by, e.g., {@code sun.security.x509.X509Key} when it re-encodes a key
 * for an algorithm it does not recognise). FIPS 203/204/205 require the
 * parameters to be absent and OpenSSL rejects the NULL form, so the KeyFactory
 * strips it before handing the bytes to OpenSSL (see
 * {@link org.openssl.jostle.util.asn1.KeyInfoCanonicalizer}).
 *
 * <p>For each algorithm this generates a (conformant) keypair, injects a NULL
 * into both the SubjectPublicKeyInfo and the PrivateKeyInfo, and asserts that
 * re-importing the NULL-padded encoding succeeds and re-encodes back to the
 * original canonical form.
 */
public class KeyInfoCanonicalizerTest
{
    @BeforeAll
    public static void before()
    {
        synchronized (JostleProvider.class)
        {
            if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
            {
                Security.addProvider(new JostleProvider());
            }
        }
    }

    @Test
    public void mldsa()
        throws Exception
    {
        run("ML-DSA-44");
    }

    @Test
    public void slhdsa()
        throws Exception
    {
        run("SLH-DSA-SHA2-128F");
    }

    @Test
    public void mlkem()
        throws Exception
    {
        run("ML-KEM-768");
    }

    // Output side (gap #10): a FIPS 203/204/205 key's own getEncoded() must
    // already carry absent AlgorithmIdentifier parameters, regardless of whether
    // the provider is globally installed — running it through the canonicaliser
    // must be a byte-for-byte no-op (a stray NULL would change it).

    @Test
    public void mldsa_outputCanonical() throws Exception
    {
        assertEncodedCanonical("ML-DSA-44");
    }

    @Test
    public void slhdsa_outputCanonical() throws Exception
    {
        assertEncodedCanonical("SLH-DSA-SHA2-128F");
    }

    @Test
    public void mlkem_outputCanonical() throws Exception
    {
        assertEncodedCanonical("ML-KEM-768");
    }

    private void assertEncodedCanonical(String alg) throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance(alg, JostleProvider.PROVIDER_NAME).generateKeyPair();

        byte[] spki = kp.getPublic().getEncoded();
        Assertions.assertArrayEquals(spki, KeyInfoCanonicalizer.subjectPublicKeyInfo(spki),
                alg + ": getEncoded() SPKI carries non-absent AlgorithmIdentifier parameters");

        byte[] pkcs8 = kp.getPrivate().getEncoded();
        Assertions.assertArrayEquals(pkcs8, KeyInfoCanonicalizer.privateKeyInfo(pkcs8),
                alg + ": getEncoded() PKCS#8 carries non-absent privateKeyAlgorithm parameters");
    }

    // -----------------------------------------------------------------
    // Direct synthetic unit tests of the canonicaliser's branches: an exact
    // NULL parameters element is stripped, and any other shape is returned
    // byte-for-byte unchanged (the negative / pass-through path that the
    // round-trip tests above can't reach, since a JSL-generated key is always
    // already conformant).
    // -----------------------------------------------------------------

    private static final byte[] OID = {0x06, 0x03, 0x55, 0x04, 0x03};       // a placeholder OID TLV (2.5.4.3)
    private static final byte[] NULL_PARAMS = {0x05, 0x00};
    private static final byte[] BIT_STRING = {0x03, 0x02, 0x00, 0x2A};      // dummy subjectPublicKey

    @Test
    public void spki_nullParameters_stripped()
    {
        byte[] withNull = derSequence(concat(derSequence(concat(OID, NULL_PARAMS)), BIT_STRING));
        byte[] stripped = derSequence(concat(derSequence(OID), BIT_STRING));
        Assertions.assertArrayEquals(stripped, KeyInfoCanonicalizer.subjectPublicKeyInfo(withNull),
                "stray NULL parameters were not stripped from the SPKI AlgorithmIdentifier");
    }

    @Test
    public void spki_nonNullParameters_returnedUnchanged()
    {
        byte[] param = {0x02, 0x01, 0x01};                                  // INTEGER 1 (not a NULL)
        byte[] spki = derSequence(concat(derSequence(concat(OID, param)), BIT_STRING));
        Assertions.assertArrayEquals(spki, KeyInfoCanonicalizer.subjectPublicKeyInfo(spki),
                "non-NULL parameters must be left untouched");
    }

    @Test
    public void spki_noParameters_returnedUnchanged()
    {
        byte[] spki = derSequence(concat(derSequence(OID), BIT_STRING));
        Assertions.assertArrayEquals(spki, KeyInfoCanonicalizer.subjectPublicKeyInfo(spki),
                "already-conformant SPKI must be left untouched");
    }

    @Test
    public void spki_malformed_returnedUnchanged()
    {
        byte[] notASequence = {0x05, 0x00, 0x01, 0x02};
        Assertions.assertArrayEquals(notASequence, KeyInfoCanonicalizer.subjectPublicKeyInfo(notASequence),
                "non-SEQUENCE input must be returned unchanged");
        byte[] truncated = {0x30, 0x05, 0x30, 0x03, 0x06};                  // length claims more than present
        Assertions.assertArrayEquals(truncated, KeyInfoCanonicalizer.subjectPublicKeyInfo(truncated),
                "truncated input must be returned unchanged");
    }

    @Test
    public void pkcs8_malformed_returnedUnchanged()
    {
        byte[] notASequence = {0x02, 0x01, 0x00};                           // INTEGER, not a SEQUENCE
        Assertions.assertArrayEquals(notASequence, KeyInfoCanonicalizer.privateKeyInfo(notASequence),
                "non-SEQUENCE PrivateKeyInfo must be returned unchanged");
        byte[] truncated = {0x30, 0x20, 0x02, 0x01, 0x00};                  // SEQUENCE claims 32 bytes, 3 present
        Assertions.assertArrayEquals(truncated, KeyInfoCanonicalizer.privateKeyInfo(truncated),
                "truncated PrivateKeyInfo must be returned unchanged");
    }

    @Test
    public void lengthOverrun_returnedUnchanged()
    {
        // SEQUENCE with a 4-octet long-form length of 0x7FFFFFFF — far beyond
        // the buffer. The canonicaliser's length reader must not index out of
        // bounds; both paths fall back to returning the input unchanged.
        byte[] overrun = {0x30, (byte) 0x84, 0x7F, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                0x06, 0x03, 0x55, 0x04, 0x03};
        Assertions.assertArrayEquals(overrun, KeyInfoCanonicalizer.subjectPublicKeyInfo(overrun),
                "SPKI length-overrun must be returned unchanged (no AIOOBE)");
        Assertions.assertArrayEquals(overrun, KeyInfoCanonicalizer.privateKeyInfo(overrun),
                "PrivateKeyInfo length-overrun must be returned unchanged (no AIOOBE)");
    }

    @Test
    public void pkcs8_nullParameters_stripped()
    {
        byte[] version = {0x02, 0x01, 0x00};                                // INTEGER 0
        byte[] privateKey = {0x04, 0x02, (byte) 0xAA, (byte) 0xBB};         // OCTET STRING privateKey
        byte[] withNull = derSequence(concat(concat(version, derSequence(concat(OID, NULL_PARAMS))), privateKey));
        byte[] stripped = derSequence(concat(concat(version, derSequence(OID)), privateKey));
        Assertions.assertArrayEquals(stripped, KeyInfoCanonicalizer.privateKeyInfo(withNull),
                "stray NULL parameters were not stripped from the PrivateKeyInfo AlgorithmIdentifier");
    }

    @Test
    public void pkcs8_nonNullParameters_returnedUnchanged()
    {
        byte[] version = {0x02, 0x01, 0x00};
        byte[] param = {0x02, 0x01, 0x01};
        byte[] privateKey = {0x04, 0x02, (byte) 0xAA, (byte) 0xBB};
        byte[] pki = derSequence(concat(concat(version, derSequence(concat(OID, param))), privateKey));
        Assertions.assertArrayEquals(pki, KeyInfoCanonicalizer.privateKeyInfo(pki),
                "non-NULL parameters must be left untouched");
    }

    private void run(String alg)
        throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance(alg, JostleProvider.PROVIDER_NAME).generateKeyPair();
        KeyFactory kf = KeyFactory.getInstance(alg, JostleProvider.PROVIDER_NAME);

        // SubjectPublicKeyInfo path.
        byte[] canonicalSpki = kp.getPublic().getEncoded();
        byte[] paddedSpki = injectNullParams(canonicalSpki, false);
        Assertions.assertFalse(Arrays.equals(canonicalSpki, paddedSpki), alg + ": NULL injection was a no-op");
        PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(paddedSpki));
        Assertions.assertArrayEquals(canonicalSpki, pub.getEncoded(), alg + ": SPKI not canonicalised");

        // PrivateKeyInfo path.
        byte[] canonicalPkcs8 = kp.getPrivate().getEncoded();
        byte[] paddedPkcs8 = injectNullParams(canonicalPkcs8, true);
        Assertions.assertFalse(Arrays.equals(canonicalPkcs8, paddedPkcs8), alg + ": NULL injection was a no-op");
        PrivateKey priv = kf.generatePrivate(new PKCS8EncodedKeySpec(paddedPkcs8));
        Assertions.assertArrayEquals(canonicalPkcs8, priv.getEncoded(), alg + ": PKCS8 not canonicalised");
    }

    /**
     * Insert an explicit NULL ({@code 05 00}) as the AlgorithmIdentifier
     * parameters. {@code isPkcs8 == false} treats {@code der} as a
     * SubjectPublicKeyInfo (AlgorithmIdentifier is the first element);
     * {@code isPkcs8 == true} treats it as a PrivateKeyInfo (AlgorithmIdentifier
     * follows the version INTEGER).
     */
    private static byte[] injectNullParams(byte[] der, boolean isPkcs8)
    {
        int[] pos = {0};
        int outerEnd = readSequenceHeader(der, pos);

        byte[] prefix;
        if (isPkcs8)
        {
            int versionStart = pos[0];
            int[] vp = {versionStart};
            skipTlv(der, vp);                       // version INTEGER
            prefix = copyOfRange(der, versionStart, vp[0]);
            pos[0] = vp[0];
        }
        else
        {
            prefix = new byte[0];
        }

        int[] algPos = {pos[0]};
        int algEnd = readSequenceHeader(der, algPos);
        byte[] algContent = copyOfRange(der, algPos[0], algEnd);
        byte[] newAlg = derSequence(concat(algContent, new byte[]{0x05, 0x00}));
        byte[] rest = copyOfRange(der, algEnd, outerEnd);

        return derSequence(concat(concat(prefix, newAlg), rest));
    }

    private static int readSequenceHeader(byte[] data, int[] pos)
    {
        if ((data[pos[0]++] & 0xFF) != 0x30)
        {
            throw new IllegalArgumentException("expected SEQUENCE");
        }
        int len = readLength(data, pos);
        return pos[0] + len;
    }

    private static void skipTlv(byte[] data, int[] pos)
    {
        pos[0]++;   // tag
        int len = readLength(data, pos);
        pos[0] += len;
    }

    private static int readLength(byte[] data, int[] pos)
    {
        int b = data[pos[0]++] & 0xFF;
        if ((b & 0x80) == 0)
        {
            return b;
        }
        int count = b & 0x7F;
        int len = 0;
        for (int i = 0; i < count; i++)
        {
            len = (len << 8) | (data[pos[0]++] & 0xFF);
        }
        return len;
    }

    private static byte[] derSequence(byte[] content)
    {
        return concat(concat(new byte[]{0x30}, derLength(content.length)), content);
    }

    private static byte[] derLength(int len)
    {
        if (len < 0x80)
        {
            return new byte[]{(byte) len};
        }
        if (len < 0x100)
        {
            return new byte[]{(byte) 0x81, (byte) len};
        }
        if (len < 0x10000)
        {
            return new byte[]{(byte) 0x82, (byte) (len >>> 8), (byte) len};
        }
        return new byte[]{(byte) 0x83, (byte) (len >>> 16), (byte) (len >>> 8), (byte) len};
    }

    private static byte[] copyOfRange(byte[] a, int from, int to)
    {
        byte[] out = new byte[to - from];
        System.arraycopy(a, from, out, 0, out.length);
        return out;
    }

    private static byte[] concat(byte[] a, byte[] b)
    {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
