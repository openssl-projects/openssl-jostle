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

package org.openssl.jostle.test.util;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.junit.jupiter.api.Assertions;
import org.openssl.jostle.jcajce.SecretKeyWithEncapsulation;
import org.openssl.jostle.jcajce.interfaces.MLDSAPrivateKey;
import org.openssl.jostle.jcajce.interfaces.MLKEMPrivateKey;
import org.openssl.jostle.jcajce.spec.KEMExtractSpec;
import org.openssl.jostle.jcajce.spec.KEMGenerateSpec;
import org.openssl.jostle.jcajce.spec.MLDSAParameterSpec;
import org.openssl.jostle.jcajce.spec.MLDSAPrivateKeySpec;
import org.openssl.jostle.jcajce.spec.MLKEMParameterSpec;
import org.openssl.jostle.jcajce.spec.MLKEMPrivateKeySpec;
import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.asn1.KeyInfoCanonicalizer;

import javax.crypto.KeyGenerator;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 * The bare PKCS#8 private key forms OpenSSL decodes for ML-DSA and ML-KEM: the seed, or the expanded key, directly
 * in the privateKey OCTET STRING with no CHOICE tag. Fixtures are built from a freshly generated key; nothing is
 * checked in.
 * <p>
 * Each bare key must import, re-encode in the structured form of what it carried (seed-only for a seed, expanded
 * for an expanded key), report its seed or none, and perform its operation against the generated public key. A
 * bare key whose first byte equals a CHOICE tag (0x80, 0x04, 0x30) is driven separately, since a classifier reading
 * the first byte mistakes it for a structured form.
 */
public final class BarePrivateKeyForms
{
    /** The first bytes a bare key can share with a structured form's tag. */
    private static final int[] COLLIDING = {
            KeyInfoCanonicalizer.FORM_SEED, KeyInfoCanonicalizer.FORM_EXPANDED, KeyInfoCanonicalizer.FORM_BOTH};

    /** Keys tried for an expanded key with a given first byte; a miss at this bound is 1 in e^16. */
    private static final int SEARCH_BOUND = 4096;

    private BarePrivateKeyForms()
    {
    }

    /** A PrivateKeyInfo with the AlgorithmIdentifier of template and content bare in its privateKey. */
    public static byte[] bare(byte[] template, byte[] content) throws Exception
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(0));
        v.add(PrivateKeyInfo.getInstance(template).getPrivateKeyAlgorithm());
        v.add(new DEROctetString(content));
        return new DERSequence(v).getEncoded(ASN1Encoding.DER);
    }

    /** Every bare ML-DSA form, and every colliding first byte, for one parameter set on one provider. */
    public static void assertMLDSA(String provider, String set, SecureRandom sr) throws Exception
    {
        MLDSAParameterSpec spec = MLDSAParameterSpec.fromName(set);
        KeyFactory kf = KeyFactory.getInstance(set, provider);
        KeyPair kp = KeyPairGenerator.getInstance(set, provider).generateKeyPair();
        MLDSAPrivateKey priv = (MLDSAPrivateKey) kp.getPrivate();
        byte[] template = priv.getEncoded();
        byte[] seed = priv.getSeed();
        byte[] expanded = priv.getPrivateData();

        assertMLDSABare(kf, set + " bare seed", bare(template, seed), priv.getPrivateKey(true).getEncoded(), seed,
                kp.getPublic(), sr);
        byte[] expandedOnly = kf.generatePrivate(new MLDSAPrivateKeySpec(spec, expanded,
                priv.getPublicKey().getPublicData())).getEncoded();
        assertMLDSABare(kf, set + " bare expanded", bare(template, expanded), expandedOnly, null, kp.getPublic(), sr);

        for (int b : COLLIDING)
        {
            String label = set + " first byte " + Integer.toHexString(b);
            byte[] s = new byte[seed.length];
            sr.nextBytes(s);
            s[0] = (byte) b;
            MLDSAPrivateKey fromSeed = (MLDSAPrivateKey) kf.generatePrivate(new MLDSAPrivateKeySpec(spec, s));
            assertMLDSABare(kf, label + " bare seed", bare(template, s), fromSeed.getEncoded(), s,
                    fromSeed.getPublicKey(), sr);

            MLDSAPrivateKey found = null;
            for (int i = 0; i < SEARCH_BOUND && found == null; i++)
            {
                sr.nextBytes(s);
                MLDSAPrivateKey k = (MLDSAPrivateKey) kf.generatePrivate(new MLDSAPrivateKeySpec(spec, s));
                if ((k.getPrivateData()[0] & 0xFF) == b)
                {
                    found = k;
                }
            }
            Assertions.assertNotNull(found, label + ": no expanded key found");
            byte[] x = found.getPrivateData();
            byte[] xOnly = kf.generatePrivate(new MLDSAPrivateKeySpec(spec, x, found.getPublicKey().getPublicData()))
                    .getEncoded();
            assertMLDSABare(kf, label + " bare expanded", bare(template, x), xOnly, null, found.getPublicKey(), sr);
        }
    }

    private static void assertMLDSABare(KeyFactory kf, String label, byte[] pkcs8, byte[] expectedEncoding,
                                        byte[] expectedSeed, PublicKey pub, SecureRandom sr) throws Exception
    {
        PrivateKey k = kf.generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
        Assertions.assertArrayEquals(expectedEncoding, k.getEncoded(), label + ": encoded form");
        Assertions.assertArrayEquals(expectedSeed, ((MLDSAPrivateKey) k).getSeed(), label + ": seed");

        byte[] msg = new byte[1 + sr.nextInt(256)];
        sr.nextBytes(msg);
        Signature signer = Signature.getInstance(kf.getAlgorithm(), kf.getProvider());
        signer.initSign(k);
        signer.update(msg);
        byte[] sig = signer.sign();
        Signature verifier = Signature.getInstance(kf.getAlgorithm(), kf.getProvider());
        verifier.initVerify(pub);
        verifier.update(msg);
        Assertions.assertTrue(verifier.verify(sig), label + ": the generated public key refused the signature");
        msg[sr.nextInt(msg.length)] ^= 1;
        verifier.initVerify(pub);
        verifier.update(msg);
        Assertions.assertFalse(verifier.verify(sig), label + ": a changed message verified");
    }

    /** Every bare ML-KEM form, and every colliding first byte, for one parameter set on one provider. */
    public static void assertMLKEM(String provider, String set, SecureRandom sr) throws Exception
    {
        MLKEMParameterSpec spec = MLKEMParameterSpec.fromName(set);
        KeyFactory kf = KeyFactory.getInstance(set, provider);
        KeyPair kp = KeyPairGenerator.getInstance(set, provider).generateKeyPair();
        MLKEMPrivateKey priv = (MLKEMPrivateKey) kp.getPrivate();
        byte[] template = priv.getEncoded();
        byte[] seed = priv.getSeed();
        byte[] expanded = priv.getPrivateData();

        assertMLKEMBare(kf, set + " bare seed", bare(template, seed), priv.getPrivateKey(true).getEncoded(), seed,
                kp.getPublic(), sr);
        byte[] expandedOnly = kf.generatePrivate(new MLKEMPrivateKeySpec(spec, expanded,
                priv.getPublicKey().getPublicData())).getEncoded();
        assertMLKEMBare(kf, set + " bare expanded", bare(template, expanded), expandedOnly, null, kp.getPublic(), sr);

        for (int b : COLLIDING)
        {
            String label = set + " first byte " + Integer.toHexString(b);
            byte[] s = new byte[seed.length];
            sr.nextBytes(s);
            s[0] = (byte) b;
            MLKEMPrivateKey fromSeed = (MLKEMPrivateKey) kf.generatePrivate(new MLKEMPrivateKeySpec(spec, s));
            assertMLKEMBare(kf, label + " bare seed", bare(template, s), fromSeed.getEncoded(), s,
                    fromSeed.getPublicKey(), sr);

            MLKEMPrivateKey found = null;
            for (int i = 0; i < SEARCH_BOUND && found == null; i++)
            {
                sr.nextBytes(s);
                MLKEMPrivateKey k = (MLKEMPrivateKey) kf.generatePrivate(new MLKEMPrivateKeySpec(spec, s));
                if ((k.getPrivateData()[0] & 0xFF) == b)
                {
                    found = k;
                }
            }
            Assertions.assertNotNull(found, label + ": no expanded key found");
            byte[] x = found.getPrivateData();
            byte[] xOnly = kf.generatePrivate(new MLKEMPrivateKeySpec(spec, x, found.getPublicKey().getPublicData()))
                    .getEncoded();
            assertMLKEMBare(kf, label + " bare expanded", bare(template, x), xOnly, null, found.getPublicKey(), sr);
        }
    }

    private static void assertMLKEMBare(KeyFactory kf, String label, byte[] pkcs8, byte[] expectedEncoding,
                                        byte[] expectedSeed, PublicKey pub, SecureRandom sr) throws Exception
    {
        PrivateKey k = kf.generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
        Assertions.assertArrayEquals(expectedEncoding, k.getEncoded(), label + ": encoded form");
        Assertions.assertArrayEquals(expectedSeed, ((MLKEMPrivateKey) k).getSeed(), label + ": seed");

        KeyGenerator g = KeyGenerator.getInstance("ML-KEM", kf.getProvider());
        g.init(KEMGenerateSpec.builder()
                .withKeySizeInBits(256).withPublicKey(pub).withAlgorithmName("AES").withNoKdf().build());
        SecretKeyWithEncapsulation sent = (SecretKeyWithEncapsulation) g.generateKey();
        Assertions.assertArrayEquals(sent.getEncoded(), extract(kf, k, sent.getEncapsulation()),
                label + ": decapsulated a different secret");
        byte[] tampered = sent.getEncapsulation();
        tampered[sr.nextInt(tampered.length)] ^= 1;
        Assertions.assertFalse(Arrays.areEqual(sent.getEncoded(), extract(kf, k, tampered)),
                label + ": a changed encapsulation recovered the secret");
    }

    private static byte[] extract(KeyFactory kf, PrivateKey k, byte[] encapsulation) throws Exception
    {
        KeyGenerator g = KeyGenerator.getInstance("ML-KEM", kf.getProvider());
        g.init(KEMExtractSpec.builder().withPrivate(k).withEncapsulatedKey(encapsulation)
                .withAlgorithmName("AES").withKeySizeInBits(256).withNoKdf().build());
        return g.generateKey().getEncoded();
    }
}
