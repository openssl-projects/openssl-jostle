/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.rsa;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAESOAEPparams;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.util.Arrays;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * MT-78: an RSA key whose AlgorithmIdentifier is one the native decoder will not
 * accept must still decode, and must re-encode byte-identically.
 *
 * <h2>What the canonicalizer does, and what it does not</h2>
 *
 * <p>{@code id-RSASSA-PSS} and {@code id-RSAES-OAEP} both carry an ordinary RSA
 * key (RFC 4055 §4.1); the OID only restricts the intended use. OpenSSL refuses
 * them as key algorithms, so the identifier is swapped for {@code rsaEncryption}
 * on the way in — and the ORIGINAL is restored whole on the way out, parameters
 * included. Nothing about the declared use is lost, which is why these cells
 * assert byte-identity rather than merely that the key decoded.
 *
 * <h2>Driven from the OID list, not from names</h2>
 *
 * <p>Both rewritten OIDs go through the same cells, so adding a third to
 * {@code KeyInfoCanonicalizer} is a data change and this test covers it without
 * edit. `rsaEncryption` is the control: it is NOT rewritten, and must still
 * round-trip as itself.
 */
public class RsaAlgIdCanonicalisationTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;

    /** The OIDs the canonicalizer rewrites, each with real parameters. */
    private static AlgorithmIdentifier[] rewrittenAlgIds()
    {
        AlgorithmIdentifier sha256 = new AlgorithmIdentifier(
                new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1"), DERNull.INSTANCE);
        AlgorithmIdentifier mgf1 = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, sha256);

        return new AlgorithmIdentifier[]{
                new AlgorithmIdentifier(PKCSObjectIdentifiers.id_RSASSA_PSS,
                        new RSASSAPSSparams(sha256, mgf1, new ASN1Integer(32), new ASN1Integer(1))),
                new AlgorithmIdentifier(PKCSObjectIdentifiers.id_RSAES_OAEP,
                        new RSAESOAEPparams(sha256, mgf1,
                                new AlgorithmIdentifier(PKCSObjectIdentifiers.id_pSpecified,
                                        new DEROctetString(new byte[0]))))
        };
    }

    private static KeyPair keyPair;

    @BeforeAll
    public static void setUp() throws Exception
    {
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", JSL);
        kpg.initialize(2048);
        keyPair = kpg.generateKeyPair();
    }

    @Test
    public void everyRewrittenAlgIdDecodesAndReEncodesByteIdenticallyAsAnSpki() throws Exception
    {
        for (AlgorithmIdentifier algId : rewrittenAlgIds())
        {
            byte[] spki = spkiWith(algId);
            PublicKey key = KeyFactory.getInstance("RSA", JSL)
                    .generatePublic(new X509EncodedKeySpec(spki));
            Assertions.assertTrue(Arrays.areEqual(spki, key.getEncoded()),
                    algId.getAlgorithm().getId()
                            + ": the SPKI must round-trip byte-identically, parameters included");
        }
    }

    @Test
    public void everyRewrittenAlgIdDecodesAndReEncodesByteIdenticallyAsPkcs8() throws Exception
    {
        for (AlgorithmIdentifier algId : rewrittenAlgIds())
        {
            byte[] pkcs8 = pkcs8With(algId);
            PrivateKey key = KeyFactory.getInstance("RSA", JSL)
                    .generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
            Assertions.assertTrue(Arrays.areEqual(pkcs8, key.getEncoded()),
                    algId.getAlgorithm().getId()
                            + ": the PrivateKeyInfo must round-trip byte-identically");
        }
    }

    /**
     * BouncyCastle is why the private-key half is in scope at all: it decodes
     * these and round-trips them byte-identically, so a refusal on our side is a
     * divergence rather than a choice. Asserting BC's half means a bcprov bump
     * that moves the reference fails here loudly.
     */
    @Test
    public void bouncyCastleAgreesThatTheseAreDecodableRsaKeys() throws Exception
    {
        for (AlgorithmIdentifier algId : rewrittenAlgIds())
        {
            byte[] spki = spkiWith(algId);
            Assertions.assertTrue(Arrays.areEqual(spki,
                            KeyFactory.getInstance("RSA", "BC")
                                    .generatePublic(new X509EncodedKeySpec(spki)).getEncoded()),
                    algId.getAlgorithm().getId() + ": BC SPKI round-trip");

            byte[] pkcs8 = pkcs8With(algId);
            Assertions.assertTrue(Arrays.areEqual(pkcs8,
                            KeyFactory.getInstance("RSA", "BC")
                                    .generatePrivate(new PKCS8EncodedKeySpec(pkcs8)).getEncoded()),
                    algId.getAlgorithm().getId() + ": BC PKCS#8 round-trip");
        }
    }

    /** Control: rsaEncryption is NOT rewritten and must still round-trip as itself. */
    @Test
    public void plainRsaEncryptionIsUntouched() throws Exception
    {
        byte[] spki = keyPair.getPublic().getEncoded();
        Assertions.assertTrue(Arrays.areEqual(spki, KeyFactory.getInstance("RSA", JSL)
                .generatePublic(new X509EncodedKeySpec(spki)).getEncoded()));

        byte[] pkcs8 = keyPair.getPrivate().getEncoded();
        Assertions.assertTrue(Arrays.areEqual(pkcs8, KeyFactory.getInstance("RSA", JSL)
                .generatePrivate(new PKCS8EncodedKeySpec(pkcs8)).getEncoded()));
    }

    private static byte[] spkiWith(AlgorithmIdentifier algId) throws Exception
    {
        ASN1Sequence s = ASN1Sequence.getInstance(keyPair.getPublic().getEncoded());
        return new DERSequence(new ASN1Encodable[]{algId, s.getObjectAt(1)}).getEncoded("DER");
    }

    private static byte[] pkcs8With(AlgorithmIdentifier algId) throws Exception
    {
        ASN1Sequence s = ASN1Sequence.getInstance(keyPair.getPrivate().getEncoded());
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(s.getObjectAt(0));
        v.add(algId);
        for (int i = 2; i < s.size(); i++)
        {
            v.add(s.getObjectAt(i));
        }
        return new DERSequence(v).getEncoded("DER");
    }
}
