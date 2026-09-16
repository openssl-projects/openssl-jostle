/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.crypto;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.agreement.kdf.ConcatenationKDFGenerator;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.kts.KtsKdf;
import org.openssl.jostle.jcajce.spec.KTSParameterSpec;
import org.openssl.jostle.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;

/**
 * The KTS ciphers' KDF derivations against BouncyCastle, over all eleven KDF
 * identifiers they accept.
 *
 * <p>Since the digest set was narrowed, our accepted X9.44 set is EXACTLY BC's
 * — SHA-256, SHA-512, SHAKE128, SHAKE256 — so every row here is served by both
 * JCE layers and every row runs cross-provider in both directions.
 *
 * <p>The low-level cell ({@code KDF2BytesGenerator} /
 * {@code ConcatenationKDFGenerator} over {@code SHAKEDigest}) is kept as a
 * SECOND witness on SHAKE, not the only one: it compares the derivation itself
 * rather than the wrap, so it would catch a divergence that a round-trip
 * through both providers happened to absorb.
 *
 * <p>SHA-384 is no longer accepted as an X9.44 digest parameter. The HKDF-SHA384
 * OID is unaffected and still served: RFC 8619 fixes the digest in the
 * algorithm identifier, so it is not a free parameter, and BC serves it — see
 * the comment on that row in {@link #kdfs()}.
 */
public class KtsKdfAgreementTest
{
    private static final SecureRandom RANDOM = new SecureRandom();

    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
    private static final String JSL = JostleProvider.PROVIDER_NAME;

    @BeforeAll
    public static void setUp()
    {
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    private static AlgorithmIdentifier x944(ASN1ObjectIdentifier kdf, ASN1ObjectIdentifier digest)
    {
        return new AlgorithmIdentifier(kdf, new AlgorithmIdentifier(digest, DERNull.INSTANCE));
    }

    /** Every KDF identifier the ciphers accept. BC's JCE layer serves them all. */
    private static Object[][] kdfs()
    {
        return new Object[][]{
                {"KDF2-SHA256", x944(X9ObjectIdentifiers.id_kdf_kdf2, NISTObjectIdentifiers.id_sha256)},
                {"KDF2-SHA512", x944(X9ObjectIdentifiers.id_kdf_kdf2, NISTObjectIdentifiers.id_sha512)},
                {"KDF2-SHAKE128", x944(X9ObjectIdentifiers.id_kdf_kdf2, NISTObjectIdentifiers.id_shake128)},
                {"KDF2-SHAKE256", x944(X9ObjectIdentifiers.id_kdf_kdf2, NISTObjectIdentifiers.id_shake256)},
                {"KDF3-SHA256", x944(X9ObjectIdentifiers.id_kdf_kdf3, NISTObjectIdentifiers.id_sha256)},
                {"KDF3-SHA512", x944(X9ObjectIdentifiers.id_kdf_kdf3, NISTObjectIdentifiers.id_sha512)},
                {"KDF3-SHAKE128", x944(X9ObjectIdentifiers.id_kdf_kdf3, NISTObjectIdentifiers.id_shake128)},
                {"KDF3-SHAKE256", x944(X9ObjectIdentifiers.id_kdf_kdf3, NISTObjectIdentifiers.id_shake256)},
                {"HKDF-SHA256", new AlgorithmIdentifier(PKCSObjectIdentifiers.id_alg_hkdf_with_sha256)},
                // SHA-384 survives HERE and nowhere else: RFC 8619 fixes the
                // digest in the OID, so it is not the free X9.44 parameter the
                // narrowing removed, and BC serves this OID.
                {"HKDF-SHA384", new AlgorithmIdentifier(PKCSObjectIdentifiers.id_alg_hkdf_with_sha384)},
                {"HKDF-SHA512", new AlgorithmIdentifier(PKCSObjectIdentifiers.id_alg_hkdf_with_sha512)},
        };
    }

    private static KeyPair rsaPair() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", JSL);
        kpg.initialize(2048, RANDOM);
        return kpg.generateKeyPair();
    }

    private static SecretKey cek() throws Exception
    {
        KeyGenerator kg = KeyGenerator.getInstance("AES", JSL);
        kg.init(256, RANDOM);
        return kg.generateKey();
    }

    /** For driving BouncyCastle's own Cipher — BC's spec type, not ours. */
    private static org.bouncycastle.jcajce.spec.KTSParameterSpec bcSpec(AlgorithmIdentifier kdf, byte[] otherInfo)
    {
        return new org.bouncycastle.jcajce.spec.KTSParameterSpec.Builder("AESWRAP", 256, otherInfo)
                .withKdfAlgorithm(kdf).build();
    }

    /** For driving Jostle's Cipher — the same kdf/otherInfo, our own spec type. */
    private static KTSParameterSpec spec(AlgorithmIdentifier kdf, byte[] otherInfo) throws java.io.IOException
    {
        return new KTSParameterSpec.Builder("AESWRAP", 256, otherInfo).withKdfAlgorithm(kdf.getEncoded()).build();
    }

    /**
     * Cross-direction agreement on RSA-KTS-KEM-KWS: BC wraps and we unwrap,
     * then we wrap and BC unwraps. RSASVE is randomised, so byte-equality of
     * two wraps is not available — recovering the same CEK through the other
     * implementation is the equivalent semantic check.
     */
    @Test
    public void rsaKtsAgreesWithBouncyCastleOnEveryKdfBothDirections() throws Exception
    {
        KeyPair kp = rsaPair();
        int driven = 0;
        for (Object[] row : kdfs())
        {
            String label = (String) row[0];
            driven++;
            AlgorithmIdentifier kdf = (AlgorithmIdentifier) row[1];
            byte[] otherInfo = new byte[1 + RANDOM.nextInt(48)];
            RANDOM.nextBytes(otherInfo);
            SecretKey key = cek();

            Cipher bcWrap = Cipher.getInstance("RSA-KTS-KEM-KWS", BC);
            bcWrap.init(Cipher.WRAP_MODE, kp.getPublic(), bcSpec(kdf, otherInfo), RANDOM);
            byte[] fromBc = bcWrap.wrap(key);

            Cipher joUnwrap = Cipher.getInstance("RSA-KTS-KEM-KWS", JSL);
            joUnwrap.init(Cipher.UNWRAP_MODE, kp.getPrivate(), spec(kdf, otherInfo), RANDOM);
            Assertions.assertTrue(
                    Arrays.areEqual(key.getEncoded(),
                            joUnwrap.unwrap(fromBc, "AES", Cipher.SECRET_KEY).getEncoded()),
                    label + ": Jostle must unwrap BouncyCastle's wrap");

            Cipher joWrap = Cipher.getInstance("RSA-KTS-KEM-KWS", JSL);
            joWrap.init(Cipher.WRAP_MODE, kp.getPublic(), spec(kdf, otherInfo), RANDOM);
            byte[] fromJo = joWrap.wrap(key);

            Cipher bcUnwrap = Cipher.getInstance("RSA-KTS-KEM-KWS", BC);
            bcUnwrap.init(Cipher.UNWRAP_MODE, kp.getPrivate(), bcSpec(kdf, otherInfo), RANDOM);
            Assertions.assertTrue(
                    Arrays.areEqual(key.getEncoded(),
                            bcUnwrap.unwrap(fromJo, "AES", Cipher.SECRET_KEY).getEncoded()),
                    label + ": BouncyCastle must unwrap Jostle's wrap");
        }
        Assertions.assertEquals(11, driven,
                "every KDF identifier must be driven against BC; a row silently skipped would hollow this sweep out");
    }

    /** The same matrix on ML-KEM-768, whose BC gap is identical. */
    @Test
    public void mlKemKtsAgreesWithBouncyCastleOnEveryKdfBothDirections() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM-768", JSL);
        KeyPair kp = kpg.generateKeyPair();
        byte[] pub = kp.getPublic().getEncoded();
        byte[] priv = kp.getPrivate().getEncoded();
        java.security.KeyFactory bcKf = java.security.KeyFactory.getInstance("ML-KEM-768", BC);
        java.security.PublicKey bcPub =
                bcKf.generatePublic(new java.security.spec.X509EncodedKeySpec(pub));
        java.security.PrivateKey bcPriv =
                bcKf.generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(priv));

        int driven = 0;
        for (Object[] row : kdfs())
        {
            String label = (String) row[0];
            driven++;
            AlgorithmIdentifier kdf = (AlgorithmIdentifier) row[1];
            byte[] otherInfo = new byte[1 + RANDOM.nextInt(48)];
            RANDOM.nextBytes(otherInfo);
            SecretKey key = cek();

            Cipher bcWrap = Cipher.getInstance("ML-KEM-768", BC);
            bcWrap.init(Cipher.WRAP_MODE, bcPub, bcSpec(kdf, otherInfo), RANDOM);
            byte[] fromBc = bcWrap.wrap(key);

            Cipher joUnwrap = Cipher.getInstance("ML-KEM", JSL);
            joUnwrap.init(Cipher.UNWRAP_MODE, kp.getPrivate(), spec(kdf, otherInfo), RANDOM);
            Assertions.assertTrue(
                    Arrays.areEqual(key.getEncoded(),
                            joUnwrap.unwrap(fromBc, "AES", Cipher.SECRET_KEY).getEncoded()),
                    label + ": Jostle must unwrap BouncyCastle's ML-KEM wrap");

            Cipher joWrap = Cipher.getInstance("ML-KEM", JSL);
            joWrap.init(Cipher.WRAP_MODE, kp.getPublic(), spec(kdf, otherInfo), RANDOM);
            byte[] fromJo = joWrap.wrap(key);

            Cipher bcUnwrap = Cipher.getInstance("ML-KEM-768", BC);
            bcUnwrap.init(Cipher.UNWRAP_MODE, bcPriv, bcSpec(kdf, otherInfo), RANDOM);
            Assertions.assertTrue(
                    Arrays.areEqual(key.getEncoded(),
                            bcUnwrap.unwrap(fromJo, "AES", Cipher.SECRET_KEY).getEncoded()),
                    label + ": BouncyCastle must unwrap Jostle's ML-KEM wrap");
        }
        Assertions.assertEquals(11, driven,
                "every KDF identifier must be driven against BC; a row silently skipped would hollow this sweep out");
    }

    /**
     * SHAKE against BC's LOW-LEVEL generators — the second witness. The
     * cross-provider cells above compare the WRAP; this compares the
     * derivation itself, so it catches a divergence a round-trip through both
     * providers would absorb.
     *
     * <p>One z and one otherInfo per trial, shared by all four derivations: two
     * draws would differ whatever the KDF did.
     */
    @Test
    public void shakeDerivationsMatchBouncyCastlesLowLevelGenerators() throws Exception
    {
        Provider jsl = Security.getProvider(JSL);
        for (int trial = 0; trial < 6; trial++)
        {
            byte[] z = new byte[1 + RANDOM.nextInt(256)];
            RANDOM.nextBytes(z);
            byte[] otherInfo = new byte[RANDOM.nextInt(40)];
            RANDOM.nextBytes(otherInfo);
            // Past one block for both: SHAKE-128 squeezes 32 bytes, SHAKE-256
            // 64, so a shorter output would agree on the first block alone.
            int outLen = 65 + RANDOM.nextInt(160);

            for (int bits : new int[]{128, 256})
            {
                String name = "SHAKE-" + bits;

                byte[] ourKdf2 = KtsKdf.derive(jsl, KtsKdf.Kind.KDF2, name, z, otherInfo, outLen);
                byte[] bcKdf2 = new byte[outLen];
                KDF2BytesGenerator g2 = new KDF2BytesGenerator(new SHAKEDigest(bits));
                g2.init(new KDFParameters(z, otherInfo));
                g2.generateBytes(bcKdf2, 0, outLen);
                Assertions.assertTrue(Arrays.areEqual(ourKdf2, bcKdf2),
                        "KDF2-" + name + " diverged from BC");

                byte[] ourKdf3 = KtsKdf.derive(jsl, KtsKdf.Kind.KDF3, name, z, otherInfo, outLen);
                byte[] bcKdf3 = new byte[outLen];
                ConcatenationKDFGenerator g3 = new ConcatenationKDFGenerator(new SHAKEDigest(bits));
                g3.init(new KDFParameters(z, otherInfo));
                g3.generateBytes(bcKdf3, 0, outLen);
                Assertions.assertTrue(Arrays.areEqual(ourKdf3, bcKdf3),
                        "KDF3-" + name + " diverged from BC");

                // Differentiator: one implementation wired to both kinds would
                // satisfy the two assertions above.
                Assertions.assertFalse(Arrays.areEqual(ourKdf2, ourKdf3),
                        name + ": KDF2 and KDF3 must differ on identical inputs");
            }
        }
    }


    /** HKDF against BC's own generator, for all three digests. */
    @Test
    public void hkdfDerivationMatchesBouncyCastleAcrossDigests() throws Exception
    {
        Provider jsl = Security.getProvider(JSL);
        Digest[] digests = {new SHA256Digest(), new SHA384Digest(), new SHA512Digest()};
        String[] names = {"SHA-256", "SHA-384", "SHA-512"};
        for (int i = 0; i < names.length; i++)
        {
            byte[] z = new byte[1 + RANDOM.nextInt(200)];
            RANDOM.nextBytes(z);
            byte[] info = new byte[RANDOM.nextInt(40)];
            RANDOM.nextBytes(info);
            int outLen = 1 + RANDOM.nextInt(200);

            byte[] ours = KtsKdf.derive(jsl, KtsKdf.Kind.HKDF, names[i], z, info, outLen);
            byte[] theirs = new byte[outLen];
            org.bouncycastle.crypto.generators.HKDFBytesGenerator g =
                    new org.bouncycastle.crypto.generators.HKDFBytesGenerator(digests[i]);
            g.init(new org.bouncycastle.crypto.params.HKDFParameters(z, null, info));
            g.generateBytes(theirs, 0, outLen);
            Assertions.assertTrue(Arrays.areEqual(ours, theirs), "HKDF-" + names[i] + " diverged from BC");
        }
    }

    /** An unknown KDF is still refused, with the unified message. */
    @Test
    public void unknownKdfIsRefusedWithTheUnifiedMessage() throws Exception
    {
        KeyPair kp = rsaPair();
        AlgorithmIdentifier bogus = x944(new ASN1ObjectIdentifier("1.2.3.4.5.6.7"),
                NISTObjectIdentifiers.id_sha256);
        for (String xform : new String[]{"RSA-KTS-KEM-KWS"})
        {
            Cipher c = Cipher.getInstance(xform, JSL);
            InvalidAlgorithmParameterException ex = Assertions.assertThrows(
                    InvalidAlgorithmParameterException.class,
                    () -> c.init(Cipher.WRAP_MODE, kp.getPublic(), spec(bogus, new byte[8]), RANDOM));
            Assertions.assertEquals(KtsKdf.unsupportedKdfMessage("1.2.3.4.5.6.7"), ex.getMessage(),
                    xform + ": unknown KDF must use the unified message");
        }
    }

    /**
     * The two shapes are enforced in both directions: HKDF must have absent
     * parameters, KDF2/KDF3 must have them. BouncyCastle refuses the first with
     * an unchecked {@code IllegalStateException("HDKF parameter support not
     * added")}; we use the JCE-canonical checked type for an init failure, and
     * that divergence is deliberate.
     */
    @Test
    public void parameterShapeIsEnforcedForBothFamilies() throws Exception
    {
        KeyPair kp = rsaPair();

        AlgorithmIdentifier hkdfWithParams = new AlgorithmIdentifier(
                PKCSObjectIdentifiers.id_alg_hkdf_with_sha256, DERNull.INSTANCE);
        Cipher c1 = Cipher.getInstance("RSA-KTS-KEM-KWS", JSL);
        InvalidAlgorithmParameterException e1 = Assertions.assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> c1.init(Cipher.WRAP_MODE, kp.getPublic(), spec(hkdfWithParams, new byte[8]), RANDOM));
        Assertions.assertEquals(KtsKdf.hkdfParametersForbiddenMessage(), e1.getMessage());

        AlgorithmIdentifier kdf2NoParams =
                new AlgorithmIdentifier(X9ObjectIdentifiers.id_kdf_kdf2);
        Cipher c2 = Cipher.getInstance("RSA-KTS-KEM-KWS", JSL);
        InvalidAlgorithmParameterException e2 = Assertions.assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> c2.init(Cipher.WRAP_MODE, kp.getPublic(), spec(kdf2NoParams, new byte[8]), RANDOM));
        Assertions.assertEquals(KtsKdf.digestParameterRequiredMessage(), e2.getMessage());
    }
}
