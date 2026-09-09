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
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.kts.KtsKdf;
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
 * MT-73: the KTS ciphers accept KDF2 and HKDF alongside X9.44 KDF3.
 *
 * <h2>Two references, because BouncyCastle cannot supply one of the cells</h2>
 *
 * <p>Measured against bcprov 1.85.2: BC's KTS ciphers accept SHA-256 and
 * SHA-512 for KDF2 and KDF3 but REFUSE SHA-384 —
 * {@code InvalidKeyException: unrecognized digest OID: 2.16.840.1.101.3.4.2.2}
 * — while accepting all three HKDF OIDs. Our {@code digestNameForOid} has
 * always accepted SHA-384, so on those two cells we are a <b>superset of BC by
 * design</b> and a parity sweep must not narrow us to match. Both ciphers show
 * the identical gap, so it lives in BC's shared KDF-digest mapping.
 *
 * <p>The seven cells BC's JCE layer can serve are compared against it. The two
 * SHA-384 cells are compared against BC's LOW-LEVEL generators
 * ({@code KDF2BytesGenerator} / {@code ConcatenationKDFGenerator}), which are
 * still an independent implementation of the derivation — not self-reference.
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

    /** The nine KDF identifiers, and whether BC's JCE layer will serve each. */
    private static Object[][] kdfs()
    {
        return new Object[][]{
                {"KDF2-SHA256", x944(X9ObjectIdentifiers.id_kdf_kdf2, NISTObjectIdentifiers.id_sha256), true},
                {"KDF2-SHA384", x944(X9ObjectIdentifiers.id_kdf_kdf2, NISTObjectIdentifiers.id_sha384), false},
                {"KDF2-SHA512", x944(X9ObjectIdentifiers.id_kdf_kdf2, NISTObjectIdentifiers.id_sha512), true},
                {"KDF3-SHA256", x944(X9ObjectIdentifiers.id_kdf_kdf3, NISTObjectIdentifiers.id_sha256), true},
                {"KDF3-SHA384", x944(X9ObjectIdentifiers.id_kdf_kdf3, NISTObjectIdentifiers.id_sha384), false},
                {"KDF3-SHA512", x944(X9ObjectIdentifiers.id_kdf_kdf3, NISTObjectIdentifiers.id_sha512), true},
                {"HKDF-SHA256", new AlgorithmIdentifier(PKCSObjectIdentifiers.id_alg_hkdf_with_sha256), true},
                {"HKDF-SHA384", new AlgorithmIdentifier(PKCSObjectIdentifiers.id_alg_hkdf_with_sha384), true},
                {"HKDF-SHA512", new AlgorithmIdentifier(PKCSObjectIdentifiers.id_alg_hkdf_with_sha512), true},
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

    private static KTSParameterSpec spec(AlgorithmIdentifier kdf, byte[] otherInfo)
    {
        return new KTSParameterSpec.Builder("AESWRAP", 256, otherInfo).withKdfAlgorithm(kdf).build();
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
        for (Object[] row : kdfs())
        {
            if (!((Boolean) row[2]).booleanValue())
            {
                continue;   // BC's JCE layer refuses this one; covered below.
            }
            String label = (String) row[0];
            AlgorithmIdentifier kdf = (AlgorithmIdentifier) row[1];
            byte[] otherInfo = new byte[1 + RANDOM.nextInt(48)];
            RANDOM.nextBytes(otherInfo);
            SecretKey key = cek();

            Cipher bcWrap = Cipher.getInstance("RSA-KTS-KEM-KWS", BC);
            bcWrap.init(Cipher.WRAP_MODE, kp.getPublic(), spec(kdf, otherInfo), RANDOM);
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
            bcUnwrap.init(Cipher.UNWRAP_MODE, kp.getPrivate(), spec(kdf, otherInfo), RANDOM);
            Assertions.assertTrue(
                    Arrays.areEqual(key.getEncoded(),
                            bcUnwrap.unwrap(fromJo, "AES", Cipher.SECRET_KEY).getEncoded()),
                    label + ": BouncyCastle must unwrap Jostle's wrap");
        }
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

        for (Object[] row : kdfs())
        {
            if (!((Boolean) row[2]).booleanValue())
            {
                continue;
            }
            String label = (String) row[0];
            AlgorithmIdentifier kdf = (AlgorithmIdentifier) row[1];
            byte[] otherInfo = new byte[1 + RANDOM.nextInt(48)];
            RANDOM.nextBytes(otherInfo);
            SecretKey key = cek();

            Cipher bcWrap = Cipher.getInstance("ML-KEM-768", BC);
            bcWrap.init(Cipher.WRAP_MODE, bcPub, spec(kdf, otherInfo), RANDOM);
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
            bcUnwrap.init(Cipher.UNWRAP_MODE, bcPriv, spec(kdf, otherInfo), RANDOM);
            Assertions.assertTrue(
                    Arrays.areEqual(key.getEncoded(),
                            bcUnwrap.unwrap(fromJo, "AES", Cipher.SECRET_KEY).getEncoded()),
                    label + ": BouncyCastle must unwrap Jostle's ML-KEM wrap");
        }
    }

    /**
     * The two cells BC's JCE layer refuses, against BC's LOW-LEVEL generators.
     * Independent code, so this is a real reference and not self-comparison —
     * and it is the only evidence available for KDF2/KDF3 with SHA-384.
     */
    @Test
    public void sha384DerivationsMatchBouncyCastlesLowLevelGenerators() throws Exception
    {
        Provider jsl = Security.getProvider(JSL);
        for (int trial = 0; trial < 6; trial++)
        {
            byte[] z = new byte[1 + RANDOM.nextInt(256)];
            RANDOM.nextBytes(z);
            byte[] otherInfo = new byte[RANDOM.nextInt(40)];
            RANDOM.nextBytes(otherInfo);
            int outLen = 1 + RANDOM.nextInt(160);

            byte[] ourKdf2 = KtsKdf.derive(jsl, KtsKdf.Kind.KDF2, "SHA-384", z, otherInfo, outLen);
            byte[] bcKdf2 = new byte[outLen];
            KDF2BytesGenerator g2 = new KDF2BytesGenerator(sha384());
            g2.init(new KDFParameters(z, otherInfo));
            g2.generateBytes(bcKdf2, 0, outLen);
            Assertions.assertTrue(Arrays.areEqual(ourKdf2, bcKdf2), "KDF2-SHA384 diverged from BC");

            byte[] ourKdf3 = KtsKdf.derive(jsl, KtsKdf.Kind.KDF3, "SHA-384", z, otherInfo, outLen);
            byte[] bcKdf3 = new byte[outLen];
            ConcatenationKDFGenerator g3 = new ConcatenationKDFGenerator(sha384());
            g3.init(new KDFParameters(z, otherInfo));
            g3.generateBytes(bcKdf3, 0, outLen);
            Assertions.assertTrue(Arrays.areEqual(ourKdf3, bcKdf3), "KDF3-SHA384 diverged from BC");

            // Differentiator: the two must not be the same derivation, or the
            // pair of assertions above would pass against one implementation
            // wired to both kinds.
            Assertions.assertFalse(Arrays.areEqual(ourKdf2, ourKdf3),
                    "KDF2 and KDF3 must differ on identical inputs");
        }
    }

    private static Digest sha384()
    {
        return new SHA384Digest();
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
