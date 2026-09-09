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

package org.openssl.jostle.test.rsa;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.test.util.CipherFamilies;
import org.openssl.jostle.test.util.ProviderSurfaceGuard;
import org.openssl.jostle.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.SortedSet;

/**
 * Cross-implementation agreement for Jostle's RSA surface: JSL against
 * BouncyCastle, both directions, across every registered name.
 *
 * <p>This is the family's SWEEP and its completeness GUARD. The depth stays
 * where it is — {@link RSATest} keeps the PSS/PKCS#1 parameter and
 * state-machine coverage, {@link RSAOAEPCipherTest} and
 * {@link RSAPKCS1CipherTest} the padding contracts, {@link RSAKEMCipherTest}
 * the KTS one.
 *
 * <p>The Signature sweep is discovery-driven: all 41 names are read from the
 * provider, and every one exists in BC too. Deterministic PKCS#1 is checked
 * for BYTE equality; PSS and both encryption paddings are randomised, so those
 * cross-verify and cross-decrypt instead.
 */
public class RSAAgreementTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    /** 2048 bits keeps every registered digest inside PSS's salt bound. */
    private static final int KEY_BITS = 2048;

    private static final SecureRandom RANDOM = new SecureRandom();

    private static KeyPair keyPair;

    private static SecureRandom seededRandom(String testName) throws Exception
    {
        long seed = RANDOM.nextLong();
        System.out.println(testName + " seed=" + seed);
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(seed);
        return sr;
    }

    @BeforeAll
    static void before() throws Exception
    {
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        // One keypair per JVM: generation is the expensive part and every test
        // here needs the SAME key in both providers anyway.
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", JSL);
        kpg.initialize(KEY_BITS);
        keyPair = kpg.generateKeyPair();
    }

    private static PublicKey bcPublic() throws Exception
    {
        return KeyFactory.getInstance("RSA", BC)
                .generatePublic(new X509EncodedKeySpec(keyPair.getPublic().getEncoded()));
    }

    private static PrivateKey bcPrivate() throws Exception
    {
        return KeyFactory.getInstance("RSA", BC)
                .generatePrivate(new PKCS8EncodedKeySpec(keyPair.getPrivate().getEncoded()));
    }

    /**
     * The registered Signature names, discovered rather than listed.
     * {@code NONEWITHRSA} is excluded: it signs a pre-hashed DigestInfo, not a
     * message, so it has no comparable form here —
     * {@link RSANoneWithRSASignatureTest} drives it against BC on its terms.
     */
    private static SortedSet<String> signatureNames()
    {
        SortedSet<String> names = ProviderSurfaceGuard.registeredSurface(
                Security.getProvider(JSL), CipherFamilies.RSA_PREFIX, new String[]{"Signature"});
        names.remove("Signature.NONEWITHRSA");
        return names;
    }

    /**
     * Service discovery returns each object identifier in BOTH registered
     * spellings — bare and JCA's {@code "OID."}-prefixed form — and the two
     * name the same algorithm. Classification by name must therefore
     * normalise, or the prefixed spelling falls into the wrong bucket: it was
     * driven as deterministic PKCS#1 rather than as PSS, and as a plain
     * Cipher rather than as KTS, when the prefixed aliases were first
     * registered.
     */
    private static String bareName(String alg)
    {
        String n = alg.toUpperCase(Locale.ROOT);
        return n.startsWith("OID.") ? n.substring("OID.".length()) : n;
    }

    /**
     * Name to ask BC for. The surface includes aliases, and the two JDK
     * spellings ({@code SHA512/224withRSA}) are the same algorithm under BC's
     * {@code SHA512(224)WITHRSA}, so translate rather than exclude — or the
     * alias drops out of every agreement sweep while the guard counts it
     * covered.
     */
    private static String bcName(String alg)
    {
        String n = bareName(alg);
        if (n.equals("SHA512/224WITHRSA"))
        {
            return "SHA512(224)WITHRSA";
        }
        if (n.equals("SHA512/256WITHRSA"))
        {
            return "SHA512(256)WITHRSA";
        }
        return alg;
    }

    /** PSS and MGF1 names are randomised; the rest are deterministic PKCS#1. */
    private static boolean isRandomised(String alg)
    {
        String n = bareName(alg);
        return n.contains("PSS") || n.contains("MGF1") || n.equals("1.2.840.113549.1.1.10");
    }

    /**
     * The two names whose digest comes from the SPI default, where Jostle
     * (SHA-256) deliberately differs from BC (SHA-1). Both need an EXPLICIT
     * spec — a default-vs-default comparison would assert the deviation away.
     * {@link #pssDefaultsDeliberatelyDifferFromBouncyCastle} pins it instead.
     */
    private static boolean usesSpiDefaultDigest(String alg)
    {
        String n = bareName(alg);
        return n.equals("RSASSA-PSS") || n.equals("1.2.840.113549.1.1.10");
    }

    private static final PSSParameterSpec PSS_SHA256 = new PSSParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);

    // -----------------------------------------------------------------
    // 1. Signature sweep
    // -----------------------------------------------------------------

    /**
     * Every registered Signature name: JSL signs / BC verifies, then the
     * reverse. Both directions, because a malformed-but-self-consistent
     * signature only shows up against the other parser. Failures are collected
     * and reported together.
     */
    @Test
    public void everyRegisteredSignatureAgreesWithBouncyCastle() throws Exception
    {
        SecureRandom sr = seededRandom("everyRegisteredSignatureAgreesWithBouncyCastle");
        SortedSet<String> names = signatureNames();
        Assertions.assertFalse(names.isEmpty(), "no RSA Signature names discovered");

        List<String> failures = new ArrayList<String>();
        for (String entry : names)
        {
            String alg = entry.substring("Signature.".length());
            byte[] msg = new byte[16 + sr.nextInt(200)];
            sr.nextBytes(msg);
            try
            {
                Signature joSign = Signature.getInstance(alg, JSL);
                if (usesSpiDefaultDigest(alg))
                {
                    joSign.setParameter(PSS_SHA256);
                }
                joSign.initSign(keyPair.getPrivate());
                joSign.update(msg);
                byte[] joSig = joSign.sign();

                Signature bcVerify = Signature.getInstance(bcName(alg), BC);
                if (usesSpiDefaultDigest(alg))
                {
                    bcVerify.setParameter(PSS_SHA256);
                }
                bcVerify.initVerify(bcPublic());
                bcVerify.update(msg);
                if (!bcVerify.verify(joSig))
                {
                    failures.add(alg + ": BC rejected a JSL signature");
                    continue;
                }

                Signature bcSign = Signature.getInstance(bcName(alg), BC);
                if (usesSpiDefaultDigest(alg))
                {
                    bcSign.setParameter(PSS_SHA256);
                }
                bcSign.initSign(bcPrivate());
                bcSign.update(msg);
                byte[] bcSig = bcSign.sign();

                Signature joVerify = Signature.getInstance(alg, JSL);
                if (usesSpiDefaultDigest(alg))
                {
                    joVerify.setParameter(PSS_SHA256);
                }
                joVerify.initVerify(keyPair.getPublic());
                joVerify.update(msg);
                if (!joVerify.verify(bcSig))
                {
                    failures.add(alg + ": JSL rejected a BC signature");
                }
            }
            catch (Throwable t)
            {
                failures.add(alg + " -> " + t.getClass().getSimpleName() + ": " + t.getMessage());
            }
        }

        Assertions.assertTrue(failures.isEmpty(),
                "RSA Signature names that did not agree with BouncyCastle ("
                        + failures.size() + " of " + names.size() + "):\n  "
                        + String.join("\n  ", failures));
    }

    /**
     * The deterministic half, checked for byte equality. Cross-verification
     * alone would accept a wrong-digest signature if both providers made the
     * same substitution. PSS is excluded — its salt is fresh per call.
     */
    @Test
    public void deterministicSignaturesAreByteIdenticalToBouncyCastle() throws Exception
    {
        SecureRandom sr = seededRandom("deterministicSignaturesAreByteIdenticalToBouncyCastle");
        List<String> failures = new ArrayList<String>();
        int checked = 0;

        for (String entry : signatureNames())
        {
            String alg = entry.substring("Signature.".length());
            if (isRandomised(alg))
            {
                continue;
            }
            checked++;
            byte[] msg = new byte[32 + sr.nextInt(100)];
            sr.nextBytes(msg);

            Signature joSign = Signature.getInstance(alg, JSL);
            joSign.initSign(keyPair.getPrivate());
            joSign.update(msg);
            byte[] joSig = joSign.sign();

            Signature bcSign = Signature.getInstance(bcName(alg), BC);
            bcSign.initSign(bcPrivate());
            bcSign.update(msg);
            byte[] bcSig = bcSign.sign();

            if (!Arrays.areEqual(joSig, bcSig))
            {
                failures.add(alg);
            }
        }

        Assertions.assertTrue(checked > 0, "no deterministic RSA signature names were checked");
        Assertions.assertTrue(failures.isEmpty(),
                "deterministic RSA signatures that differ from BouncyCastle: " + failures);
    }

    /**
     * The differentiator the sweep needs. A tampered message must fail
     * verification on every registered name, in both providers — without it,
     * a verifier stubbed to return true would satisfy every assertion above.
     */
    @Test
    public void tamperedMessageFailsVerificationOnEveryName() throws Exception
    {
        SecureRandom sr = seededRandom("tamperedMessageFailsVerificationOnEveryName");
        List<String> failures = new ArrayList<String>();

        for (String entry : signatureNames())
        {
            String alg = entry.substring("Signature.".length());
            byte[] msg = new byte[64];
            sr.nextBytes(msg);

            Signature joSign = Signature.getInstance(alg, JSL);
            if (usesSpiDefaultDigest(alg))
            {
                joSign.setParameter(PSS_SHA256);
            }
            joSign.initSign(keyPair.getPrivate());
            joSign.update(msg);
            byte[] sig = joSign.sign();

            byte[] tampered = Arrays.clone(msg);
            tampered[sr.nextInt(tampered.length)] ^= (byte) 0x01;

            Signature joVerify = Signature.getInstance(alg, JSL);
            if (usesSpiDefaultDigest(alg))
            {
                joVerify.setParameter(PSS_SHA256);
            }
            joVerify.initVerify(keyPair.getPublic());
            joVerify.update(tampered);
            if (joVerify.verify(sig))
            {
                failures.add(alg + ": JSL verified a tampered message");
            }

            Signature bcVerify = Signature.getInstance(bcName(alg), BC);
            if (usesSpiDefaultDigest(alg))
            {
                bcVerify.setParameter(PSS_SHA256);
            }
            bcVerify.initVerify(bcPublic());
            bcVerify.update(tampered);
            if (bcVerify.verify(sig))
            {
                failures.add(alg + ": BC verified a tampered message");
            }
        }

        Assertions.assertTrue(failures.isEmpty(), "tampering was not detected: " + failures);
    }

    // -----------------------------------------------------------------
    // 2. Cipher sweep
    // -----------------------------------------------------------------

    /** Jostle's bare "RSA" is OAEP with this digest; BC's bare "RSA" is PKCS#1 v1.5. */
    private static final OAEPParameterSpec OAEP_SHA256 = new OAEPParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);

    /**
     * The two encryption paddings, both directions. Randomised, so the check
     * is that each provider decrypts the other's ciphertext.
     *
     * <p>Named transformations on both sides: the bare "RSA" name means
     * different things in the two providers, which
     * {@link #bareRsaCipherNameDeliberatelyDiffersFromBouncyCastle} pins.
     * RSA-KTS-KEM-KWS is excluded — it needs a {@code KTSParameterSpec}, and
     * {@link RSAKEMCipherTest} agrees it on its own terms.
     */
    @Test
    public void encryptionPaddingsAgreeBothDirections() throws Exception
    {
        SecureRandom sr = seededRandom("encryptionPaddingsAgreeBothDirections");

        for (String xform : new String[]{
                "RSA/ECB/OAEPWithSHA-256AndMGF1Padding", "RSA/ECB/PKCS1Padding"})
        {
            boolean oaep = xform.contains("OAEP");
            for (int trial = 0; trial < 5; trial++)
            {
                byte[] msg = new byte[1 + sr.nextInt(64)];
                sr.nextBytes(msg);

                Cipher joEnc = Cipher.getInstance(xform, JSL);
                initCipher(joEnc, Cipher.ENCRYPT_MODE, keyPair.getPublic(), oaep, sr);
                byte[] joCt = joEnc.doFinal(msg);

                Cipher bcDec = Cipher.getInstance(xform, BC);
                initCipher(bcDec, Cipher.DECRYPT_MODE, bcPrivate(), oaep, sr);
                Assertions.assertTrue(Arrays.areEqual(msg, bcDec.doFinal(joCt)),
                        xform + " trial " + trial + ": BC could not decrypt JSL ciphertext");

                Cipher bcEnc = Cipher.getInstance(xform, BC);
                initCipher(bcEnc, Cipher.ENCRYPT_MODE, bcPublic(), oaep, sr);
                byte[] bcCt = bcEnc.doFinal(msg);

                Cipher joDec = Cipher.getInstance(xform, JSL);
                initCipher(joDec, Cipher.DECRYPT_MODE, keyPair.getPrivate(), oaep, sr);
                Assertions.assertTrue(Arrays.areEqual(msg, joDec.doFinal(bcCt)),
                        xform + " trial " + trial + ": JSL could not decrypt BC ciphertext");

                // Randomised padding: the same plaintext twice must not give
                // the same ciphertext, or the padding is not being applied.
                Cipher again = Cipher.getInstance(xform, JSL);
                initCipher(again, Cipher.ENCRYPT_MODE, keyPair.getPublic(), oaep, sr);
                Assertions.assertFalse(Arrays.areEqual(joCt, again.doFinal(msg)),
                        xform + ": two encryptions of the same plaintext were identical");
            }
        }
    }

    private static void initCipher(Cipher c, int mode, java.security.Key key,
                                   boolean oaep, SecureRandom sr) throws Exception
    {
        if (oaep)
        {
            c.init(mode, key, OAEP_SHA256, sr);
        }
        else
        {
            c.init(mode, key, sr);
        }
    }

    // -----------------------------------------------------------------
    // 2b. The deliberate deviations from BouncyCastle, pinned
    // -----------------------------------------------------------------

    /**
     * Jostle's bare {@code Cipher.getInstance("RSA")} is OAEP-SHA-256;
     * BouncyCastle's is PKCS#1 v1.5. Deliberate, and invisible unless
     * asserted — both round-trip fine within their own provider. A caller
     * porting from BC gets a different wire format from the same code.
     */
    @Test
    public void bareRsaCipherNameDeliberatelyDiffersFromBouncyCastle() throws Exception
    {
        SecureRandom sr = seededRandom("bareRsaCipherNameDeliberatelyDiffersFromBouncyCastle");
        byte[] msg = new byte[32];
        sr.nextBytes(msg);

        Cipher bare = Cipher.getInstance("RSA", JSL);
        bare.init(Cipher.ENCRYPT_MODE, keyPair.getPublic(), sr);
        byte[] ct = bare.doFinal(msg);

        Cipher asOaep = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", JSL);
        asOaep.init(Cipher.DECRYPT_MODE, keyPair.getPrivate(), OAEP_SHA256);
        Assertions.assertTrue(Arrays.areEqual(msg, asOaep.doFinal(ct)),
                "the bare RSA name is no longer OAEP-SHA-256");

        Cipher asPkcs1 = Cipher.getInstance("RSA/ECB/PKCS1Padding", JSL);
        asPkcs1.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        boolean opened;
        try
        {
            opened = Arrays.areEqual(msg, asPkcs1.doFinal(ct));
        }
        catch (Exception e)
        {
            opened = false;
        }
        Assertions.assertFalse(opened,
                "the bare RSA name produced PKCS#1 v1.5 — BC's meaning, not Jostle's");
    }

    /**
     * With no explicit spec, Jostle's PSS digest defaults to SHA-256 and BC's
     * to SHA-1, so the bare name does NOT interoperate. Deliberate, and the
     * reason the sweep passes an explicit spec for those two names. Asserted
     * rather than assumed: change the default and this fails, where the sweep
     * would keep passing.
     */
    @Test
    public void pssDefaultsDeliberatelyDifferFromBouncyCastle() throws Exception
    {
        SecureRandom sr = seededRandom("pssDefaultsDeliberatelyDifferFromBouncyCastle");
        byte[] msg = new byte[48];
        sr.nextBytes(msg);

        Signature joSign = Signature.getInstance("RSASSA-PSS", JSL);
        joSign.initSign(keyPair.getPrivate());
        joSign.update(msg);
        byte[] sig = joSign.sign();

        Signature bcDefault = Signature.getInstance("RSASSA-PSS", BC);
        bcDefault.initVerify(bcPublic());
        bcDefault.update(msg);
        Assertions.assertFalse(bcDefault.verify(sig),
                "BC's default-PSS verifier accepted a Jostle default-PSS signature — "
                        + "the documented SHA-256 vs SHA-1 default deviation is gone");

        // ...and the same signature DOES verify once BC is told SHA-256, which
        // proves the difference is the digest default and not a broken signer.
        Signature bcExplicit = Signature.getInstance("RSASSA-PSS", BC);
        bcExplicit.setParameter(PSS_SHA256);
        bcExplicit.initVerify(bcPublic());
        bcExplicit.update(msg);
        Assertions.assertTrue(bcExplicit.verify(sig),
                "BC could not verify a Jostle PSS signature even with SHA-256 named explicitly");
    }

    // -----------------------------------------------------------------
    // 3. Key encodings cross in both directions
    // -----------------------------------------------------------------

    /**
     * Keys must survive a round trip through the other provider's KeyFactory
     * and still operate. "Still operate" is the load-bearing half: a key that
     * re-derives but has lost its algorithm identifier passes a
     * decode-succeeded assertion and fails at a peer.
     */
    @Test
    public void keyEncodingsCrossBothDirections() throws Exception
    {
        SecureRandom sr = seededRandom("keyEncodingsCrossBothDirections");

        PublicKey viaBcPub = bcPublic();
        PrivateKey viaBcPriv = bcPrivate();
        Assertions.assertTrue(Arrays.areEqual(keyPair.getPublic().getEncoded(), viaBcPub.getEncoded()),
                "BC re-encoded a JSL public key differently");
        Assertions.assertTrue(Arrays.areEqual(keyPair.getPrivate().getEncoded(), viaBcPriv.getEncoded()),
                "BC re-encoded a JSL private key differently");

        KeyPairGenerator bcKpg = KeyPairGenerator.getInstance("RSA", BC);
        bcKpg.initialize(KEY_BITS);
        KeyPair bcPair = bcKpg.generateKeyPair();

        PublicKey viaJoPub = KeyFactory.getInstance("RSA", JSL)
                .generatePublic(new X509EncodedKeySpec(bcPair.getPublic().getEncoded()));
        PrivateKey viaJoPriv = KeyFactory.getInstance("RSA", JSL)
                .generatePrivate(new PKCS8EncodedKeySpec(bcPair.getPrivate().getEncoded()));
        Assertions.assertTrue(Arrays.areEqual(bcPair.getPublic().getEncoded(), viaJoPub.getEncoded()),
                "JSL re-encoded a BC public key differently");
        Assertions.assertTrue(Arrays.areEqual(bcPair.getPrivate().getEncoded(), viaJoPriv.getEncoded()),
                "JSL re-encoded a BC private key differently");

        // The round-tripped BC keypair still signs and verifies under JSL.
        byte[] msg = new byte[48];
        sr.nextBytes(msg);
        Signature s = Signature.getInstance("SHA256withRSA", JSL);
        s.initSign(viaJoPriv);
        s.update(msg);
        byte[] sig = s.sign();

        Signature v = Signature.getInstance("SHA256withRSA", JSL);
        v.initVerify(viaJoPub);
        v.update(msg);
        Assertions.assertTrue(v.verify(sig), "a round-tripped BC keypair no longer operates under JSL");
    }

    // -----------------------------------------------------------------
    // 4. Completeness guards
    // -----------------------------------------------------------------

    private static final String[] GUARDED_TYPES = {"Cipher", "KeyFactory", "KeyPairGenerator", "Signature"};

    /**
     * Every RSA service JSL registers is DRIVEN, with the surface discovered
     * from the provider rather than listed.
     *
     * <p>No covered list on purpose: a fifty-entry list drifts, and deriving
     * one from the provider would compare the provider against itself — a
     * guard that always passes. An unknown name THROWS below, so a
     * registration added later fails until someone teaches it an operation.
     *
     * <p>What discovery cannot see is a REMOVED registration; that belongs in
     * one provider-wide golden snapshot, not a list per family.
     */
    @Test
    public void everyRegisteredRsaServiceIsDriven() throws Exception
    {
        final SecureRandom sr = seededRandom("everyRegisteredRsaServiceIsDriven");

        ProviderSurfaceGuard.assertEveryServiceDriven(Security.getProvider(JSL),
                CipherFamilies.RSA_PREFIX, "RSA (JSL)", GUARDED_TYPES,
                new ProviderSurfaceGuard.ServiceDriver()
                {
                    public void drive(String type, String alg) throws Exception
                    {
                        if ("Signature".equals(type))
                        {
                            driveSignature(alg, sr);
                        }
                        else if ("Cipher".equals(type))
                        {
                            driveCipher(alg, sr);
                        }
                        else if ("KeyFactory".equals(type))
                        {
                            PublicKey pub = KeyFactory.getInstance(alg, JSL)
                                    .generatePublic(new X509EncodedKeySpec(
                                            keyPair.getPublic().getEncoded()));
                            Assertions.assertTrue(Arrays.areEqual(
                                    keyPair.getPublic().getEncoded(), pub.getEncoded()), alg);
                        }
                        else if ("KeyPairGenerator".equals(type))
                        {
                            KeyPairGenerator kpg = KeyPairGenerator.getInstance(alg, JSL);
                            kpg.initialize(KEY_BITS);
                            Assertions.assertNotNull(kpg.generateKeyPair());
                        }
                        else
                        {
                            throw new IllegalStateException("no drive defined for " + type + "." + alg
                                    + " — teach this driver rather than letting it go unexercised");
                        }
                    }
                });
    }

    /**
     * Sign and verify under one registered name. {@code NONEwithRSA} takes a
     * pre-hashed DigestInfo rather than a message, so it is fed one.
     */
    private static void driveSignature(String alg, SecureRandom sr) throws Exception
    {
        byte[] msg = new byte[32];
        sr.nextBytes(msg);

        Signature sign = Signature.getInstance(alg, JSL);
        if (usesSpiDefaultDigest(alg))
        {
            sign.setParameter(PSS_SHA256);
        }
        sign.initSign(keyPair.getPrivate());
        sign.update(alg.equalsIgnoreCase("NONEWITHRSA") ? digestInfoSha256(msg) : msg);
        byte[] sig = sign.sign();

        Signature verify = Signature.getInstance(alg, JSL);
        if (usesSpiDefaultDigest(alg))
        {
            verify.setParameter(PSS_SHA256);
        }
        verify.initVerify(keyPair.getPublic());
        verify.update(alg.equalsIgnoreCase("NONEWITHRSA") ? digestInfoSha256(msg) : msg);
        Assertions.assertTrue(verify.verify(sig), alg + ": did not verify its own signature");
    }

    /** A SHA-256 DigestInfo, which is what NONEwithRSA expects to be handed. */
    private static byte[] digestInfoSha256(byte[] msg) throws Exception
    {
        byte[] h = java.security.MessageDigest.getInstance("SHA-256").digest(msg);
        byte[] prefix = org.openssl.jostle.util.encoders.Hex.decode(
                "3031300d060960864801650304020105000420");
        byte[] out = new byte[prefix.length + h.length];
        System.arraycopy(prefix, 0, out, 0, prefix.length);
        System.arraycopy(h, 0, out, prefix.length, h.length);
        return out;
    }

    /**
     * Encrypt/decrypt or wrap/unwrap under one registered Cipher name. The KTS
     * names need a {@code KTSParameterSpec}; the rest take a plaintext.
     */
    private static void driveCipher(String alg, SecureRandom sr) throws Exception
    {
        String n = bareName(alg);
        boolean kts = n.contains("KTS") || n.equals("1.0.18033.2.2.4")
                || n.equals("1.2.840.113549.1.9.16.3.14");

        if (kts)
        {
            byte[] cekBytes = new byte[32];
            sr.nextBytes(cekBytes);
            javax.crypto.spec.SecretKeySpec cek =
                    new javax.crypto.spec.SecretKeySpec(cekBytes, "AES");
            org.bouncycastle.jcajce.spec.KTSParameterSpec spec =
                    new org.bouncycastle.jcajce.spec.KTSParameterSpec.Builder("AES", 256)
                            .withKdfAlgorithm(new org.bouncycastle.asn1.x509.AlgorithmIdentifier(
                                    org.bouncycastle.asn1.x9.X9ObjectIdentifiers.id_kdf_kdf3,
                                    new org.bouncycastle.asn1.x509.AlgorithmIdentifier(
                                            org.bouncycastle.asn1.nist.NISTObjectIdentifiers.id_sha256)))
                            .build();

            Cipher w = Cipher.getInstance(alg, JSL);
            w.init(Cipher.WRAP_MODE, keyPair.getPublic(), spec);
            byte[] wrapped = w.wrap(cek);
            Cipher u = Cipher.getInstance(alg, JSL);
            u.init(Cipher.UNWRAP_MODE, keyPair.getPrivate(), spec);
            Assertions.assertTrue(Arrays.areEqual(cekBytes,
                    u.unwrap(wrapped, "AES", Cipher.SECRET_KEY).getEncoded()), alg);
            return;
        }

        byte[] msg = new byte[32];
        sr.nextBytes(msg);
        Cipher enc = Cipher.getInstance(alg, JSL);
        enc.init(Cipher.ENCRYPT_MODE, keyPair.getPublic(), sr);
        byte[] ct = enc.doFinal(msg);
        Assertions.assertFalse(Arrays.areEqual(msg, ct),
                alg + ": ciphertext equals plaintext — no transform");
        Cipher dec = Cipher.getInstance(alg, JSL);
        dec.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        Assertions.assertTrue(Arrays.areEqual(msg, dec.doFinal(ct)), alg + ": round trip");
    }
}
