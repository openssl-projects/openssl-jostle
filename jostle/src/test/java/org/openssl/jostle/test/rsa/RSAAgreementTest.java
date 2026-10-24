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

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.spec.KTSParameterSpec;
import org.openssl.jostle.test.util.CipherFamilies;
import org.openssl.jostle.test.util.ProviderSurfaceGuard;
import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.encoders.Hex;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.SortedSet;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.MessageDigest;

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

    private static void initCipher(Cipher c, int mode, Key key,
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
        byte[] h = MessageDigest.getInstance("SHA-256").digest(msg);
        byte[] prefix = Hex.decode(
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
            SecretKeySpec cek =
                    new SecretKeySpec(cekBytes, "AES");
            KTSParameterSpec spec =
                    new KTSParameterSpec.Builder("AES", 256)
                            .withKdfAlgorithm(new AlgorithmIdentifier(
                                    X9ObjectIdentifiers.id_kdf_kdf3,
                                    new AlgorithmIdentifier(
                                            NISTObjectIdentifiers.id_sha256)).getEncoded())
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

    private static final String SUN = "SunRsaSign";

    private static byte[] randomMessage()
    {
        byte[] m = new byte[1 + RANDOM.nextInt(200)];
        RANDOM.nextBytes(m);
        return m;
    }

    private static PSSParameterSpec pss(String digest, int salt)
    {
        return new PSSParameterSpec(digest, "MGF1", new MGF1ParameterSpec(digest), salt, 1);
    }

    private static boolean verifies(String alg, String provider, PSSParameterSpec spec, byte[] msg, byte[] sig)
        throws Exception
    {
        Signature v = Signature.getInstance(alg, provider);
        if (spec != null)
        {
            v.setParameter(spec);
        }
        v.initVerify(keyPair.getPublic());
        v.update(msg);
        return v.verify(sig);
    }

    /** NoneWithRSA one byte past k - 11: ours refuses at the update that passes it, BC at sign; both typed. */
    @Test
    public void noneWithRsaPastTheBoundIsASignatureExceptionOnBothProviders() throws Exception
    {
        byte[] tooLong = new byte[KEY_BITS / 8 - 10];
        RANDOM.nextBytes(tooLong);
        Signature ours = Signature.getInstance("NoneWithRSA", JSL);
        ours.initSign(keyPair.getPrivate());
        Assertions.assertThrows(SignatureException.class, () -> ours.update(tooLong));

        Signature bc = Signature.getInstance("NoneWithRSA", BC);
        bc.initSign(bcPrivate());
        bc.update(tooLong);
        Assertions.assertThrows(SignatureException.class, bc::sign);
    }

    /** Parameters set after initSign are the ones signed under: SunRsaSign and BC verify under them. */
    @Test
    public void pssParametersSetAfterInitAreSignedUnder() throws Exception
    {
        byte[] msg = randomMessage();
        PSSParameterSpec sha384 = pss("SHA-384", 48);
        Signature signer = Signature.getInstance("RSASSA-PSS", JSL);
        signer.initSign(keyPair.getPrivate());
        signer.setParameter(sha384);
        signer.update(msg);
        byte[] sig = signer.sign();
        Assertions.assertTrue(verifies("RSASSA-PSS", SUN, sha384, msg, sig), "SunRsaSign");
        Assertions.assertTrue(verifies("RSASSA-PSS", BC, sha384, msg, sig), "BC");
        Assertions.assertFalse(verifies("RSASSA-PSS", SUN, pss("SHA-256", 32), msg, sig), "earlier parameters");
    }

    /**
     * A salt past the key is refused at init. Ours and SunRsaSign: InvalidKeyException naming the minimum. BC
     * throws an unchecked IllegalArgumentException from init, outside the JCE contract; pinned as the divergence.
     */
    @Test
    public void pssSaltPastTheKeyIsRefusedAtInit() throws Exception
    {
        PSSParameterSpec over = pss("SHA-256", 223);
        for (String provider : new String[]{JSL, SUN})
        {
            Signature s = Signature.getInstance("RSASSA-PSS", provider);
            s.setParameter(over);
            InvalidKeyException e = Assertions.assertThrows(InvalidKeyException.class,
                    () -> s.initSign(provider.equals(JSL) ? keyPair.getPrivate() : sunPrivate()), provider);
            // JDK 8's SunRsaSign wraps the same text in a SignatureException message; the reason is the same.
            Assertions.assertTrue(e.getMessage().endsWith("Key is too short, need min 257 bytes"), provider);
            if (provider.equals(JSL))
            {
                Assertions.assertEquals("Key is too short, need min 257 bytes", e.getMessage());
            }
        }
        Signature bc = Signature.getInstance("RSASSA-PSS", BC);
        bc.setParameter(over);
        Assertions.assertThrows(IllegalArgumentException.class, () -> bc.initSign(bcPrivate()));

        byte[] msg = randomMessage();
        Signature max = Signature.getInstance("RSASSA-PSS", JSL);
        max.setParameter(pss("SHA-256", 222));
        max.initSign(keyPair.getPrivate());
        max.update(msg);
        byte[] sig = max.sign();
        Assertions.assertTrue(verifies("RSASSA-PSS", SUN, pss("SHA-256", 222), msg, sig));
        Assertions.assertTrue(verifies("RSASSA-PSS", BC, pss("SHA-256", 222), msg, sig));
    }

    /** A digest too long for the key fails at sign as SignatureException, ours and BC's. */
    @Test
    public void aDigestTooLongForTheKeyIsASignatureExceptionOnBothProviders() throws Exception
    {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA", JSL);
        g.initialize(512);
        KeyPair small = g.generateKeyPair();
        byte[] msg = randomMessage();
        Signature ours = Signature.getInstance("SHA512withRSA", JSL);
        ours.initSign(small.getPrivate());
        ours.update(msg);
        Assertions.assertThrows(SignatureException.class, ours::sign);

        Signature bc = Signature.getInstance("SHA512withRSA", BC);
        bc.initSign(KeyFactory.getInstance("RSA", BC).generatePrivate(
                new PKCS8EncodedKeySpec(small.getPrivate().getEncoded())));
        bc.update(msg);
        Assertions.assertThrows(SignatureException.class, bc::sign);
    }

    /**
     * BouncyCastle's non-CRT private key encodes e = 0, and OpenSSL cannot sign without e, so translation refuses
     * it typed rather than returning a key whose signatures do not verify; BC itself signs with it.
     */
    @Test
    public void bouncyCastleNonCrtKeyWithoutExponentIsRefusedTyped() throws Exception
    {
        RSAPrivateCrtKey crt = (RSAPrivateCrtKey) sunPrivate();
        PrivateKey bcNonCrt = KeyFactory.getInstance("RSA", BC).generatePrivate(
                new RSAPrivateKeySpec(crt.getModulus(), crt.getPrivateExponent()));
        InvalidKeyException e = Assertions.assertThrows(InvalidKeyException.class,
                () -> KeyFactory.getInstance("RSA", JSL).translateKey(bcNonCrt));
        Assertions.assertEquals("RSA private key without CRT components or public exponent is not supported"
                + " - OpenSSL requires the public exponent to construct an EVP_PKEY", e.getMessage());

        byte[] msg = randomMessage();
        Signature bc = Signature.getInstance("SHA256withRSA", BC);
        bc.initSign(bcNonCrt);
        bc.update(msg);
        byte[] sig = bc.sign();
        Signature ours = Signature.getInstance("SHA256withRSA", JSL);
        ours.initVerify(keyPair.getPublic());
        ours.update(msg);
        Assertions.assertTrue(ours.verify(sig));
    }

    /** verify(null): ours the declared SignatureException, BC false; pinned as the divergence. */
    @Test
    public void verifyNullIsASignatureExceptionWhereBouncyCastleAnswersFalse() throws Exception
    {
        Signature ours = Signature.getInstance("SHA256withRSA", JSL);
        ours.initVerify(keyPair.getPublic());
        ours.update(new byte[16]);
        Assertions.assertThrows(SignatureException.class, () -> ours.verify(null));

        Signature bc = Signature.getInstance("SHA256withRSA", BC);
        bc.initVerify(keyPair.getPublic());
        bc.update(new byte[16]);
        Assertions.assertFalse(bc.verify(null));
    }

    /**
     * A named PSS signature accepts a known digest other than its name's, signing under it; BC refuses one,
     * pinned beside ours as the divergence.
     */
    @Test
    public void namedPssAcceptsAnotherKnownDigestWhereBouncyCastleRefuses() throws Exception
    {
        byte[] msg = randomMessage();
        PSSParameterSpec sha384 = pss("SHA-384", 48);
        Signature ours = Signature.getInstance("SHA256WITHRSAANDMGF1", JSL);
        ours.setParameter(sha384);
        ours.initSign(keyPair.getPrivate());
        ours.update(msg);
        Assertions.assertTrue(verifies("RSASSA-PSS", BC, sha384, msg, ours.sign()));

        InvalidAlgorithmParameterException e = Assertions.assertThrows(InvalidAlgorithmParameterException.class,
                () -> Signature.getInstance("SHA256WITHRSAANDMGF1", BC).setParameter(sha384));
        Assertions.assertEquals("parameter must be using SHA-256", e.getMessage());
    }

    private static PrivateKey sunPrivate() throws Exception
    {
        return KeyFactory.getInstance("RSA", SUN).generatePrivate(
                new PKCS8EncodedKeySpec(keyPair.getPrivate().getEncoded()));
    }


    private static final String SUN_JCE = "SunJCE";

    /** OAEP specs non-DEFAULT in turn in each field, and the all-DEFAULT one. */
    private static OAEPParameterSpec[] oaepSpecs()
    {
        return new OAEPParameterSpec[]{
                OAEPParameterSpec.DEFAULT,
                new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT),
                new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256,
                        new PSource.PSpecified(new byte[]{1, 2, 3})),
                new OAEPParameterSpec("SHA-1", "MGF1", MGF1ParameterSpec.SHA1, new PSource.PSpecified(new byte[]{9}))};
    }

    private static String describe(OAEPParameterSpec spec)
    {
        return spec.getDigestAlgorithm() + "/" + ((MGF1ParameterSpec) spec.getMGFParameters()).getDigestAlgorithm()
                + "/" + ((PSource.PSpecified) spec.getPSource()).getValue().length;
    }

    private static void assertSameOaep(OAEPParameterSpec want, OAEPParameterSpec got, String what)
    {
        Assertions.assertEquals(want.getDigestAlgorithm(), got.getDigestAlgorithm(), what);
        Assertions.assertEquals(((MGF1ParameterSpec) want.getMGFParameters()).getDigestAlgorithm(),
                ((MGF1ParameterSpec) got.getMGFParameters()).getDigestAlgorithm(), what);
        Assertions.assertArrayEquals(((PSource.PSpecified) want.getPSource()).getValue(),
                ((PSource.PSpecified) got.getPSource()).getValue(), what);
    }

    /**
     * OAEP AlgorithmParameters on the provider named: DER byte-equal to BouncyCastle's, decodable by SunJCE, and
     * decoding both references' encodings (SunJCE writes every DEFAULT out); an OAEP cipher's getParameters
     * answers the same bytes for the spec it was initialised with.
     */
    public static void assertOaepParametersAgree(String ours, PublicKey publicKey) throws Exception
    {
        for (OAEPParameterSpec spec : oaepSpecs())
        {
            String what = describe(spec);
            AlgorithmParameters mine = AlgorithmParameters.getInstance("OAEP", ours);
            mine.init(spec);
            AlgorithmParameters bc = AlgorithmParameters.getInstance("OAEP", BC);
            bc.init(spec);
            Assertions.assertEquals(Hex.toHexString(bc.getEncoded()), Hex.toHexString(mine.getEncoded()), what);

            AlgorithmParameters sun = AlgorithmParameters.getInstance("OAEP", SUN_JCE);
            sun.init(mine.getEncoded());
            assertSameOaep(spec, sun.getParameterSpec(OAEPParameterSpec.class), what + " SunJCE decodes ours");

            for (byte[] theirs : new byte[][]{bc.getEncoded(), sunEncoding(spec)})
            {
                AlgorithmParameters back = AlgorithmParameters.getInstance("OAEP", ours);
                back.init(theirs);
                assertSameOaep(spec, back.getParameterSpec(OAEPParameterSpec.class), what + " ours decodes");
            }

            Cipher c = Cipher.getInstance("RSA/ECB/OAEPPadding", ours);
            c.init(Cipher.ENCRYPT_MODE, publicKey, spec);
            Assertions.assertEquals(Hex.toHexString(bc.getEncoded()),
                    Hex.toHexString(c.getParameters().getEncoded()), what + " cipher");
        }
    }

    private static byte[] sunEncoding(OAEPParameterSpec spec) throws Exception
    {
        AlgorithmParameters sun = AlgorithmParameters.getInstance("OAEP", SUN_JCE);
        sun.init(spec);
        return sun.getEncoded();
    }

    /**
     * The OAEP input bound on the provider named, at 2048 bits: k - 2hLen - 2 encrypts, one more is refused with
     * IllegalBlockSizeException naming the limit through doFinal and through update; decrypt refuses past k the
     * same way. SunJCE refuses with the same type and message; BouncyCastle refuses the same inputs with an
     * unchecked ArrayIndexOutOfBoundsException, off the JCA contract. All three halves are pinned.
     */
    public static void assertOaepBoundsBesideBouncyCastle(String ours, PublicKey publicKey, PrivateKey privateKey,
                                                          PublicKey bcPublicKey, PrivateKey bcPrivateKey)
        throws Exception
    {
        KeyFactory sunKf = KeyFactory.getInstance("RSA", "SunRsaSign");
        KeyPair sunKeys = new KeyPair(sunKf.generatePublic(new X509EncodedKeySpec(publicKey.getEncoded())),
                sunKf.generatePrivate(new PKCS8EncodedKeySpec(privateKey.getEncoded())));
        String[][] rows = {{"SHA-1", "214"}, {"SHA-256", "190"}, {"SHA-512", "126"}};
        for (String[] row : rows)
        {
            String xf = "RSA/ECB/OAEPWith" + row[0] + "AndMGF1Padding";
            int limit = Integer.parseInt(row[1]);
            String refusal = "Data must not be longer than " + limit + " bytes";

            Cipher c = Cipher.getInstance(xf, ours);
            c.init(Cipher.ENCRYPT_MODE, publicKey);
            Assertions.assertEquals(256, c.doFinal(new byte[limit]).length, xf);
            IllegalBlockSizeException e = Assertions.assertThrows(IllegalBlockSizeException.class,
                    () -> c.doFinal(new byte[limit + 1]), xf);
            Assertions.assertEquals(refusal, e.getMessage(), xf);
            c.update(new byte[limit]);
            e = Assertions.assertThrows(IllegalBlockSizeException.class, () -> c.doFinal(new byte[1]), xf);
            Assertions.assertEquals(refusal, e.getMessage(), xf + " update");
            Assertions.assertEquals(256, c.doFinal(new byte[limit]).length, xf + " after a refusal");

            Cipher bc = Cipher.getInstance(xf, BC);
            bc.init(Cipher.ENCRYPT_MODE, bcPublicKey);
            Assertions.assertEquals(256, bc.doFinal(new byte[limit]).length, xf);
            Assertions.assertThrows(ArrayIndexOutOfBoundsException.class, () -> bc.doFinal(new byte[limit + 1]), xf);

            Cipher sun = Cipher.getInstance(xf, SUN_JCE);
            sun.init(Cipher.ENCRYPT_MODE, sunKeys.getPublic());
            Assertions.assertEquals(256, sun.doFinal(new byte[limit]).length, xf);
            e = Assertions.assertThrows(IllegalBlockSizeException.class, () -> sun.doFinal(new byte[limit + 1]), xf);
            Assertions.assertEquals(refusal, e.getMessage(), xf + " SunJCE");
        }

        Cipher d = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", ours);
        d.init(Cipher.DECRYPT_MODE, privateKey);
        IllegalBlockSizeException e = Assertions.assertThrows(IllegalBlockSizeException.class,
                () -> d.doFinal(new byte[257]));
        Assertions.assertEquals("Data must not be longer than 256 bytes", e.getMessage());
        Cipher bd = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", BC);
        bd.init(Cipher.DECRYPT_MODE, bcPrivateKey);
        Assertions.assertThrows(ArrayIndexOutOfBoundsException.class, () -> bd.doFinal(new byte[257]));
        Cipher sd = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", SUN_JCE);
        sd.init(Cipher.DECRYPT_MODE, sunKeys.getPrivate());
        e = Assertions.assertThrows(IllegalBlockSizeException.class, () -> sd.doFinal(new byte[257]));
        Assertions.assertEquals("Data must not be longer than 256 bytes", e.getMessage(), "SunJCE");
    }

    @Test
    public void oaepParametersAgreeWithBouncyCastleAndSunJce() throws Exception
    {
        assertOaepParametersAgree(JSL, keyPair.getPublic());
    }

    @Test
    public void oaepBoundsBesideBouncyCastle() throws Exception
    {
        assertOaepBoundsBesideBouncyCastle(JSL, keyPair.getPublic(), keyPair.getPrivate(), bcPublic(), bcPrivate());
    }

    /** SunJCE's keys for the shared pair, through SunRsaSign, which serves its RSA keys. */
    private static KeyPair sunPair() throws Exception
    {
        KeyFactory kf = KeyFactory.getInstance("RSA", "SunRsaSign");
        return new KeyPair(kf.generatePublic(new X509EncodedKeySpec(keyPair.getPublic().getEncoded())),
                kf.generatePrivate(new PKCS8EncodedKeySpec(keyPair.getPrivate().getEncoded())));
    }

    private static byte[] encrypt(String xf, String provider, PublicKey key, byte[] msg) throws Exception
    {
        Cipher c = Cipher.getInstance(xf, provider);
        c.init(Cipher.ENCRYPT_MODE, key);
        return c.doFinal(msg);
    }

    private static byte[] decrypt(String xf, String provider, PrivateKey key, byte[] ct) throws Exception
    {
        Cipher c = Cipher.getInstance(xf, provider);
        c.init(Cipher.DECRYPT_MODE, key);
        return c.doFinal(ct);
    }

    /**
     * One OAEPWith name against both references, both directions. Ours defaults MGF1 to the name's digest, as
     * BouncyCastle does; SunJCE defaults MGF1 to SHA-1 for every name, so only SHA-1 crosses with it. A name a
     * reference does not serve is pinned as its refusal.
     */
    private static void assertOaepNameBesideReferences(String digest, boolean bcServes, int sun) throws Exception
    {
        String xf = "RSA/ECB/OAEPWith" + digest + "AndMGF1Padding";
        byte[] msg = new byte[24];
        RANDOM.nextBytes(msg);
        if (bcServes)
        {
            Assertions.assertArrayEquals(msg, decrypt(xf, BC, bcPrivate(), encrypt(xf, JSL, keyPair.getPublic(), msg)));
            Assertions.assertArrayEquals(msg, decrypt(xf, JSL, keyPair.getPrivate(), encrypt(xf, BC, bcPublic(), msg)));
        }
        else
        {
            Assertions.assertThrows(NoSuchPaddingException.class, () -> Cipher.getInstance(xf, BC));
        }
        KeyPair sunKeys = sunPair();
        if (sun == SUN_REFUSES)
        {
            Assertions.assertThrows(NoSuchPaddingException.class, () -> Cipher.getInstance(xf, SUN_JCE));
            return;
        }
        byte[] ours = encrypt(xf, JSL, keyPair.getPublic(), msg);
        byte[] theirs = encrypt(xf, SUN_JCE, sunKeys.getPublic(), msg);
        if (sun == SUN_CROSSES)
        {
            Assertions.assertArrayEquals(msg, decrypt(xf, SUN_JCE, sunKeys.getPrivate(), ours));
            Assertions.assertArrayEquals(msg, decrypt(xf, JSL, keyPair.getPrivate(), theirs));
        }
        else
        {
            Assertions.assertThrows(BadPaddingException.class, () -> decrypt(xf, SUN_JCE, sunKeys.getPrivate(), ours));
            Assertions.assertThrows(BadPaddingException.class, () -> decrypt(xf, JSL, keyPair.getPrivate(), theirs));
        }
    }

    private static final int SUN_CROSSES = 0;
    private static final int SUN_DIFFERS = 1;
    private static final int SUN_REFUSES = 2;

    @Test
    public void oaepWithMd5BesideReferences() throws Exception
    {
        assertOaepNameBesideReferences("MD5", true, SUN_DIFFERS);
    }

    @Test
    public void oaepWithSha1BesideReferences() throws Exception
    {
        assertOaepNameBesideReferences("SHA-1", true, SUN_CROSSES);
    }

    @Test
    public void oaepWithSha224BesideReferences() throws Exception
    {
        assertOaepNameBesideReferences("SHA-224", true, SUN_DIFFERS);
    }

    @Test
    public void oaepWithSha256BesideReferences() throws Exception
    {
        assertOaepNameBesideReferences("SHA-256", true, SUN_DIFFERS);
    }

    @Test
    public void oaepWithSha384BesideReferences() throws Exception
    {
        assertOaepNameBesideReferences("SHA-384", true, SUN_DIFFERS);
    }

    @Test
    public void oaepWithSha512BesideReferences() throws Exception
    {
        assertOaepNameBesideReferences("SHA-512", true, SUN_DIFFERS);
    }

    @Test
    public void oaepWithSha512224BesideReferences() throws Exception
    {
        assertOaepNameBesideReferences("SHA-512/224", false, SUN_DIFFERS);
    }

    @Test
    public void oaepWithSha512256BesideReferences() throws Exception
    {
        assertOaepNameBesideReferences("SHA-512/256", false, SUN_DIFFERS);
    }

    @Test
    public void oaepWithSha3256BesideReferences() throws Exception
    {
        assertOaepNameBesideReferences("SHA3-256", true, SUN_REFUSES);
    }
}
