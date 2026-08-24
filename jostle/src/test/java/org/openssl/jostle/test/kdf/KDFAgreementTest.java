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

package org.openssl.jostle.test.kdf;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.agreement.kdf.ConcatenationKDFGenerator;
import org.bouncycastle.crypto.digests.Blake2bDigest;
import org.bouncycastle.crypto.digests.Blake2sDigest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHA512tDigest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.generators.KDFCounterBytesGenerator;
import org.bouncycastle.crypto.generators.KDFFeedbackBytesGenerator;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.params.KDFCounterParameters;
import org.bouncycastle.crypto.params.KDFFeedbackParameters;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.spec.Argon2KeySpec;
import org.openssl.jostle.jcajce.spec.HKDFParameterSpec;
import org.openssl.jostle.jcajce.spec.KBKDFParameterSpec;
import org.openssl.jostle.jcajce.spec.SSHKDFParameterSpec;
import org.openssl.jostle.jcajce.spec.SSKDFParameterSpec;
import org.openssl.jostle.jcajce.spec.ScryptKeySpec;
import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.Strings;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.KeySpec;
import java.util.Set;
import java.util.TreeSet;

/**
 * Cross-provider agreement for the BASE provider's whole {@code SecretKeyFactory}
 * surface: every KDF JSL registers, compared against BouncyCastle.
 *
 * <p>The non-FIPS half of the pair {@link org.openssl.jostle.test.fips.FIPSKDFAgreementTest}
 * completes. The two are not redundant — this one drives
 * {@code libinterface_{jni,ffi}} against the base {@code OSSL_LIB_CTX} and runs
 * always; that one drives {@code libinterface_fips_{jni,ffi}} against the FIPS
 * lib ctx and only with {@code TEST_FIPS_LIB} set. A base-only KDF (scrypt,
 * Argon2, the unapproved PBKDF2 PRFs) can only be covered here.</p>
 *
 * <p><b>Why this class exists when the per-algorithm classes already compare
 * against BC.</b> {@code HkdfTest}, {@code PBKdf2Test}, {@code ScryptTest},
 * {@code Argon2Test}, {@code KBKDFTest}, {@code SSKDFTest} and
 * {@code SSHKDFTest} carry the depth — chunking, boundaries, spec contracts.
 * What none of them carries is BREADTH: nothing failed when a name was
 * registered and added to no test. {@link #everyRegisteredSecretKeyFactoryIsCovered()}
 * is that missing check, and the per-group drivers below are what make it
 * meaningful rather than a list-versus-list comparison.</p>
 *
 * <p>Inputs are drawn from a per-test SHA1PRNG whose seed is logged, so a flaky
 * run is reproducible.</p>
 */
public class KDFAgreementTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    /** PBKDF2 PRFs BouncyCastle serves through its JCE {@code SecretKeyFactory}. */
    private static final String[] PBKDF2_BC_JCE = {
            "PBKDF2",
            "PBKDF2WITHHMACSHA1",
            "PBKDF2WITHHMACSHA224",
            "PBKDF2WITHHMACSHA256",
            "PBKDF2WITHHMACSHA384",
            "PBKDF2WITHHMACSHA512",
            "PBKDF2WITHHMACSHA3-224",
            "PBKDF2WITHHMACSHA3-256",
            "PBKDF2WITHHMACSHA3-384",
            "PBKDF2WITHHMACSHA3-512",
            "PBKDF2WITHHMACSM3",
    };

    /**
     * PBKDF2 PRFs the pinned BouncyCastle release does not register through the
     * JCE, so the reference is BC's lightweight {@code PKCS5S2ParametersGenerator}
     * over the corresponding BC {@code Digest}. A missing BC JCE name is not a
     * reason to skip agreement testing.
     */
    private static final String[] PBKDF2_BC_LOWLEVEL = {
            "PBKDF2WITHHMACBLAKE2B-512",
            "PBKDF2WITHHMACBLAKE2S-256",
            "PBKDF2WITHHMACMD5",
            "PBKDF2WITHHMACMD5-SHA1",
            "PBKDF2WITHHMACRIPEMD160",
            "PBKDF2WITHHMACSHA512-224",
            "PBKDF2WITHHMACSHA512-256",
    };

    private static final String[] HKDF_ALGS = {"HKDF-SHA256", "HKDF-SHA384", "HKDF-SHA512"};

    private static final String[] KBKDF_HMAC_ALGS = {
            "KBKDF-HMAC-SHA1", "KBKDF-HMAC-SHA224", "KBKDF-HMAC-SHA256",
            "KBKDF-HMAC-SHA384", "KBKDF-HMAC-SHA512"
    };

    private static final String[] KBKDF_CMAC_ALGS = {
            "KBKDF-CMAC-AES128", "KBKDF-CMAC-AES192", "KBKDF-CMAC-AES256"
    };

    private static final String[] SSKDF_ALGS = {
            "SSKDF-SHA1", "SSKDF-SHA224", "SSKDF-SHA256", "SSKDF-SHA384", "SSKDF-SHA512"
    };

    /**
     * BouncyCastle has no SSH KDF at all, so the reference is RFC 4253's own
     * recurrence over a JDK {@code MessageDigest} — an independent
     * implementation in the sense that matters (different code, different
     * digest provider). See {@link #rfc4253Reference}.
     */
    private static final String[] SSHKDF_ALGS = {
            "SSHKDF-SHA1", "SSHKDF-SHA224", "SSHKDF-SHA256", "SSHKDF-SHA384", "SSHKDF-SHA512"
    };

    /** scrypt and its RFC 7914 OID alias, both compared against BC's JCE. */
    private static final String[] SCRYPT_ALGS = {"SCRYPT", "1.3.6.1.4.1.11591.4.11"};

    /** Argon2, compared against BC's own JCE {@code SecretKeyFactory}. */
    private static final String[] ARGON2_ALGS = {"ARGON2"};

    private static final SecureRandom RANDOM = new SecureRandom();

    private static SecureRandom seededRandom(String testName) throws Exception
    {
        long seed = RANDOM.nextLong();
        System.out.println(testName + " seed=" + seed);
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(seed);
        return sr;
    }

    @BeforeAll
    static void before()
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

    private static byte[] random(int length, SecureRandom sr)
    {
        byte[] bytes = new byte[length];
        sr.nextBytes(bytes);
        return bytes;
    }

    private static byte[] derive(String provider, String alg, KeySpec spec) throws Exception
    {
        return SecretKeyFactory.getInstance(alg, provider).generateSecret(spec).getEncoded();
    }

    /** A BC digest for a name whose digest is a bare suffix ({@code -SHA256}). */
    private static Digest bcDigestBySuffix(String alg)
    {
        if (alg.endsWith("SHA1"))
        {
            return new SHA1Digest();
        }
        if (alg.endsWith("SHA224"))
        {
            return new SHA224Digest();
        }
        if (alg.endsWith("SHA256"))
        {
            return new SHA256Digest();
        }
        if (alg.endsWith("SHA384"))
        {
            return new SHA384Digest();
        }
        if (alg.endsWith("SHA512"))
        {
            return new SHA512Digest();
        }
        throw new IllegalArgumentException("no BC digest for " + alg);
    }

    private static Digest bcDigestForPbkdf2(String alg)
    {
        if (alg.endsWith("BLAKE2B-512"))
        {
            return new Blake2bDigest(512);
        }
        if (alg.endsWith("BLAKE2S-256"))
        {
            return new Blake2sDigest(256);
        }
        if (alg.endsWith("MD5-SHA1"))
        {
            return new MD5SHA1Digest();
        }
        if (alg.endsWith("MD5"))
        {
            return new MD5Digest();
        }
        if (alg.endsWith("RIPEMD160"))
        {
            return new RIPEMD160Digest();
        }
        if (alg.endsWith("SHA512-224"))
        {
            return new SHA512tDigest(224);
        }
        if (alg.endsWith("SHA512-256"))
        {
            return new SHA512tDigest(256);
        }
        throw new IllegalArgumentException("no BC digest for " + alg);
    }

    private static int aesKeyBytesFor(String alg)
    {
        if (alg.endsWith("AES128"))
        {
            return 16;
        }
        if (alg.endsWith("AES192"))
        {
            return 24;
        }
        if (alg.endsWith("AES256"))
        {
            return 32;
        }
        throw new IllegalArgumentException("no AES size for " + alg);
    }

    @SuppressWarnings("deprecation")
    private static BlockCipher aesEngine()
    {
        return new AESEngine();
    }

    // ------------------------------------------------- the completeness guard

    /**
     * Every {@code SecretKeyFactory} the BASE provider registers appears in one
     * of this class's coverage groups, and every name in those groups is still
     * registered.
     * <p>
     * The base-side twin of
     * {@code FIPSKDFAgreementTest.everyRegisteredSecretKeyFactoryIsCovered},
     * and the check that was missing entirely until this class existed: BC
     * comparison lived scattered across the per-algorithm KDF tests, so a name
     * registered in a {@code Prov*KDF} and added to none of them was exercised
     * by nothing. The FIPS guard cannot cover that — it reads JSLFIPS's
     * registered set, and scrypt, Argon2 and the unapproved PBKDF2 PRFs are
     * base-only.
     */
    @Test
    public void everyRegisteredSecretKeyFactoryIsCovered()
    {
        Provider provider = Security.getProvider(JSL);
        Assertions.assertNotNull(provider, "JSL provider is not registered");

        Set<String> covered = new TreeSet<String>();
        covered.addAll(java.util.Arrays.asList(PBKDF2_BC_JCE));
        covered.addAll(java.util.Arrays.asList(PBKDF2_BC_LOWLEVEL));
        covered.addAll(java.util.Arrays.asList(HKDF_ALGS));
        covered.addAll(java.util.Arrays.asList(KBKDF_HMAC_ALGS));
        covered.addAll(java.util.Arrays.asList(KBKDF_CMAC_ALGS));
        covered.addAll(java.util.Arrays.asList(SSKDF_ALGS));
        covered.addAll(java.util.Arrays.asList(SSHKDF_ALGS));
        covered.addAll(java.util.Arrays.asList(SCRYPT_ALGS));
        covered.addAll(java.util.Arrays.asList(ARGON2_ALGS));

        Set<String> registered = new TreeSet<String>();
        for (Provider.Service service : provider.getServices())
        {
            if ("SecretKeyFactory".equals(service.getType()))
            {
                registered.add(service.getAlgorithm());
            }
        }
        Assertions.assertFalse(registered.isEmpty(), "JSL registered no SecretKeyFactory services");

        Set<String> uncovered = new TreeSet<String>(registered);
        uncovered.removeAll(covered);
        Assertions.assertTrue(uncovered.isEmpty(),
                "JSL registers SecretKeyFactory services with no agreement coverage in this class: "
                        + uncovered + "\nAdd them to a coverage group — a KDF registered and "
                        + "compared against nothing is the gap this class exists to close.");

        // And the reverse, so a rename leaves a dead entry rather than
        // silently testing nothing.
        Set<String> stale = new TreeSet<String>(covered);
        stale.removeAll(registered);
        Assertions.assertTrue(stale.isEmpty(),
                "this class names SecretKeyFactory services JSL does not register: " + stale);
    }

    // ------------------------------------------------------------- PBKDF2

    @Test
    public void pbkdf2AgreesWithBouncyCastleJce() throws Exception
    {
        SecureRandom sr = seededRandom("pbkdf2AgreesWithBouncyCastleJce");

        for (String alg : PBKDF2_BC_JCE)
        {
            char[] password = new String(random(8, sr), "UTF-8").toCharArray();
            byte[] salt = random(16, sr);
            int iterations = 100 + sr.nextInt(400);
            int keyBits = (16 + sr.nextInt(32)) * 8;

            PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyBits);
            byte[] jsl = derive(JSL, alg, spec);

            Assertions.assertArrayEquals(derive(BC, alg, spec), jsl, alg);
            Assertions.assertEquals(keyBits >> 3, jsl.length, alg + " key length");

            // Differentiator: a changed salt must change the derived key.
            byte[] salt2 = Arrays.clone(salt);
            salt2[0] ^= 0x01;
            Assertions.assertFalse(Arrays.areEqual(jsl,
                            derive(JSL, alg, new PBEKeySpec(password, salt2, iterations, keyBits))),
                    alg + ": changed salt produced identical key");
        }
    }

    @Test
    public void pbkdf2AgreesWithBouncyCastleLowLevel() throws Exception
    {
        SecureRandom sr = seededRandom("pbkdf2AgreesWithBouncyCastleLowLevel");

        for (String alg : PBKDF2_BC_LOWLEVEL)
        {
            char[] password = new String(random(8, sr), "UTF-8").toCharArray();
            byte[] salt = random(16, sr);
            int iterations = 100 + sr.nextInt(400);
            int keyBits = 256;

            PKCS5S2ParametersGenerator gen =
                    new PKCS5S2ParametersGenerator(bcDigestForPbkdf2(alg));
            gen.init(Strings.toUTF8ByteArray(password), salt, iterations);
            byte[] bc = ((KeyParameter) gen.generateDerivedParameters(keyBits)).getKey();

            byte[] jsl = derive(JSL, alg, new PBEKeySpec(password, salt, iterations, keyBits));
            Assertions.assertArrayEquals(bc, jsl, alg);

            byte[] salt2 = Arrays.clone(salt);
            salt2[0] ^= 0x01;
            Assertions.assertFalse(Arrays.areEqual(jsl,
                            derive(JSL, alg, new PBEKeySpec(password, salt2, iterations, keyBits))),
                    alg + ": changed salt produced identical key");
        }
    }

    // --------------------------------------------------------------- HKDF

    @Test
    public void hkdfAgreesWithBouncyCastle() throws Exception
    {
        SecureRandom sr = seededRandom("hkdfAgreesWithBouncyCastle");

        for (String alg : HKDF_ALGS)
        {
            byte[] ikm = random(16 + sr.nextInt(32), sr);
            byte[] salt = random(sr.nextInt(32), sr);
            byte[] info = random(sr.nextInt(32), sr);
            int len = 1 + sr.nextInt(96);

            HKDFBytesGenerator gen = new HKDFBytesGenerator(bcDigestBySuffix(alg));
            gen.init(new HKDFParameters(ikm, salt, info));
            byte[] bc = new byte[len];
            gen.generateBytes(bc, 0, len);

            byte[] jsl = derive(JSL, alg, new HKDFParameterSpec(ikm, salt, info, len));
            Assertions.assertArrayEquals(bc, jsl, alg);

            // Differentiator at >= 16 bytes: len can be 1, where two honest
            // derivations collide 1-in-256 of the time.
            int diffLen = Math.max(len, 16);
            byte[] ikm2 = Arrays.clone(ikm);
            ikm2[0] ^= 0x01;
            Assertions.assertFalse(Arrays.areEqual(
                            derive(JSL, alg, new HKDFParameterSpec(ikm, salt, info, diffLen)),
                            derive(JSL, alg, new HKDFParameterSpec(ikm2, salt, info, diffLen))),
                    alg + ": changed IKM produced identical key");
        }
    }

    // -------------------------------------------------------------- KBKDF

    @Test
    public void kbkdfCounterAgreesWithBouncyCastle() throws Exception
    {
        SecureRandom sr = seededRandom("kbkdfCounterAgreesWithBouncyCastle");
        int[] rValues = {8, 16, 24, 32};

        for (String alg : KBKDF_HMAC_ALGS)
        {
            byte[] ki = random(16 + sr.nextInt(32), sr);
            byte[] fixed = random(1 + sr.nextInt(64), sr);
            int r = rValues[sr.nextInt(rValues.length)];
            int len = 1 + sr.nextInt(96);

            KDFCounterBytesGenerator gen =
                    new KDFCounterBytesGenerator(new HMac(bcDigestBySuffix(alg)));
            gen.init(new KDFCounterParameters(ki, fixed, r));
            byte[] bc = new byte[len];
            gen.generateBytes(bc, 0, len);

            // useL and useSeparator OFF: OpenSSL defaults both ON, BC emits
            // neither. See KBKDFTest.useLAndSeparatorChangeTheOutput.
            Assertions.assertArrayEquals(bc, derive(JSL, alg, new KBKDFParameterSpec(
                    ki, null, fixed, null, KBKDFParameterSpec.Mode.COUNTER, r, false, false, len)),
                    alg + " counter r=" + r);
        }

        for (String alg : KBKDF_CMAC_ALGS)
        {
            byte[] ki = random(aesKeyBytesFor(alg), sr);
            byte[] fixed = random(1 + sr.nextInt(64), sr);
            int r = rValues[sr.nextInt(rValues.length)];
            int len = 1 + sr.nextInt(96);

            KDFCounterBytesGenerator gen = new KDFCounterBytesGenerator(new CMac(aesEngine()));
            gen.init(new KDFCounterParameters(ki, fixed, r));
            byte[] bc = new byte[len];
            gen.generateBytes(bc, 0, len);

            Assertions.assertArrayEquals(bc, derive(JSL, alg, new KBKDFParameterSpec(
                    ki, null, fixed, null, KBKDFParameterSpec.Mode.COUNTER, r, false, false, len)),
                    alg + " counter r=" + r);
        }
    }

    @Test
    public void kbkdfFeedbackAgreesWithBouncyCastle() throws Exception
    {
        SecureRandom sr = seededRandom("kbkdfFeedbackAgreesWithBouncyCastle");

        for (String alg : KBKDF_HMAC_ALGS)
        {
            byte[] ki = random(16 + sr.nextInt(32), sr);
            // OpenSSL requires the feedback IV to be exactly the PRF output
            // size; see KBKDFTest.feedbackIvMustMatchThePrfOutputSize.
            byte[] iv = random(bcDigestBySuffix(alg).getDigestSize(), sr);
            byte[] fixed = random(1 + sr.nextInt(64), sr);
            int len = 1 + sr.nextInt(96);

            KDFFeedbackBytesGenerator gen =
                    new KDFFeedbackBytesGenerator(new HMac(bcDigestBySuffix(alg)));
            gen.init(KDFFeedbackParameters.createWithCounter(ki, iv, fixed, 32));
            byte[] bc = new byte[len];
            gen.generateBytes(bc, 0, len);

            Assertions.assertArrayEquals(bc, derive(JSL, alg, new KBKDFParameterSpec(
                    ki, null, fixed, iv, KBKDFParameterSpec.Mode.FEEDBACK, 32, false, false, len)),
                    alg + " feedback");
        }

        for (String alg : KBKDF_CMAC_ALGS)
        {
            byte[] ki = random(aesKeyBytesFor(alg), sr);
            byte[] iv = random(16, sr);
            byte[] fixed = random(1 + sr.nextInt(64), sr);
            int len = 1 + sr.nextInt(96);

            KDFFeedbackBytesGenerator gen = new KDFFeedbackBytesGenerator(new CMac(aesEngine()));
            gen.init(KDFFeedbackParameters.createWithCounter(ki, iv, fixed, 32));
            byte[] bc = new byte[len];
            gen.generateBytes(bc, 0, len);

            Assertions.assertArrayEquals(bc, derive(JSL, alg, new KBKDFParameterSpec(
                    ki, null, fixed, iv, KBKDFParameterSpec.Mode.FEEDBACK, 32, false, false, len)),
                    alg + " feedback");
        }
    }

    // -------------------------------------------------------------- SSKDF

    @Test
    public void sskdfAgreesWithBouncyCastle() throws Exception
    {
        SecureRandom sr = seededRandom("sskdfAgreesWithBouncyCastle");

        for (String alg : SSKDF_ALGS)
        {
            byte[] secret = random(16 + sr.nextInt(32), sr);
            byte[] info = random(1 + sr.nextInt(32), sr);
            int len = 1 + sr.nextInt(96);

            ConcatenationKDFGenerator gen = new ConcatenationKDFGenerator(bcDigestBySuffix(alg));
            gen.init(new KDFParameters(secret, info));
            byte[] bc = new byte[len];
            gen.generateBytes(bc, 0, len);

            byte[] jsl = derive(JSL, alg, new SSKDFParameterSpec(secret, info, len));
            Assertions.assertArrayEquals(bc, jsl, alg);

            int diffLen = Math.max(len, 16);
            byte[] info2 = Arrays.clone(info);
            info2[0] ^= 0x01;
            Assertions.assertFalse(Arrays.areEqual(
                            derive(JSL, alg, new SSKDFParameterSpec(secret, info, diffLen)),
                            derive(JSL, alg, new SSKDFParameterSpec(secret, info2, diffLen))),
                    alg + ": changed FixedInfo produced identical key");
        }
    }

    // ------------------------------------------------------------- SSHKDF

    /**
     * RFC 4253 section 7.2, written out against a JDK {@code MessageDigest}
     * resolved through BouncyCastle. BC has no SSH KDF, and a specification
     * recurrence written independently is a stronger reference than a pinned
     * table because it covers arbitrary random inputs and every output length.
     */
    private static byte[] rfc4253Reference(String digestName, byte[] k, byte[] h,
                                           byte[] sessionId, char type, int len)
            throws Exception
    {
        MessageDigest md = MessageDigest.getInstance(digestName, BC);
        ByteArrayOutputStream produced = new ByteArrayOutputStream();

        md.update(k);
        md.update(h);
        md.update((byte) type);
        md.update(sessionId);
        produced.write(md.digest());

        while (produced.size() < len)
        {
            md.reset();
            md.update(k);
            md.update(h);
            md.update(produced.toByteArray());
            produced.write(md.digest());
        }

        return Arrays.copyOfRange(produced.toByteArray(), 0, len);
    }

    private static String jceDigestFor(String alg)
    {
        if (alg.endsWith("SHA1"))
        {
            return "SHA-1";
        }
        if (alg.endsWith("SHA224"))
        {
            return "SHA-224";
        }
        if (alg.endsWith("SHA256"))
        {
            return "SHA-256";
        }
        if (alg.endsWith("SHA384"))
        {
            return "SHA-384";
        }
        if (alg.endsWith("SHA512"))
        {
            return "SHA-512";
        }
        throw new IllegalArgumentException("no digest for " + alg);
    }

    @Test
    public void sshkdfAgreesWithRfc4253Reference() throws Exception
    {
        SecureRandom sr = seededRandom("sshkdfAgreesWithRfc4253Reference");

        for (String alg : SSHKDF_ALGS)
        {
            for (SSHKDFParameterSpec.KeyType type : SSHKDFParameterSpec.KeyType.values())
            {
                byte[] k = random(32 + sr.nextInt(64), sr);
                byte[] h = random(20 + sr.nextInt(44), sr);
                byte[] sessionId = random(20 + sr.nextInt(44), sr);
                int len = 1 + sr.nextInt(96);

                Assertions.assertArrayEquals(
                        rfc4253Reference(jceDigestFor(alg), k, h, sessionId,
                                type.getCode().charAt(0), len),
                        derive(JSL, alg, new SSHKDFParameterSpec(k, h, sessionId, type, len)),
                        alg + " type=" + type.getCode());
            }
        }
    }

    // ------------------------------------------------------ scrypt, Argon2

    @Test
    public void scryptAgreesWithBouncyCastle() throws Exception
    {
        SecureRandom sr = seededRandom("scryptAgreesWithBouncyCastle");

        for (String alg : SCRYPT_ALGS)
        {
            char[] password = new String(random(8, sr), "UTF-8").toCharArray();
            byte[] salt = random(16, sr);
            int keyBits = 256;

            ScryptKeySpec spec = new ScryptKeySpec(password, salt, 1024, 8, 1, keyBits);
            byte[] jsl = derive(JSL, alg, spec);

            // BC registers the bare name only, so both Jostle names are
            // compared against BC's "SCRYPT" — which is the point: the OID
            // alias must derive the same key as the name it aliases.
            byte[] bc = derive(BC, "SCRYPT",
                    new org.bouncycastle.jcajce.spec.ScryptKeySpec(password, salt, 1024, 8, 1, keyBits));
            Assertions.assertArrayEquals(bc, jsl, alg);

            byte[] salt2 = Arrays.clone(salt);
            salt2[0] ^= 0x01;
            Assertions.assertFalse(Arrays.areEqual(jsl, derive(JSL, alg,
                            new ScryptKeySpec(password, salt2, 1024, 8, 1, keyBits))),
                    alg + ": changed salt produced identical key");
        }
    }

    @Test
    public void argon2AgreesWithBouncyCastle() throws Exception
    {
        SecureRandom sr = seededRandom("argon2AgreesWithBouncyCastle");

        for (String alg : ARGON2_ALGS)
        {
            char[] password = new String(random(8, sr), "UTF-8").toCharArray();
            byte[] salt = random(16, sr);
            int keyBits = 256;
            int iterations = 2;
            int memoryKb = 1 << 8;
            int lanes = 1;

            byte[] jsl = derive(JSL, alg, new Argon2KeySpec(Argon2KeySpec.ARGON2_id,
                    Argon2KeySpec.ARGON2_VERSION_13, password, salt,
                    iterations, memoryKb, lanes, keyBits));

            byte[] bc = derive(BC, "ARGON2", new org.bouncycastle.jcajce.spec.Argon2KeySpec(
                    org.bouncycastle.crypto.params.Argon2Parameters.ARGON2_id,
                    org.bouncycastle.crypto.params.Argon2Parameters.ARGON2_VERSION_13,
                    password, salt, iterations, memoryKb, lanes, keyBits));

            Assertions.assertArrayEquals(bc, jsl, alg);

            byte[] salt2 = Arrays.clone(salt);
            salt2[0] ^= 0x01;
            Assertions.assertFalse(Arrays.areEqual(jsl, derive(JSL, alg, new Argon2KeySpec(
                            Argon2KeySpec.ARGON2_id, Argon2KeySpec.ARGON2_VERSION_13,
                            password, salt2, iterations, memoryKb, lanes, keyBits))),
                    alg + ": changed salt produced identical key");
        }
    }

    /**
     * BouncyCastle has no MD5-SHA1 digest, so PBKDF2's MD5-SHA1 PRF needs one
     * built from BC's own {@code MD5Digest} and {@code SHA1Digest} per the
     * algorithm's definition — the same test-local helper {@code PBKdf2Test}
     * and {@code MacAgreementTest} each carry. A missing BC name is not a
     * reason to skip agreement testing.
     */
    private static final class MD5SHA1Digest implements ExtendedDigest
    {
        private final MD5Digest md5 = new MD5Digest();
        private final SHA1Digest sha1 = new SHA1Digest();

        @Override
        public String getAlgorithmName()
        {
            return "MD5-SHA1";
        }

        @Override
        public int getDigestSize()
        {
            return 16 + 20;
        }

        @Override
        public void update(byte in)
        {
            md5.update(in);
            sha1.update(in);
        }

        @Override
        public void update(byte[] in, int inOff, int len)
        {
            md5.update(in, inOff, len);
            sha1.update(in, inOff, len);
        }

        @Override
        public int doFinal(byte[] out, int outOff)
        {
            md5.doFinal(out, outOff);
            sha1.doFinal(out, outOff + md5.getDigestSize());
            return 16 + 20;
        }

        @Override
        public void reset()
        {
            md5.reset();
            sha1.reset();
        }

        @Override
        public int getByteLength()
        {
            return 64;
        }
    }
}
