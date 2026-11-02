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

package org.openssl.jostle.test.rand;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.SecretKeyWithEncapsulation;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.spec.KEMExtractSpec;
import org.openssl.jostle.jcajce.spec.KEMGenerateSpec;
import org.openssl.jostle.jcajce.spec.KTSParameterSpec;
import org.openssl.jostle.jcajce.spec.MLDSAParameterSpec;
import org.openssl.jostle.jcajce.spec.MLKEMParameterSpec;
import org.openssl.jostle.jcajce.spec.MLXKEMParameterSpec;
import org.openssl.jostle.jcajce.spec.SLHDSAParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.DrbgParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Cross-SPI coverage for the strength-validation gate at
 * {@code KeyPairGenerator.initialize(spec, random)} and
 * {@code KeyGenerator.init(spec, random)} for the post-quantum SPIs
 * (ML-KEM, ML-DSA, SLH-DSA).
 *
 * <p>The validation: when the caller hands us a {@link SecureRandom}
 * constructed via {@link DrbgParameters} that reports a strength
 * below what the algorithm requires (e.g. a 128-bit DRBG passed to
 * ML-KEM-768 which needs 192), the SPI throws
 * {@link InvalidAlgorithmParameterException} immediately rather than
 * letting the C-side RAND gate surface a generic
 * {@code OpenSSLException} at first {@code generate*} call.
 *
 * <p>This file lives under {@code src/test/java25/} because
 * {@code DrbgParameters} is a Java 9+ API. The Java 8 baseline test
 * source set can't construct strength-typed DRBGs, so there's nothing
 * to assert there — the strength-of helper returns 0 on Java 8 which
 * the SPIs treat as "unknown, accept".
 *
 * <p>Sources that don't expose a strength claim report 0 here and are
 * accepted — the C-side gate is the safety net for genuinely-weak sources
 * passed through unchecked. Note {@code new SecureRandom()} is NOT a
 * portable example of such a source: it reports 0 on POSIX (NativePRNG) but
 * a 128-bit DRBG strength on Windows JDK 9+, so the "unknown strength" tests
 * use {@link #unknownStrengthRandom()} (SHA1PRNG, no DrbgParameters) instead.
 */
public class UserRandStrengthValidationTest
{
    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }


    // -----------------------------------------------------------------
    // ML-KEM
    // -----------------------------------------------------------------

    @Test
    public void mlkem768_userSuppliedWeakDrbg_keyPairGen_rejectsAtInit() throws Exception
    {
        SecureRandom weakDrbg = newDrbg(128);
        assumeDrbgAvailable(weakDrbg);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM-768",
                JostleProvider.PROVIDER_NAME);
        InvalidAlgorithmParameterException ex = Assertions.assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> kpg.initialize(MLKEMParameterSpec.ml_kem_768, weakDrbg));
        Assertions.assertTrue(ex.getMessage().contains("128"),
                "message should report supplied strength: " + ex.getMessage());
        Assertions.assertTrue(ex.getMessage().contains("192"),
                "message should report required strength: " + ex.getMessage());
    }

    @Test
    public void mlkem1024_userSuppliedWeakDrbg_keyPairGen_rejectsAtInit() throws Exception
    {
        SecureRandom weakDrbg = newDrbg(192);
        assumeDrbgAvailable(weakDrbg);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM-1024",
                JostleProvider.PROVIDER_NAME);
        Assertions.assertThrows(InvalidAlgorithmParameterException.class,
                () -> kpg.initialize(MLKEMParameterSpec.ml_kem_1024, weakDrbg));
    }

    @Test
    public void mlkem512_userSuppliedOverStrengthDrbg_keyPairGen_accepts() throws Exception
    {
        // 256-bit DRBG handed to a 128-bit-required ML-KEM-512 —
        // over-strength is fine.
        SecureRandom strongDrbg = newDrbg(256);
        assumeDrbgAvailable(strongDrbg);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM-512",
                JostleProvider.PROVIDER_NAME);
        kpg.initialize(MLKEMParameterSpec.ml_kem_512, strongDrbg);
        Assertions.assertNotNull(kpg.generateKeyPair());
    }

    @Test
    public void mlkem1024_userSuppliedPlainSecureRandom_keyPairGen_accepts() throws Exception
    {
        // An unknown-strength source (no DrbgParameters, reports 0) must be
        // treated as "unknown" not "insufficient" — the SPI must NOT pre-
        // emptively reject. (Whether generateKeyPair later succeeds is the
        // C-side gate's territory.) Uses SHA1PRNG, not new SecureRandom(),
        // which reports a 128-bit DRBG strength on Windows JDK 9+ and would be
        // (correctly) rejected for this 256-bit algorithm.
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM-1024",
                JostleProvider.PROVIDER_NAME);
        kpg.initialize(MLKEMParameterSpec.ml_kem_1024, unknownStrengthRandom());
    }

    @Test
    public void mlkem768_userSuppliedWeakDrbg_engineInit_encap_rejectsAtInit() throws Exception
    {
        // A caller's weak DRBG is refused at init; only the JCE's injected default is replaced.
        SecureRandom weakDrbg = newDrbg(128);
        assumeDrbgAvailable(weakDrbg);
        KeyPair kp = generateKeyPair(MLKEMParameterSpec.ml_kem_768);
        KEMGenerateSpec spec = KEMGenerateSpec.builder()
                .withPublicKey(kp.getPublic())
                .withAlgorithmName("AES")
                .withKeySizeInBits(256)
                .build();
        KeyGenerator kg = KeyGenerator.getInstance("ML-KEM-768",
                JostleProvider.PROVIDER_NAME);
        InvalidAlgorithmParameterException ex = Assertions.assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> kg.init(spec, weakDrbg));
        Assertions.assertTrue(ex.getMessage().contains("128"),
                "message should report supplied strength: " + ex.getMessage());
        Assertions.assertTrue(ex.getMessage().contains("192"),
                "message should report required strength: " + ex.getMessage());

        KeyGenerator fresh = KeyGenerator.getInstance("ML-KEM-768",
                JostleProvider.PROVIDER_NAME);
        fresh.init(spec);
        SecretKey encapKey = fresh.generateKey();
        byte[] encapsulation =
                ((SecretKeyWithEncapsulation) encapKey).getEncapsulation();
        Assertions.assertTrue(encapsulation.length > 0,
                "encap with the injected default must produce an encapsulation");
    }

    @Test
    public void mlkem768_userSuppliedWeakDrbg_engineInit_decap_accepts() throws Exception
    {
        // The decap path doesn't consume entropy — a low-strength
        // user-supplied SecureRandom must NOT be rejected (would break
        // legitimate use where the caller reuses one SecureRandom
        // across operations of mixed strength).
        SecureRandom weakDrbg = newDrbg(128);
        assumeDrbgAvailable(weakDrbg);
        KeyPair kp = generateKeyPair(MLKEMParameterSpec.ml_kem_768);
        // Encap with a default RNG first to get a real wrapped key.
        KeyGenerator encapKg = KeyGenerator.getInstance("ML-KEM-768",
                JostleProvider.PROVIDER_NAME);
        encapKg.init(KEMGenerateSpec.builder()
                .withPublicKey(kp.getPublic())
                .withAlgorithmName("AES")
                .withKeySizeInBits(256)
                .build());
        SecretKey encapKey = encapKg.generateKey();
        byte[] wrapped = ((SecretKeyWithEncapsulation) encapKey).getEncapsulation();

        KeyGenerator decapKg = KeyGenerator.getInstance("ML-KEM-768",
                JostleProvider.PROVIDER_NAME);
        // Weak DRBG against decap spec — should NOT throw.
        decapKg.init(KEMExtractSpec.builder()
                .withPrivate(kp.getPrivate())
                .withAlgorithmName("AES")
                .withKeySizeInBits(256)
                .withEncapsulatedKey(wrapped)
                .build(), weakDrbg);
        Assertions.assertNotNull(decapKg.generateKey());
    }


    // -----------------------------------------------------------------
    // ML-DSA
    // -----------------------------------------------------------------

    @Test
    public void mldsa65_userSuppliedWeakDrbg_rejectsAtInit() throws Exception
    {
        SecureRandom weakDrbg = newDrbg(128);
        assumeDrbgAvailable(weakDrbg);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA-65",
                JostleProvider.PROVIDER_NAME);
        InvalidAlgorithmParameterException ex = Assertions.assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> kpg.initialize(MLDSAParameterSpec.ml_dsa_65, weakDrbg));
        Assertions.assertTrue(ex.getMessage().contains("128"),
                "message should report supplied strength: " + ex.getMessage());
        Assertions.assertTrue(ex.getMessage().contains("192"),
                "message should report required strength: " + ex.getMessage());
    }

    @Test
    public void mldsa87_userSuppliedWeakDrbg_rejectsAtInit() throws Exception
    {
        SecureRandom weakDrbg = newDrbg(192);
        assumeDrbgAvailable(weakDrbg);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA-87",
                JostleProvider.PROVIDER_NAME);
        Assertions.assertThrows(InvalidAlgorithmParameterException.class,
                () -> kpg.initialize(MLDSAParameterSpec.ml_dsa_87, weakDrbg));
    }

    @Test
    public void mldsa44_userSuppliedOverStrengthDrbg_accepts() throws Exception
    {
        SecureRandom strongDrbg = newDrbg(256);
        assumeDrbgAvailable(strongDrbg);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA-44",
                JostleProvider.PROVIDER_NAME);
        kpg.initialize(MLDSAParameterSpec.ml_dsa_44, strongDrbg);
        Assertions.assertNotNull(kpg.generateKeyPair());
    }

    @Test
    public void mldsa87_userSuppliedPlainSecureRandom_accepts() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA-87",
                JostleProvider.PROVIDER_NAME);
        kpg.initialize(MLDSAParameterSpec.ml_dsa_87, unknownStrengthRandom());
    }


    // -----------------------------------------------------------------
    // SLH-DSA
    // -----------------------------------------------------------------

    @Test
    public void slhdsa_192f_userSuppliedWeakDrbg_rejectsAtInit() throws Exception
    {
        SecureRandom weakDrbg = newDrbg(128);
        assumeDrbgAvailable(weakDrbg);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(SLHDSAParameterSpec.slh_dsa_sha2_192f.getName(),
                JostleProvider.PROVIDER_NAME);
        InvalidAlgorithmParameterException ex = Assertions.assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> kpg.initialize(SLHDSAParameterSpec.slh_dsa_sha2_192f, weakDrbg));
        Assertions.assertTrue(ex.getMessage().contains("128"),
                "message should report supplied strength: " + ex.getMessage());
        Assertions.assertTrue(ex.getMessage().contains("192"),
                "message should report required strength: " + ex.getMessage());
    }

    @Test
    public void slhdsa_256s_userSuppliedWeakDrbg_rejectsAtInit() throws Exception
    {
        SecureRandom weakDrbg = newDrbg(192);
        assumeDrbgAvailable(weakDrbg);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(SLHDSAParameterSpec.slh_dsa_shake_256s.getName(),
                JostleProvider.PROVIDER_NAME);
        Assertions.assertThrows(InvalidAlgorithmParameterException.class,
                () -> kpg.initialize(SLHDSAParameterSpec.slh_dsa_shake_256s, weakDrbg));
    }

    @Test
    public void slhdsa_128f_userSuppliedOverStrengthDrbg_accepts() throws Exception
    {
        SecureRandom strongDrbg = newDrbg(256);
        assumeDrbgAvailable(strongDrbg);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(SLHDSAParameterSpec.slh_dsa_sha2_128f.getName(),
                JostleProvider.PROVIDER_NAME);
        kpg.initialize(SLHDSAParameterSpec.slh_dsa_sha2_128f, strongDrbg);
        Assertions.assertNotNull(kpg.generateKeyPair());
    }

    @Test
    public void slhdsa_256f_userSuppliedPlainSecureRandom_accepts() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(SLHDSAParameterSpec.slh_dsa_sha2_256f.getName(),
                JostleProvider.PROVIDER_NAME);
        kpg.initialize(SLHDSAParameterSpec.slh_dsa_sha2_256f, unknownStrengthRandom());
    }


    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    /**
     * A SecureRandom of undeclared ("unknown") strength, portably. Plain
     * {@code new SecureRandom()} reports strength 0 on POSIX (NativePRNG) but a
     * 128-bit DRBG on Windows JDK 9+, so it can't portably stand in for an
     * unknown-strength source; SHA1PRNG carries no DrbgParameters and reports 0
     * on every platform.
     */
    /**
     * The KTS Cipher's encapsulating init refuses a 128-bit DRBG for ML-KEM-768 with the gate's message, on every
     * platform rather than only where the JDK default happens to be one; a 256-bit DRBG wraps and the key unwraps.
     */
    @Test
    public void mlkem768_userSuppliedWeakDrbg_ktsWrapInit_rejectsAtInit() throws Exception
    {
        SecureRandom weakDrbg = newDrbg(128);
        assumeDrbgAvailable(weakDrbg);
        SecureRandom strongDrbg = newDrbg(256);
        KeyPair kp = generateKeyPair(MLKEMParameterSpec.ml_kem_768);
        KTSParameterSpec spec = new KTSParameterSpec.Builder("AES-KWP", 256).build();

        Cipher refused = Cipher.getInstance("ML-KEM", JostleProvider.PROVIDER_NAME);
        InvalidAlgorithmParameterException ex = Assertions.assertThrows(InvalidAlgorithmParameterException.class,
                () -> refused.init(Cipher.WRAP_MODE, kp.getPublic(), spec, weakDrbg));
        Assertions.assertEquals("supplied SecureRandom reports 128-bit strength but ML-KEM-768 requires 192; "
                + "pass a SecureRandom of at least 192 bits", ex.getMessage());

        byte[] raw = new byte[32];
        strongDrbg.nextBytes(raw);
        Cipher wrap = Cipher.getInstance("ML-KEM", JostleProvider.PROVIDER_NAME);
        wrap.init(Cipher.WRAP_MODE, kp.getPublic(), spec, strongDrbg);
        byte[] wrapped = wrap.wrap(new SecretKeySpec(raw, "AES"));
        Cipher unwrap = Cipher.getInstance("ML-KEM", JostleProvider.PROVIDER_NAME);
        unwrap.init(Cipher.UNWRAP_MODE, kp.getPrivate(), spec);
        Assertions.assertArrayEquals(raw, unwrap.unwrap(wrapped, "AES", Cipher.SECRET_KEY).getEncoded());
    }

    /**
     * Every hybrid KEM's encapsulating init refuses a 128-bit DRBG with the gate's message; a 256-bit DRBG
     * encapsulates and the private key decapsulates the same secret.
     */
    @Test
    public void mlxkem_userSuppliedWeakDrbg_encapsulateInit_rejectsAtInit() throws Exception
    {
        SecureRandom weakDrbg = newDrbg(128);
        assumeDrbgAvailable(weakDrbg);
        SecureRandom strongDrbg = newDrbg(256);
        Map<String, Integer> required = new LinkedHashMap<String, Integer>();
        required.put("X25519MLKEM768", 192);
        required.put("SecP256r1MLKEM768", 192);
        required.put("X448MLKEM1024", 256);
        required.put("SecP384r1MLKEM1024", 256);
        Assertions.assertEquals(required.size(), MLXKEMParameterSpec.all().size(), "the hybrid set changed");

        for (Map.Entry<String, Integer> e : required.entrySet())
        {
            String name = e.getKey();
            MLXKEMParameterSpec params = MLXKEMParameterSpec.fromName(name);
            KeyPair kp = KeyPairGenerator.getInstance(name, JostleProvider.PROVIDER_NAME).generateKeyPair();
            KEMGenerateSpec gen = KEMGenerateSpec.builder().withPublicKey(kp.getPublic()).withAlgorithmName("AES")
                    .withKeySizeInBits(params.getSharedSecretBytes() * 8).build();

            KeyGenerator refused = KeyGenerator.getInstance(name, JostleProvider.PROVIDER_NAME);
            InvalidAlgorithmParameterException ex = Assertions.assertThrows(
                    InvalidAlgorithmParameterException.class, () -> refused.init(gen, weakDrbg), name);
            Assertions.assertEquals("supplied SecureRandom reports 128-bit strength but " + name + " requires "
                    + e.getValue() + "; pass a SecureRandom of at least " + e.getValue() + " bits", ex.getMessage());

            KeyGenerator sender = KeyGenerator.getInstance(name, JostleProvider.PROVIDER_NAME);
            sender.init(gen, strongDrbg);
            SecretKeyWithEncapsulation sent = (SecretKeyWithEncapsulation) sender.generateKey();
            KeyGenerator receiver = KeyGenerator.getInstance(name, JostleProvider.PROVIDER_NAME);
            receiver.init(KEMExtractSpec.builder().withPrivate(kp.getPrivate()).withAlgorithmName("AES")
                    .withKeySizeInBits(params.getSharedSecretBytes() * 8)
                    .withEncapsulatedKey(sent.getEncapsulation()).build());
            Assertions.assertArrayEquals(sent.getEncoded(), receiver.generateKey().getEncoded(), name);
        }
    }

    private static SecureRandom unknownStrengthRandom() throws NoSuchAlgorithmException
    {
        return SecureRandom.getInstance("SHA1PRNG");
    }

    private static KeyPair generateKeyPair(MLKEMParameterSpec spec) throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(spec.getName(),
                JostleProvider.PROVIDER_NAME);
        kpg.initialize(spec);
        return kpg.generateKeyPair();
    }

    /**
     * Construct a DRBG SecureRandom with the requested strength via
     * {@code DrbgParameters}, or return {@code null} if the platform
     * can't satisfy the request.
     */
    private static SecureRandom newDrbg(int strengthBits)
    {
        try
        {
            return SecureRandom.getInstance("DRBG",
                    DrbgParameters.instantiation(strengthBits,
                            DrbgParameters.Capability.NONE, null));
        }
        catch (NoSuchAlgorithmException e)
        {
            return null;
        }
    }

    /**
     * Skip the test (rather than fail) if the platform can't supply a
     * strength-typed DRBG. Strength validation requires
     * {@code DrbgParameters} to introspect the supplied source; a
     * platform without it has nothing for the SPI to assert against.
     */
    private static void assumeDrbgAvailable(SecureRandom rand)
    {
        Assumptions.assumeTrue(rand != null,
                "platform DRBG not available — skipping strength-validation test");
    }
}
