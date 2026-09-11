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

package org.openssl.jostle.test.module;

import org.bouncycastle.jcajce.spec.AEADParameterSpec;
import org.bouncycastle.jcajce.spec.ContextParameterSpec;
import org.bouncycastle.jcajce.spec.HKDFParameterSpec;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.jcajce.spec.ScryptKeySpec;
import org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.util.Arrays;

/**
 * Jostle reads BouncyCastle spec types by REFLECTION so it can support them
 * without a compile-time dependency. Every classpath leg in this build runs
 * with modules switched off, so nothing else in the suite exercises those
 * reads across a module boundary.
 *
 * <p>Sites covered, measured at 9911e94 by grepping {@code src/main} for
 * {@code getMethod} / {@code getDeclaredMethod} / {@code Class.forName}:
 *
 * <table>
 * <tr><th>site</th><th>reads</th><th>driven here by</th></tr>
 * <tr><td>rsa/RSAKEMCipherSpi:586 (java9 :589)</td><td>KTSParameterSpec getters</td><td>{@link #rsaKtsReadsTheBouncyCastleSpec}</td></tr>
 * <tr><td>mlkem/MLKEMKTSCipherSpi:584 (java9 :587)</td><td>KTSParameterSpec getters</td><td>{@link #mlkemKtsReadsTheBouncyCastleSpec}</td></tr>
 * <tr><td>mlkem/MLKEMKTSCipherSpi:600 (java9 :603)</td><td>AlgorithmIdentifier.getEncoded</td><td>{@link #mlkemKtsReadsTheBouncyCastleSpec}</td></tr>
 * <tr><td>kdf/ScryptSecretKeyFactory:71-76</td><td>six ScryptKeySpec getters</td><td>{@link #scryptReadsTheBouncyCastleSpec}</td></tr>
 * <tr><td>kdf/HKDFSecretKeyFactory:128-131</td><td>four HKDF spec getters</td><td>{@link #hkdfReadsTheBouncyCastleSpec}</td></tr>
 * <tr><td>kdf/KeyAgreementKDF:283</td><td>getUserKeyingMaterial</td><td>{@link #keyAgreementKdfReadsTheBouncyCastleUkm}</td></tr>
 * <tr><td>blockcipher/AEADParameterSpecAccessor:88,:89,:102</td><td>AEADParameterSpec getters</td><td>{@link #aeadReadsTheBouncyCastleSpec}</td></tr>
 * <tr><td>jcajce/util/SpecUtil:34</td><td>getName</td><td>{@link #specUtilReadsAForeignName}</td></tr>
 * <tr><td>jcajce/util/SpecUtil:56</td><td>getContext</td><td>{@link #specUtilReadsAForeignContext}</td></tr>
 * </table>
 *
 * <p>{@code Loader:420}'s {@code Class.forName} is excluded: same module, no
 * boundary crossed.
 *
 * <p>BouncyCastle is a SPEC SOURCE here and is never registered: the
 * automatic-module cell runs an UNSIGNED copy the JCE would refuse, and a
 * registered BC could answer a lookup meant for jostle.
 */
public class ModuleReflectiveSpecReadTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final SecureRandom RANDOM = new SecureRandom();

    /** id-aes128-wrap, the KEK the X9.63 agreements are asked to size. */
    private static final String AES128_WRAP_OID = "2.16.840.1.101.3.4.1.5";

    @BeforeAll
    public static void setUp()
    {
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    /**
     * The reflective read works WITHOUT a read edge, and the call adds none —
     * a public member of a public class in an exported package needs no
     * readability. java-spi.md records this as "core reflection adds the read
     * edge itself", which measurement contradicts; the guide edit is queued.
     * MT-96 in reviews/misc-tasks-plan.md carries the measurement.
     */
    @Test
    public void theReadEdgeIsNeverAddedAndTheReadStillWorks() throws Exception
    {
        Module jostle = JostleProvider.class.getModule();
        Module bc = KTSParameterSpec.class.getModule();
        boolean before = jostle.canRead(bc);

        rsaKtsReadsTheBouncyCastleSpec();

        Assertions.assertEquals(before, jostle.canRead(bc),
                "a read edge appeared during the reflective call; the mechanism recorded in"
                        + " java-spi.md needs re-measuring");

        // Only where bcprov is its OWN named module. In the UNNAMED cell the
        // JaCoCo agent, attached to every Test task, adds jostle -> unnamed
        // itself, so the claim would measure the coverage harness.
        if (ModuleCell.current() == ModuleCell.NAMED || ModuleCell.current() == ModuleCell.AUTOMATIC)
        {
            Assertions.assertFalse(jostle.canRead(bc),
                    "jostle reads bcprov, so this cell no longer shows that the reflective read"
                            + " works WITHOUT readability");
        }
    }

    @Test
    public void rsaKtsReadsTheBouncyCastleSpec() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", JSL);
        kpg.initialize(2048, RANDOM);
        KeyPair kp = kpg.generateKeyPair();
        ktsRoundTrip("RSA-KTS-KEM-KWS", kp, spec("AES-KWP"));
    }

    @Test
    public void mlkemKtsReadsTheBouncyCastleSpec() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM", JSL);
        kpg.initialize(MLKEMParameterSpec.ml_kem_768, RANDOM);
        KeyPair kp = kpg.generateKeyPair();
        ktsRoundTrip("ML-KEM", kp, spec("AES-KWP"));
    }

    @Test
    public void scryptReadsTheBouncyCastleSpec() throws Exception
    {
        byte[] salt = random(16);
        SecretKeyFactory f = SecretKeyFactory.getInstance("SCRYPT", JSL);
        byte[] derived = f.generateSecret(
                new ScryptKeySpec("a-password".toCharArray(), salt, 1024, 8, 1, 256)).getEncoded();
        Assertions.assertEquals(32, derived.length);

        // A differentiator: the reflective read must carry the SALT through,
        // not merely return bytes of the right length.
        byte[] other = f.generateSecret(
                new ScryptKeySpec("a-password".toCharArray(), random(16), 1024, 8, 1, 256)).getEncoded();
        Assertions.assertFalse(Arrays.equals(derived, other),
                "two salts produced the same key, so the spec was not really read");
    }

    @Test
    public void hkdfReadsTheBouncyCastleSpec() throws Exception
    {
        byte[] ikm = random(32);
        byte[] info = random(12);
        SecretKeyFactory f = SecretKeyFactory.getInstance("HKDF-SHA256", JSL);
        byte[] derived = f.generateSecret(new HKDFParameterSpec(ikm, random(16), info, 32)).getEncoded();
        Assertions.assertEquals(32, derived.length);

        byte[] other = f.generateSecret(new HKDFParameterSpec(ikm, random(16), info, 32)).getEncoded();
        Assertions.assertFalse(Arrays.equals(derived, other),
                "two salts produced the same key, so the spec was not really read");
    }

    @Test
    public void aeadReadsTheBouncyCastleSpec() throws Exception
    {
        KeyGenerator kg = KeyGenerator.getInstance("AES", JSL);
        kg.init(256, RANDOM);
        SecretKey key = kg.generateKey();

        byte[] nonce = random(12);
        byte[] aad = random(20);
        byte[] plain = random(64);

        Cipher enc = Cipher.getInstance("AES/GCM/NoPadding", JSL);
        enc.init(Cipher.ENCRYPT_MODE, key, new AEADParameterSpec(nonce, 128, aad), RANDOM);
        byte[] ct = enc.doFinal(plain);

        Cipher dec = Cipher.getInstance("AES/GCM/NoPadding", JSL);
        dec.init(Cipher.DECRYPT_MODE, key, new AEADParameterSpec(nonce, 128, aad), RANDOM);
        Assertions.assertArrayEquals(plain, dec.doFinal(ct));

        // The AAD is carried by the reflective read alone; a spec read as a
        // bare IvParameterSpec would decrypt fine WITHOUT it, so prove it did not.
        Cipher noAad = Cipher.getInstance("AES/GCM/NoPadding", JSL);
        noAad.init(Cipher.DECRYPT_MODE, key, new AEADParameterSpec(nonce, 128, random(20)), RANDOM);
        Assertions.assertThrows(AEADBadTagException.class, () -> noAad.doFinal(ct),
                "decryption succeeded under different associated data, so the AAD was never read");
    }

    @Test
    public void keyAgreementKdfReadsTheBouncyCastleUkm() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", JSL);
        kpg.initialize(new java.security.spec.ECGenParameterSpec("P-256"), RANDOM);
        KeyPair alice = kpg.generateKeyPair();
        KeyPair bob = kpg.generateKeyPair();

        byte[] ukm = random(16);
        byte[] first = derive(alice, bob, ukm);
        byte[] same = derive(alice, bob, ukm);
        byte[] other = derive(alice, bob, random(16));

        Assertions.assertArrayEquals(first, same, "the same UKM must derive the same KEK");
        Assertions.assertFalse(Arrays.equals(first, other),
                "a different UKM derived the same KEK, so the UKM was never read");
    }

    /**
     * ML-DSA, not Ed25519: plain {@code ED25519} refuses a context outright
     * ("ED25519 does not accept a context parameter"), so it can never reach
     * the reflective read this cell exists to drive.
     */
    @Test
    public void specUtilReadsAForeignContext() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA-65", JSL);
        KeyPair kp = kpg.generateKeyPair();
        byte[] message = random(48);
        byte[] context = random(8);

        Signature signer = Signature.getInstance("MLDSA", JSL);
        signer.initSign(kp.getPrivate());
        signer.setParameter(new ContextParameterSpec(context));
        signer.update(message);
        byte[] sig = signer.sign();

        Assertions.assertTrue(verifyMlDsa(kp, message, sig, context),
                "the signature must verify under the context it was made with");
        Assertions.assertFalse(verifyMlDsa(kp, message, sig, random(8)),
                "it verified under a DIFFERENT context, so the context was never read");
    }

    @Test
    public void specUtilReadsAForeignName() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM", JSL);
        kpg.initialize(MLKEMParameterSpec.ml_kem_512, RANDOM);
        int small = kpg.generateKeyPair().getPublic().getEncoded().length;

        kpg = KeyPairGenerator.getInstance("ML-KEM", JSL);
        kpg.initialize(MLKEMParameterSpec.ml_kem_1024, RANDOM);
        int large = kpg.generateKeyPair().getPublic().getEncoded().length;

        Assertions.assertTrue(large > small,
                "ML-KEM-512 and ML-KEM-1024 produced the same key size, so the spec NAME was"
                        + " never read: small=" + small + " large=" + large);
    }

    /**
     * BouncyCastle must never be a registered provider on this leg. In the
     * automatic-module cell the jar is an UNSIGNED copy, which the JCE will
     * not accept for Cipher services; more generally a registered BC could
     * answer a lookup this leg means to put to jostle.
     */
    @Test
    public void bouncyCastleIsNeverRegistered()
    {
        Assertions.assertNull(Security.getProvider("BC"),
                "BouncyCastle is registered: this leg uses it as a SPEC SOURCE only");
    }

    private static boolean verifyMlDsa(KeyPair kp, byte[] message, byte[] sig, byte[] context)
            throws Exception
    {
        Signature v = Signature.getInstance("MLDSA", JSL);
        v.initVerify(kp.getPublic());
        v.setParameter(new ContextParameterSpec(context));
        v.update(message);
        return v.verify(sig);
    }

    private static byte[] derive(KeyPair local, KeyPair peer, byte[] ukm) throws Exception
    {
        KeyAgreement ka = KeyAgreement.getInstance("ECDHWITHSHA256KDF", JSL);
        ka.init(local.getPrivate(), new UserKeyingMaterialSpec(ukm));
        ka.doPhase(peer.getPublic(), true);
        return ka.generateSecret(AES128_WRAP_OID).getEncoded();
    }

    private static void ktsRoundTrip(String transformation, KeyPair kp, KTSParameterSpec spec)
            throws Exception
    {
        byte[] raw = random(20);
        SecretKeySpec cek = new SecretKeySpec(raw, "HMACSHA1");

        Cipher w = Cipher.getInstance(transformation, JSL);
        w.init(Cipher.WRAP_MODE, kp.getPublic(), spec, RANDOM);
        byte[] blob = w.wrap(cek);

        Cipher u = Cipher.getInstance(transformation, JSL);
        u.init(Cipher.UNWRAP_MODE, kp.getPrivate(), spec, RANDOM);
        byte[] back = u.unwrap(blob, "HMACSHA1", Cipher.SECRET_KEY).getEncoded();

        Assertions.assertArrayEquals(raw, back, transformation + " did not round-trip");
    }

    /**
     * A 20-byte CEK and AES-KWP: the only shape that tells RFC 5649 from RFC
     * 3394, so the name read out of the spec is load-bearing. At 32 bytes both
     * produce 40 wrapped bytes and the read could be skipped unnoticed.
     */
    private static KTSParameterSpec spec(String keyAlgorithmName)
    {
        return new KTSParameterSpec.Builder(keyAlgorithmName, 256, random(16)).build();
    }

    private static byte[] random(int n)
    {
        byte[] b = new byte[n];
        RANDOM.nextBytes(b);
        return b;
    }
}
