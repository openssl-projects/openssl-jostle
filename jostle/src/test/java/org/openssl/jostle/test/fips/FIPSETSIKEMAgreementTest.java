/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.fips;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.jcajce.spec.IESKEMParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Cross-provider agreement for {@code Cipher.ETSIKEMwithSHA256} on the FIPS
 * provider, against both {@code JSL} and BouncyCastle.
 *
 * <p>Not a duplicate of {@link
 * org.openssl.jostle.test.ec.ETSIKEMAgreementTest}: this one drives the FIPS
 * interface library and the module's own {@code OSSL_LIB_CTX}, and runs only
 * with {@code TEST_FIPS_LIB} set.
 *
 * <p><b>The registration is ungated and the CURVE is what varies by module.</b>
 * The construction needs EC key management, ECDH derive, SHA-256 and
 * HMAC-SHA-256, all of which both supported modules serve — so there is no
 * capability gate. {@code brainpoolP256r1}, the KEM's other ITS curve, is a
 * different question and is asked of the module here rather than pinned:
 * measured 2026-09-13, NEITHER 3.1.2 nor 3.5.8 serves it, and the refusal comes
 * from EC key generation rather than from the KEM.
 */
public class FIPSETSIKEMAgreementTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    private static final String KEM = "ETSIKEMwithSHA256";

    private static final int TRIALS = 4;

    private static final SecureRandom RANDOM = new SecureRandom();

    /** Established by the class-level gate below; null only if it aborted. */
    private static JostleFIPSProvider fipsProvider;

    /**
     * The module gate lives here rather than per test method, so it fails
     * CLOSED: a cell added later without its own gate is skipped with the rest
     * instead of running against no module at all.
     */
    @BeforeAll
    static void before()
    {
        fipsProvider = FIPSTestUtil.assumeFipsProvider();

        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }


    private static SecureRandom seededRandom(String testName) throws Exception
    {
        long seed = RANDOM.nextLong();
        System.out.println(testName + " seed=" + seed);
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(seed);
        return sr;
    }

    private static KeyPair generate(Provider provider, String curve, SecureRandom sr) throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", provider);
        kpg.initialize(new ECGenParameterSpec(curve), sr);
        return kpg.generateKeyPair();
    }

    private static PublicKey crossPublic(PublicKey key, String provider) throws Exception
    {
        return KeyFactory.getInstance("EC", provider)
                .generatePublic(new X509EncodedKeySpec(key.getEncoded()));
    }

    private static PublicKey crossPublic(PublicKey key, Provider provider) throws Exception
    {
        return KeyFactory.getInstance("EC", provider)
                .generatePublic(new X509EncodedKeySpec(key.getEncoded()));
    }

    private static PrivateKey crossPrivate(PrivateKey key, String provider) throws Exception
    {
        return KeyFactory.getInstance("EC", provider)
                .generatePrivate(new PKCS8EncodedKeySpec(key.getEncoded()));
    }

    private static byte[] wrap(Provider provider, PublicKey recipient, byte[] recipientInfo,
                               boolean compress, Key cek, SecureRandom sr) throws Exception
    {
        Cipher c = Cipher.getInstance(KEM, provider);
        c.init(Cipher.WRAP_MODE, recipient, new IESKEMParameterSpec(recipientInfo, compress), sr);
        return c.wrap(cek);
    }

    private static Key unwrap(Provider provider, PrivateKey recipient, byte[] recipientInfo,
                              byte[] wrapped) throws Exception
    {
        Cipher c = Cipher.getInstance(KEM, provider);
        c.init(Cipher.UNWRAP_MODE, recipient, new IESKEMParameterSpec(recipientInfo));
        return c.unwrap(wrapped, "AES", Cipher.SECRET_KEY);
    }

    /** The scheme is registered on JSLFIPS, and reaches an SPI that can run. */
    @Test
    public void theSchemeIsServedByTheFipsProvider() throws Exception
    {
        JostleFIPSProvider fips = fipsProvider;
        Assertions.assertNotNull(fips.getService("Cipher", KEM),
                "JSLFIPS must register " + KEM);
        Assertions.assertNotNull(Cipher.getInstance(KEM, fips),
                "the registration must resolve through the ordinary JCE lookup too");
    }

    /**
     * A key made under the module, recovered by JSL and by BouncyCastle, and
     * the reverse — so the FIPS library's derivation is compared against two
     * independent implementations rather than against itself.
     */
    @Test
    public void agreesWithJslAndBouncyCastleOnSecp256r1() throws Exception
    {
        JostleFIPSProvider fips = fipsProvider;
        Provider jsl = Security.getProvider(JSL);
        Provider bc = Security.getProvider(BC);
        SecureRandom sr = seededRandom("agreesWithJslAndBouncyCastleOnSecp256r1");

        for (boolean compress : new boolean[]{false, true})
        {
            for (int t = 0; t < TRIALS; t++)
            {
                KeyPair recipient = generate(fips, "secp256r1", sr);
                byte[] recipientInfo = new byte[1 + sr.nextInt(32)];
                sr.nextBytes(recipientInfo);
                byte[] cek = new byte[16];
                sr.nextBytes(cek);
                SecretKeySpec key = new SecretKeySpec(cek, "AES");

                // Keys cross as encodings — the only sanctioned crossing.
                PublicKey jslPub = crossPublic(recipient.getPublic(), JSL);
                PrivateKey jslPriv = crossPrivate(recipient.getPrivate(), JSL);
                PublicKey bcPub = crossPublic(recipient.getPublic(), BC);
                PrivateKey bcPriv = crossPrivate(recipient.getPrivate(), BC);

                byte[] underModule = wrap(fips, recipient.getPublic(), recipientInfo, compress, key, sr);
                Assertions.assertArrayEquals(cek,
                        unwrap(jsl, jslPriv, recipientInfo, underModule).getEncoded(),
                        "JSL must recover a wrap made under the module");
                Assertions.assertArrayEquals(cek,
                        unwrapThroughBc(bc, bcPriv, recipientInfo, underModule),
                        "BouncyCastle must recover a wrap made under the module");

                byte[] underJsl = wrap(jsl, jslPub, recipientInfo, compress, key, sr);
                Assertions.assertArrayEquals(cek,
                        unwrap(fips, recipient.getPrivate(), recipientInfo, underJsl).getEncoded(),
                        "the module must recover a wrap made by JSL");

                byte[] underBc = wrapThroughBc(bc, bcPub, recipientInfo, compress, key, sr);
                Assertions.assertArrayEquals(cek,
                        unwrap(fips, recipient.getPrivate(), recipientInfo, underBc).getEncoded(),
                        "the module must recover a wrap made by BouncyCastle");
            }
        }
    }

    /** BouncyCastle takes its own spec type, so drive it with that one. */
    private static byte[] wrapThroughBc(Provider bc, PublicKey recipient, byte[] recipientInfo,
                                        boolean compress, Key cek, SecureRandom sr) throws Exception
    {
        Cipher c = Cipher.getInstance(KEM, bc);
        c.init(Cipher.WRAP_MODE, recipient,
                new org.bouncycastle.jcajce.spec.IESKEMParameterSpec(recipientInfo, compress), sr);
        return c.wrap(cek);
    }

    private static byte[] unwrapThroughBc(Provider bc, PrivateKey recipient, byte[] recipientInfo,
                                          byte[] wrapped) throws Exception
    {
        Cipher c = Cipher.getInstance(KEM, bc);
        c.init(Cipher.UNWRAP_MODE, recipient,
                new org.bouncycastle.jcajce.spec.IESKEMParameterSpec(recipientInfo));
        return c.unwrap(wrapped, "AES", Cipher.SECRET_KEY).getEncoded();
    }

    /**
     * The ITS KEM's other curve, asked of the module rather than pinned. Both
     * branches are asserted: where the module serves the curve the KEM must
     * work on it, and where it does not the refusal must come from EC key
     * generation as an {@code InvalidAlgorithmParameterException} naming the
     * curve — not from the KEM, and not as some untyped failure.
     */
    @Test
    public void brainpoolFollowsWhateverTheModuleServes() throws Exception
    {
        JostleFIPSProvider fips = fipsProvider;
        SecureRandom sr = seededRandom("brainpoolFollowsWhateverTheModuleServes");

        KeyPair recipient;
        try
        {
            recipient = generate(fips, "brainpoolP256r1", sr);
        }
        catch (InvalidAlgorithmParameterException e)
        {
            Assertions.assertTrue(e.getMessage().contains("brainpoolP256r1"),
                    "the refusal must name the curve, got: " + e.getMessage());
            System.out.println("brainpoolFollowsWhateverTheModuleServes: module does not serve the curve");
            return;
        }

        byte[] recipientInfo = new byte[8];
        sr.nextBytes(recipientInfo);
        byte[] cek = new byte[16];
        sr.nextBytes(cek);
        byte[] wrapped = wrap(fips, recipient.getPublic(), recipientInfo, true,
                new SecretKeySpec(cek, "AES"), sr);
        Assertions.assertArrayEquals(cek,
                unwrap(fips, recipient.getPrivate(), recipientInfo, wrapped).getEncoded(),
                "a curve the module serves must work through the KEM");
    }

    /**
     * A key belongs to the provider INSTANCE that made it, so a JSL key handed
     * to the FIPS KEM is refused in both halves — the operation would otherwise
     * be served outside the module.
     */
    @Test
    public void aJslKeyIsRefusedByTheFipsKem() throws Exception
    {
        JostleFIPSProvider fips = fipsProvider;
        Provider jsl = Security.getProvider(JSL);
        SecureRandom sr = seededRandom("aJslKeyIsRefusedByTheFipsKem");
        KeyPair jslPair = generate(jsl, "secp256r1", sr);

        for (int mode : new int[]{Cipher.WRAP_MODE, Cipher.UNWRAP_MODE})
        {
            Key key = mode == Cipher.WRAP_MODE ? jslPair.getPublic() : jslPair.getPrivate();
            java.security.InvalidKeyException e = Assertions.assertThrows(
                    java.security.InvalidKeyException.class, () ->
                    {
                        Cipher c = Cipher.getInstance(KEM, fips);
                        c.init(mode, key, new IESKEMParameterSpec(new byte[8]));
                    }, "a JSL key must not be accepted by the FIPS KEM in mode " + mode);
            Assertions.assertTrue(
                    e.getMessage().contains("created by a different Jostle provider instance"),
                    "expected the isolation message, got: " + e.getMessage());
        }

        // Control: the same key material, re-decoded through the FIPS
        // KeyFactory, IS accepted — so the refusals above are about provenance
        // and not about the key.
        PublicKey pub = crossPublic(jslPair.getPublic(), (Provider) fips);
        Cipher c = Cipher.getInstance(KEM, fips);
        c.init(Cipher.WRAP_MODE, pub, new IESKEMParameterSpec(new byte[8]));
    }
}
