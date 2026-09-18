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

package org.openssl.jostle.test.ec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.spec.UserKeyingMaterialSpec;
import org.openssl.jostle.util.Arrays;

import javax.crypto.KeyAgreement;
import javax.crypto.ShortBufferException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * RFC 6637 §7 {@code ECCDHwithSHA{256,384,512}CKDF} — the SP 800-56C one-step
 * KDF over an ECDH shared secret, which OpenPGP's ECDH uses. No SHA-1 (RFC
 * 6637 §13 forbids it with this KDF); the completeness sweep in
 * {@code ECAgreementTest.everyRegisteredEcdhKdfAgreesWithBouncyCastle} already
 * drives all three names against live BouncyCastle over random inputs and
 * random UKM (RFC 6637 §8's {@code Param}) — this file adds the cells that
 * sweep does not: explicit per-digest naming, the "no algorithm" refusal
 * parity with BC, and typed refusal of a foreign parameter spec.
 */
public class ECCDHKDFAgreementTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
    private static final SecureRandom RANDOM = new SecureRandom();

    /** AES-128/192/256 key wrap, as {@code KeyAgreementKDF.wrapKeyLenBytes} recognises. */
    private static final String[] WRAP_OIDS = {
            "2.16.840.1.101.3.4.1.5", "2.16.840.1.101.3.4.1.25", "2.16.840.1.101.3.4.1.45"
    };

    private static final String[] NAMES = {
            "ECCDHwithSHA256CKDF", "ECCDHwithSHA384CKDF", "ECCDHwithSHA512CKDF"
    };

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private static KeyPair generate(String curve) throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", JSL);
        kpg.initialize(new ECGenParameterSpec(curve));
        return kpg.generateKeyPair();
    }

    private static PrivateKey bcPrivate(PrivateKey k) throws Exception
    {
        return java.security.KeyFactory.getInstance("EC", BC)
                .generatePrivate(new PKCS8EncodedKeySpec(k.getEncoded()));
    }

    private static PublicKey bcPublic(PublicKey k) throws Exception
    {
        return java.security.KeyFactory.getInstance("EC", BC)
                .generatePublic(new X509EncodedKeySpec(k.getEncoded()));
    }

    /** Every registered name, both directions (JSL agreement vs BC agreement over the same keys), random inputs. */
    @Test
    public void everyNameAgreesWithBouncyCastleBothDirections() throws Exception
    {
        for (String name : NAMES)
        {
            for (int trial = 0; trial < 10; trial++)
            {
                KeyPair alice = generate("P-256");
                KeyPair bob = generate("P-256");
                byte[] param = new byte[16 + RANDOM.nextInt(48)];
                RANDOM.nextBytes(param);

                for (String wrapOid : WRAP_OIDS)
                {
                    KeyAgreement jsl = KeyAgreement.getInstance(name, JSL);
                    jsl.init(alice.getPrivate(), new UserKeyingMaterialSpec(param));
                    jsl.doPhase(bob.getPublic(), true);
                    byte[] jslKek = jsl.generateSecret(wrapOid).getEncoded();

                    KeyAgreement bc = KeyAgreement.getInstance(name, BC);
                    bc.init(bcPrivate(alice.getPrivate()),
                            new org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec(param));
                    bc.doPhase(bcPublic(bob.getPublic()), true);
                    byte[] bcKek = bc.generateSecret(wrapOid).getEncoded();

                    Assertions.assertArrayEquals(bcKek, jslKek,
                            name + " wrap=" + wrapOid + ": derived KEK differs from BC");
                }
            }
        }
    }

    @Test
    public void rawSharedSecretIsRefused()
    {
        for (String name : NAMES)
        {
            Assertions.assertThrows(UnsupportedOperationException.class, () ->
            {
                KeyPair alice = generate("P-256");
                KeyPair bob = generate("P-256");
                KeyAgreement ka = KeyAgreement.getInstance(name, JSL);
                ka.init(alice.getPrivate(), new UserKeyingMaterialSpec(new byte[16]));
                ka.doPhase(bob.getPublic(), true);
                ka.generateSecret();
            }, name + ": raw generateSecret() must be refused");

            Assertions.assertThrows(UnsupportedOperationException.class, () ->
            {
                KeyPair alice = generate("P-256");
                KeyPair bob = generate("P-256");
                KeyAgreement ka = KeyAgreement.getInstance(name, JSL);
                ka.init(alice.getPrivate(), new UserKeyingMaterialSpec(new byte[16]));
                ka.doPhase(bob.getPublic(), true);
                try
                {
                    ka.generateSecret(new byte[128], 0);
                }
                catch (ShortBufferException e)
                {
                    throw new AssertionError(e);
                }
            }, name + ": raw generateSecret(byte[],int) must be refused");
        }
    }

    /**
     * RFC 6637 §8 makes {@code Param} mandatory. No UKM at all (the no-spec
     * {@code init(Key)} overload), a null UKM, and an empty one are all
     * refused typed — the first as {@link java.security.InvalidKeyException}
     * ({@code KeyAgreement.init(Key)} declares no other type), the other two
     * as {@link java.security.InvalidAlgorithmParameterException}.
     */
    @Test
    public void missingParamIsRefusedTyped() throws Exception
    {
        for (String name : NAMES)
        {
            KeyPair alice = generate("P-256");

            Assertions.assertThrows(java.security.InvalidKeyException.class, () ->
                    KeyAgreement.getInstance(name, JSL).init(alice.getPrivate()),
                    name + ": init(Key) with no Param must be refused typed");

            Assertions.assertThrows(java.security.InvalidAlgorithmParameterException.class, () ->
                    KeyAgreement.getInstance(name, JSL).init(alice.getPrivate(),
                            new UserKeyingMaterialSpec(null)),
                    name + ": a null Param must be refused typed");

            Assertions.assertThrows(java.security.InvalidAlgorithmParameterException.class, () ->
                    KeyAgreement.getInstance(name, JSL).init(alice.getPrivate(),
                            new UserKeyingMaterialSpec(new byte[0])),
                    name + ": an empty Param must be refused typed");
        }
    }

    @Test
    public void foreignParameterSpecIsRefusedTyped() throws Exception
    {
        for (String name : NAMES)
        {
            KeyPair alice = generate("P-256");
            KeyAgreement ka = KeyAgreement.getInstance(name, JSL);
            Assertions.assertThrows(java.security.InvalidAlgorithmParameterException.class, () ->
                    ka.init(alice.getPrivate(),
                            new org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec(new byte[16])),
                    name + ": BC's own UserKeyingMaterialSpec must be refused typed");
        }
    }

    /** A different UKM (RFC 6637 §8 Param) must derive a different KEK. */
    @Test
    public void differentParamDerivesDifferentKek() throws Exception
    {
        for (String name : NAMES)
        {
            KeyPair alice = generate("P-256");
            KeyPair bob = generate("P-256");
            byte[] param1 = new byte[20];
            byte[] param2 = new byte[20];
            RANDOM.nextBytes(param1);
            RANDOM.nextBytes(param2);

            KeyAgreement ka1 = KeyAgreement.getInstance(name, JSL);
            ka1.init(alice.getPrivate(), new UserKeyingMaterialSpec(param1));
            ka1.doPhase(bob.getPublic(), true);
            byte[] kek1 = ka1.generateSecret(WRAP_OIDS[0]).getEncoded();

            KeyAgreement ka2 = KeyAgreement.getInstance(name, JSL);
            ka2.init(alice.getPrivate(), new UserKeyingMaterialSpec(param2));
            ka2.doPhase(bob.getPublic(), true);
            byte[] kek2 = ka2.generateSecret(WRAP_OIDS[0]).getEncoded();

            Assertions.assertFalse(Arrays.areEqual(kek1, kek2),
                    name + ": different Param derived the same KEK");
        }
    }
}
