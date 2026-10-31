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

package org.openssl.jostle.test.fips;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.spec.KTSParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;

/**
 * The JSLFIPS ML-KEM KTS cipher against BouncyCastle, each divergence held in both halves: the opmode refusal type,
 * and a KEK size AES key wrap cannot take, refused here at init and by BouncyCastle at wrap. Those cells need a
 * module that serves ML-KEM (3.1.2 has none); the registration cell runs on every module.
 */
public class FIPSMLKEMKTSAgreementTest
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static Provider fips;

    @BeforeAll
    static void before()
    {
        fips = FIPSTestUtil.assumeFipsProvider();
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private static void assumeMlKem()
    {
        Assumptions.assumeTrue(FIPSTestUtil.moduleServesKeyMgmt("ML-KEM-768"),
                "the loaded FIPS module implements no ML-KEM (3.1.2)");
    }

    /**
     * JSLFIPS registers the ML-KEM KTS cipher if and only if the loaded module implements ML-KEM, asked of the
     * module itself; where it does not, the cipher still resolves through JSL. Runs on every module.
     */
    @Test
    public void mlKemKtsServedIffModuleImplementsIt() throws Exception
    {
        boolean implemented = FIPSTestUtil.moduleServesKeyMgmt("ML-KEM-768");
        Assertions.assertEquals(implemented, fips.getService("Cipher", "ML-KEM") != null,
                "JSLFIPS Cipher.ML-KEM registration disagrees with the loaded module");
        if (!implemented)
        {
            Assertions.assertNotNull(Cipher.getInstance("ML-KEM", new JostleProvider()),
                    "ML-KEM must still resolve through JSL");
        }
    }

    /** ENCRYPT_MODE and DECRYPT_MODE: InvalidParameterException on both, each with its own message. */
    @Test
    public void encryptAndDecryptModesAreRefusedAsBouncyCastleRefusesThem() throws Exception
    {
        assumeMlKem();
        KeyPair ours = KeyPairGenerator.getInstance("ML-KEM-768", fips).generateKeyPair();
        KeyPair theirs = KeyPairGenerator.getInstance("ML-KEM-768", BC).generateKeyPair();
        for (int mode : new int[]{Cipher.ENCRYPT_MODE, Cipher.DECRYPT_MODE})
        {
            Cipher jo = Cipher.getInstance("ML-KEM", fips);
            InvalidParameterException e = Assertions.assertThrows(InvalidParameterException.class,
                    () -> jo.init(mode, ours.getPublic(), new KTSParameterSpec.Builder("AES-KWP", 256).build()));
            Assertions.assertEquals("ML-KEM KTS cipher only supports WRAP_MODE/UNWRAP_MODE", e.getMessage());

            Cipher bc = Cipher.getInstance("ML-KEM", BC);
            // KTSParameterSpec is qualified where BouncyCastle's is meant: jostle's of that name is imported
            e = Assertions.assertThrows(InvalidParameterException.class, () -> bc.init(mode, theirs.getPublic(),
                    new org.bouncycastle.jcajce.spec.KTSParameterSpec.Builder("AES-KWP", 256).build()));
            Assertions.assertEquals("Cipher only valid for wrapping/unwrapping", e.getMessage());
        }
    }

    /** A KEK size AES key wrap cannot take: refused at init here, accepted at init and refused at wrap by BC. */
    @Test
    public void anUnsupportedKekSizeDivergesFromBouncyCastleOnPurpose() throws Exception
    {
        assumeMlKem();
        KeyPair theirs = KeyPairGenerator.getInstance("ML-KEM-768", BC).generateKeyPair();
        Cipher w = Cipher.getInstance("ML-KEM", BC);
        // KTSParameterSpec is qualified where BouncyCastle's is meant: jostle's of that name is imported
        w.init(Cipher.WRAP_MODE, theirs.getPublic(),
                new org.bouncycastle.jcajce.spec.KTSParameterSpec.Builder("AESWRAP", 136).build());
        byte[] raw = new byte[16];
        RANDOM.nextBytes(raw);
        IllegalBlockSizeException bcRefusal = Assertions.assertThrows(IllegalBlockSizeException.class,
                () -> w.wrap(new SecretKeySpec(raw, "AES")));
        Assertions.assertEquals("unable to generate KTS secret: Key length not 128/192/256 bits.",
                bcRefusal.getMessage());

        KeyPair ours = KeyPairGenerator.getInstance("ML-KEM-768", fips).generateKeyPair();
        Cipher c = Cipher.getInstance("ML-KEM", fips);
        InvalidAlgorithmParameterException e = Assertions.assertThrows(InvalidAlgorithmParameterException.class,
                () -> c.init(Cipher.WRAP_MODE, ours.getPublic(), new KTSParameterSpec.Builder("AESWRAP", 136).build()));
        Assertions.assertEquals("unsupported AES-KW KEK size: 136 bits; AES key wrap takes 128, 192 or 256",
                e.getMessage());
    }
}
