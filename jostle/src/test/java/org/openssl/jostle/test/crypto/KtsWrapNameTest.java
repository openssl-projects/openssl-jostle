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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.spec.KTSParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;

/**
 * The KTS ciphers honour {@code KTSParameterSpec.getKeyAlgorithmName()}, which selects RFC 3394 (KW) or RFC 5649
 * (KWP): the ML-KEM cipher refuses an unsupported name typed at init, and the two RFCs are not interchangeable. The
 * comparisons with BouncyCastle are in MLKEMKTSAgreementTest.
 */
public class KtsWrapNameTest
{
    private static final SecureRandom RANDOM = new SecureRandom();

    private static final String JSL = JostleProvider.PROVIDER_NAME;

    private static final String RSA_KTS = "RSA-KTS-KEM-KWS";

    private static final String ACCEPTED = "(accepted: AESWRAP, AES, AES-KWP)";

    @BeforeAll
    public static void setUp()
    {
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    private static KTSParameterSpec spec(String keyAlgorithmName)
    {
        byte[] otherInfo = new byte[1 + RANDOM.nextInt(32)];
        RANDOM.nextBytes(otherInfo);
        return new KTSParameterSpec.Builder(keyAlgorithmName, 256, otherInfo).build();
    }

    private static SecretKeySpec cek(int len)
    {
        byte[] raw = new byte[len];
        RANDOM.nextBytes(raw);
        return new SecretKeySpec(raw, "HMACSHA1");
    }

    private static KeyPair rsaPair() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", JSL);
        kpg.initialize(2048, RANDOM);
        return kpg.generateKeyPair();
    }

    /**
     * The same refusal on the ML-KEM SPI. Its own cell, because the AES-KWP
     * cell would not catch an ML-KEM copy that dropped the null check — that
     * path fails later in {@code oidFor} with a different type.
     */
    @Test
    public void unsupportedNameIsRefusedTypedAtInitOnMlKemToo() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM-768", JSL);
        KeyPair kp = kpg.generateKeyPair();
        for (String name : new String[]{"NOSUCHWRAP", "ARIA", "AESWrapPad"})
        {
            Cipher jo = Cipher.getInstance("ML-KEM", JSL);
            InvalidAlgorithmParameterException e = Assertions.assertThrows(
                    InvalidAlgorithmParameterException.class,
                    () -> jo.init(Cipher.WRAP_MODE, kp.getPublic(), spec(name), RANDOM),
                    name + ": ML-KEM must refuse an unsupported name at init");
            Assertions.assertEquals("unsupported key algorithm name: " + name + " " + ACCEPTED,
                    e.getMessage(), name + ": ML-KEM refusal message");
        }
    }

    /**
     * The selection is load-bearing: a KWP-wrapped blob read back as KW must
     * not yield the CEK. Without this the two arms could both be reached and
     * still be interchangeable, making every cell above vacuous.
     *
     * <p>Measured 10/10 as {@code InvalidKeyException}, never a value.
     */
    @Test
    public void theTwoRfcsAreNotInterchangeable() throws Exception
    {
        KeyPair kp = rsaPair();
        SecretKeySpec key = cek(24);

        // Both specs must share otherInfo, or the KEKs differ and the cell is vacuous.
        byte[] sharedOtherInfo = new byte[24];
        RANDOM.nextBytes(sharedOtherInfo);
        KTSParameterSpec kwp = new KTSParameterSpec.Builder("AES-KWP", 256, sharedOtherInfo).build();
        KTSParameterSpec kw = new KTSParameterSpec.Builder("AESWRAP", 256, sharedOtherInfo).build();

        Cipher w = Cipher.getInstance(RSA_KTS, JSL);
        w.init(Cipher.WRAP_MODE, kp.getPublic(), kwp, RANDOM);
        byte[] blob = w.wrap(key);

        Cipher u = Cipher.getInstance(RSA_KTS, JSL);
        u.init(Cipher.UNWRAP_MODE, kp.getPrivate(), kw, RANDOM);
        Assertions.assertThrows(InvalidKeyException.class,
                () -> u.unwrap(blob, "HMACSHA1", Cipher.SECRET_KEY),
                "a KWP wrap must not be readable as KW, or the name selects nothing");
    }
}
