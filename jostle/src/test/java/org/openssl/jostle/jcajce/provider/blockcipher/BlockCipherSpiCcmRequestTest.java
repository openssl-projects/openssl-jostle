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

package org.openssl.jostle.jcajce.provider.blockcipher;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.SecureRandom;

/**
 * CCM asked for through the generic SPI's setMode never runs there: setPadding refuses any padding, and init
 * refuses until another mode is set, so a caller that skips setPadding cannot run the previous mode.
 *
 * <p>In this package because the SPI entry points are protected.
 */
public class BlockCipherSpiCcmRequestTest
{
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String REFUSAL =
            "CCM mode is only available via the dedicated <cipher>/CCM/NoPadding transformation";

    @BeforeAll
    public static void loadProvider()
    {
        new JostleProvider();
    }

    private static SecretKeySpec key()
    {
        byte[] k = new byte[16];
        RANDOM.nextBytes(k);
        return new SecretKeySpec(k, "AES");
    }

    @Test
    public void setPaddingRefusesEveryPaddingAfterCcm() throws Exception
    {
        for (String padding : new String[]{"NoPadding", "PKCS5Padding", "PKCS7Padding"})
        {
            AESBlockCipherSpi spi = new AESBlockCipherSpi();
            spi.engineSetMode("CCM");
            NoSuchPaddingException ex = Assertions.assertThrows(NoSuchPaddingException.class,
                    () -> spi.engineSetPadding(padding), padding);
            Assertions.assertEquals(REFUSAL, ex.getMessage(), padding);
        }
    }

    @Test
    public void initRefusesWhileCcmIsPendingAndAnotherModeClearsIt() throws Exception
    {
        AESBlockCipherSpi spi = new AESBlockCipherSpi();
        spi.engineSetMode("CCM");
        InvalidKeyException ex = Assertions.assertThrows(InvalidKeyException.class,
                () -> spi.engineInit(Cipher.ENCRYPT_MODE, key(), RANDOM));
        Assertions.assertEquals(REFUSAL, ex.getMessage());

        spi.engineSetMode("CBC");
        spi.engineSetPadding("NoPadding");
        byte[] iv = new byte[16];
        RANDOM.nextBytes(iv);
        spi.engineInit(Cipher.ENCRYPT_MODE, key(), new IvParameterSpec(iv), RANDOM);
        Assertions.assertEquals(16, spi.engineDoFinal(new byte[16], 0, 16).length);
    }
}
