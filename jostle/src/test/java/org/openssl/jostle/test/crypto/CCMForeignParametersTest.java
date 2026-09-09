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

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidParameterSpecException;

/**
 * MT-85: an {@code AlgorithmParameters} object produced by another provider
 * must be usable, not just one produced by us.
 *
 * <h2>Why this is not a DER disagreement</h2>
 *
 * <p>BouncyCastle and Jostle encode CCM parameters identically — measured,
 * {@code 3011040c<nonce>020108} from both for a 12-byte nonce and a 64-bit
 * tag. What differs is the VIEW the objects offer: BC's CCM parameters refuse
 * {@code getParameterSpec(GCMParameterSpec.class)} and offer
 * {@code IvParameterSpec}, while ours offer the GCM view. Asking a foreign
 * object for a view it does not implement is what failed, so the fix re-reads
 * its encoding through our own codec.
 *
 * <h2>Why GCM is here as a control</h2>
 *
 * <p>BC's GCM parameters DO offer the GCM view, so all four GCM cells passed
 * before the fix and must keep passing after it. Without them a change that
 * broke the ordinary path would look like the CCM fix working.
 */
public class CCMForeignParametersTest
{
    private static final SecureRandom RANDOM = new SecureRandom();

    @BeforeAll
    public static void setUp()
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    /**
     * Encrypt under {@code encProvider}, hand its {@code getParameters()} to
     * {@code decProvider}, and require the plaintext back. This is what a real
     * peer does: the parameters travel with the message.
     */
    private static void crossing(String xform, String encProvider, String decProvider) throws Exception
    {
        KeyGenerator kg = KeyGenerator.getInstance("AES", JostleProvider.PROVIDER_NAME);
        kg.init(128, RANDOM);
        SecretKey key = kg.generateKey();
        byte[] msg = new byte[1 + RANDOM.nextInt(64)];
        RANDOM.nextBytes(msg);

        Cipher enc = Cipher.getInstance(xform, encProvider);
        enc.init(Cipher.ENCRYPT_MODE, key);
        byte[] ct = enc.doFinal(msg);
        AlgorithmParameters params = enc.getParameters();

        Cipher dec = Cipher.getInstance(xform, decProvider);
        dec.init(Cipher.DECRYPT_MODE, key, params);
        Assertions.assertTrue(Arrays.areEqual(msg, dec.doFinal(ct)),
                xform + ": " + encProvider + " parameters must be usable by " + decProvider);
    }

    /** The cell that was red: BouncyCastle's CCM parameters, consumed by us. */
    @Test
    public void ccmParametersFromBouncyCastleAreUsable() throws Exception
    {
        crossing("AES/CCM/NoPadding", BouncyCastleProvider.PROVIDER_NAME, JostleProvider.PROVIDER_NAME);
    }

    /** The other three CCM cells, which were green and must stay green. */
    @Test
    public void theOtherThreeCcmCrossingsStillWork() throws Exception
    {
        crossing("AES/CCM/NoPadding", BouncyCastleProvider.PROVIDER_NAME, BouncyCastleProvider.PROVIDER_NAME);
        crossing("AES/CCM/NoPadding", JostleProvider.PROVIDER_NAME, BouncyCastleProvider.PROVIDER_NAME);
        crossing("AES/CCM/NoPadding", JostleProvider.PROVIDER_NAME, JostleProvider.PROVIDER_NAME);
    }

    /**
     * GCM control. BC's GCM parameters offer the GCM view, so these four
     * passed before the fix; they exist so a regression in the ordinary path
     * cannot hide behind the CCM repair.
     */
    @Test
    public void allFourGcmCrossingsWork() throws Exception
    {
        for (String enc : new String[]{BouncyCastleProvider.PROVIDER_NAME, JostleProvider.PROVIDER_NAME})
        {
            for (String dec : new String[]{BouncyCastleProvider.PROVIDER_NAME, JostleProvider.PROVIDER_NAME})
            {
                crossing("AES/GCM/NoPadding", enc, dec);
            }
        }
    }

    /**
     * The fallback must not turn a genuinely unusable parameter set into a
     * silent acceptance. A DES parameter block offers no GCM view AND its
     * encoding is not CCMParameters, so both the direct read and the re-read
     * fail — and the caller still gets the typed refusal naming the original
     * cause.
     */
    @Test
    public void parametersThatAreNotCcmStillRefuseTyped() throws Exception
    {
        KeyGenerator kg = KeyGenerator.getInstance("AES", JostleProvider.PROVIDER_NAME);
        kg.init(128, RANDOM);
        SecretKey key = kg.generateKey();

        byte[] desIv = new byte[8];
        RANDOM.nextBytes(desIv);
        AlgorithmParameters foreign = AlgorithmParameters.getInstance("DES");
        foreign.init(new javax.crypto.spec.IvParameterSpec(desIv));
        // Precondition: it really does refuse the GCM view, so the test drives
        // the fallback rather than the direct path.
        Assertions.assertThrows(InvalidParameterSpecException.class,
                () -> foreign.getParameterSpec(GCMParameterSpec.class),
                "DES parameters must refuse the GCM view, or this test proves nothing");

        Cipher c = Cipher.getInstance("AES/CCM/NoPadding", JostleProvider.PROVIDER_NAME);
        InvalidAlgorithmParameterException ex = Assertions.assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> c.init(Cipher.ENCRYPT_MODE, key, foreign),
                "parameters that are not CCM must be refused");
        Assertions.assertTrue(ex.getMessage().startsWith("CCM init: "),
                "refusal must keep the original cause's message, was: " + ex.getMessage());
    }
}
