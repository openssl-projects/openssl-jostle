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
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.security.Security;

/**
 * MT-82: {@code init(ENCRYPT_MODE, key)} with no parameters must generate a
 * nonce, the way GCM already does, rather than refusing.
 *
 * <h2>Why the generated values are BouncyCastle's and not arbitrary</h2>
 *
 * <p>CCM permits a 7-to-13-byte nonce and a 32-to-128-bit tag, so a provider
 * choosing its own defaults produces a valid ciphertext that no other provider
 * reproduces. Measured against bcprov 1.85.2, BouncyCastle generates a
 * <b>12-byte nonce</b> and a <b>64-bit tag</b> — note the tag is NOT GCM's
 * 128, which is the value a reader would assume. {@link
 * #generatedLengthsMatchBouncyCastle()} measures BC live rather than asserting
 * the two numbers, so a bcprov bump that moves either one fails here instead of
 * silently diverging.
 *
 * <h2>Why a fixed nonce would pass the round-trip</h2>
 *
 * <p>A nonce generated once and reused round-trips perfectly and has the right
 * length, so the round-trip and length pins cannot see it — and nonce reuse
 * under one key is a total loss of CCM's authenticity. {@link
 * #successiveInitsGenerateDifferentNonces()} is the differentiator.
 */
public class AESCCMAutoParametersTest
{
    /** id-aes128-CCM. The OIDs MT-72 registered reach the same SPI. */
    private static final String AES128_CCM_OID = "2.16.840.1.101.3.4.1.7";

    private static final String CCM = "AES/CCM/NoPadding";

    /** Measured from BouncyCastle in {@link #generatedLengthsMatchBouncyCastle()}. */
    private static final int EXPECTED_NONCE_BYTES = 12;
    private static final int EXPECTED_TAG_BITS = 64;

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

    private static SecretKey aesKey() throws Exception
    {
        KeyGenerator kg = KeyGenerator.getInstance("AES", JostleProvider.PROVIDER_NAME);
        kg.init(128, RANDOM);
        return kg.generateKey();
    }

    private static byte[] randomMessage()
    {
        byte[] msg = new byte[1 + RANDOM.nextInt(64)];
        RANDOM.nextBytes(msg);
        return msg;
    }

    /**
     * The property a caller depends on: encrypt with no spec, hand the
     * resulting parameters to the recipient, and the recipient recovers the
     * plaintext. Asserting only that {@code getParameters()} is non-null would
     * pass against parameters that do not describe the ciphertext.
     */
    @Test
    public void encryptWithoutSpecProducesDecryptableParameters() throws Exception
    {
        SecretKey key = aesKey();
        byte[] msg = randomMessage();

        Cipher enc = Cipher.getInstance(CCM, JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, key);
        byte[] ct = enc.doFinal(msg);

        AlgorithmParameters params = enc.getParameters();
        Assertions.assertNotNull(params, "no-spec encrypt must expose its generated parameters");

        GCMParameterSpec spec = params.getParameterSpec(GCMParameterSpec.class);
        Assertions.assertEquals(EXPECTED_NONCE_BYTES, spec.getIV().length, "generated nonce length");
        Assertions.assertEquals(EXPECTED_TAG_BITS, spec.getTLen(), "generated tag length");
        Assertions.assertEquals(msg.length + EXPECTED_TAG_BITS / 8, ct.length,
                "ciphertext must carry a tag of the advertised length");

        Cipher dec = Cipher.getInstance(CCM, JostleProvider.PROVIDER_NAME);
        dec.init(Cipher.DECRYPT_MODE, key, params);
        Assertions.assertTrue(Arrays.areEqual(msg, dec.doFinal(ct)),
                "the generated parameters must decrypt their own ciphertext");
    }

    /** The same, driven through the OID MT-72 registered rather than the name. */
    @Test
    public void encryptWithoutSpecWorksThroughTheOid() throws Exception
    {
        SecretKey key = aesKey();
        byte[] msg = randomMessage();

        Cipher enc = Cipher.getInstance(AES128_CCM_OID, JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, key);
        byte[] ct = enc.doFinal(msg);

        Cipher dec = Cipher.getInstance(AES128_CCM_OID, JostleProvider.PROVIDER_NAME);
        dec.init(Cipher.DECRYPT_MODE, key, enc.getParameters());
        Assertions.assertTrue(Arrays.areEqual(msg, dec.doFinal(ct)),
                "the OID surface must auto-generate parameters too");
    }

    /**
     * Both generated lengths are BouncyCastle's, measured live. A transcribed
     * pair of numbers would keep passing after a bcprov change moved them.
     */
    @Test
    public void generatedLengthsMatchBouncyCastle() throws Exception
    {
        SecretKey key = aesKey();
        byte[] msg = randomMessage();

        Cipher bc = Cipher.getInstance(CCM, BouncyCastleProvider.PROVIDER_NAME);
        bc.init(Cipher.ENCRYPT_MODE, key);
        int bcTagBits = (bc.doFinal(msg).length - msg.length) * 8;
        // BC's CCM AlgorithmParameters refuse a GCMParameterSpec view, so the
        // nonce comes from getIV() and the tag from the ciphertext expansion.
        int bcNonceBytes = bc.getIV().length;

        Cipher jsl = Cipher.getInstance(CCM, JostleProvider.PROVIDER_NAME);
        jsl.init(Cipher.ENCRYPT_MODE, key);
        int jslTagBits = (jsl.doFinal(msg).length - msg.length) * 8;
        int jslNonceBytes = jsl.getIV().length;

        Assertions.assertEquals(bcNonceBytes, jslNonceBytes,
                "generated nonce length must match BouncyCastle's");
        Assertions.assertEquals(bcTagBits, jslTagBits,
                "default tag length must match BouncyCastle's");
        // Guard the constants this file documents against both moving together.
        Assertions.assertEquals(EXPECTED_NONCE_BYTES, bcNonceBytes, "BC nonce length moved");
        Assertions.assertEquals(EXPECTED_TAG_BITS, bcTagBits, "BC default tag length moved");
    }

    /**
     * A nonce generated once and reused would satisfy every other test here.
     * Reuse under one key destroys CCM's authenticity, so it gets its own pin.
     */
    @Test
    public void successiveInitsGenerateDifferentNonces() throws Exception
    {
        SecretKey key = aesKey();

        Cipher c = Cipher.getInstance(CCM, JostleProvider.PROVIDER_NAME);
        c.init(Cipher.ENCRYPT_MODE, key);
        byte[] first = c.getIV();
        c.init(Cipher.ENCRYPT_MODE, key);
        byte[] second = c.getIV();

        Assertions.assertNotNull(first);
        Assertions.assertNotNull(second);
        Assertions.assertFalse(Arrays.areEqual(first, second),
                "each no-spec init must draw a fresh nonce");
    }

    /**
     * Decrypt cannot invent a nonce, so the refusal stays — and it stays with
     * the same type BouncyCastle uses, asserted here rather than assumed.
     */
    @Test
    public void decryptWithoutSpecStillRefuses() throws Exception
    {
        SecretKey key = aesKey();

        Cipher jsl = Cipher.getInstance(CCM, JostleProvider.PROVIDER_NAME);
        InvalidKeyException ours = Assertions.assertThrows(InvalidKeyException.class,
                () -> jsl.init(Cipher.DECRYPT_MODE, key),
                "CCM decrypt with no nonce must refuse");
        Assertions.assertEquals("CCM requires a GCMParameterSpec (tagLen + nonce)", ours.getMessage());

        Cipher bc = Cipher.getInstance(CCM, BouncyCastleProvider.PROVIDER_NAME);
        Assertions.assertThrows(InvalidKeyException.class,
                () -> bc.init(Cipher.DECRYPT_MODE, key),
                "BouncyCastle refuses the same call with the same type");
    }

    /** CCM has no key-wrap, so those modes keep refusing with no spec too. */
    @Test
    public void wrapAndUnwrapWithoutSpecStillRefuse() throws Exception
    {
        SecretKey key = aesKey();

        for (int opmode : new int[]{Cipher.WRAP_MODE, Cipher.UNWRAP_MODE})
        {
            Cipher c = Cipher.getInstance(CCM, JostleProvider.PROVIDER_NAME);
            InvalidKeyException ex = Assertions.assertThrows(InvalidKeyException.class,
                    () -> c.init(opmode, key),
                    "CCM must refuse wrap/unwrap with no parameters");
            Assertions.assertEquals("CCM requires a GCMParameterSpec (tagLen + nonce)", ex.getMessage());
        }
    }
}
