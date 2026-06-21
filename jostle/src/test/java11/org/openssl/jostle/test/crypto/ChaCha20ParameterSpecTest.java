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

package org.openssl.jostle.test.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Exercises the Java-11+ {@code ChaCha20BlockCipherSpi} override (loaded from
 * {@code META-INF/versions/11}) that accepts {@code javax.crypto.spec.ChaCha20ParameterSpec}.
 *
 * <p>Lives in {@code src/test/java11} so it compiles at {@code release = 11}
 * (where the spec exists) and runs under {@code unitTest11} on JDK 11 — i.e. the
 * multi-release override is verified on its actual target JDK, not only on 25.
 */
public class ChaCha20ParameterSpecTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final SecureRandom R = new SecureRandom();

    @BeforeAll
    static void before()
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    private static SecretKey randomKey()
    {
        byte[] key = new byte[32];
        R.nextBytes(key);
        return new SecretKeySpec(key, "ChaCha20");
    }

    /**
     * ChaCha20ParameterSpec(nonce, counter=0) is accepted and produces the same
     * keystream as the equivalent IvParameterSpec(nonce) — confirming the
     * counter-0 convention the native layer assumes.
     */
    @Test
    public void chaChaParameterSpec_counter0_matchesIvParameterSpec() throws Exception
    {
        SecretKey key = randomKey();
        byte[] nonce = new byte[12];
        R.nextBytes(nonce);
        byte[] msg = new byte[80];
        R.nextBytes(msg);

        Cipher viaSpec = Cipher.getInstance("ChaCha20", JSL);
        viaSpec.init(Cipher.ENCRYPT_MODE, key, new ChaCha20ParameterSpec(nonce, 0));
        byte[] ctSpec = viaSpec.doFinal(msg);

        Cipher viaIv = Cipher.getInstance("ChaCha20", JSL);
        viaIv.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(nonce));
        byte[] ctIv = viaIv.doFinal(msg);

        Assertions.assertArrayEquals(ctIv, ctSpec, "ChaCha20ParameterSpec(counter 0) == IvParameterSpec");

        // Round-trip via the spec.
        Cipher dec = Cipher.getInstance("ChaCha20", JSL);
        dec.init(Cipher.DECRYPT_MODE, key, new ChaCha20ParameterSpec(nonce, 0));
        Assertions.assertArrayEquals(msg, dec.doFinal(ctSpec));
    }

    /** A non-zero initial counter is rejected (arbitrary counters unsupported). */
    @Test
    public void chaChaParameterSpec_nonZeroCounter_rejected() throws Exception
    {
        SecretKey key = randomKey();
        byte[] nonce = new byte[12];
        R.nextBytes(nonce);

        Cipher c = Cipher.getInstance("ChaCha20", JSL);
        InvalidAlgorithmParameterException ex = assertThrows(InvalidAlgorithmParameterException.class,
                () -> c.init(Cipher.ENCRYPT_MODE, key, new ChaCha20ParameterSpec(nonce, 1)));
        Assertions.assertTrue(ex.getMessage().contains("counter"), ex.getMessage());
    }

    /** ChaCha20ParameterSpec(counter 0) agrees byte-for-byte with BC CHACHA7539. */
    @Test
    public void chaChaParameterSpec_agreesWithBC() throws Exception
    {
        SecretKey key = randomKey();
        byte[] nonce = new byte[12];
        R.nextBytes(nonce);
        byte[] msg = new byte[150];
        R.nextBytes(msg);

        Cipher jsl = Cipher.getInstance("ChaCha20", JSL);
        jsl.init(Cipher.ENCRYPT_MODE, key, new ChaCha20ParameterSpec(nonce, 0));
        byte[] jslCt = jsl.doFinal(msg);

        Cipher bc = Cipher.getInstance("CHACHA7539", "BC");
        bc.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(nonce));
        Assertions.assertArrayEquals(bc.doFinal(msg), jslCt);
    }
}
