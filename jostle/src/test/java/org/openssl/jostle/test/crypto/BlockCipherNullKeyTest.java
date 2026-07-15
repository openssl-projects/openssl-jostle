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

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidKeyException;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Verifies that the per-algorithm block-cipher SPIs reject a {@link SecretKey}
 * whose {@code getEncoded()} returns {@code null} (an opaque / HSM-backed key)
 * with the JCE-correct {@link InvalidKeyException} — and NOT a
 * {@link NullPointerException} from dereferencing {@code encoded.length}.
 *
 * <p>The wrong exception type would also break JCE provider fallback (a runtime
 * NPE does not trigger the next-provider retry that {@code InvalidKeyException}
 * from {@code init} does). {@code CCMCipherSpi} already threw the correct typed
 * exception with the message pinned here; this test extends the same guarantee
 * to AES / ARIA / SM4 (and by construction CAMELLIA / DESede, which share the
 * pattern).
 */
public class BlockCipherNullKeyTest
{
    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    /**
     * A {@link SecretKey} carrying a cipher algorithm name but no encoded form —
     * the shape an opaque / HSM-backed key presents to a software provider.
     */
    private static final class NullEncodedKey implements SecretKey
    {
        private final String algorithm;

        NullEncodedKey(String algorithm)
        {
            this.algorithm = algorithm;
        }

        @Override
        public String getAlgorithm()
        {
            return algorithm;
        }

        @Override
        public String getFormat()
        {
            return "RAW";
        }

        @Override
        public byte[] getEncoded()
        {
            return null;
        }
    }

    @Test
    public void aesCbc_nullEncodedKey_rejectedTyped() throws Exception
    {
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", JostleProvider.PROVIDER_NAME);
        SecretKey nullKey = new NullEncodedKey("AES");

        // 2-arg init -> engineInit(int, Key, SecureRandom)
        InvalidKeyException ex = assertThrows(InvalidKeyException.class,
                () -> cipher.init(Cipher.ENCRYPT_MODE, nullKey));
        assertEquals("key has no encoded form", ex.getMessage());

        // 3-arg init with a spec -> engineInit(int, Key, AlgorithmParameterSpec, SecureRandom)
        InvalidKeyException ex2 = assertThrows(InvalidKeyException.class,
                () -> cipher.init(Cipher.ENCRYPT_MODE, nullKey, new IvParameterSpec(new byte[16])));
        assertEquals("key has no encoded form", ex2.getMessage());
    }

    @Test
    public void sm4Cbc_nullEncodedKey_rejectedTyped() throws Exception
    {
        Cipher cipher = Cipher.getInstance("SM4/CBC/NoPadding", JostleProvider.PROVIDER_NAME);
        SecretKey nullKey = new NullEncodedKey("SM4");

        InvalidKeyException ex = assertThrows(InvalidKeyException.class,
                () -> cipher.init(Cipher.ENCRYPT_MODE, nullKey));
        assertEquals("key has no encoded form", ex.getMessage());

        InvalidKeyException ex2 = assertThrows(InvalidKeyException.class,
                () -> cipher.init(Cipher.ENCRYPT_MODE, nullKey, new IvParameterSpec(new byte[16])));
        assertEquals("key has no encoded form", ex2.getMessage());
    }

    @Test
    public void ariaCbc_nullEncodedKey_rejectedTyped() throws Exception
    {
        Cipher cipher = Cipher.getInstance("ARIA/CBC/NoPadding", JostleProvider.PROVIDER_NAME);
        SecretKey nullKey = new NullEncodedKey("ARIA");

        InvalidKeyException ex = assertThrows(InvalidKeyException.class,
                () -> cipher.init(Cipher.ENCRYPT_MODE, nullKey));
        assertEquals("key has no encoded form", ex.getMessage());

        InvalidKeyException ex2 = assertThrows(InvalidKeyException.class,
                () -> cipher.init(Cipher.ENCRYPT_MODE, nullKey, new IvParameterSpec(new byte[16])));
        assertEquals("key has no encoded form", ex2.getMessage());
    }
}
