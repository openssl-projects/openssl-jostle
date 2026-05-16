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
import org.openssl.jostle.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.security.Security;

/**
 * Tests for AES Key Wrap (AES-KW, RFC 3394, JCE transformation
 * {@code AESWrap}) and AES Key Wrap with Padding (AES-KWP, RFC 5649,
 * JCE transformation {@code AESWrapPad}).
 *
 * <p>The suite covers:
 * <ol>
 *   <li>self-roundtrip across all three key sizes and both wrap variants,</li>
 *   <li>BC interop in both directions (wrap-Jostle/unwrap-BC and the
 *       reverse) — confirms the on-the-wire wrapped form matches the
 *       RFC and that BC accepts our output verbatim,</li>
 *   <li>OID-based {@code Cipher.getInstance} resolves to a working
 *       wrap cipher,</li>
 *   <li>negative cases — unaligned plaintext rejected by AES-KW,
 *       tampered ciphertext rejected by the ICV check, wrong unwrap key
 *       rejected by the ICV check.</li>
 * </ol>
 *
 * <p>CMP relies on these heavily: every recipient mechanism in CMS
 * EnvelopedData that uses key transport or key agreement wraps a
 * content-encryption key using one of these transformations.
 */
public class AESWrapTest
{
    private static final SecureRandom RANDOM = new SecureRandom();

    private static final int[] KEK_SIZES = {16, 24, 32};

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }


    // -----------------------------------------------------------------
    // Self-roundtrip (Jostle ↔ Jostle)
    // -----------------------------------------------------------------

    @Test
    public void aesWrap_selfRoundTrip_allKekSizes() throws Exception
    {
        // RFC 3394 requires the wrapped material to be a multiple of 8.
        // Use AES-128 / AES-256 content keys (16 / 32 bytes) so the
        // wrap satisfies KW's input-alignment requirement.
        int[] contentSizes = {16, 24, 32};
        for (int kekBytes : KEK_SIZES)
        {
            SecretKey kek = newAesKey(kekBytes);
            for (int ckSize : contentSizes)
            {
                SecretKey content = newAesKey(ckSize);

                Cipher wrap = Cipher.getInstance("AESWrap", JostleProvider.PROVIDER_NAME);
                wrap.init(Cipher.WRAP_MODE, kek);
                byte[] wrapped = wrap.wrap(content);

                // RFC 3394: ciphertext = plaintext + 8 bytes.
                Assertions.assertEquals(ckSize + 8, wrapped.length,
                        "KW wrapped length must be plaintext length + 8");

                Cipher unwrap = Cipher.getInstance("AESWrap", JostleProvider.PROVIDER_NAME);
                unwrap.init(Cipher.UNWRAP_MODE, kek);
                SecretKey unwrapped = (SecretKey) unwrap.unwrap(wrapped, "AES", Cipher.SECRET_KEY);

                Assertions.assertArrayEquals(content.getEncoded(),
                        unwrapped.getEncoded(),
                        "KEK=" + (kekBytes * 8) + " content=" + (ckSize * 8)
                                + ": unwrap produced different bytes");
            }
        }
    }

    @Test
    public void aesWrapPad_selfRoundTrip_arbitraryLengths() throws Exception
    {
        // KWP supports any plaintext length >= 1. Cover a handful of
        // lengths including ones that straddle the 8-byte boundary
        // (which is where the padding logic lives).
        int[] lengths = {1, 7, 8, 9, 15, 16, 17, 31, 32, 33, 64, 100};
        for (int kekBytes : KEK_SIZES)
        {
            SecretKey kek = newAesKey(kekBytes);
            for (int n : lengths)
            {
                byte[] payload = new byte[n];
                RANDOM.nextBytes(payload);
                SecretKey content = new SecretKeySpec(payload, "Generic");

                Cipher wrap = Cipher.getInstance("AESWrapPad", JostleProvider.PROVIDER_NAME);
                wrap.init(Cipher.WRAP_MODE, kek);
                byte[] wrapped = wrap.wrap(content);

                // KWP: ceil(n/8)*8 + 8.
                int expectedLen = ((n + 7) & ~7) + 8;
                Assertions.assertEquals(expectedLen, wrapped.length,
                        "KWP wrapped length wrong for n=" + n);

                Cipher unwrap = Cipher.getInstance("AESWrapPad", JostleProvider.PROVIDER_NAME);
                unwrap.init(Cipher.UNWRAP_MODE, kek);
                SecretKey unwrapped = (SecretKey) unwrap.unwrap(wrapped, "Generic", Cipher.SECRET_KEY);

                Assertions.assertArrayEquals(payload, unwrapped.getEncoded(),
                        "KEK=" + (kekBytes * 8) + " n=" + n
                                + ": unwrap produced different bytes");
            }
        }
    }


    // -----------------------------------------------------------------
    // BC interop
    // -----------------------------------------------------------------

    @Test
    public void aesWrap_BC_jostleWrap_bcUnwrap() throws Exception
    {
        for (int kekBytes : KEK_SIZES)
        {
            byte[] kekBytesRaw = newRandom(kekBytes);
            SecretKey kek = new SecretKeySpec(kekBytesRaw, "AES");

            // Wrap a 16-byte content key using Jostle.
            byte[] contentRaw = newRandom(16);
            SecretKey content = new SecretKeySpec(contentRaw, "AES");

            Cipher wrap = Cipher.getInstance("AESWrap", JostleProvider.PROVIDER_NAME);
            wrap.init(Cipher.WRAP_MODE, kek);
            byte[] wrapped = wrap.wrap(content);

            // Unwrap with BC — should produce the exact same content bytes.
            Cipher bcUnwrap = Cipher.getInstance("AESWrap", BouncyCastleProvider.PROVIDER_NAME);
            bcUnwrap.init(Cipher.UNWRAP_MODE, kek);
            SecretKey unwrapped = (SecretKey) bcUnwrap.unwrap(wrapped, "AES", Cipher.SECRET_KEY);

            Assertions.assertArrayEquals(contentRaw, unwrapped.getEncoded(),
                    "BC did not accept Jostle's wrapped output (KEK=" + (kekBytes * 8) + ")");
        }
    }

    @Test
    public void aesWrap_BC_bcWrap_jostleUnwrap() throws Exception
    {
        for (int kekBytes : KEK_SIZES)
        {
            byte[] kekBytesRaw = newRandom(kekBytes);
            SecretKey kek = new SecretKeySpec(kekBytesRaw, "AES");

            byte[] contentRaw = newRandom(16);
            SecretKey content = new SecretKeySpec(contentRaw, "AES");

            // Wrap with BC.
            Cipher bcWrap = Cipher.getInstance("AESWrap", BouncyCastleProvider.PROVIDER_NAME);
            bcWrap.init(Cipher.WRAP_MODE, kek);
            byte[] wrapped = bcWrap.wrap(content);

            // Unwrap with Jostle.
            Cipher unwrap = Cipher.getInstance("AESWrap", JostleProvider.PROVIDER_NAME);
            unwrap.init(Cipher.UNWRAP_MODE, kek);
            SecretKey unwrapped = (SecretKey) unwrap.unwrap(wrapped, "AES", Cipher.SECRET_KEY);

            Assertions.assertArrayEquals(contentRaw, unwrapped.getEncoded(),
                    "Jostle did not accept BC's wrapped output (KEK=" + (kekBytes * 8) + ")");
        }
    }

    @Test
    public void aesWrapPad_BC_jostleWrap_bcUnwrap() throws Exception
    {
        for (int kekBytes : KEK_SIZES)
        {
            byte[] kekBytesRaw = newRandom(kekBytes);
            SecretKey kek = new SecretKeySpec(kekBytesRaw, "AES");

            // Use a 17-byte payload so KWP padding is non-trivial.
            byte[] contentRaw = newRandom(17);
            SecretKey content = new SecretKeySpec(contentRaw, "Generic");

            Cipher wrap = Cipher.getInstance("AESWrapPad", JostleProvider.PROVIDER_NAME);
            wrap.init(Cipher.WRAP_MODE, kek);
            byte[] wrapped = wrap.wrap(content);

            Cipher bcUnwrap = Cipher.getInstance("AESWrapPad", BouncyCastleProvider.PROVIDER_NAME);
            bcUnwrap.init(Cipher.UNWRAP_MODE, kek);
            SecretKey unwrapped = (SecretKey) bcUnwrap.unwrap(wrapped, "Generic", Cipher.SECRET_KEY);

            Assertions.assertArrayEquals(contentRaw, unwrapped.getEncoded(),
                    "BC did not accept Jostle's KWP output (KEK=" + (kekBytes * 8) + ")");
        }
    }

    @Test
    public void aesWrapPad_BC_bcWrap_jostleUnwrap() throws Exception
    {
        for (int kekBytes : KEK_SIZES)
        {
            byte[] kekBytesRaw = newRandom(kekBytes);
            SecretKey kek = new SecretKeySpec(kekBytesRaw, "AES");

            byte[] contentRaw = newRandom(17);
            SecretKey content = new SecretKeySpec(contentRaw, "Generic");

            Cipher bcWrap = Cipher.getInstance("AESWrapPad", BouncyCastleProvider.PROVIDER_NAME);
            bcWrap.init(Cipher.WRAP_MODE, kek);
            byte[] wrapped = bcWrap.wrap(content);

            Cipher unwrap = Cipher.getInstance("AESWrapPad", JostleProvider.PROVIDER_NAME);
            unwrap.init(Cipher.UNWRAP_MODE, kek);
            SecretKey unwrapped = (SecretKey) unwrap.unwrap(wrapped, "Generic", Cipher.SECRET_KEY);

            Assertions.assertArrayEquals(contentRaw, unwrapped.getEncoded(),
                    "Jostle did not accept BC's KWP output (KEK=" + (kekBytes * 8) + ")");
        }
    }


    // -----------------------------------------------------------------
    // OID lookup
    // -----------------------------------------------------------------

    @Test
    public void aesWrap_OIDLookup_perKeySize() throws Exception
    {
        String[][] oidPairs = {
                {"2.16.840.1.101.3.4.1.5", "16"},   // id-aes128-wrap
                {"2.16.840.1.101.3.4.1.25", "24"},  // id-aes192-wrap
                {"2.16.840.1.101.3.4.1.45", "32"},  // id-aes256-wrap
        };
        for (String[] pair : oidPairs)
        {
            String oid = pair[0];
            int kekBytes = Integer.parseInt(pair[1]);

            SecretKey kek = newAesKey(kekBytes);
            SecretKey content = newAesKey(16);

            Cipher wrap = Cipher.getInstance(oid, JostleProvider.PROVIDER_NAME);
            wrap.init(Cipher.WRAP_MODE, kek);
            byte[] wrapped = wrap.wrap(content);

            Cipher unwrap = Cipher.getInstance(oid, JostleProvider.PROVIDER_NAME);
            unwrap.init(Cipher.UNWRAP_MODE, kek);
            SecretKey unwrapped = (SecretKey) unwrap.unwrap(wrapped, "AES", Cipher.SECRET_KEY);

            Assertions.assertArrayEquals(content.getEncoded(), unwrapped.getEncoded(),
                    "OID " + oid + ": roundtrip mismatch");
        }
    }

    @Test
    public void aesWrapPad_OIDLookup_perKeySize() throws Exception
    {
        String[][] oidPairs = {
                {"2.16.840.1.101.3.4.1.8", "16"},   // id-aes128-wrap-pad
                {"2.16.840.1.101.3.4.1.28", "24"},  // id-aes192-wrap-pad
                {"2.16.840.1.101.3.4.1.48", "32"},  // id-aes256-wrap-pad
        };
        for (String[] pair : oidPairs)
        {
            String oid = pair[0];
            int kekBytes = Integer.parseInt(pair[1]);

            SecretKey kek = newAesKey(kekBytes);
            byte[] payload = newRandom(13); // non-aligned length
            SecretKey content = new SecretKeySpec(payload, "Generic");

            Cipher wrap = Cipher.getInstance(oid, JostleProvider.PROVIDER_NAME);
            wrap.init(Cipher.WRAP_MODE, kek);
            byte[] wrapped = wrap.wrap(content);

            Cipher unwrap = Cipher.getInstance(oid, JostleProvider.PROVIDER_NAME);
            unwrap.init(Cipher.UNWRAP_MODE, kek);
            SecretKey unwrapped = (SecretKey) unwrap.unwrap(wrapped, "Generic", Cipher.SECRET_KEY);

            Assertions.assertArrayEquals(payload, unwrapped.getEncoded(),
                    "OID " + oid + ": KWP roundtrip mismatch");
        }
    }


    // -----------------------------------------------------------------
    // Negative paths
    // -----------------------------------------------------------------

    @Test
    public void aesWrap_TamperedWrapped_isRejected() throws Exception
    {
        SecretKey kek = newAesKey(32);
        SecretKey content = newAesKey(16);

        Cipher wrap = Cipher.getInstance("AESWrap", JostleProvider.PROVIDER_NAME);
        wrap.init(Cipher.WRAP_MODE, kek);
        byte[] wrapped = wrap.wrap(content);

        // Flip a byte in the middle so the ICV check at unwrap time fails.
        byte[] tampered = Arrays.clone(wrapped);
        tampered[tampered.length / 2] ^= 0x01;

        Cipher unwrap = Cipher.getInstance("AESWrap", JostleProvider.PROVIDER_NAME);
        unwrap.init(Cipher.UNWRAP_MODE, kek);
        try
        {
            unwrap.unwrap(tampered, "AES", Cipher.SECRET_KEY);
            Assertions.fail("expected InvalidKeyException for tampered wrapped key");
        }
        catch (InvalidKeyException expected)
        {
            // Good — RFC 3394 ICV mismatch surfaces as InvalidKeyException
            // (we collapse all unwrap failures into this type so no
            // padding-oracle channel leaks). The BlockCipherSpi
            // engineUnwrap wraps the underlying OpenSSLException with
            // a "unwrap failed: ..." message.
            Assertions.assertNotNull(expected.getMessage());
            Assertions.assertTrue(
                    expected.getMessage().startsWith("unwrap failed:"),
                    "unexpected message: " + expected.getMessage());
        }
    }

    @Test
    public void aesWrap_WrongKek_isRejected() throws Exception
    {
        SecretKey kek1 = newAesKey(32);
        SecretKey kek2 = newAesKey(32);
        SecretKey content = newAesKey(16);

        Cipher wrap = Cipher.getInstance("AESWrap", JostleProvider.PROVIDER_NAME);
        wrap.init(Cipher.WRAP_MODE, kek1);
        byte[] wrapped = wrap.wrap(content);

        Cipher unwrap = Cipher.getInstance("AESWrap", JostleProvider.PROVIDER_NAME);
        unwrap.init(Cipher.UNWRAP_MODE, kek2);
        try
        {
            unwrap.unwrap(wrapped, "AES", Cipher.SECRET_KEY);
            Assertions.fail("expected InvalidKeyException for wrong KEK");
        }
        catch (InvalidKeyException expected)
        {
            Assertions.assertNotNull(expected.getMessage());
            Assertions.assertTrue(
                    expected.getMessage().startsWith("unwrap failed:"),
                    "unexpected message: " + expected.getMessage());
        }
    }

    @Test
    public void aesWrap_UnalignedInput_isRejected() throws Exception
    {
        // RFC 3394 requires the wrapped material to be a multiple of 8.
        // A 17-byte payload should be rejected at wrap time (KWP would
        // accept it; KW must not). JCE contract is that wrap() funnels
        // input-shape failures through IllegalBlockSizeException.
        SecretKey kek = newAesKey(32);
        SecretKey unaligned = new SecretKeySpec(newRandom(17), "Generic");

        Cipher wrap = Cipher.getInstance("AESWrap", JostleProvider.PROVIDER_NAME);
        wrap.init(Cipher.WRAP_MODE, kek);
        try
        {
            wrap.wrap(unaligned);
            Assertions.fail("expected wrap to reject 17-byte input");
        }
        catch (IllegalBlockSizeException expected)
        {
            // BlockCipherSpi.engineWrap translates the underlying
            // BadPaddingException into IllegalBlockSizeException; the
            // OpenSSL-side message survives in the cause chain but
            // the surface message is the original engineDoFinal error
            // text.
            Assertions.assertNotNull(expected.getMessage());
        }
    }


    // -----------------------------------------------------------------
    // SPI reset / reuse (CLAUDE.md "Test that the SPI is correctly
    // usable after reset")
    // -----------------------------------------------------------------

    /**
     * Two wraps through one Cipher instance must each produce the
     * correct ciphertext. Catches an SPI that leaves stale state in
     * the native ctx between calls — e.g. a bad reInit that re-uses
     * the previous key's EVP_CIPHER_CTX without re-seeding.
     */
    @Test
    public void aesWrap_TwoWrapsOnSameInstance_bothUnwrap() throws Exception
    {
        SecretKey kek = newAesKey(32);
        SecretKey contentA = newAesKey(16);
        SecretKey contentB = newAesKey(24);

        Cipher wrap = Cipher.getInstance("AESWrap", JostleProvider.PROVIDER_NAME);
        wrap.init(Cipher.WRAP_MODE, kek);
        byte[] wrappedA = wrap.wrap(contentA);
        byte[] wrappedB = wrap.wrap(contentB);

        Cipher unwrap = Cipher.getInstance("AESWrap", JostleProvider.PROVIDER_NAME);
        unwrap.init(Cipher.UNWRAP_MODE, kek);
        Assertions.assertArrayEquals(contentA.getEncoded(),
                ((SecretKey) unwrap.unwrap(wrappedA, "AES", Cipher.SECRET_KEY)).getEncoded());
        Assertions.assertArrayEquals(contentB.getEncoded(),
                ((SecretKey) unwrap.unwrap(wrappedB, "AES", Cipher.SECRET_KEY)).getEncoded());
    }

    /**
     * Negative-then-positive reuse pattern. Drive the SPI to a failure
     * (tampered ciphertext → InvalidKeyException), re-init, then a
     * legitimate unwrap on the SAME instance must succeed.
     *
     * <p>The underlying {@code EVP_CIPHER_CTX} is poisoned on
     * {@code EVP_DecryptUpdate} failure to prevent reuse of partial
     * state; {@code init} clears the flag so the standard recovery
     * pattern works.
     */
    @Test
    public void aesWrap_NegativeThenPositive_failureDoesNotPoison() throws Exception
    {
        SecretKey kek = newAesKey(32);
        SecretKey content = newAesKey(16);

        Cipher wrap = Cipher.getInstance("AESWrap", JostleProvider.PROVIDER_NAME);
        wrap.init(Cipher.WRAP_MODE, kek);
        byte[] good = wrap.wrap(content);
        byte[] tampered = Arrays.clone(good);
        tampered[tampered.length / 2] ^= 0x01;

        Cipher unwrap = Cipher.getInstance("AESWrap", JostleProvider.PROVIDER_NAME);
        unwrap.init(Cipher.UNWRAP_MODE, kek);
        try
        {
            unwrap.unwrap(tampered, "AES", Cipher.SECRET_KEY);
            Assertions.fail("expected InvalidKeyException for tampered wrapped key");
        }
        catch (InvalidKeyException expected)
        {
            // Expected.
        }

        // Re-init the same Cipher instance and confirm a legitimate
        // unwrap then succeeds — proves init properly clears any
        // residual state from the prior failure.
        unwrap.init(Cipher.UNWRAP_MODE, kek);
        SecretKey unwrapped = (SecretKey) unwrap.unwrap(good, "AES", Cipher.SECRET_KEY);
        Assertions.assertArrayEquals(content.getEncoded(), unwrapped.getEncoded(),
                "follow-up unwrap after re-init must succeed");
    }


    // -----------------------------------------------------------------
    // KW alignment boundary (CLAUDE.md "Probe range-check boundaries
    // at exactly boundary + 1, not arbitrary values")
    // -----------------------------------------------------------------

    /**
     * RFC 3394 AES-KW requires the plaintext to be a multiple of 8
     * bytes with minimum 16. Probe the boundary directly:
     * <ul>
     *   <li>16 bytes — accepted (minimum valid).</li>
     *   <li>24 bytes — accepted (next valid).</li>
     *   <li>15 bytes — rejected (one less than minimum).</li>
     *   <li>17 bytes — rejected (one more than minimum, mis-aligned).</li>
     * </ul>
     */
    @Test
    public void aesWrap_KW_alignmentBoundary() throws Exception
    {
        SecretKey kek = newAesKey(32);

        // Accepted lengths
        for (int validLen : new int[]{16, 24})
        {
            byte[] payload = newRandom(validLen);
            Cipher wrap = Cipher.getInstance("AESWrap", JostleProvider.PROVIDER_NAME);
            wrap.init(Cipher.WRAP_MODE, kek);
            byte[] wrapped = wrap.wrap(new SecretKeySpec(payload, "Generic"));
            Assertions.assertEquals(validLen + 8, wrapped.length,
                    validLen + "-byte input should wrap to " + (validLen + 8) + " bytes");
        }

        // Rejected lengths — probe at exactly boundary - 1 and
        // boundary + 1 (the smallest unaligned values either side of
        // the valid range).
        for (int badLen : new int[]{15, 17})
        {
            SecretKey bad = new SecretKeySpec(newRandom(badLen), "Generic");
            Cipher wrap = Cipher.getInstance("AESWrap", JostleProvider.PROVIDER_NAME);
            wrap.init(Cipher.WRAP_MODE, kek);
            try
            {
                wrap.wrap(bad);
                Assertions.fail("KW should have rejected " + badLen + "-byte input");
            }
            catch (IllegalBlockSizeException expected)
            {
                // Expected — KW alignment violated.
                Assertions.assertNotNull(expected.getMessage());
            }
        }
    }


    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    private static SecretKey newAesKey(int sizeBytes) throws Exception
    {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(sizeBytes * 8);
        return kg.generateKey();
    }

    private static byte[] newRandom(int n)
    {
        byte[] b = new byte[n];
        RANDOM.nextBytes(b);
        return b;
    }

}
