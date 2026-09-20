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

package org.openssl.jostle.test.util;

import org.junit.jupiter.api.Assertions;
import org.openssl.jostle.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidParameterException;
import java.security.SecureRandom;
import java.util.Locale;

/**
 * Drives one registered symmetric {@code KeyGenerator} name, for every
 * family's guard and both providers.
 *
 * <p>Shared rather than copied per family because the checks are identical and
 * only the length table differs; four copies would be four things to keep in
 * step.
 *
 * <p>What each name must satisfy: it generates at every length its table
 * accepts and yields the table's byte count; it defaults to the table's
 * default; it refuses a length outside the set typed; the key reports the
 * family's base algorithm; two keys differ; and the key drives the family's
 * primary Cipher against BouncyCastle one block each way.
 */
public final class KeyGeneratorSurfaceDriver
{
    /** Where BouncyCastle is registered. */
    private static final String BC = "BC";

    /**
     * The sizes every name is probed at: each width any family in the tree
     * accepts, plus neighbours either side.
     */
    private static final int[] SPREAD = {64, 112, 128, 168, 192, 256, 512};

    private KeyGeneratorSurfaceDriver()
    {
    }

    /**
     * @param provider    provider to drive
     * @param table       the accepted sizes for this family's names
     * @param fixedBaseAlg the algorithm every name in this group generates for
     *                     ({@code "AES"}, {@code "ChaCha20"}, {@code "DESede"}),
     *                     or {@code null} where the registered name IS the base
     *                     algorithm, as it is for the three families sharing
     *                     {@code SymmetricKeyGenerator}
     * @param divergenceBits a size WE refuse and BouncyCastle accepts, measured
     *                     2026-09-20; see
     *                     {@link #assertRefusesALengthOutsideTheSet}
     */
    public static ProviderSurfaceGuard.ServiceDriver forProvider(final String provider,
                                                                 final CipherSurfaceDriver.KeyGenLengths table,
                                                                 final String fixedBaseAlg,
                                                                 final int divergenceBits)
    {
        return new ProviderSurfaceGuard.ServiceDriver()
        {
            public void drive(String type, String alg) throws Exception
            {
                if (!"KeyGenerator".equals(type))
                {
                    throw new IllegalStateException("no drive defined for " + type + "." + alg
                            + " — teach this driver rather than letting it go unexercised");
                }
                driveOne(provider, table, fixedBaseAlg, divergenceBits, alg);
            }
        };
    }

    static void driveOne(String provider, CipherSurfaceDriver.KeyGenLengths table,
                         String fixedBaseAlg, int divergenceBits, String alg)
        throws Exception
    {
        SecureRandom sr = new SecureRandom();
        String base = fixedBaseAlg == null ? alg : fixedBaseAlg;

        SecretKey dflt = KeyGenerator.getInstance(alg, provider).generateKey();
        Assertions.assertEquals(table.defaultKeyBytes(alg), dflt.getEncoded().length,
                alg + ": uninitialised generator produced the wrong key length");
        Assertions.assertEquals(base.toUpperCase(Locale.ROOT),
                dflt.getAlgorithm().toUpperCase(Locale.ROOT),
                alg + ": the key does not report the family's base algorithm");

        assertTheAcceptedSetIsExact(provider, table, alg, base);

        SecretKey a = KeyGenerator.getInstance(alg, provider).generateKey();
        SecretKey b = KeyGenerator.getInstance(alg, provider).generateKey();
        Assertions.assertFalse(Arrays.areEqual(a.getEncoded(), b.getEncoded()),
                alg + ": two generated keys are identical");

        assertRefusesALengthOutsideTheSet(provider, table, alg, base, divergenceBits);
        driveTheFamilyCipherAgainstBc(provider, base, a, sr, alg);
    }

    /**
     * The table is the EXPECTATION and the provider the subject, in BOTH
     * directions: every size the table lists is accepted and yields the
     * table's byte count, and every other size on the probe spread is refused
     * typed.
     *
     * <p>Both directions matter. Checking only the listed sizes makes the
     * table unfalsifiable — deleting a row would merely test less and stay
     * green, so the guard could quietly stop covering a length nobody noticed
     * had gone. With the complement checked, a deleted row asserts a refusal
     * the provider does not make, and the name goes red.
     *
     * <p>The spread is fixed rather than exhaustive: it carries every size any
     * family in the tree accepts, plus neighbours on both sides.
     */
    private static void assertTheAcceptedSetIsExact(String provider,
                                                    CipherSurfaceDriver.KeyGenLengths table,
                                                    String alg, String base)
        throws Exception
    {
        for (int bits : SPREAD)
        {
            boolean expected = false;
            for (int ok : table.acceptedBits(alg))
            {
                if (ok == bits)
                {
                    expected = true;
                    break;
                }
            }

            if (!expected)
            {
                try
                {
                    KeyGenerator.getInstance(alg, provider).init(bits);
                    Assertions.fail(alg + ": init(" + bits + ") is not in the accepted set and was"
                            + " accepted — the table and the provider disagree");
                }
                catch (InvalidParameterException refused)
                {
                    continue;
                }
            }

            KeyGenerator kg = KeyGenerator.getInstance(alg, provider);
            kg.init(bits);
            SecretKey k = kg.generateKey();
            Assertions.assertEquals(table.keyBytesFor(alg, bits), k.getEncoded().length,
                    alg + ": init(" + bits + ") produced the wrong key length");
            Assertions.assertEquals(base.toUpperCase(Locale.ROOT),
                    k.getAlgorithm().toUpperCase(Locale.ROOT),
                    alg + ": init(" + bits + ") key does not report the base algorithm");
        }
    }

    /**
     * A length outside the accepted set is refused with
     * {@link InvalidParameterException}, the JCE-canonical type for
     * {@code KeyGenerator.init(int)}, and the message names the permitted
     * sizes.
     *
     * <p>BouncyCastle's answer at the SAME size is pinned beside ours rather
     * than matched, because BC is the divergent side and the divergence has two
     * shapes, both measured 2026-09-20 across sizes 8 to 512:
     *
     * <ul>
     * <li>AES, ARIA, Camellia, SM4 and ChaCha20 — BC validates NOTHING. Every
     * size from 8 to 512 is accepted and yields {@code bits / 8} bytes, so
     * {@code AES.init(64)} hands back an 8-byte "AES" key. The divergence point
     * used here is 64.</li>
     * <li>Triple-DES — BC DOES validate, and accepts 112, 128, 168 and 192. The
     * divergence is narrower and is a DECISION rather than a type: BC serves
     * 2-key TDES at 112 and 128, which we refuse because the module implements
     * only the 3-key form. The divergence point used here is 128.</li>
     * </ul>
     *
     * <p>Per the exception-type rule, where BC departs from the JCE contract
     * the canonical type wins and the divergence is pinned in BOTH halves, so a
     * bcprov bump that moves either side fails here instead of leaving our half
     * looking like parity.
     *
     * <p>The BC half is taken only where BC serves the name. The per-width and
     * OID spellings are ours alone — {@code KeyGenerator.getInstance("AES128",
     * "BC")} raises {@code NoSuchAlgorithmException}.
     */
    private static void assertRefusesALengthOutsideTheSet(String provider,
                                                          CipherSurfaceDriver.KeyGenLengths table,
                                                          String alg, String base, int bad)
        throws Exception
    {
        for (int ok : table.acceptedBits(alg))
        {
            Assertions.assertNotEquals(ok, bad,
                    alg + ": the divergence point is inside the accepted set, so this pin proves"
                            + " nothing — re-measure it");
        }

        try
        {
            KeyGenerator.getInstance(alg, provider).init(bad);
            Assertions.fail(alg + ": init(" + bad + ") is outside the accepted set and was accepted");
        }
        catch (InvalidParameterException expected)
        {
            Assertions.assertNotNull(expected.getMessage(),
                    alg + ": refused init(" + bad + ") without saying what is permitted");
            Assertions.assertTrue(expected.getMessage().toLowerCase(Locale.ROOT).contains("key size")
                            || expected.getMessage().toLowerCase(Locale.ROOT).contains("key must be"),
                    alg + ": refusal does not name the key size: " + expected.getMessage());
        }

        if (!alg.equalsIgnoreCase(base))
        {
            // BC has no per-width or OID spelling of these names.
            return;
        }

        KeyGenerator bc;
        try
        {
            bc = KeyGenerator.getInstance(base, BC);
        }
        catch (java.security.NoSuchAlgorithmException absent)
        {
            return;
        }
        bc.init(bad);
        Assertions.assertEquals(bad / 8, bc.generateKey().getEncoded().length,
                base + ": BouncyCastle no longer accepts init(" + bad + ") as it did when this"
                        + " divergence was measured. Re-measure BOTH halves before changing it.");
    }

    /**
     * The generated key drives the family's primary Cipher and agrees with
     * BouncyCastle byte for byte, both directions. The key crosses as an
     * ENCODING, the only sanctioned route between providers.
     */
    private static void driveTheFamilyCipherAgainstBc(String provider, String base, SecretKey key,
                                                      SecureRandom sr, String alg)
        throws Exception
    {
        boolean stream = "ChaCha20".equalsIgnoreCase(base);
        String xform = stream ? "ChaCha20" : base + "/ECB/NoPadding";
        int block = stream ? 64 : ("DESede".equalsIgnoreCase(base) ? 8 : 16);

        byte[] iv = null;
        if (stream)
        {
            iv = new byte[12];
            sr.nextBytes(iv);
        }
        byte[] pt = new byte[block];
        sr.nextBytes(pt);

        SecretKey theirKey = new SecretKeySpec(key.getEncoded(), key.getAlgorithm());

        byte[] theirs = doFinal(xform, BC, Cipher.ENCRYPT_MODE, theirKey, iv, pt);

        byte[] ours;
        try
        {
            ours = doFinal(xform, provider, Cipher.ENCRYPT_MODE, key, iv, pt);
        }
        catch (java.security.InvalidKeyException e)
        {
            // tdes-encrypt-disabled is a fipsinstall switch: the module may
            // refuse encryption while still decrypting. Accepted only with its
            // own pinned message, and the decrypt direction still has to work,
            // so a refusal for any other reason still fails the guard.
            Assertions.assertTrue(
                    String.valueOf(e.getMessage()).contains("Triple-DES encryption is not supported"),
                    alg + ": refused, but not by the tdes-encrypt-disabled gate: " + e.getMessage());
            Assertions.assertTrue(
                    Arrays.areEqual(pt, doFinal(xform, provider, Cipher.DECRYPT_MODE, key, iv, theirs)),
                    alg + ": encryption is gated off, and this key could not decrypt BouncyCastle's"
                            + " ciphertext either");
            return;
        }

        Assertions.assertTrue(Arrays.areEqual(ours, theirs),
                alg + ": a key from this generator encrypts differently from BouncyCastle under "
                        + xform);
        Assertions.assertTrue(
                Arrays.areEqual(pt, doFinal(xform, BC, Cipher.DECRYPT_MODE, theirKey, iv, ours)),
                alg + ": BouncyCastle could not decrypt what this key encrypted");
    }

    private static byte[] doFinal(String xform, String provider, int mode, SecretKey key,
                                  byte[] iv, byte[] in)
        throws Exception
    {
        Cipher c = Cipher.getInstance(xform, provider);
        if (iv == null)
        {
            c.init(mode, key);
        }
        else
        {
            c.init(mode, key, new IvParameterSpec(iv));
        }
        return c.doFinal(in);
    }
}
