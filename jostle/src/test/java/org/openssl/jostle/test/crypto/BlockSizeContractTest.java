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
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * MT-57: {@code Cipher.getBlockSize()} answers WITHOUT initialisation, and a
 * stream cipher answers 0.
 *
 * <h2>The 0 belongs to the stream ALGORITHM, never to the mode</h2>
 *
 * <p>That sentence is the whole reason this pin is shaped the way it is.
 * {@code AES/CTR} and {@code AES/CFB} are streaming MODES of a block cipher and
 * every provider reports 16 for them; {@code ChaCha20} is a stream ALGORITHM
 * and every provider reports 0. A pin that keyed on "is this a streaming mode"
 * would get CTR wrong, and a fix that keyed on {@code OSSLCipherType.STREAM}
 * would miss {@code ChaCha20-Poly1305}, which is typed AEAD and is one of the
 * two transformations this fix exists for. The discriminator is OpenSSL's own
 * marker - a reported block size of 1 - translated to the JCE's 0.
 *
 * <h2>Two boundaries, two tests, neither subsuming the other</h2>
 *
 * <ul>
 *   <li>{@link #blockSizeIsAnswerableBeforeInit} witnesses the TRANSLATION:
 *       EVP's 1 becomes the JCE's 0, and the answer does not depend on init.</li>
 *   <li>{@link #blockSizeAgreesWithIndependentImplementations} witnesses the
 *       TABLE, against implementations that do not share our source.</li>
 * </ul>
 *
 * <p>The second exists because the value is TRANSCRIBED in two places - the
 * {@code OSSLCipher} enum and the C tree's {@code BLOCK_SIZE_*} defines - and
 * {@code EVP_CIPHER_get_block_size} is called nowhere on the cipher path. So
 * asking our own native layer would compare two transcriptions of one fact and
 * witness neither. BouncyCastle and the JDK are independent of both.
 */
public class BlockSizeContractTest
{
    private static Provider jsl;
    private static Provider bc;
    private static final SecureRandom SR = new SecureRandom();

    /** transformation -> the block size every provider should report. */
    private static final Map<String, Integer> EXPECTED = new LinkedHashMap<String, Integer>();

    static
    {
        EXPECTED.put("AES/ECB/PKCS5Padding", 16);
        EXPECTED.put("AES/CBC/PKCS5Padding", 16);
        EXPECTED.put("AES/CTR/NoPadding", 16);
        EXPECTED.put("AES/CFB/NoPadding", 16);
        EXPECTED.put("AES/GCM/NoPadding", 16);
        EXPECTED.put("ARIA/CBC/PKCS5Padding", 16);
        EXPECTED.put("CAMELLIA/CBC/PKCS5Padding", 16);
        EXPECTED.put("SM4/CBC/PKCS5Padding", 16);
        EXPECTED.put("DESede/CBC/PKCS5Padding", 8);
        // Stream ALGORITHMS. OpenSSL says 1; the JCE reserves 0 for exactly this.
        EXPECTED.put("ChaCha20", 0);
        EXPECTED.put("ChaCha20-Poly1305", 0);
    }

    @BeforeAll
    public static void setUp()
    {
        jsl = Security.getProvider(JostleProvider.PROVIDER_NAME);
        if (jsl == null)
        {
            jsl = new JostleProvider();
            Security.addProvider(jsl);
        }
        bc = Security.getProvider("BC");
        if (bc == null)
        {
            bc = new BouncyCastleProvider();
            Security.addProvider(bc);
        }
    }

    private static int keyBytesFor(String xform)
    {
        String alg = xform.split("/")[0];
        if ("DESede".equals(alg))
        {
            return 24;
        }
        return "SM4".equals(alg) ? 16 : 32;
    }

    private static void init(Cipher c, String xform) throws Exception
    {
        String alg = xform.split("/")[0];
        byte[] key = new byte[keyBytesFor(xform)];
        SR.nextBytes(key);
        SecretKeySpec k = new SecretKeySpec(key, alg.startsWith("ChaCha") ? "ChaCha20" : alg);
        if (xform.contains("GCM"))
        {
            c.init(Cipher.ENCRYPT_MODE, k, new GCMParameterSpec(128, new byte[12]));
        }
        else if (xform.startsWith("ChaCha"))
        {
            c.init(Cipher.ENCRYPT_MODE, k, new IvParameterSpec(new byte[12]));
        }
        else if (xform.contains("/ECB/"))
        {
            c.init(Cipher.ENCRYPT_MODE, k);
        }
        else
        {
            c.init(Cipher.ENCRYPT_MODE, k, new IvParameterSpec(new byte["DESede".equals(alg) ? 8 : 16]));
        }
    }

    /**
     * The contract: answerable before init, and the SAME answer after.
     *
     * <p>Both halves matter. Fixing only the uninitialised one would have left
     * us reporting 0 before init and 1 after for the stream ciphers - a
     * self-inconsistency of our own making, and worse than the refusal it
     * replaced.
     */
    @Test
    public void blockSizeIsAnswerableBeforeInit() throws Exception
    {
        List<String> failures = new ArrayList<String>();
        for (Map.Entry<String, Integer> e : EXPECTED.entrySet())
        {
            String xform = e.getKey();
            int want = e.getValue().intValue();
            Cipher fresh = Cipher.getInstance(xform, jsl);
            int before;
            try
            {
                before = fresh.getBlockSize();
            }
            catch (Throwable t)
            {
                failures.add(xform + ": uninitialised getBlockSize threw " + t.getClass().getSimpleName());
                continue;
            }
            if (before != want)
            {
                failures.add(xform + ": uninitialised reported " + before + ", expected " + want);
            }
            Cipher inited = Cipher.getInstance(xform, jsl);
            init(inited, xform);
            int after = inited.getBlockSize();
            if (after != want)
            {
                failures.add(xform + ": initialised reported " + after + ", expected " + want);
            }
            if (before != after)
            {
                failures.add(xform + ": before-init " + before + " != after-init " + after);
            }
        }
        Assertions.assertTrue(failures.isEmpty(), "block-size contract violations: " + failures);
        Assertions.assertEquals(11, EXPECTED.size(), "the expectation table shrank");
    }

    /**
     * Every registered Cipher transformation answers uninitialised.
     *
     * <p>The behavioural guard on {@code blockSizeReference()} being non-null.
     * It is a NULL DEFAULT on the base class, so a new subclass that forgets it
     * compiles cleanly and fails only when someone asks - which is the shape of
     * defect a source-level default hides best. This drives every registered
     * name rather than the eleven named above, so a family added later is
     * covered without anyone remembering to add it here.
     */
    @Test
    public void everyRegisteredCipherAnswersBlockSizeUninitialised()
    {
        List<String> failures = new ArrayList<String>();
        int checked = 0;
        for (Provider.Service sv : jsl.getServices())
        {
            if (!"Cipher".equals(sv.getType()))
            {
                continue;
            }
            String name = sv.getAlgorithm();
            try
            {
                Cipher.getInstance(name, jsl).getBlockSize();
                checked++;
            }
            catch (java.security.NoSuchAlgorithmException | javax.crypto.NoSuchPaddingException absent)
            {
                // A bare primary that needs a mode/padding to resolve is not a
                // block-size question; skip rather than fabricate a failure.
            }
            catch (Throwable t)
            {
                failures.add(name + " -> " + t.getClass().getSimpleName());
            }
        }
        Assertions.assertTrue(checked >= 20,
                "only " + checked + " Cipher services answered; not reading the provider");
        Assertions.assertTrue(failures.isEmpty(),
                "registered Ciphers that cannot answer getBlockSize before init: " + failures);
    }

    /**
     * The TABLE, witnessed against implementations that do not share our source.
     *
     * <p>Our block size is transcribed twice - the {@code OSSLCipher} enum and
     * the C tree's {@code BLOCK_SIZE_*} defines - and nothing on the cipher path
     * calls {@code EVP_CIPHER_get_block_size}. Comparing those two to each other
     * would witness a transcription against its own copy. BouncyCastle and the
     * JDK are genuinely independent, so agreement with BOTH is evidence about
     * the value rather than about our internal consistency.
     */
    @Test
    public void blockSizeAgreesWithIndependentImplementations() throws Exception
    {
        List<String> rows = new ArrayList<String>();
        List<String> failures = new ArrayList<String>();
        int compared = 0;
        for (Map.Entry<String, Integer> e : EXPECTED.entrySet())
        {
            String xform = e.getKey();
            Integer ours = Integer.valueOf(Cipher.getInstance(xform, jsl).getBlockSize());
            Integer theirBc = sizeFrom(bc, xform);
            Integer theirJdk = null;
            for (Provider p : Security.getProviders())
            {
                if ("JSL".equals(p.getName()) || "BC".equals(p.getName()))
                {
                    continue;
                }
                Integer v = sizeFrom(p, xform);
                if (v != null)
                {
                    theirJdk = v;
                    break;
                }
            }
            rows.add(String.format("  %-28s ours=%-4s bc=%-6s jdk=%s", xform, ours,
                    theirBc == null ? "-" : theirBc, theirJdk == null ? "-" : theirJdk));
            if (theirBc != null && !ours.equals(theirBc))
            {
                // BouncyCastle returns -1 for ChaCha20-Poly1305, which is not a
                // legal value under any reading of the contract; it is in the
                // upstream bundle and must not drag our pin with it.
                if (theirBc.intValue() < 0)
                {
                    rows.add("        (BouncyCastle reported an illegal " + theirBc + "; see the upstream bundle)");
                }
                else
                {
                    failures.add(xform + ": ours " + ours + " vs BouncyCastle " + theirBc);
                }
            }
            if (theirJdk != null && !ours.equals(theirJdk))
            {
                failures.add(xform + ": ours " + ours + " vs the JDK " + theirJdk);
            }
            if (theirBc != null || theirJdk != null)
            {
                compared++;
            }
        }
        System.out.println("\n=== block size, three ways ===\n" + String.join("\n", rows));
        Assertions.assertTrue(compared >= 9,
                "only " + compared + " transformations had an independent comparator");
        Assertions.assertTrue(failures.isEmpty(), "block size disagrees with an independent implementation: " + failures);
    }

    private static Integer sizeFrom(Provider p, String xform)
    {
        try
        {
            return Integer.valueOf(Cipher.getInstance(xform, p).getBlockSize());
        }
        catch (Throwable t)
        {
            return null;
        }
    }
}
