/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.fips;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.SortedSet;
import java.util.TreeSet;

/**
 * Cross-provider agreement and capability contract for 3-key Triple DES
 * (DES-EDE3) through JSLFIPS — the FIPS half of the pair whose base half is
 * {@code DESedeAgreementTest} (JSL vs BC). Per the "Every family needs BOTH
 * agreement classes" rule in {@code testing.md} the two are not redundant:
 * this one drives {@code libinterface_fips_*} against the FIPS
 * {@code OSSL_LIB_CTX}, and compares JSLFIPS against both JSL and BC.
 *
 * <h2>Two independent contracts, and both must be asserted by probe</h2>
 *
 * JSLFIPS ships one build that has to serve modules disagreeing about
 * Triple-DES in two separate ways, so no fixed assertion is right against all
 * of them (measured: {@code fips-c-review/probes/tdes_gate_probe.c}):
 *
 * <ol>
 *   <li><b>Is it implemented at all?</b> A module-VERSION difference: the
 *       3.1.2 module refuses every DES-EDE3 fetch under {@code fips=yes}, the
 *       3.5.x module serves them. {@code ProvFIPSDESede} gates registration on
 *       the cipher fetch, so on 3.1.2 {@code getInstance} throws
 *       {@code NoSuchAlgorithmException}. Asserted all-or-nothing against what
 *       the module answers, never against one module's answer.</li>
 *   <li><b>Will it ENCRYPT?</b> A fipsinstall CONFIG difference, invisible to
 *       any fetch: {@code tdes-encrypt-disabled} is off at defaults and on
 *       under {@code -pedantic}, so the SAME 3.5.7 module answers both ways.
 *       The refusal lands at {@code Cipher.init} and raises nothing on its own
 *       error queue, so it is classified in C
 *       ({@code classify_tdes_encrypt_init_failure}) and surfaces as
 *       {@code InvalidKeyException} carrying
 *       {@link FIPSTestUtil#TDES_ENCRYPT_REFUSED_MESSAGE}.</li>
 * </ol>
 *
 * <p>Decryption works on every configuration, so it is the load-bearing
 * direction here and every decrypt-side test runs unconditionally. Only the
 * genuinely encrypt-side tests take the capability skip — and that skip is
 * legitimate rather than silent because {@link FIPSTestUtil#fipsTripleDesCanEncrypt()}
 * pins the typed refusal and its exact message on the way to returning false.
 *
 * <p>Ciphertext fixtures for the decrypt-side tests are produced by
 * BouncyCastle, an independent implementation that works on every
 * configuration — which is also what a real caller on a decrypt-only module
 * has to do, and is a stronger check than round-tripping our own output.
 */
public class FIPSDESedeAgreementTest
{
    private static final String FIPS = JostleFIPSProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
    private static final String JSL = JostleProvider.PROVIDER_NAME;

    /** PKCS#9 OID for {@code des-EDE3-CBC}. */
    private static final String DES_EDE3_CBC_OID = "1.2.840.113549.3.7";

    /** DES block size in bytes. */
    private static final int DES_BLOCK = 8;

    /** 3-key TDES raw key size in bytes. */
    private static final int KEY_BYTES = 24;

    private static final SecureRandom RANDOM = new SecureRandom();

    private static SecureRandom seededRandom(String testName) throws Exception
    {
        long seed = RANDOM.nextLong();
        System.out.println(testName + " seed=" + seed);
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(seed);
        return sr;
    }

    @BeforeAll
    static void beforeFips()
    {
        FIPSTestUtil.assumeFipsProvider();
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    /** Skip unless the loaded module implements Triple-DES at all. */
    private static void assumeServed()
    {
        Assumptions.assumeTrue(FIPSTestUtil.moduleServesTripleDes(),
                "the loaded module (" + FIPSTestUtil.moduleDescription()
                        + ") does not implement Triple-DES");
    }

    /** Skip unless the loaded module will also ENCRYPT with Triple-DES. */
    private static void assumeCanEncrypt() throws Exception
    {
        assumeServed();
        Assumptions.assumeTrue(FIPSTestUtil.fipsTripleDesCanEncrypt(),
                "the loaded module (" + FIPSTestUtil.moduleDescription()
                        + ") is configured tdes-encrypt-disabled");
    }


    // -----------------------------------------------------------------
    // Contract 1 — registration tracks the module, all or nothing.
    // -----------------------------------------------------------------

    /**
     * Every Triple-DES service JSLFIPS could register is present exactly when
     * the module implements the cipher, and absent exactly when it does not.
     * <p>
     * All-or-nothing, because a PARTIAL registration is a real defect a
     * single-service check misses: a Cipher without its KeyGenerator, or a
     * primary without its OID, resolves for some callers and not others. The
     * expected answer comes from the module ({@link FIPSTestUtil#moduleServesTripleDes()}),
     * not from a fixed list, so this holds on both supported modules.
     */
    @Test
    public void tripleDesServedIffModuleImplementsIt()
    {
        boolean served = FIPSTestUtil.moduleServesTripleDes();
        Provider provider = FIPSTestUtil.assumeFipsProvider();

        // type -> name, including the two addAlias spellings (which are NOT
        // separate Services, so they must be probed through getInstance).
        String[][] surface = {
                {"Cipher", "DESede"},
                {"Cipher", "TripleDES"},
                {"Cipher", DES_EDE3_CBC_OID},
                {"KeyGenerator", "DESede"},
                {"KeyGenerator", "TripleDES"},
        };

        List<String> disagreements = new ArrayList<String>();
        for (String[] e : surface)
        {
            boolean resolves;
            try
            {
                if ("Cipher".equals(e[0]))
                {
                    resolves = Cipher.getInstance(e[1], FIPS) != null;
                }
                else
                {
                    resolves = KeyGenerator.getInstance(e[1], FIPS) != null;
                }
            }
            catch (NoSuchAlgorithmException ex)
            {
                resolves = false;
            }
            catch (Exception ex)
            {
                disagreements.add(e[0] + "." + e[1] + " threw " + ex);
                continue;
            }
            if (resolves != served)
            {
                disagreements.add(e[0] + "." + e[1] + " resolves=" + resolves
                        + " but the module implements Triple-DES=" + served);
            }
        }

        Assertions.assertTrue(disagreements.isEmpty(),
                "JSLFIPS's Triple-DES surface disagrees with the loaded module ("
                        + FIPSTestUtil.moduleDescription() + "):\n  "
                        + String.join("\n  ", disagreements));

        // And the Service view agrees with the getInstance view — a primary
        // registered under a wrong class name resolves as a Service but fails
        // to construct, which is the "registration is not usability" trap.
        Assertions.assertEquals(served, provider.getService("Cipher", "DESede") != null,
                "Cipher.DESede Service presence must track the module");
        Assertions.assertEquals(served, provider.getService("KeyGenerator", "DESede") != null,
                "KeyGenerator.DESede Service presence must track the module");
    }


    // -----------------------------------------------------------------
    // Contract 2 — the encrypt direction, both branches.
    // -----------------------------------------------------------------

    /**
     * Encryption is either refused with the exact capability message, or it
     * actually WORKS — never merely "resolves". Asserting only the refusal
     * would let a stale gate survive the capability arriving; asserting only
     * the success is wrong against a {@code -pedantic} module.
     * <p>
     * Decryption is asserted to work in BOTH branches, since that is the
     * property that makes keeping the family registered correct.
     */
    @Test
    public void encryptRefusedWhenDisabled_worksWhenNot() throws Exception
    {
        assumeServed();
        SecureRandom sr = seededRandom("encryptRefusedWhenDisabled_worksWhenNot");

        SecretKey key = fipsKey();
        byte[] iv = randomIv(sr);
        byte[] msg = randomMessage(sr);

        if (!FIPSTestUtil.fipsTripleDesCanEncrypt())
        {
            // fipsTripleDesCanEncrypt already pinned the typed exception and
            // its message; re-assert here on a DIFFERENT transformation so the
            // refusal is not specific to the probe's own one.
            InvalidKeyException e = Assertions.assertThrows(InvalidKeyException.class,
                    () -> Cipher.getInstance("DESede/ECB/NoPadding", FIPS)
                            .init(Cipher.ENCRYPT_MODE, key));
            Assertions.assertEquals(FIPSTestUtil.TDES_ENCRYPT_REFUSED_MESSAGE, e.getMessage());
        }
        else
        {
            byte[] ct = doFinal("DESede/CBC/PKCS5Padding", FIPS, Cipher.ENCRYPT_MODE, key, iv, msg);
            Assertions.assertFalse(Arrays.areEqual(msg, java.util.Arrays.copyOf(ct, msg.length)),
                    "encryption must transform its input");
            Assertions.assertArrayEquals(msg,
                    doFinal("DESede/CBC/PKCS5Padding", FIPS, Cipher.DECRYPT_MODE, key, iv, ct),
                    "JSLFIPS encrypt -> JSLFIPS decrypt");
        }

        // Either way, decryption of an independently-produced ciphertext works.
        byte[] bcCt = doFinal("DESede/CBC/PKCS5Padding", BC, Cipher.ENCRYPT_MODE, key, iv, msg);
        Assertions.assertArrayEquals(msg,
                doFinal("DESede/CBC/PKCS5Padding", FIPS, Cipher.DECRYPT_MODE, key, iv, bcCt),
                "Triple-DES decryption must work on every supported configuration");
    }


    // -----------------------------------------------------------------
    // Agreement — the decrypt direction runs everywhere and is the
    // load-bearing one (SP 800-131A keeps decryption for legacy data).
    // -----------------------------------------------------------------

    @Test
    public void decryptsWhatBouncyCastleEncrypted() throws Exception
    {
        assumeServed();
        SecureRandom sr = seededRandom("decryptsWhatBouncyCastleEncrypted");

        for (String xform : new String[]{
                "DESede/CBC/PKCS5Padding", "DESede/CBC/PKCS7Padding", "DESede/CBC/NoPadding",
                "DESede/ECB/PKCS5Padding", "DESede/ECB/PKCS7Padding", "DESede/ECB/NoPadding"})
        {
            for (int trial = 0; trial < 10; trial++)
            {
                SecretKey key = fipsKey();
                byte[] iv = xform.contains("/CBC/") ? randomIv(sr) : null;
                byte[] msg = xform.endsWith("NoPadding")
                        ? randomAligned(sr) : randomMessage(sr);

                byte[] bcCt = doFinal(xform, BC, Cipher.ENCRYPT_MODE, key, iv, msg);
                Assertions.assertArrayEquals(msg,
                        doFinal(xform, FIPS, Cipher.DECRYPT_MODE, key, iv, bcCt),
                        xform + ": BC encrypt -> JSLFIPS decrypt");
            }
        }
    }

    @Test
    public void decryptsWhatTheBaseProviderEncrypted() throws Exception
    {
        assumeServed();
        SecureRandom sr = seededRandom("decryptsWhatTheBaseProviderEncrypted");

        for (String xform : new String[]{"DESede/CBC/PKCS5Padding", "DESede/ECB/NoPadding"})
        {
            for (int trial = 0; trial < 10; trial++)
            {
                SecretKey key = fipsKey();
                byte[] iv = xform.contains("/CBC/") ? randomIv(sr) : null;
                byte[] msg = xform.endsWith("NoPadding")
                        ? randomAligned(sr) : randomMessage(sr);

                byte[] jslCt = doFinal(xform, JSL, Cipher.ENCRYPT_MODE, key, iv, msg);
                Assertions.assertArrayEquals(msg,
                        doFinal(xform, FIPS, Cipher.DECRYPT_MODE, key, iv, jslCt),
                        xform + ": JSL encrypt -> JSLFIPS decrypt");
            }
        }
    }

    /**
     * The encrypt direction, where the module allows it: JSLFIPS must produce
     * byte-identical ciphertext to both BouncyCastle and JSL, and each of them
     * must decrypt what JSLFIPS produced.
     */
    @Test
    public void encryptAgreesByteForByteWithBCAndTheBaseProvider() throws Exception
    {
        assumeCanEncrypt();
        SecureRandom sr = seededRandom("encryptAgreesByteForByteWithBCAndTheBaseProvider");

        for (String xform : new String[]{
                "DESede/CBC/PKCS5Padding", "DESede/CBC/NoPadding",
                "DESede/ECB/PKCS5Padding", "DESede/ECB/NoPadding"})
        {
            for (int trial = 0; trial < 10; trial++)
            {
                SecretKey key = fipsKey();
                byte[] iv = xform.contains("/CBC/") ? randomIv(sr) : null;
                byte[] msg = xform.endsWith("NoPadding")
                        ? randomAligned(sr) : randomMessage(sr);

                byte[] fipsCt = doFinal(xform, FIPS, Cipher.ENCRYPT_MODE, key, iv, msg);
                Assertions.assertArrayEquals(
                        doFinal(xform, BC, Cipher.ENCRYPT_MODE, key, iv, msg), fipsCt,
                        xform + ": JSLFIPS and BC must agree byte-for-byte");
                Assertions.assertArrayEquals(
                        doFinal(xform, JSL, Cipher.ENCRYPT_MODE, key, iv, msg), fipsCt,
                        xform + ": JSLFIPS and JSL must agree byte-for-byte");
                Assertions.assertArrayEquals(msg,
                        doFinal(xform, BC, Cipher.DECRYPT_MODE, key, iv, fipsCt),
                        xform + ": JSLFIPS encrypt -> BC decrypt");
            }
        }
    }


    // -----------------------------------------------------------------
    // Negative path.
    // -----------------------------------------------------------------

    @Test
    public void tamperedCiphertextDoesNotRoundTrip() throws Exception
    {
        assumeServed();
        SecureRandom sr = seededRandom("tamperedCiphertextDoesNotRoundTrip");

        SecretKey key = fipsKey();
        byte[] iv = randomIv(sr);
        byte[] msg = randomAligned(sr);
        byte[] ct = doFinal("DESede/CBC/NoPadding", BC, Cipher.ENCRYPT_MODE, key, iv, msg);

        byte[] tampered = Arrays.clone(ct);
        tampered[sr.nextInt(tampered.length)] ^= (byte) 0x01;

        byte[] decoded = doFinal("DESede/CBC/NoPadding", FIPS, Cipher.DECRYPT_MODE, key, iv, tampered);
        Assertions.assertFalse(Arrays.areEqual(msg, decoded),
                "a tampered ciphertext must not decrypt to the original plaintext");
    }

    @Test
    public void wrongKeyDoesNotRecoverPlaintext() throws Exception
    {
        assumeServed();
        SecureRandom sr = seededRandom("wrongKeyDoesNotRecoverPlaintext");

        SecretKey key = fipsKey();
        SecretKey wrong = fipsKey();
        byte[] iv = randomIv(sr);
        byte[] msg = randomAligned(sr);
        byte[] ct = doFinal("DESede/CBC/NoPadding", BC, Cipher.ENCRYPT_MODE, key, iv, msg);

        byte[] decoded = doFinal("DESede/CBC/NoPadding", FIPS, Cipher.DECRYPT_MODE, wrong, iv, ct);
        Assertions.assertFalse(Arrays.areEqual(msg, decoded),
                "decrypting with a different key must not recover the plaintext");
    }


    // -----------------------------------------------------------------
    // Chunking, on the direction that runs everywhere.
    // -----------------------------------------------------------------

    @Test
    public void chunkedDecryptMatchesOneShot() throws Exception
    {
        assumeServed();
        SecureRandom sr = seededRandom("chunkedDecryptMatchesOneShot");

        SecretKey key = fipsKey();
        byte[] iv = randomIv(sr);
        byte[] msg = new byte[41];
        sr.nextBytes(msg);
        byte[] ct = doFinal("DESede/CBC/PKCS5Padding", BC, Cipher.ENCRYPT_MODE, key, iv, msg);

        // 1 — one shot (the reference is BC's plaintext, not our own output).
        Assertions.assertArrayEquals(msg,
                doFinal("DESede/CBC/PKCS5Padding", FIPS, Cipher.DECRYPT_MODE, key, iv, ct),
                "one-shot decrypt");

        // 2 — byte by byte.
        int[] oneByOne = new int[ct.length];
        java.util.Arrays.fill(oneByOne, 1);
        Assertions.assertArrayEquals(msg, chunkedDecrypt(key, iv, ct, oneByOne),
                "byte-by-byte decrypt must match");

        // 3 — adversarial offsets around the block boundary.
        Assertions.assertArrayEquals(msg, chunkedDecrypt(key, iv, ct, adversarialChunks(ct.length)),
                "block-1 / block / block+1 chunking must match");

        // 4 — random splits.
        for (int trial = 0; trial < 10; trial++)
        {
            Assertions.assertArrayEquals(msg,
                    chunkedDecrypt(key, iv, ct, randomSplits(sr, ct.length)),
                    "random-split chunking must match");
        }
    }


    // -----------------------------------------------------------------
    // Reset / reuse.
    // -----------------------------------------------------------------

    @Test
    public void twoDecryptsOnOneInstanceBothCorrect() throws Exception
    {
        assumeServed();
        SecureRandom sr = seededRandom("twoDecryptsOnOneInstanceBothCorrect");

        SecretKey key = fipsKey();
        byte[] iv = randomIv(sr);
        byte[] a = randomAligned(sr);
        byte[] b = randomAligned(sr);
        byte[] ctA = doFinal("DESede/CBC/NoPadding", BC, Cipher.ENCRYPT_MODE, key, iv, a);
        byte[] ctB = doFinal("DESede/CBC/NoPadding", BC, Cipher.ENCRYPT_MODE, key, iv, b);

        Cipher dec = Cipher.getInstance("DESede/CBC/NoPadding", FIPS);
        dec.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        Assertions.assertArrayEquals(a, dec.doFinal(ctA), "first decrypt");
        Assertions.assertArrayEquals(b, dec.doFinal(ctB), "second decrypt on the same instance");
    }

    /**
     * The strongest reset test: drive the instance to a failure, then a
     * success. A native path that releases state only on success, or leaves a
     * partial-result buffer unscrubbed, surfaces here and nowhere else.
     */
    @Test
    public void failureThenSuccessOnOneInstance() throws Exception
    {
        assumeServed();
        SecureRandom sr = seededRandom("failureThenSuccessOnOneInstance");

        SecretKey key = fipsKey();
        byte[] iv = randomIv(sr);
        byte[] msg = randomMessage(sr);
        byte[] ct = doFinal("DESede/CBC/PKCS5Padding", BC, Cipher.ENCRYPT_MODE, key, iv, msg);

        Cipher dec = Cipher.getInstance("DESede/CBC/PKCS5Padding", FIPS);

        // Failure: a ciphertext one byte short of a block multiple.
        dec.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] truncated = java.util.Arrays.copyOf(ct, ct.length - 1);
        Assertions.assertThrows(Exception.class, () -> dec.doFinal(truncated),
                "a non-block-aligned ciphertext must be refused");

        // Success on the SAME instance.
        dec.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        Assertions.assertArrayEquals(msg, dec.doFinal(ct),
                "the instance must be usable after a refused doFinal");
    }


    // -----------------------------------------------------------------
    // In-place / aliased buffers, and the whole destination.
    // -----------------------------------------------------------------

    /**
     * {@code doFinal(buf, off, len, buf, off)} — the only in-place layout a
     * streaming transform supports (see {@code testing.md}; partial overlap at
     * a different offset is not an EVP contract and is platform-dependent).
     * The whole destination is verified, not just the written region.
     */
    @Test
    public void inPlaceSameOffsetDecrypt() throws Exception
    {
        assumeServed();
        SecureRandom sr = seededRandom("inPlaceSameOffsetDecrypt");

        SecretKey key = fipsKey();
        byte[] iv = randomIv(sr);
        byte[] msg = randomAligned(sr);
        byte[] ct = doFinal("DESede/CBC/NoPadding", BC, Cipher.ENCRYPT_MODE, key, iv, msg);

        int prefix = 5;
        int suffix = 7;
        byte[] buf = new byte[prefix + ct.length + suffix];
        sr.nextBytes(buf);
        byte[] snapshot = Arrays.clone(buf);
        System.arraycopy(ct, 0, buf, prefix, ct.length);

        Cipher dec = Cipher.getInstance("DESede/CBC/NoPadding", FIPS);
        dec.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        int written = dec.doFinal(buf, prefix, ct.length, buf, prefix);

        Assertions.assertEquals(msg.length, written, "in-place write length");
        Assertions.assertArrayEquals(msg,
                java.util.Arrays.copyOfRange(buf, prefix, prefix + written),
                "in-place decrypt must equal the separate-buffer result");
        Assertions.assertArrayEquals(
                java.util.Arrays.copyOfRange(snapshot, 0, prefix),
                java.util.Arrays.copyOfRange(buf, 0, prefix),
                "bytes before the offset must be untouched");
        Assertions.assertArrayEquals(
                java.util.Arrays.copyOfRange(snapshot, prefix + ct.length, buf.length),
                java.util.Arrays.copyOfRange(buf, prefix + ct.length, buf.length),
                "bytes after the written region must be untouched");
    }

    /**
     * Offset write into a separate buffer: prefix untouched, written region
     * functionally correct, and a window starting one byte early must NOT
     * round-trip — which is what catches an off-by-one in the bridge.
     */
    @Test
    public void doFinalWritesAtOffsetWithoutClobberingPrefix() throws Exception
    {
        assumeServed();
        SecureRandom sr = seededRandom("doFinalWritesAtOffsetWithoutClobberingPrefix");

        SecretKey key = fipsKey();
        byte[] iv = randomIv(sr);
        byte[] msg = randomAligned(sr);
        byte[] ct = doFinal("DESede/CBC/NoPadding", BC, Cipher.ENCRYPT_MODE, key, iv, msg);

        int outOff = 9;
        byte[] big = new byte[outOff + ct.length + 11];
        sr.nextBytes(big);
        byte[] expectedPrefix = java.util.Arrays.copyOf(big, outOff);

        Cipher dec = Cipher.getInstance("DESede/CBC/NoPadding", FIPS);
        dec.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        int written = dec.doFinal(ct, 0, ct.length, big, outOff);

        Assertions.assertArrayEquals(expectedPrefix, java.util.Arrays.copyOf(big, outOff),
                "bytes preceding outOff must be untouched");
        Assertions.assertArrayEquals(msg,
                java.util.Arrays.copyOfRange(big, outOff, outOff + written),
                "the written region must be the plaintext");
        Assertions.assertFalse(
                Arrays.areEqual(msg, java.util.Arrays.copyOfRange(big, outOff - 1, outOff - 1 + written)),
                "a window starting one byte early must NOT be the plaintext");
    }


    // -----------------------------------------------------------------
    // Key and IV length boundaries.
    // -----------------------------------------------------------------

    /**
     * 24 bytes is the only accepted key length. The 2-key (16-byte) form is
     * refused: the module does not implement DES-EDE-CBC at all, and DES-EDE3
     * itself refuses a 16-byte key — probe-measured on every configuration.
     */
    @Test
    public void keyLengthBoundaries() throws Exception
    {
        assumeServed();
        SecureRandom sr = seededRandom("keyLengthBoundaries");
        byte[] iv = randomIv(sr);

        for (int len : new int[]{1, 8, 15, 16, 17, 23, 25, 32, 64})
        {
            byte[] raw = new byte[len];
            sr.nextBytes(raw);
            SecretKeySpec bad = new SecretKeySpec(raw, "DESede");
            Assertions.assertThrows(InvalidKeyException.class,
                    () -> Cipher.getInstance("DESede/CBC/NoPadding", FIPS)
                            .init(Cipher.DECRYPT_MODE, bad, new IvParameterSpec(iv)),
                    len + "-byte key must be rejected");
        }

        // The accepted length, on the direction that runs everywhere.
        byte[] good = new byte[KEY_BYTES];
        sr.nextBytes(good);
        Cipher.getInstance("DESede/CBC/NoPadding", FIPS)
                .init(Cipher.DECRYPT_MODE, new SecretKeySpec(good, "DESede"), new IvParameterSpec(iv));
    }

    @Test
    public void ivLengthBoundaries() throws Exception
    {
        assumeServed();
        SecureRandom sr = seededRandom("ivLengthBoundaries");
        SecretKey key = fipsKey();

        for (int len : new int[]{0, 1, 7, 9, 16})
        {
            byte[] iv = new byte[len];
            sr.nextBytes(iv);
            Assertions.assertThrows(InvalidAlgorithmParameterException.class,
                    () -> Cipher.getInstance("DESede/CBC/NoPadding", FIPS)
                            .init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv)),
                    len + "-byte IV must be rejected");
        }

        Cipher.getInstance("DESede/CBC/NoPadding", FIPS)
                .init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(randomIv(sr)));
    }


    // -----------------------------------------------------------------
    // KeyGenerator and the OID alias.
    // -----------------------------------------------------------------

    @Test
    public void keyGeneratorProduces24ByteKeysUnderBothNames() throws Exception
    {
        assumeServed();

        for (String name : new String[]{"DESede", "TripleDES"})
        {
            SecretKey k1 = KeyGenerator.getInstance(name, FIPS).generateKey();
            SecretKey k2 = KeyGenerator.getInstance(name, FIPS).generateKey();
            Assertions.assertEquals(KEY_BYTES, k1.getEncoded().length, name + " key size");
            Assertions.assertFalse(Arrays.areEqual(k1.getEncoded(), k2.getEncoded()),
                    name + ": two generated keys must differ");
        }

        // 168 and 192 both denote 3-key TDES; anything else is rejected.
        KeyGenerator kg = KeyGenerator.getInstance("DESede", FIPS);
        kg.init(168);
        Assertions.assertEquals(KEY_BYTES, kg.generateKey().getEncoded().length);
        kg.init(192);
        Assertions.assertEquals(KEY_BYTES, kg.generateKey().getEncoded().length);
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> KeyGenerator.getInstance("DESede", FIPS).init(112));
    }

    /**
     * The OID primary has CBC pre-locked (JCE form-1 lookup never calls
     * {@code engineSetMode}), so it must decrypt what {@code DESede/CBC/NoPadding}
     * encrypted — not what ECB did.
     */
    @Test
    public void oidPrimaryIsCbcLocked() throws Exception
    {
        assumeServed();
        SecureRandom sr = seededRandom("oidPrimaryIsCbcLocked");

        SecretKey key = fipsKey();
        byte[] iv = randomIv(sr);
        byte[] msg = randomAligned(sr);
        byte[] cbcCt = doFinal("DESede/CBC/NoPadding", BC, Cipher.ENCRYPT_MODE, key, iv, msg);

        Cipher viaOid = Cipher.getInstance(DES_EDE3_CBC_OID, FIPS);
        viaOid.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        Assertions.assertArrayEquals(msg, viaOid.doFinal(cbcCt),
                "the OID primary must be CBC, not the SPI's ECB default");
    }


    // -----------------------------------------------------------------
    // Helpers.
    // -----------------------------------------------------------------

    /** A random 24-byte key from the FIPS provider's own KeyGenerator. */
    private static SecretKey fipsKey() throws Exception
    {
        return KeyGenerator.getInstance("DESede", FIPS).generateKey();
    }

    private static byte[] randomIv(SecureRandom sr)
    {
        byte[] iv = new byte[DES_BLOCK];
        sr.nextBytes(iv);
        return iv;
    }

    /** Random content AND random length, not a block multiple in general. */
    private static byte[] randomMessage(SecureRandom sr)
    {
        byte[] msg = new byte[1 + sr.nextInt(120)];
        sr.nextBytes(msg);
        return msg;
    }

    /** Random content, random block-aligned length (for NoPadding). */
    private static byte[] randomAligned(SecureRandom sr)
    {
        byte[] msg = new byte[DES_BLOCK * (1 + sr.nextInt(12))];
        sr.nextBytes(msg);
        return msg;
    }

    private static byte[] doFinal(String xform, String provider, int mode,
                                  java.security.Key key, byte[] iv, byte[] in) throws Exception
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

    private static byte[] chunkedDecrypt(SecretKey key, byte[] iv, byte[] ct, int[] splits)
            throws Exception
    {
        Cipher c = Cipher.getInstance("DESede/CBC/PKCS5Padding", FIPS);
        c.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int off = 0;
        for (int n : splits)
        {
            if (n <= 0 || off >= ct.length)
            {
                continue;
            }
            int take = Math.min(n, ct.length - off);
            byte[] part = c.update(ct, off, take);
            if (part != null)
            {
                out.write(part);
            }
            off += take;
        }
        if (off < ct.length)
        {
            byte[] part = c.update(ct, off, ct.length - off);
            if (part != null)
            {
                out.write(part);
            }
        }
        out.write(c.doFinal());
        return out.toByteArray();
    }

    /** BLOCK-1, BLOCK, BLOCK+1 repeating, so boundaries land differently. */
    private static int[] adversarialChunks(int total)
    {
        List<Integer> parts = new ArrayList<Integer>();
        int[] sizes = {DES_BLOCK - 1, DES_BLOCK, DES_BLOCK + 1};
        int remaining = total;
        int i = 0;
        while (remaining > 0)
        {
            int n = Math.min(sizes[i++ % sizes.length], remaining);
            parts.add(n);
            remaining -= n;
        }
        int[] out = new int[parts.size()];
        for (int j = 0; j < out.length; j++)
        {
            out[j] = parts.get(j);
        }
        return out;
    }

    private static int[] randomSplits(SecureRandom sr, int total)
    {
        List<Integer> parts = new ArrayList<Integer>();
        int remaining = total;
        while (remaining > 0)
        {
            int n = 1 + sr.nextInt(remaining);
            parts.add(n);
            remaining -= n;
        }
        int[] out = new int[parts.size()];
        for (int j = 0; j < out.length; j++)
        {
            out[j] = parts.get(j);
        }
        return out;
    }

    /**
     * Every DESede service and alias JSLFIPS registers is driven by a test in
     * this file, and every name this file claims to drive is registered —
     * measured against what the loaded MODULE serves, never a fixed list
     * (testing.md rule 6: a gated family is legitimately absent on one
     * module).
     * <p>
     * Distinct from {@link #tripleDesServedIffModuleImplementsIt}, which asks
     * whether a known list resolves. This asks the reverse — whether anything
     * registered goes untested — so a transformation added to
     * {@code ProvFIPSDESede} later fails here even though it would sail
     * through the other test.
     */
    @Test
    public void everyRegisteredDESedeServiceIsCovered()
    {
        Provider provider = FIPSTestUtil.assumeFipsProvider();
        SortedSet<String> registered = registeredDESedeSurface(provider);

        if (!FIPSTestUtil.moduleServesTripleDes())
        {
            Assertions.assertTrue(registered.isEmpty(),
                    "the module does not implement Triple-DES, yet JSLFIPS registers: " + registered);
            return;
        }

        SortedSet<String> covered = new TreeSet<String>(java.util.Arrays.asList(COVERED));

        Assertions.assertFalse(registered.isEmpty(),
                "the module serves Triple-DES but no DESede service was discovered — "
                        + "the guard would pass vacuously; check DESEDE_PREFIX still matches "
                        + "ProvFIPSDESede");

        SortedSet<String> uncovered = new TreeSet<String>(registered);
        uncovered.removeAll(covered);
        Assertions.assertTrue(uncovered.isEmpty(),
                "JSLFIPS registers DESede services this file does not exercise: " + uncovered);

        SortedSet<String> dead = new TreeSet<String>(covered);
        dead.removeAll(registered);
        Assertions.assertTrue(dead.isEmpty(),
                "COVERED names nothing registers (a rename left a dead entry): " + dead);
    }

    /**
     * The DESede names this file actually drives. Hand-written rather than
     * discovered, because the tests take a different transformation string per
     * mode/padding — which is exactly why the guard above is what makes the
     * list safe.
     */
    private static final String[] COVERED = {
            "Cipher.DESEDE",                    // the agreement, chunking, reset and boundary tests
            "Cipher.1.2.840.113549.3.7",        // oidPrimaryIsCbcLocked
            "Cipher.TRIPLEDES",                 // tripleDesServedIffModuleImplementsIt
            "KeyGenerator.DESEDE",              // fipsKey(), keyGeneratorProduces24ByteKeysUnderBothNames
            "KeyGenerator.TRIPLEDES",           // keyGeneratorProduces24ByteKeysUnderBothNames
    };

    // -----------------------------------------------------------------
    // Completeness guard (testing.md, "Every family needs BOTH agreement
    // classes", rule 2). Without it a transformation registered later is
    // exercised by nothing, and the omission is invisible: every existing
    // test still passes.
    // -----------------------------------------------------------------

    /**
     * The class name prefix both DESede registrars pass to
     * {@code addAlgorithmImplementation}. Discovering the surface by SPI class
     * rather than by algorithm NAME is what makes the guard bite: a future
     * registration picks up this prefix automatically, whereas a name-matching
     * filter would have to be taught the new name — the very thing being
     * guarded against.
     */
    private static final String DESEDE_PREFIX = "org.openssl.jostle.jcajce.provider.ProvDESede";

    /**
     * Every {@code <Type>.<NAME>} the provider registers from a DESede
     * registrar, primaries AND alias spellings.
     * <p>
     * Aliases have to be read out of the provider's own property map:
     * {@code addAlias} writes {@code Alg.Alias.<Type>.<ALIAS> -> <PRIMARY>},
     * and they are not Services, so {@code getServices()} alone would miss
     * them — and a broken alias is a real caller-visible defect
     * ({@code Cipher.getInstance("TripleDES")} is what a lot of code writes).
     */
    private static SortedSet<String> registeredDESedeSurface(Provider provider)
    {
        SortedSet<String> out = new TreeSet<String>();
        Map<String, String> primaries = new HashMap<String, String>();

        for (Provider.Service s : provider.getServices())
        {
            String cn = s.getClassName();
            if (cn != null && cn.startsWith(DESEDE_PREFIX))
            {
                String alg = s.getAlgorithm().toUpperCase(Locale.ROOT);
                out.add(s.getType() + "." + alg);
                primaries.put(s.getType() + "." + alg, alg);
            }
        }

        for (Map.Entry<Object, Object> e : provider.entrySet())
        {
            String key = String.valueOf(e.getKey());
            if (!key.startsWith("Alg.Alias."))
            {
                continue;
            }
            String rest = key.substring("Alg.Alias.".length());
            int dot = rest.indexOf('.');
            if (dot < 0)
            {
                continue;
            }
            String type = rest.substring(0, dot);
            String alias = rest.substring(dot + 1).toUpperCase(Locale.ROOT);
            String target = String.valueOf(e.getValue()).toUpperCase(Locale.ROOT);
            if (primaries.containsKey(type + "." + target))
            {
                out.add(type + "." + alias);
            }
        }
        return out;
    }

}
