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
import org.openssl.jostle.test.util.ProviderSurfaceGuard;
import org.openssl.jostle.test.util.Rfc3211WrapFamilies;
import org.openssl.jostle.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.SortedSet;
import java.util.TreeSet;

/**
 * RFC 3211 key wrap against BouncyCastle.
 *
 * <p>Byte equality is not asserted and cannot be: §2.3.1 pads with random
 * bytes, so two conforming implementations differ by design. The instruments
 * are cross-unwrap in both directions, equality of the wrapped LENGTH, and the
 * per-position tamper table below.
 *
 * <p>JSL only. JSLFIPS registers no RFC 3211 wrap; that absence is asserted
 * in {@code FIPSRFC3211WrapAgreementTest}, which is where a FIPS-touching cell
 * has to live so the module sweep's name filter can see it.
 */
public class RFC3211WrapAgreementTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    private static final SecureRandom RANDOM = new SecureRandom();

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    // ------------------------------------------------------------------
    // the registered surface
    // ------------------------------------------------------------------

    /**
     * Every registered RFC 3211 name is DRIVEN, discovered rather than listed,
     * aliases included. There are no aliases today; the guard does not assume
     * it.
     */
    @Test
    public void everyRegisteredRfc3211WrapIsDriven()
    {
        ProviderSurfaceGuard.assertEveryServiceDriven(
                Security.getProvider(JSL), Rfc3211WrapFamilies.PREFIX, "RFC 3211 wrap (JSL)",
                new String[]{"Cipher"},
                new ProviderSurfaceGuard.ServiceDriver()
                {
                    public void drive(String type, String alg) throws Exception
                    {
                        crossUnwrapBothWays(alg, 1);
                        crossUnwrapBothWays(alg, 16);
                        crossUnwrapBothWays(alg, 255);
                    }
                });
    }

    // ------------------------------------------------------------------
    // cross-unwrap
    // ------------------------------------------------------------------

    /** Both directions, at every CEK length the construction distinguishes. */
    @Test
    public void crossUnwrapsWithBouncyCastleBothDirectionsAtEveryCekLength() throws Exception
    {
        for (String alg : Rfc3211WrapFamilies.registeredNames())
        {
            for (int cekLen : new int[]{1, 2, 3, 5, 8, 16, 24, 32, 40})
            {
                crossUnwrapBothWays(alg, cekLen);
            }
        }
    }

    private static void crossUnwrapBothWays(String alg, int cekLen) throws Exception
    {
        int block = Rfc3211WrapFamilies.blockOf(alg);
        byte[] kek = rand(Rfc3211WrapFamilies.anyValidKek(alg));
        byte[] iv = rand(block);
        byte[] cek = rand(cekLen);
        String tag = alg + " cek=" + cekLen;

        byte[] ours = wrap(JSL, alg, kek, iv, cek);
        byte[] theirs = wrap(BC, alg, kek, iv, cek);

        Assertions.assertEquals(theirs.length, ours.length, tag + ": wrapped length");
        Assertions.assertTrue(Arrays.areEqual(cek, unwrap(BC, alg, kek, iv, ours)),
                tag + ": BouncyCastle could not unwrap ours");
        Assertions.assertTrue(Arrays.areEqual(cek, unwrap(JSL, alg, kek, iv, theirs)),
                tag + ": we could not unwrap BouncyCastle's");
    }

    // ------------------------------------------------------------------
    // the per-position tamper table
    // ------------------------------------------------------------------

    /**
     * Neither provider ever returns the ORIGINAL key from a tampered wrap, the
     * two agree on the outcome class at every position, and the blocks that
     * refuse are exactly {@code {0, n-2, n-1}} — the header block and the two
     * that feed its IV.
     *
     * <p>Only the third pins the construction; the first two stay green if
     * both implementations strengthen together.
     */
    @Test
    public void tamperOutcomesAgreeWithBouncyCastlePositionByPosition() throws Exception
    {
        for (String alg : Rfc3211WrapFamilies.registeredNames())
        {
            for (int cekLen : new int[]{1, 16, 32, 128, 255})
            {
                int block = Rfc3211WrapFamilies.blockOf(alg);
                byte[] kek = rand(Rfc3211WrapFamilies.anyValidKek(alg));
                byte[] iv = rand(block);
                byte[] cek = rand(cekLen);
                byte[] wrapped = wrap(JSL, alg, kek, iv, cek);
                int n = wrapped.length / block;
                String tag = alg + " cek=" + cekLen + " n=" + n;

                SortedSet<Integer> refusingBlocks = new TreeSet<Integer>();
                List<String> disagreements = new ArrayList<String>();

                for (int i = 0; i < wrapped.length; i++)
                {
                    byte[] bad = Arrays.clone(wrapped);
                    bad[i] ^= 0x01;

                    String ours = outcome(JSL, alg, kek, iv, bad, cek);
                    String theirs = outcome(BC, alg, kek, iv, bad, cek);

                    Assertions.assertNotEquals("original", ours,
                            tag + ": a tampered wrap returned the original key at byte " + i);
                    Assertions.assertNotEquals("original", theirs,
                            tag + ": BouncyCastle returned the original key at byte " + i);

                    if (!ours.equals(theirs))
                    {
                        disagreements.add("block " + (i / block) + " byte " + i
                                + ": ours " + ours + ", BouncyCastle " + theirs);
                    }
                    if ("threw".equals(ours))
                    {
                        refusingBlocks.add(i / block);
                    }
                }

                Assertions.assertTrue(disagreements.isEmpty(),
                        tag + ": the two providers classify a tampered wrap differently:\n  "
                                + String.join("\n  ", disagreements));

                SortedSet<Integer> expected = new TreeSet<Integer>();
                expected.add(0);
                expected.add(n - 2);
                expected.add(n - 1);
                Assertions.assertEquals(expected, refusingBlocks,
                        tag + ": the blocks that refuse a flip are not the header block and the"
                                + " two that feed it");
            }
        }
    }

    /** A flip in block 0 is refused, and both providers say the same thing. */
    @Test
    public void aFlipInTheHeaderBlockIsRefusedTypedByBothProviders() throws Exception
    {
        for (String alg : Rfc3211WrapFamilies.registeredNames())
        {
            int block = Rfc3211WrapFamilies.blockOf(alg);
            byte[] kek = rand(Rfc3211WrapFamilies.anyValidKek(alg));
            byte[] iv = rand(block);
            byte[] cek = rand(32);
            byte[] wrapped = wrap(JSL, alg, kek, iv, cek);

            // Block 0: a flip elsewhere in a long wrap returns wrong material
            // without refusing.
            byte[] bad = Arrays.clone(wrapped);
            bad[RANDOM.nextInt(block)] ^= 0x01;

            for (String provider : new String[]{JSL, BC})
            {
                InvalidKeyException e = Assertions.assertThrows(InvalidKeyException.class,
                        () -> unwrap(provider, alg, kek, iv, bad),
                        alg + " / " + provider + ": a flip in the header block must be refused");
                Assertions.assertEquals("wrapped key corrupted", e.getMessage(),
                        alg + " / " + provider + ": the refusal message has moved");
            }
        }
    }

    // ------------------------------------------------------------------
    // divergences, pinned in both halves
    // ------------------------------------------------------------------

    /**
     * A CEK over 255 bytes: RFC 3211 encodes the length in one byte. We raise
     * the type {@code Cipher.wrap} declares; BouncyCastle raises an unchecked
     * one.
     */
    @Test
    public void anOversizedCekDivergesInTypeFromBouncyCastle() throws Exception
    {
        for (String alg : Rfc3211WrapFamilies.registeredNames())
        {
            byte[] kek = rand(Rfc3211WrapFamilies.anyValidKek(alg));
            byte[] iv = rand(Rfc3211WrapFamilies.blockOf(alg));
            byte[] cek = rand(256);

            Assertions.assertThrows(javax.crypto.IllegalBlockSizeException.class,
                    () -> wrap(JSL, alg, kek, iv, cek),
                    alg + ": a 256-byte CEK must be refused with the declared type");
            Assertions.assertThrows(IllegalArgumentException.class,
                    () -> wrap(BC, alg, kek, iv, cek),
                    alg + ": BouncyCastle no longer raises IllegalArgumentException here."
                            + " The divergence has moved, re-measure both halves.");
        }
    }

    /**
     * A wrapped blob one byte short of three blocks. Ours is the type
     * {@code Cipher.unwrap} declares; BouncyCastle lets a lightweight
     * {@code DataLengthException} escape its JCE layer.
     */
    @Test
    public void aTruncatedWrapDivergesInTypeFromBouncyCastle() throws Exception
    {
        for (String alg : Rfc3211WrapFamilies.registeredNames())
        {
            int block = Rfc3211WrapFamilies.blockOf(alg);
            byte[] kek = rand(Rfc3211WrapFamilies.anyValidKek(alg));
            byte[] iv = rand(block);
            byte[] blob = new byte[3 * block - 1];

            Assertions.assertThrows(InvalidKeyException.class,
                    () -> unwrap(JSL, alg, kek, iv, blob),
                    alg + ": a truncated wrap must be refused with the declared type");
            Assertions.assertThrows(org.bouncycastle.crypto.DataLengthException.class,
                    () -> unwrap(BC, alg, kek, iv, blob),
                    alg + ": BouncyCastle no longer lets DataLengthException escape."
                            + " The divergence has moved, re-measure both halves.");
        }
    }

    /**
     * A wrong-length KEK. We refuse at init; BouncyCastle accepts the init and
     * refuses at the operation, unchecked. Its IV twin is pinned in
     * {@code RFC3211WrapTest}.
     */
    @Test
    public void aWrongLengthKekIsRefusedAtInitWhereBouncyCastleDefersToTheOperation()
        throws Exception
    {
        for (String alg : Rfc3211WrapFamilies.registeredNames())
        {
            int block = Rfc3211WrapFamilies.blockOf(alg);
            byte[] iv = rand(block);
            byte[] kek = rand(Rfc3211WrapFamilies.anyValidKek(alg) - 1);

            Assertions.assertThrows(InvalidKeyException.class,
                    () -> initWrap(JSL, alg, kek, iv),
                    alg + ": a short KEK must be refused at init");

            Cipher theirs = initWrap(BC, alg, kek, iv);
            Assertions.assertNotNull(theirs,
                    alg + ": BouncyCastle now refuses a short KEK at init. The divergence has"
                            + " moved, re-measure both halves.");
            Assertions.assertThrows(IllegalArgumentException.class,
                    () -> theirs.wrap(new SecretKeySpec(rand(16), "RAW")),
                    alg + ": BouncyCastle accepted a short KEK through the wrap as well");
        }
    }

    /** A null key: ours is typed, BouncyCastle's is a raw NPE. */
    @Test
    public void aNullKeyIsRefusedTypedWhereBouncyCastleRaisesNpe() throws Exception
    {
        for (String alg : Rfc3211WrapFamilies.registeredNames())
        {
            byte[] iv = rand(Rfc3211WrapFamilies.blockOf(alg));

            Assertions.assertThrows(InvalidKeyException.class,
                    () -> initWrapWithKey(JSL, alg, null, iv),
                    alg + ": a null key must be refused typed");
            Assertions.assertThrows(NullPointerException.class,
                    () -> initWrapWithKey(BC, alg, null, iv),
                    alg + ": BouncyCastle no longer raises a raw NPE, re-measure both halves");
        }
    }

    // ------------------------------------------------------------------
    // helpers
    // ------------------------------------------------------------------

    private static byte[] rand(int n)
    {
        byte[] b = new byte[n];
        RANDOM.nextBytes(b);
        return b;
    }

    private static byte[] wrap(String provider, String alg, byte[] kek, byte[] iv, byte[] cek)
        throws Exception
    {
        Cipher c = Cipher.getInstance(alg, provider);
        c.init(Cipher.WRAP_MODE, new SecretKeySpec(kek, alg), new IvParameterSpec(iv));
        return c.wrap(new SecretKeySpec(cek, "RAW"));
    }

    private static byte[] unwrap(String provider, String alg, byte[] kek, byte[] iv, byte[] blob)
        throws Exception
    {
        Cipher c = Cipher.getInstance(alg, provider);
        c.init(Cipher.UNWRAP_MODE, new SecretKeySpec(kek, alg), new IvParameterSpec(iv));
        return c.unwrap(blob, "RAW", Cipher.SECRET_KEY).getEncoded();
    }

    private static Cipher initWrap(String provider, String alg, byte[] kek, byte[] iv)
        throws Exception
    {
        return initWrapWithKey(provider, alg, new SecretKeySpec(kek, alg), iv);
    }

    private static Cipher initWrapWithKey(String provider, String alg, Key key, byte[] iv)
        throws Exception
    {
        Cipher c = Cipher.getInstance(alg, provider);
        c.init(Cipher.WRAP_MODE, key, new IvParameterSpec(iv));
        return c;
    }

    /** "threw", "wrong" or "original". */
    private static String outcome(String provider, String alg, byte[] kek, byte[] iv,
                                  byte[] blob, byte[] expected)
    {
        try
        {
            return Arrays.areEqual(expected, unwrap(provider, alg, kek, iv, blob))
                    ? "original" : "wrong";
        }
        catch (Throwable t)
        {
            return "threw";
        }
    }

    /**
     * Every row of the family table is reached by a registered name, so a row
     * cannot outlive the registration it describes.
     */
    @Test
    public void everyFamilyTableRowIsReachedByARegisteredName()
    {
        SortedSet<String> unreached = new TreeSet<String>(Rfc3211WrapFamilies.tableNames());
        unreached.removeAll(Rfc3211WrapFamilies.registeredNames());
        Assertions.assertTrue(unreached.isEmpty(),
                "the family table carries rows no registered name resolves to, so those rows"
                        + " read as coverage and describe nothing: " + unreached);
    }
}
