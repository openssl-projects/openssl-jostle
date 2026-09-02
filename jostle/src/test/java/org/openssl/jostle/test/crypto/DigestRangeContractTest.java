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

import java.security.DigestException;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

/**
 * Group A asks 3, 4 and 5: the three MessageDigest range rulings, pinned
 * together because they are three decisions about one pair of methods and are
 * only intelligible side by side.
 *
 * <table>
 *   <caption>Ruled 2026-09-02, measured three ways</caption>
 *   <tr><th>call</th><th>JSL</th><th>BouncyCastle</th><th>JDK</th><th>ruling</th></tr>
 *   <tr><td>{@code digest(out, -1, n)}</td><td>{@code DigestException}</td>
 *       <td>{@code ArrayIndexOutOfBoundsException}</td><td>{@code DigestException}</td>
 *       <td>ask 3: <i>"do what the JDK does"</i> — CHANGED</td></tr>
 *   <tr><td>{@code update(buf, -1, n)}</td><td>{@code IllegalArgumentException}</td>
 *       <td>{@code ArrayIndexOutOfBoundsException}</td><td>{@code ArrayIndexOutOfBoundsException}</td>
 *       <td>ask 4: <i>"leave"</i> — UNCHANGED, we are the odd provider</td></tr>
 *   <tr><td>{@code update(buf, 0, -1)}</td><td>{@code IllegalArgumentException}</td>
 *       <td>split, see below</td><td>{@code ArrayIndexOutOfBoundsException}</td>
 *       <td>ask 5: <i>"keep"</i> — UNCHANGED</td></tr>
 * </table>
 *
 * <h2>Ask 4 is the one that needs its ruling written down</h2>
 *
 * <p>Two independent references agree with each other and NOT with us, which is
 * the exact pattern a three-way parity sweep exists to flag. Megan ruled
 * <i>"leave"</i>, so the divergence is DELIBERATE. Without that recorded here,
 * the next sweep finds the pattern it is built to find and "fixes" it.
 *
 * <h2>Ask 5: BouncyCastle offers nothing to match</h2>
 *
 * <p>It ACCEPTS a negative length on its ten {@code GeneralDigest}-derived
 * digests (silently digesting the empty message) and THROWS on its sponge and
 * BLAKE2 ones. The line is the base class, not the algorithm — so BouncyCastle
 * never made a decision here, and there is no decision to match. We and the JDK
 * refuse throughout.
 */
public class DigestRangeContractTest
{
    private static Provider jsl;
    private static Provider bc;
    private static final SecureRandom SR = new SecureRandom();

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

    private static Provider jdk()
    {
        for (Provider p : Security.getProviders())
        {
            if (p.getClass().getName().startsWith("org.openssl.jostle")
                    || p instanceof BouncyCastleProvider)
            {
                continue;
            }
            if (p.getService("MessageDigest", "SHA-256") != null)
            {
                return p;
            }
        }
        return null;
    }

    /** Ask 3: the offset now gets the same translation the length always had. */
    @Test
    public void aNegativeOutputOffsetRaisesTheDeclaredDigestException() throws Exception
    {
        byte[] msg = new byte[97];
        SR.nextBytes(msg);
        List<String> failures = new ArrayList<String>();
        for (String alg : new String[]{"SHA2-256", "SHA2-512", "SHA3-256", "SM3"})
        {
            MessageDigest d = MessageDigest.getInstance(alg, jsl);
            d.update(msg);
            byte[] out = new byte[d.getDigestLength()];
            try
            {
                d.digest(out, -1, out.length);
                failures.add(alg + ": accepted a negative output offset");
            }
            catch (DigestException expected)
            {
                Assertions.assertTrue(expected.getMessage().contains("offset"),
                        alg + ": the refusal should name the offset: " + expected.getMessage());
            }
            catch (Throwable wrong)
            {
                failures.add(alg + ": raised " + wrong.getClass().getName()
                        + ", not the declared DigestException");
            }
        }
        Assertions.assertTrue(failures.isEmpty(), String.valueOf(failures));

        // The JDK is what we were told to match; assert it still does that.
        Provider jdk = jdk();
        if (jdk != null)
        {
            MessageDigest d = MessageDigest.getInstance("SHA-256", jdk);
            d.update(msg);
            Assertions.assertThrows(DigestException.class,
                    () -> d.digest(new byte[32], -1, 32),
                    "the JDK's behaviour is the basis of ask 3's ruling; it has moved");
        }
    }

    /** Ask 3, other half: the too-small case that was already translated still is. */
    @Test
    public void aTooSmallOutputBufferStillRaisesDigestException() throws Exception
    {
        MessageDigest d = MessageDigest.getInstance("SHA2-256", jsl);
        d.update(new byte[10]);
        DigestException e = Assertions.assertThrows(DigestException.class,
                () -> d.digest(new byte[31], 0, 31));
        Assertions.assertTrue(e.getMessage().contains("too small"), e.getMessage());
    }

    /**
     * Ask 4, ruled "leave": we are the odd provider ON PURPOSE.
     *
     * <p>Both halves asserted — ours AND the two references agreeing with each
     * other — so this reads as a recorded decision rather than an oversight
     * waiting to be tidied away.
     */
    @Test
    public void aNegativeInputOffsetKeepsOurIllegalArgumentException() throws Exception
    {
        byte[] msg = new byte[97];
        SR.nextBytes(msg);

        MessageDigest ours = MessageDigest.getInstance("SHA2-256", jsl);
        Assertions.assertThrows(IllegalArgumentException.class, () -> ours.update(msg, -1, 4),
                "ask 4 ruled 'leave' - this stays IllegalArgumentException");

        MessageDigest theirs = MessageDigest.getInstance("SHA-256", bc);
        Assertions.assertThrows(ArrayIndexOutOfBoundsException.class, () -> theirs.update(msg, -1, 4),
                "BouncyCastle's half of the deliberate divergence has moved");

        Provider jdk = jdk();
        if (jdk != null)
        {
            MessageDigest j = MessageDigest.getInstance("SHA-256", jdk);
            Assertions.assertThrows(ArrayIndexOutOfBoundsException.class, () -> j.update(msg, -1, 4),
                    "the JDK's half of the deliberate divergence has moved");
        }
    }

    /**
     * Ask 5, ruled "keep": we refuse a negative length, and BouncyCastle is
     * split down its own base-class line.
     *
     * <p>The split is asserted, not just described — it is the reason there is
     * nothing to match, so if BouncyCastle ever becomes self-consistent the
     * ruling deserves revisiting and this says so by failing.
     */
    @Test
    public void aNegativeInputLengthIsRefusedAndBouncyCastleIsSplit() throws Exception
    {
        byte[] msg = new byte[97];
        SR.nextBytes(msg);

        MessageDigest ours = MessageDigest.getInstance("SHA2-256", jsl);
        Assertions.assertThrows(IllegalArgumentException.class, () -> ours.update(msg, 0, -1),
                "ask 5 ruled 'keep' - we refuse a negative length");

        // BouncyCastle, classical Merkle-Damgard: ACCEPTS, digesting nothing.
        MessageDigest md = MessageDigest.getInstance("SHA-256", bc);
        md.update(msg, 0, -1);
        Assertions.assertArrayEquals(MessageDigest.getInstance("SHA-256", bc).digest(new byte[0]),
                md.digest(),
                "BouncyCastle's GeneralDigest arm no longer silently digests the empty message");

        // BouncyCastle, sponge: THROWS. Same provider, opposite answer.
        MessageDigest sponge = MessageDigest.getInstance("SHA3-256", bc);
        Assertions.assertThrows(ArrayIndexOutOfBoundsException.class, () -> sponge.update(msg, 0, -1),
                "BouncyCastle's sponge arm no longer throws - it may have become self-consistent");
    }
}
