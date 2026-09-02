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
import org.openssl.jostle.test.parity.BouncyCastleTranscripts;
import org.openssl.jostle.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;

/**
 * MT-44: AESGMAC honours {@code Mac.doFinal}'s reset contract, and BouncyCastle
 * refuses to. The divergence is DELIBERATE.
 *
 * <h2>The ruling</h2>
 *
 * <p>Megan, 2026-09-02: <i>"With Group A's AESGMAC, don't enforce nonce reuse
 * detection, that is an issue for the user."</i>
 *
 * <h2>What is actually at stake, so nobody softens this by accident</h2>
 *
 * <p>{@code javax.crypto.Mac.doFinal} specifies that the MAC "is reset to its
 * initial state". For GMAC the initial state includes the NONCE, so a second
 * message authenticated on one instance is authenticated under a REPEATED
 * (key, nonce) pair — and GMAC under a repeated nonce leaks the GHASH subkey
 * relationship and permits forgery. We honour the contract; BouncyCastle breaks
 * it to prevent the reuse. Both positions are defensible and they cannot both
 * be held.
 *
 * <p>So this is not a latent bug someone should tidy up. Preventing (key,
 * nonce) reuse is the CALLER's responsibility here, stated in
 * {@code MacServiceSPI}'s class javadoc where a user will meet it.
 *
 * <h2>Why the assertion is byte-equality and not "no exception"</h2>
 *
 * <p>"Reuse is accepted" would also pass against a GMAC that had silently
 * stopped absorbing state — a hollow reuse producing a stale or empty tag. The
 * property is that reuse behaves EXACTLY as a fresh instance with the same key
 * and IV, which only a byte comparison can show.
 */
public class GmacNonceReuseContractTest
{
    private static Provider jsl;
    private static Provider bc;

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

    private static Mac gmac(Provider p, byte[] key, byte[] iv) throws Exception
    {
        Mac m = Mac.getInstance("AESGMAC", p);
        m.init(new SecretKeySpec(key, "AESGMAC"), new IvParameterSpec(iv));
        return m;
    }

    /** Our half: reuse is accepted, and produces exactly what a fresh instance would. */
    @Test
    public void reuseAfterDoFinalMatchesAFreshInstanceExactly() throws Exception
    {
        byte[] key = new byte[32];
        byte[] iv = new byte[12];
        SecureRandom sr = new SecureRandom();
        sr.nextBytes(key);
        sr.nextBytes(iv);
        byte[] first = new byte[40];
        byte[] second = new byte[57];
        sr.nextBytes(first);
        sr.nextBytes(second);

        Mac reused = gmac(jsl, key, iv);
        reused.update(first);
        byte[] tag1 = reused.doFinal();

        // Reuse, same message: identical to the first tag. This IS the nonce
        // reuse - the same (key, nonce) authenticating twice.
        reused.update(first);
        Assertions.assertArrayEquals(tag1, reused.doFinal(),
                "reuse must reproduce the first tag - it is the same key and nonce");

        // Reuse, different message: identical to what a FRESH instance under the
        // same key and IV produces. Byte-equality, not merely "differs".
        reused.update(second);
        byte[] tag2 = reused.doFinal();
        Mac fresh = gmac(jsl, key, iv);
        fresh.update(second);
        Assertions.assertArrayEquals(fresh.doFinal(), tag2,
                "a reused instance must behave exactly as a fresh one - a hollow "
                        + "reuse would also pass a weaker 'no exception' assertion");
    }

    /**
     * BouncyCastle's half, against the TRANSCRIBED type.
     *
     * <p>Compared to {@code BouncyCastleTranscripts.GMAC_REUSE_REFUSAL_TYPE}
     * rather than to a live re-measurement, so the pin cannot drift along
     * behind bcprov. {@code BouncyCastleDriftTest} is what notices a change.
     */
    @Test
    public void bouncyCastleRefusesTheReuseWeAllow() throws Exception
    {
        byte[] key = new byte[32];
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(key);
        new SecureRandom().nextBytes(iv);

        Mac m = gmac(bc, key, iv);
        m.update(new byte[16]);
        byte[] tag = m.doFinal();
        Assertions.assertNotNull(tag);

        Throwable t = Assertions.assertThrows(Throwable.class, () -> {
            m.update(new byte[16]);
            m.doFinal();
        }, "BouncyCastle is expected to refuse GMAC reuse");
        Assertions.assertEquals(BouncyCastleTranscripts.GMAC_REUSE_REFUSAL_TYPE, t.getClass(),
                "BouncyCastle's refusal type has moved from the transcribed value");
    }

    /**
     * The first tags agree, so this is a DIVERGENCE ABOUT REUSE and not about
     * the MAC itself.
     *
     * <p>Worth its own assertion: without it a reader could suspect the two
     * providers simply compute different GMACs, which would make the whole
     * ruling a different conversation.
     */
    @Test
    public void bothProvidersComputeTheSameTagBeforeAnyReuse() throws Exception
    {
        byte[] key = new byte[32];
        byte[] iv = new byte[12];
        byte[] msg = new byte[64];
        SecureRandom sr = new SecureRandom();
        sr.nextBytes(key);
        sr.nextBytes(iv);
        sr.nextBytes(msg);

        Mac ours = gmac(jsl, key, iv);
        ours.update(msg);
        Mac theirs = gmac(bc, key, iv);
        theirs.update(msg);
        Assertions.assertTrue(Arrays.areEqual(ours.doFinal(), theirs.doFinal()),
                "the providers must agree on the GMAC itself; only reuse is in dispute");
    }
}
