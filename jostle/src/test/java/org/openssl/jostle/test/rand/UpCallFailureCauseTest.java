/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.rand;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.OpenSSLException;

import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * MT-79: a caller-supplied {@link SecureRandom} whose {@code nextBytes} throws
 * must have its own exception reach the caller.
 *
 * <p>A Java exception cannot propagate through an OpenSSL callback frame, so the
 * RAND bridge catches everything and returns an error code; the caller used to
 * receive only {@code "rand up-call failed with code -99"} while the real cause
 * sat in a log. It is now carried across the boundary in a thread-local and
 * attached as the cause of whatever the enclosing operation throws.
 *
 * <p>The three cells below are one property and two guards against the way this
 * mechanism could go wrong — a stale cause attaching to an unrelated failure.
 */
public class UpCallFailureCauseTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;

    /** Distinctive so the assertion is about THIS instance, not a lookalike. */
    static final class ExhaustedPoolException extends RuntimeException
    {
        ExhaustedPoolException()
        {
            super("test random is exhausted");
        }
    }

    /** Throws on every draw, as BouncyCastle's FixedSecureRandom does when its pool runs out. */
    static final class ThrowingRandom extends SecureRandom
    {
        final ExhaustedPoolException boom = new ExhaustedPoolException();

        @Override
        public void nextBytes(byte[] bytes)
        {
            throw boom;
        }
    }

    @BeforeAll
    public static void setUp()
    {
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    /** (i) The property: the caller's own exception reaches them. */
    @Test
    public void theCallersOwnExceptionIsTheCause() throws Exception
    {
        ThrowingRandom random = new ThrowingRandom();

        OpenSSLException ex = Assertions.assertThrows(OpenSSLException.class,
                () -> generateWith(random),
                "a random that always throws cannot produce a key pair");

        Assertions.assertTrue(causeChainContains(ex, random.boom),
                "the caller's own exception must be in the cause chain, not only in a log; got: "
                        + describeCauses(ex));
    }

    /**
     * (ii) The stale-cause guard: an unrelated failure on the same thread,
     * after a captured one, must NOT inherit it.
     *
     * <p>Without the take-and-clear at the top of {@code baseErrorHandler} the
     * stored throwable would still be sitting there, and this failure — which
     * has nothing to do with randomness — would report it as its cause.
     */
    @Test
    public void anUnrelatedLaterFailureHasNoCause() throws Exception
    {
        ThrowingRandom random = new ThrowingRandom();
        Assertions.assertThrows(OpenSSLException.class, () -> generateWith(random));

        Throwable unrelated = provokeUnrelatedFailure();
        assertReachedTheHandler(unrelated);
        Assertions.assertFalse(causeChainContains(unrelated, random.boom),
                "a later, unrelated failure must not inherit the earlier up-call cause; got: "
                        + describeCauses(unrelated));
    }

    /** (iii) A SUCCESS between the two must also leave nothing behind. */
    @Test
    public void aSuccessfulOperationClearsAnyPendingCause() throws Exception
    {
        ThrowingRandom random = new ThrowingRandom();
        Assertions.assertThrows(OpenSSLException.class, () -> generateWith(random));

        // A working random on the same thread: this must succeed, and must not
        // carry the previous failure forward.
        generateWith(new SecureRandom());

        Throwable unrelated = provokeUnrelatedFailure();
        assertReachedTheHandler(unrelated);
        Assertions.assertFalse(causeChainContains(unrelated, random.boom),
                "a success between must leave no pending cause; got: " + describeCauses(unrelated));
    }

    private static void generateWith(SecureRandom random) throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", JSL);
        kpg.initialize(new ECGenParameterSpec("P-256"), random);
        kpg.generateKeyPair();
    }

    /**
     * An unrelated failure that genuinely reaches
     * {@code baseErrorHandler}'s {@code JO_OPENSSL_ERROR} arm — decoding
     * garbage as an SPKI. No randomness is involved, so nothing here can
     * legitimately produce an up-call cause.
     *
     * <p>The obvious choice — an unknown EC curve name — is <b>useless here</b>
     * and was tried first: it is refused in the Java layer with
     * {@code InvalidAlgorithmParameterException}, never reaches the handler, and
     * therefore never has a cause attached whatever the mechanism does. Both
     * clearing cells passed against a deliberately-broken holder until this was
     * changed. Measured: EC-unknown-curve gives no OpenSSLException; garbage
     * SPKI gives {@code InvalidKeySpecException <- OpenSSLException}.
     */
    private static Throwable provokeUnrelatedFailure()
    {
        try
        {
            KeyFactory.getInstance("EC", JSL)
                    .generatePublic(new X509EncodedKeySpec(new byte[]{1, 2, 3, 4, 5}));
            return null;
        }
        catch (Exception e)
        {
            return e;
        }
    }

    /**
     * NON-VACUITY: the probe must actually have gone through the handler arm
     * that attaches causes, or the assertion beneath it proves nothing.
     */
    private static void assertReachedTheHandler(Throwable unrelated)
    {
        Assertions.assertNotNull(unrelated, "the probe must fail, or it tests nothing");
        boolean sawOpenSsl = false;
        for (Throwable c = unrelated; c != null; c = c.getCause())
        {
            if (c instanceof OpenSSLException)
            {
                sawOpenSsl = true;
            }
        }
        Assertions.assertTrue(sawOpenSsl,
                "the probe must reach baseErrorHandler's JO_OPENSSL_ERROR arm, else no cause could"
                        + " ever be attached and this cell is vacuous; got: " + describeCauses(unrelated));
    }

    private static boolean causeChainContains(Throwable t, Throwable wanted)
    {
        for (Throwable c = t; c != null; c = c.getCause())
        {
            if (c == wanted)
            {
                return true;
            }
        }
        return false;
    }

    private static String describeCauses(Throwable t)
    {
        StringBuilder sb = new StringBuilder();
        for (Throwable c = t; c != null; c = c.getCause())
        {
            sb.append(sb.length() == 0 ? "" : " <- ").append(c.getClass().getName());
        }
        return sb.length() == 0 ? "(nothing thrown)" : sb.toString();
    }
}
