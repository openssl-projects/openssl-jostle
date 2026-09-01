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

package org.openssl.jostle.test.parity;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

/**
 * Detects BouncyCastle moving out from under a pin that transcribed it.
 *
 * <p>{@code AESKeyWrapTest.illegalWrapLengths_raiseBouncyCastlesType} asserts
 * OUR types against literals measured from BouncyCastle. That is correct for a
 * pin - re-measuring BC inside it would make it follow BC anywhere. The gap it
 * leaves is that a bcprov bump can move the reference with nothing failing, so
 * the pin would keep asserting our conformance to a fact that expired.
 *
 * <p>This is the other consumer of {@link BouncyCastleTranscripts}: it measures
 * LIVE BouncyCastle against the same literal the pin uses. A failure here does
 * not mean we are wrong - it means the transcript is stale and both it and the
 * pin's reasoning need revisiting.
 */
public class BouncyCastleDriftTest
{
    private static final SecureRandom SR = new SecureRandom();

    @BeforeAll
    public static void setUp()
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private static Class<?> observe(String xform, int opMode, Key kek, int len)
    {
        try
        {
            Cipher c = Cipher.getInstance(xform, BouncyCastleProvider.PROVIDER_NAME);
            c.init(opMode, kek);
            c.doFinal(new byte[len]);
            return null;
        }
        catch (Throwable t)
        {
            return t.getClass();
        }
    }

    private static void check(List<String> bad, String what, String xform, int opMode,
                              Key kek, int[] lengths, Class<?> expected)
    {
        for (int len : lengths)
        {
            Class<?> got = observe(xform, opMode, kek, len);
            if (got == null || !expected.isAssignableFrom(got))
            {
                bad.add(String.format("%s len=%d: transcript says %s, live BouncyCastle gives %s",
                        what, len, expected.getSimpleName(),
                        got == null ? "(accepted)" : got.getName()));
            }
        }
    }

    /**
     * Every length in the transcript must still be refused by live BouncyCastle
     * with the transcribed type.
     */
    @Test
    public void theTranscribedBouncyCastleBehaviourIsStillTrue()
    {
        byte[] keyBytes = new byte[32];
        SR.nextBytes(keyBytes);
        Key kek = new SecretKeySpec(keyBytes, "AES");

        List<String> bad = new ArrayList<String>();
        check(bad, "KW wrap", "AESWRAP", Cipher.ENCRYPT_MODE, kek,
                BouncyCastleTranscripts.KW_WRAP_ILLEGAL, BouncyCastleTranscripts.KW_WRAP_TYPE);
        check(bad, "KW unwrap", "AESWRAP", Cipher.DECRYPT_MODE, kek,
                BouncyCastleTranscripts.KW_UNWRAP_ILLEGAL, BouncyCastleTranscripts.KW_UNWRAP_TYPE);
        check(bad, "KWP unwrap", "AESWRAPPAD", Cipher.DECRYPT_MODE, kek,
                BouncyCastleTranscripts.KWP_UNWRAP_ILLEGAL, BouncyCastleTranscripts.KWP_UNWRAP_TYPE);
        check(bad, "KWP wrap", "AESWRAPPAD", Cipher.ENCRYPT_MODE, kek,
                BouncyCastleTranscripts.KWP_WRAP_ILLEGAL, BouncyCastleTranscripts.KWP_WRAP_TYPE);

        Assertions.assertTrue(bad.isEmpty(),
                "BouncyCastle has MOVED since the transcript was taken. This does not"
                        + " mean we are wrong - it means the literal in"
                        + " BouncyCastleTranscripts is stale and the pin's reasoning"
                        + " needs revisiting:\n  " + String.join("\n  ", bad));

        // Non-vacuity: a transcript that shrank to nothing would pass silently.
        int cells = BouncyCastleTranscripts.KW_WRAP_ILLEGAL.length
                + BouncyCastleTranscripts.KW_UNWRAP_ILLEGAL.length
                + BouncyCastleTranscripts.KWP_UNWRAP_ILLEGAL.length
                + BouncyCastleTranscripts.KWP_WRAP_ILLEGAL.length;
        Assertions.assertEquals(22, cells,
                "the transcript changed size; update this count deliberately");

    }
}
