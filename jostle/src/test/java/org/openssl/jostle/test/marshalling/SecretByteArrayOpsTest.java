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

package org.openssl.jostle.test.marshalling;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.Loader;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.ops.OperationsTestNI;
import org.openssl.jostle.util.ops.OperationsTestNI.LedgerType;

import java.security.SecureRandom;
import java.security.Security;

/**
 * The JNI secret byte-array contexts, driven through the operations-test round trip: an input context and an
 * output context, then their release. Asserts what a caller depends on: the input's Java array comes back
 * unwritten although C scribbled over its copy, the output's Java array carries the copied bytes and keeps the
 * bytes C did not write, and every byte C held was measured as cleansed before it was freed.
 */
public class SecretByteArrayOpsTest
{
    private static final SecureRandom RANDOM = new SecureRandom();

    @BeforeAll
    public static void beforeAll()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    protected OperationsTestNI ops()
    {
        return NISelector.OperationsTestNI;
    }

    protected String library()
    {
        return "base";
    }

    @BeforeEach
    public void requireOpsBuild()
    {
        Assumptions.assumeTrue(ops().opsTestAvailable(), "not an operations-test build");
        ops().resetFlags();
        ops().ledgerReset();
    }

    private static void requireJni()
    {
        Assumptions.assumeFalse(Loader.isFFM(), "JNI only: the secret contexts are JNI marshalling");
    }

    /** FFM has no secret contexts by design: the round trip is refused and neither ledger type moves. */
    @Test
    public void ffmHasNoSecretContexts()
    {
        Assumptions.assumeTrue(Loader.isFFM(), "FFM only: JNI is covered by the round-trip cells");
        UnsupportedOperationException ex = Assertions.assertThrows(UnsupportedOperationException.class,
                () -> ops().op_secretRoundTrip(new byte[8], new byte[8], new int[4]));
        Assertions.assertEquals("the secret byte-array contexts are JNI only", ex.getMessage());
        assertLedger(0);
    }

    /** Random bytes with no zero, so an uncleansed buffer cannot read as cleansed. */
    private static byte[] nonZero(int len)
    {
        byte[] b = new byte[len];
        RANDOM.nextBytes(b);
        for (int i = 0; i < len; i++)
        {
            if (b[i] == 0)
            {
                b[i] = 1;
            }
        }
        return b;
    }

    private void assertLedger(int loads)
    {
        Assertions.assertEquals(loads, ops().ledgerCreated(LedgerType.SECRET_BYTEARRAY), "loads");
        Assertions.assertEquals(loads, ops().ledgerDestroyed(LedgerType.SECRET_BYTEARRAY), "releases");
        Assertions.assertEquals(loads, ops().ledgerCreated(LedgerType.SECRET_CLEANSE), "cleanse obligations");
        Assertions.assertEquals(loads, ops().ledgerDestroyed(LedgerType.SECRET_CLEANSE), "cleanses");
    }

    @Test
    public void roundTripCleansesBothCopiesAndNeverWritesTheInput()
    {
        requireJni();
        int inLen = 1 + RANDOM.nextInt(256);
        int outLen = inLen + 1 + RANDOM.nextInt(32);
        byte[] input = nonZero(inLen);
        byte[] output = nonZero(outLen);
        byte[] inputBefore = Arrays.clone(input);
        byte[] outputBefore = Arrays.clone(output);
        int[] report = new int[4];

        int rc = ops().op_secretRoundTrip(input, output, report);
        System.out.println("[secret] library=" + library() + " inLen=" + inLen + " outLen=" + outLen
                + " jvmCopy=" + report[0] + " cleansedIn=" + report[1] + " cleansedOut=" + report[2]
                + " copied=" + report[3]);

        Assertions.assertEquals(0, rc);
        Assertions.assertTrue(report[0] == 0 || report[0] == 1, "jvmCopy " + report[0]);
        Assertions.assertEquals(inLen, report[3], "bytes copied");
        Assertions.assertEquals(inLen, report[1], "input bytes cleansed");
        Assertions.assertEquals(outLen, report[2], "output bytes cleansed");
        Assertions.assertTrue(Arrays.areEqual(inputBefore, input), "the input's Java array was written");
        Assertions.assertTrue(Arrays.areEqual(inputBefore, Arrays.copyOfRange(output, 0, inLen)),
                "the output does not carry the input");
        Assertions.assertTrue(Arrays.areEqual(Arrays.copyOfRange(outputBefore, inLen, outLen),
                Arrays.copyOfRange(output, inLen, outLen)), "bytes C did not write changed");
        assertLedger(2);
    }

    @Test
    public void nullArraysLoadEmptyAndReleaseAsNoOps()
    {
        requireJni();
        int[] report = new int[]{-1, -1, -1, -1};
        Assertions.assertEquals(0, ops().op_secretRoundTrip(null, null, report));
        Assertions.assertArrayEquals(new int[]{0, 0, 0, 0}, report);
        assertLedger(0);
    }

    @Test
    public void emptyArraysLoadAndRelease()
    {
        requireJni();
        int[] report = new int[]{-1, -1, -1, -1};
        Assertions.assertEquals(0, ops().op_secretRoundTrip(new byte[0], new byte[0], report));
        System.out.println("[secret] library=" + library() + " inLen=0 outLen=0 jvmCopy=" + report[0]
                + " cleansedIn=" + report[1] + " cleansedOut=" + report[2] + " copied=" + report[3]);
        Assertions.assertTrue(report[0] == 0 || report[0] == 1, "jvmCopy " + report[0]);
        Assertions.assertEquals(0, report[1]);
        Assertions.assertEquals(0, report[2]);
        Assertions.assertEquals(0, report[3]);
        assertLedger(2);
    }
}
