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

package org.openssl.jostle.test.md;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.provider.md.MDServiceNI;

import java.security.Security;
import java.util.ArrayList;
import java.util.List;

/**
 * The MD native boundary, driven DIRECTLY — no SPI in front of it.
 *
 * <h2>Why the NI surface needs its own tests</h2>
 *
 * <p>On Java 8 there is no module system, so {@code MDServiceJNI}'s methods are
 * {@code native public} and reachable by any caller: the SPI is not the only
 * way in. The boundary therefore has to be safe on its own, and "safe" means a
 * TYPED code — never a JVM abort, never silent truncation.
 *
 * <p>Two of these were live aborts until 2026-09-02. A null {@code err} array
 * hit {@code jo_assert(_err != NULL)} in {@code md_jni.c} and killed the
 * process; measured on JDK 11 with the pre-fix library, one JVM per cell.
 * <b>That observation is this file's "before"</b> — the fix is not re-falsified
 * by aborting a shipping build to watch it happen twice.
 *
 * <h2>These run on EVERY leg, and JDK 8 is the one that counts</h2>
 *
 * <p>Written against {@code NISelector.MDServiceNI}, so the JNI legs exercise
 * the JNI bridge and the FFI legs the FFI one — the same nulls must be safe
 * through both, and the FFI path has no glue in front of the C at all. The file
 * lives in {@code src/test/java} so it reaches {@code unitTest8}, which is
 * where the exposure is real rather than theoretical.
 *
 * <h2>Guards that already existed are pinned too</h2>
 *
 * <p>Most of this boundary was already correct — the survey found two gaps in
 * twenty-three cells. The other twenty-one are pinned anyway: an unpinned guard
 * is one refactor away from gone, and nothing in the suite asserted any of them
 * from the NI surface before this file.
 */
public class MDNativeBoundaryTest
{
    private static MDServiceNI NI;

    /**
     * The provider must be registered BEFORE the NI is resolved: loading it is
     * what extracts and links the native library. A static initialiser reading
     * NISelector runs first and fails with UnsatisfiedLinkError.
     */
    @BeforeAll
    public static void beforeAll()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        NI = NISelector.MDServiceNI;
    }

    private static long freshRef()
    {
        int[] err = new int[1];
        long ref = NI.ni_allocateDigest("SHA2-256", 0, err);
        Assertions.assertNotEquals(0, ref, "could not allocate a digest to test with");
        return ref;
    }

    /**
     * The two former aborts: a null {@code err} array.
     *
     * <p>Zero is the only coherent answer — {@code err} is the sole channel
     * these two have for reporting failure, since they return the reference
     * itself, so its absence cannot be reported through it.
     */
    @Test
    public void aNullErrorArrayIsRefusedRatherThanAborting()
    {
        Assertions.assertEquals(0L, NI.ni_allocateDigest("SHA2-256", 0, null),
                "ni_allocateDigest with a null err array must return 0, not abort");
        long ref = freshRef();
        Assertions.assertEquals(0L, NI.ni_copyDigest(ref, null),
                "ni_copyDigest with a null err array must return 0, not abort");
        NI.ni_dispose(ref);
    }

    /** Every entry point rejects a null context with the same typed code. */
    @Test
    public void aNullContextIsTypedOnEveryEntryPoint()
    {
        int expected = ErrorCode.JO_MD_CTX_IS_NULL.getCode();
        List<String> failures = new ArrayList<String>();
        int[] err = new int[1];

        if (NI.ni_copyDigest(0L, err) != 0L || err[0] != expected)
        {
            failures.add("ni_copyDigest err=" + err[0]);
        }
        if (NI.ni_updateByte(0L, (byte) 1) != expected)
        {
            failures.add("ni_updateByte");
        }
        if (NI.ni_updateBytes(0L, new byte[4], 0, 4) != expected)
        {
            failures.add("ni_updateBytes");
        }
        if (NI.ni_getDigestOutputLen(0L) != expected)
        {
            failures.add("ni_getDigestOutputLen");
        }
        if (NI.ni_digest(0L, new byte[32], 0, 32) != expected)
        {
            failures.add("ni_digest");
        }
        Assertions.assertTrue(failures.isEmpty(), "entry points not returning JO_MD_CTX_IS_NULL: " + failures);
    }

    /**
     * {@code ni_reset(0)} returns SUCCESS, and that asymmetry is DELIBERATE.
     *
     * <p>Quoting the reason from {@code md_jni.c} so it survives the next
     * consistency sweep: <i>"Observed spurious resets from within the JVMs
     * provider logic in the past."</i> Every sibling returns
     * {@code JO_MD_CTX_IS_NULL} for a null context; this one must not, and I
     * nearly "fixed" it into line before reading the comment.
     */
    @Test
    public void resetOnANullContextDeliberatelySucceeds()
    {
        Assertions.assertEquals(ErrorCode.JO_SUCCESS.getCode(), NI.ni_reset(0L),
                "ni_reset(0) is deliberately tolerant - see the rationale in md_jni.c");
        NI.ni_dispose(0L);
    }

    /** Input array faults on update: null, negative, out of range. */
    @Test
    public void updateBytesRejectsEveryHostileRange()
    {
        long ref = freshRef();
        try
        {
            Assertions.assertEquals(ErrorCode.JO_INPUT_IS_NULL.getCode(),
                    NI.ni_updateBytes(ref, null, 0, 0), "null input, zero length");
            Assertions.assertEquals(ErrorCode.JO_INPUT_IS_NULL.getCode(),
                    NI.ni_updateBytes(ref, null, 0, 4), "null input, nonzero length");
            Assertions.assertEquals(ErrorCode.JO_INPUT_OFFSET_IS_NEGATIVE.getCode(),
                    NI.ni_updateBytes(ref, new byte[4], -1, 1), "negative offset");
            Assertions.assertEquals(ErrorCode.JO_INPUT_LEN_IS_NEGATIVE.getCode(),
                    NI.ni_updateBytes(ref, new byte[4], 0, -1), "negative length");
            Assertions.assertEquals(ErrorCode.JO_INPUT_OUT_OF_RANGE.getCode(),
                    NI.ni_updateBytes(ref, new byte[4], 2, 3), "offset+len past the end");
            Assertions.assertEquals(ErrorCode.JO_INPUT_OUT_OF_RANGE.getCode(),
                    NI.ni_updateBytes(ref, new byte[4], 0, Integer.MAX_VALUE), "MAX_VALUE length");
        }
        finally
        {
            NI.ni_dispose(ref);
        }
    }

    /** Output array faults on digest, including the length-query contract. */
    @Test
    public void digestRejectsEveryHostileRangeAndAnswersTheLengthQuery()
    {
        long ref = freshRef();
        try
        {
            // A null output is NOT an error here: it is the documented
            // length-query contract, answering the required size.
            Assertions.assertEquals(32, NI.ni_digest(ref, null, 0, 0),
                    "a null output buffer asks for the length");

            Assertions.assertEquals(ErrorCode.JO_OUTPUT_OFFSET_IS_NEGATIVE.getCode(),
                    NI.ni_digest(ref, new byte[32], -1, 32), "negative offset");
            Assertions.assertEquals(ErrorCode.JO_OUTPUT_LEN_IS_NEGATIVE.getCode(),
                    NI.ni_digest(ref, new byte[32], 0, -1), "negative length");
            Assertions.assertEquals(ErrorCode.JO_OUTPUT_OUT_OF_RANGE.getCode(),
                    NI.ni_digest(ref, new byte[32], 8, 32), "offset+len past the end");
            Assertions.assertEquals(ErrorCode.JO_OUTPUT_OUT_OF_RANGE.getCode(),
                    NI.ni_digest(ref, new byte[32], 0, Integer.MAX_VALUE), "MAX_VALUE length");
        }
        finally
        {
            NI.ni_dispose(ref);
        }
    }

    /**
     * The XOF length bound, at the byte.
     *
     * <p>Before 2026-09-02 SHAKE-256 accepted {@code INT32_MAX} and
     * {@code ni_getDigestOutputLen} reported it back. The C writes into the
     * caller's buffer so it allocates nothing itself — but any caller sizing an
     * allocation from that number inherits it, including
     * {@code MDServiceSPI.engineDigest}, which does
     * {@code new byte[getDigestOutputLen(...)]}.
     */
    @Test
    public void theXofLengthIsBoundedAtTheByte()
    {
        int[] err = new int[1];
        final int max = 16 * 1024 * 1024;

        long ok = NI.ni_allocateDigest("SHAKE-256", max, err);
        Assertions.assertNotEquals(0L, ok, "the bound itself must be accepted, err=" + err[0]);
        Assertions.assertEquals(max, NI.ni_getDigestOutputLen(ok));
        NI.ni_dispose(ok);

        for (int over : new int[]{max + 1, 1 << 28, Integer.MAX_VALUE})
        {
            err[0] = 0;
            Assertions.assertEquals(0L, NI.ni_allocateDigest("SHAKE-256", over, err),
                    "xof length " + over + " must be refused");
            Assertions.assertEquals(ErrorCode.JO_MD_XOF_LEN_INVALID.getCode(), err[0],
                    "xof length " + over + " must be refused with the typed code");
        }
    }

    /**
     * A fixed-length digest accepts a length of EXACTLY zero.
     *
     * <p>The old test was {@code xof_len > 0}, so a negative slipped through as
     * "not set" — measured, SHA2-256 with −1 returned a usable context. A
     * parameter that means nothing for this algorithm must be exactly its null
     * value.
     */
    @Test
    public void aFixedDigestAcceptsOnlyZeroAsItsXofLength()
    {
        int[] err = new int[1];
        long ok = NI.ni_allocateDigest("SHA2-256", 0, err);
        Assertions.assertNotEquals(0L, ok, "zero must be accepted");
        NI.ni_dispose(ok);

        for (int bad : new int[]{-1, 1, 32, Integer.MIN_VALUE})
        {
            err[0] = 0;
            Assertions.assertEquals(0L, NI.ni_allocateDigest("SHA2-256", bad, err),
                    "xof length " + bad + " is meaningless for a fixed digest and must be refused");
            Assertions.assertEquals(ErrorCode.JO_MD_XOF_LEN_INVALID.getCode(), err[0],
                    "xof length " + bad + " must be refused with the typed code");
        }
    }

    /** A null digest name is typed, not a crash. */
    @Test
    public void aNullDigestNameIsTyped()
    {
        int[] err = new int[1];
        Assertions.assertEquals(0L, NI.ni_allocateDigest(null, 0, err));
        Assertions.assertEquals(ErrorCode.JO_NAME_IS_NULL.getCode(), err[0]);
    }
}
