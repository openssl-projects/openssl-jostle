/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.spec;

import org.openssl.jostle.util.Arrays;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;

/**
 * Parameters for the NIST SP 800-108 key-based KDF, as served by
 * {@code SecretKeyFactory.getInstance("KBKDF-HMAC-SHA256")} and its siblings.
 * The PRF (HMAC with a digest, or CMAC with an AES cipher) is fixed by the
 * registered algorithm name; this spec carries everything the caller chooses.
 *
 * <p>BouncyCastle has no JCE surface for KBKDF — only the lightweight
 * {@code KDFCounterBytesGenerator} / {@code KDFFeedbackBytesGenerator} — so
 * unlike {@link KMACParameterSpec} there is no BC spec to mirror. The accessor
 * names follow SP 800-108's own vocabulary (K<sub>I</sub>, Label, Context, r).</p>
 *
 * <h2>useL and useSeparator</h2>
 *
 * <p>SP 800-108's fixed input is {@code Label || 0x00 || Context || [L]<sub>2</sub>}.
 * The two flags select whether the {@code 0x00} separator and the trailing
 * length {@code [L]} are emitted. Both default to {@code true} here, matching
 * both the specification's canonical form and OpenSSL's own defaults.</p>
 *
 * <p>Turn them OFF to interoperate with a peer that feeds the fixed input raw:
 * that includes BouncyCastle's {@code KDFCounterBytesGenerator} (which emits
 * exactly the {@code fixedInputData} it is given) and the NIST CAVP
 * CounterMode vectors. The difference is invisible in a Jostle-to-Jostle round
 * trip and shows up only against an independent implementation, which is why
 * the choice is always explicit rather than inferred.</p>
 */
public class KBKDFParameterSpec
    implements KeySpec, AlgorithmParameterSpec
{
    /**
     * SP 800-108 key-derivation mode. Both are served by every supported
     * OpenSSL build, with either MAC.
     */
    public enum Mode
    {
        /** Counter mode (SP 800-108 section 5.1). */
        COUNTER("COUNTER"),
        /** Feedback mode (SP 800-108 section 5.2). */
        FEEDBACK("FEEDBACK");

        private final String opensslName;

        Mode(String opensslName)
        {
            this.opensslName = opensslName;
        }

        /**
         * The {@code OSSL_KDF_PARAM_MODE} string for this mode.
         */
        public String getOpenSSLName()
        {
            return opensslName;
        }
    }

    /**
     * Counter width in bits. SP 800-108's CAVP test set defines RLEN as one of
     * these four, and all four supported OpenSSL builds accept exactly this set
     * and refuse 1, 33 and 64 (measured). Validated in the constructor so a bad
     * width fails with a message that names the alternatives rather than an
     * opaque provider error.
     */
    private static final int[] VALID_R = {8, 16, 24, 32};

    private static final int DEFAULT_R = 32;

    private final byte[] ki;
    private final byte[] label;
    private final byte[] context;
    private final byte[] iv;
    private final Mode mode;
    private final int r;
    private final boolean useL;
    private final boolean useSeparator;
    private final int outputLength;

    /**
     * Counter mode with the SP 800-108 canonical fixed input: r = 32, separator
     * and trailing length both emitted.
     *
     * @param ki           the key-derivation key. Must not be null.
     * @param label        the Label, or null for none.
     * @param context      the Context, or null for none.
     * @param outputLength derived key length in bytes. Must be positive.
     */
    public KBKDFParameterSpec(byte[] ki, byte[] label, byte[] context, int outputLength)
    {
        this(ki, label, context, null, Mode.COUNTER, DEFAULT_R, true, true, outputLength);
    }

    /**
     * @param ki           the key-derivation key. Must not be null.
     * @param label        the Label, or null for none.
     * @param context      the Context, or null for none.
     * @param iv           the feedback IV K(0), used only in
     *                     {@link Mode#FEEDBACK}; null or empty for none.
     *                     When supplied its length MUST equal the PRF's output
     *                     size (the digest size for HMAC, 16 for AES-CMAC) -
     *                     OpenSSL refuses any other length with "invalid seed
     *                     length". Not validated here, because the PRF is
     *                     fixed by the registered algorithm name and this spec
     *                     does not know which one it will be handed to.
     *                     Ignored in counter mode.
     * @param mode         counter or feedback. Must not be null.
     * @param r            counter width in bits: 8, 16, 24 or 32.
     * @param useL         emit the trailing {@code [L]} length field.
     * @param useSeparator emit the {@code 0x00} separator between Label and Context.
     * @param outputLength derived key length in bytes. Must be positive.
     */
    public KBKDFParameterSpec(byte[] ki, byte[] label, byte[] context, byte[] iv, Mode mode,
                              int r, boolean useL, boolean useSeparator, int outputLength)
    {
        if (ki == null)
        {
            throw new IllegalArgumentException("ki is null");
        }

        if (mode == null)
        {
            throw new IllegalArgumentException("mode is null");
        }

        if (!isValidR(r))
        {
            throw new IllegalArgumentException("r must be one of 8, 16, 24 or 32 bits, got " + r);
        }

        // Zero is refused here so it can never reach the native layer. Of the
        // three SP 800-x KDFs this release adds, SSHKDF actually ACCEPTS a
        // zero-length request and emits a zero-length key on every supported
        // OpenSSL build; refusing zero uniformly in Java means a caller need
        // not know which KDF is the lenient one.
        if (outputLength <= 0)
        {
            throw new IllegalArgumentException("output length must be positive");
        }

        this.ki = Arrays.clone(ki);
        this.label = Arrays.clone(label);
        this.context = Arrays.clone(context);
        this.iv = Arrays.clone(iv);
        this.mode = mode;
        this.r = r;
        this.useL = useL;
        this.useSeparator = useSeparator;
        this.outputLength = outputLength;
    }

    private static boolean isValidR(int r)
    {
        for (int candidate : VALID_R)
        {
            if (candidate == r)
            {
                return true;
            }
        }
        return false;
    }

    /**
     * @return a copy of the key-derivation key.
     */
    public byte[] getKI()
    {
        return Arrays.clone(ki);
    }

    /**
     * @return a copy of the Label, or null if none was supplied.
     */
    public byte[] getLabel()
    {
        return Arrays.clone(label);
    }

    /**
     * @return a copy of the Context, or null if none was supplied.
     */
    public byte[] getContext()
    {
        return Arrays.clone(context);
    }

    /**
     * @return a copy of the feedback IV K(0), or null if none was supplied.
     */
    public byte[] getIV()
    {
        return Arrays.clone(iv);
    }

    public Mode getMode()
    {
        return mode;
    }

    /**
     * @return the counter width in bits.
     */
    public int getR()
    {
        return r;
    }

    /**
     * @return whether the trailing {@code [L]} length field is emitted.
     */
    public boolean useL()
    {
        return useL;
    }

    /**
     * @return whether the {@code 0x00} Label/Context separator is emitted.
     */
    public boolean useSeparator()
    {
        return useSeparator;
    }

    /**
     * @return the derived key length in bytes.
     */
    public int getOutputLength()
    {
        return outputLength;
    }
}
