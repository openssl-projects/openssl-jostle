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

/**
 * What one provider actually did when a fault was applied: it threw, or it
 * accepted and (maybe) produced bytes.
 *
 * <p>Deliberately a RECORD OF AN OBSERVATION, never a belief. The MT-31 survey
 * exists because BouncyCastle's types were being recalled rather than measured,
 * so nothing in this package may encode an expectation about what a provider
 * does - an instance of this class is only ever built by running the call.
 *
 * <p>{@code hasComparableOutput} distinguishes "accepted and produced these
 * bytes" from "accepted, and there is nothing to compare" (an {@code init} that
 * both sides tolerate). Folding the two together would make a no-output cell
 * indistinguishable from a zero-length-output cell.
 */
public final class Observation
{
    private final Throwable thrown;
    private final byte[] output;
    private final boolean hasComparableOutput;
    private final boolean absent;
    private final Boolean returned;

    private Observation(Throwable thrown, byte[] output, boolean hasComparableOutput,
                        boolean absent, Boolean returned)
    {
        this.thrown = thrown;
        this.output = output;
        this.hasComparableOutput = hasComparableOutput;
        this.absent = absent;
        this.returned = returned;
    }

    /** The provider refused, with this throwable. */
    public static Observation threw(Throwable t)
    {
        if (t == null)
        {
            throw new IllegalArgumentException("threw(null) - use accepted*()");
        }
        return new Observation(t, null, false, false, null);
    }

    /** The provider accepted and produced bytes a caller can compare. */
    public static Observation accepted(byte[] output)
    {
        return new Observation(null, output, true, false, null);
    }

    /** The provider accepted; the cell produces nothing comparable. */
    public static Observation acceptedNoOutput()
    {
        return new Observation(null, null, false, false, null);
    }

    /** The provider serves no comparable transformation for this cell. */
    public static Observation absent()
    {
        return new Observation(null, null, false, true, null);
    }

    /**
     * The call completed and returned a boolean - a {@code Signature.verify}.
     *
     * <p>A first-class shape because verify reports REFUSAL by returning false.
     * Recording it as an ordinary accept would make a correct rejection and a
     * wrongly-accepted forgery the same observation.
     */
    public static Observation returned(boolean value)
    {
        return new Observation(null, null, false, false, Boolean.valueOf(value));
    }

    /** Non-null when the call returned a boolean. */
    public Boolean returnedValue()
    {
        return returned;
    }

    public boolean isAbsent()
    {
        return absent;
    }

    public boolean isThrow()
    {
        return thrown != null;
    }

    public Throwable thrown()
    {
        return thrown;
    }

    public byte[] output()
    {
        return output;
    }

    public boolean hasComparableOutput()
    {
        return hasComparableOutput;
    }

    /**
     * The refusal's message, truncated, or "" when nothing was thrown.
     *
     * <p>Not decoration: it is how a reader tells whether the fault that was
     * INTENDED is the fault that landed. A short-key probe on an IV-bearing
     * mode that reports {@code InvalidAlgorithmParameterException} could be the
     * provider naming the key, or it could be the harness having disturbed the
     * IV; only the text distinguishes them. Same discipline as grepping a file
     * to confirm a sabotage landed before reading the test result.
     */
    public String message()
    {
        if (thrown == null || thrown.getMessage() == null)
        {
            return "";
        }
        String m = thrown.getMessage().replace('\n', ' ');
        return m.length() > 70 ? m.substring(0, 70) + "..." : m;
    }

    /** Exact class of the throwable, or a marker for the accept cases. */
    public String typeName()
    {
        if (absent)
        {
            return "(absent)";
        }
        if (returned != null)
        {
            return returned.booleanValue() ? "(returned true)" : "(returned false)";
        }
        if (thrown == null)
        {
            return hasComparableOutput ? "(accepted)" : "(accepted,no-output)";
        }
        return thrown.getClass().getName();
    }
}
