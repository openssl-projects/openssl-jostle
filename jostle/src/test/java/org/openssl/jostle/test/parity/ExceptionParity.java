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

import org.openssl.jostle.util.Arrays;

/**
 * Classifies one pair of observations into a {@link ParityVerdict}.
 *
 * <p>A pure function of its arguments: no provider, no state, no expectation.
 * That is what makes every verdict reachable from constructed pairs in a unit
 * test, including verdicts no live cell produces today.
 *
 * <h2>Type equivalence</h2>
 *
 * <p>{@code MATCH} requires EXACT class equality. A proper subclass on either
 * side is a divergence, never a match, because catch-compatibility is
 * DIRECTIONAL:
 *
 * <ul>
 *   <li>ours is a subclass of BC's - a caller's {@code catch (BcType)} DOES
 *       catch ours. Qualifier {@code catch-compatible}.</li>
 *   <li>BC's is a subclass of ours - it does NOT. Qualifier
 *       {@code catch-incompatible}: an interop break that looks compatible,
 *       which is why "compatible" must never become {@code MATCH}.</li>
 * </ul>
 *
 * <p>Live example: BC answers {@code updateAAD} on a non-AEAD mode with
 * {@code UnsupportedOperationException}, a subclass of the bare
 * {@code RuntimeException} we raise, so a BC-shaped catch fires on nothing.
 *
 * <h2>Checked-line precedence</h2>
 *
 * <p>Where the two types sit on opposite sides of the checked/unchecked line
 * the verdict is {@code CHECKED_DIVERGENCE}, even when they are also
 * subtype-related ({@code RuntimeException} vs {@code Exception}). The line
 * decides severity; the subtype fact is still recorded in the qualifier.
 */
public final class ExceptionParity
{
    private ExceptionParity()
    {
    }

    /**
     * Compare what we did against what BouncyCastle did for the same fault.
     *
     * @param ours our provider's observation
     * @param bc   BouncyCastle's observation for the identical call
     */
    public static ParityResult classify(Observation ours, Observation bc)
    {
        if (ours == null || bc == null)
        {
            throw new IllegalArgumentException("both observations are required");
        }

        String ourType = ours.typeName();
        String bcType = bc.typeName();

        if (bc.isAbsent() || ours.isAbsent())
        {
            // Which SIDE is absent must survive. Collapsing both into one
            // unqualified verdict makes a row assert BouncyCastle is missing a
            // transformation when it may be us - a false statement about the
            // provider under survey, in the packet a reader acts on.
            String which = ours.isAbsent()
                    ? (bc.isAbsent() ? "both-absent" : "ours-absent")
                    : "bc-absent";
            return new ParityResult(ParityVerdict.BC_ABSENT, ourType, bcType, which,
                    ours.message(), bc.message());
        }

        // A boolean-returning call (Signature.verify) reports REFUSAL by its
        // return value, so these arms must precede every accept/throw arm.
        // Order matters: acceptance-vs-refusal outranks the shape of a refusal.
        Boolean ourR = ours.returnedValue();
        Boolean bcR = bc.returnedValue();
        if (ourR != null || bcR != null)
        {
            // "Accepted" spans both shapes: a returned true, and a completion
            // that produced no boolean at all. A side that did not throw and did
            // not return false did not refuse.
            boolean ourAccepted = ourR == null ? !ours.isThrow() : ourR.booleanValue();
            boolean bcAccepted = bcR == null ? !bc.isThrow() : bcR.booleanValue();
            if (ourAccepted != bcAccepted)
            {
                // One side ACCEPTED what the other refused. The forgery shape;
                // its own verdict so it cannot hide in DECISION_DIVERGENCE.
                return new ParityResult(ParityVerdict.VERIFICATION_DIVERGENCE, ourType, bcType,
                        ourAccepted ? "we-accept-bc-refuses" : "bc-accepts-we-refuse",
                        ours.message(), bc.message());
            }
            if (ourAccepted)
            {
                // Both verified. The positive baseline, and the ONLY cell where
                // true is the right answer.
                return new ParityResult(ParityVerdict.MATCH_ACCEPT, ourType, bcType,
                        "both verified", ours.message(), bc.message());
            }
            if (ourR != null && bcR != null)
            {
                return new ParityResult(ParityVerdict.MATCH_REFUSED_BY_RETURN, ourType, bcType,
                        "both returned false", ours.message(), bc.message());
            }
            // Both refused, by different mechanisms.
            return new ParityResult(ParityVerdict.REFUSAL_SHAPE_DIVERGENCE, ourType, bcType,
                    ourR == null ? "we-throw-bc-returns-false" : "we-return-false-bc-throws",
                    ours.message(), bc.message());
        }

        if (ours.isThrow() && bc.isThrow())
        {
            Class<?> a = ours.thrown().getClass();
            Class<?> b = bc.thrown().getClass();
            if (a.equals(b))
            {
                return new ParityResult(ParityVerdict.MATCH, ourType, bcType, "", ours.message(), bc.message());
            }
            return new ParityResult(checkedLineVerdict(a, b), ourType, bcType,
                    divergenceQualifier(a, b), ours.message(), bc.message());
        }

        if (ours.isThrow() != bc.isThrow())
        {
            return new ParityResult(ParityVerdict.DECISION_DIVERGENCE, ourType, bcType,
                    ours.isThrow() ? "we-refuse-bc-accepts" : "we-accept-bc-refuses", ours.message(), bc.message());
        }

        // Neither threw. An exception-level survey stops here and calls it
        // agreement; MT-3's wrap defect lived exactly in what follows.
        if (!ours.hasComparableOutput() || !bc.hasComparableOutput())
        {
            return new ParityResult(ParityVerdict.MATCH_ACCEPT, ourType, bcType, "no-output", ours.message(), bc.message());
        }
        if (Arrays.areEqual(ours.output(), bc.output()))
        {
            return new ParityResult(ParityVerdict.MATCH_ACCEPT, ourType, bcType, "outputs-equal", ours.message(), bc.message());
        }
        return new ParityResult(ParityVerdict.SILENT_DIVERGENCE, ourType, bcType,
                "both accepted, " + len(ours.output()) + " vs " + len(bc.output()) + " bytes differing", ours.message(), bc.message());
    }

    /**
     * Live BouncyCastle against a BouncyCastle type TRANSCRIBED into a pinned
     * test. A different comparison from {@link #classify} - both arguments
     * describe BouncyCastle - kept as its own method so neither function has to
     * pretend the other's inputs mean the same thing.
     *
     * <p>A pin SHOULD hold a literal; re-measuring BC inside a pin would make
     * the pin follow BC wherever it went, which is the opposite of pinning. The
     * risk a literal carries is that a bcprov bump moves the reference with
     * nothing failing, and this is what notices.
     *
     * @param liveBc      what BouncyCastle does now
     * @param transcribed the type a pinned test records BouncyCastle as doing
     */
    public static ParityResult classifyPinDrift(Observation liveBc, Class<?> transcribed)
    {
        if (liveBc == null || transcribed == null)
        {
            throw new IllegalArgumentException("live observation and transcribed type are required");
        }
        String live = liveBc.typeName();
        String pinned = transcribed.getName();
        if (liveBc.isThrow() && liveBc.thrown().getClass().equals(transcribed))
        {
            return new ParityResult(ParityVerdict.MATCH, live, pinned, "pin-still-true");
        }
        return new ParityResult(ParityVerdict.PIN_DRIFT, live, pinned,
                liveBc.isThrow() ? "bcprov moved" : "bcprov now accepts");
    }

    /**
     * Which side of the checked/unchecked line each type sits on decides the
     * SEVERITY, so it takes precedence over the subtype relation when the two
     * disagree. {@code RuntimeException} is a subclass of {@code Exception} and
     * on the other side of the line from it - that pair is a checked
     * divergence that happens to be subtype-related, not a mere type swap.
     */
    private static ParityVerdict checkedLineVerdict(Class<?> a, Class<?> b)
    {
        return isUnchecked(a) == isUnchecked(b)
                ? ParityVerdict.TYPE_DIVERGENCE
                : ParityVerdict.CHECKED_DIVERGENCE;
    }

    private static String divergenceQualifier(Class<?> ours, Class<?> bc)
    {
        StringBuilder sb = new StringBuilder();
        if (isUnchecked(ours) != isUnchecked(bc))
        {
            sb.append(isUnchecked(ours) ? "we-unchecked" : "we-checked");
        }
        if (bc.isAssignableFrom(ours))
        {
            append(sb, "SUBTYPE(ours<:bc) catch-compatible");
        }
        else if (ours.isAssignableFrom(bc))
        {
            append(sb, "SUBTYPE(bc<:ours) catch-incompatible");
        }
        return sb.toString();
    }

    private static void append(StringBuilder sb, String s)
    {
        if (sb.length() > 0)
        {
            sb.append(' ');
        }
        sb.append(s);
    }

    /** Java's own rule: {@code RuntimeException} and {@code Error} and their subclasses. */
    static boolean isUnchecked(Class<?> c)
    {
        return RuntimeException.class.isAssignableFrom(c) || Error.class.isAssignableFrom(c);
    }

    private static String len(byte[] b)
    {
        return b == null ? "null" : String.valueOf(b.length);
    }
}
