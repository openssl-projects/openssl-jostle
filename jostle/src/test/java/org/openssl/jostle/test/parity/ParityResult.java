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
 * One classified cell: the verdict, plus the EXACT types both sides produced.
 *
 * <p>The exact class names are carried on every row regardless of verdict, not
 * only on divergences. A table that prints types only when they differ cannot
 * be audited - a reader has no way to tell a cell that matched on
 * {@code BadPaddingException} from one that matched on {@code RuntimeException},
 * and those are very different kinds of agreement.
 */
public final class ParityResult
{
    private final ParityVerdict verdict;
    private final String ourType;
    private final String bcType;
    private final String qualifier;
    private final String ourMessage;
    private final String bcMessage;

    ParityResult(ParityVerdict verdict, String ourType, String bcType, String qualifier)
    {
        this(verdict, ourType, bcType, qualifier, "", "");
    }

    ParityResult(ParityVerdict verdict, String ourType, String bcType, String qualifier,
                 String ourMessage, String bcMessage)
    {
        this.verdict = verdict;
        this.ourType = ourType;
        this.bcType = bcType;
        this.qualifier = qualifier;
        this.ourMessage = ourMessage;
        this.bcMessage = bcMessage;
    }

    /** Our refusal's message; "" when we did not refuse. */
    public String ourMessage()
    {
        return ourMessage;
    }

    /** BouncyCastle's refusal message; "" when it did not refuse. */
    public String bcMessage()
    {
        return bcMessage;
    }

    public ParityVerdict verdict()
    {
        return verdict;
    }

    public String ourType()
    {
        return ourType;
    }

    public String bcType()
    {
        return bcType;
    }

    /**
     * Extra detail the verdict alone does not carry: {@code SUBTYPE(ours<:bc)},
     * {@code we-unchecked}, {@code outputs-equal}, {@code no-output}. Never
     * null; empty when the verdict says everything.
     */
    public String qualifier()
    {
        return qualifier;
    }

    /** True when this cell needs a ruling from Megan. */
    public boolean isDivergence()
    {
        return verdict == ParityVerdict.TYPE_DIVERGENCE
                || verdict == ParityVerdict.CHECKED_DIVERGENCE
                || verdict == ParityVerdict.SILENT_DIVERGENCE
                || verdict == ParityVerdict.DECISION_DIVERGENCE
                || verdict == ParityVerdict.PIN_DRIFT;
    }

    @Override
    public String toString()
    {
        return verdict + (qualifier.isEmpty() ? "" : "[" + qualifier + "]")
                + " ours=" + ourType + " bc=" + bcType;
    }
}
