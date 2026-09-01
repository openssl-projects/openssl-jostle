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
 * How our answer to a negative-path input compares with BouncyCastle's.
 *
 * <p>The vocabulary of the MT-31 survey. Each verdict names a distinct
 * relationship, and the distinctions are the point: they carry different
 * consequences for a caller and therefore need different rulings.
 *
 * <p><b>{@link #SILENT_DIVERGENCE} is why an exception-level survey is not
 * enough.</b> Two implementations that both ACCEPT an input have agreed on the
 * decision and on the type, and an exception comparison sees nothing at all -
 * yet MT-3's key-wrap defect lived exactly there. Wrap emitted its whole result
 * from one EVP update, so a chunked caller got one independent wrap per
 * {@code update()}: no exception on either side, and different bytes. A survey
 * that folded both-accepted into {@code MATCH} would have reported the wrap
 * surface clean on the very input that was broken.
 */
public enum ParityVerdict
{
    /** Both refused, with the same exception class. */
    MATCH,

    /**
     * Both accepted, and either the outputs are byte-identical or the cell
     * produces no comparable output (an {@code init} that both sides tolerate).
     * Which of the two is recorded in the qualifier.
     */
    MATCH_ACCEPT,

    /**
     * Both refused with different classes, on the SAME side of the
     * checked/unchecked line. An interop break - the caller's handler does not
     * fire - but the error still lands where the caller's compiler expected an
     * error to be possible.
     */
    TYPE_DIVERGENCE,

    /**
     * Both refused with different classes, on OPPOSITE sides of the
     * checked/unchecked line. The severity class: where we are the unchecked
     * side, a BouncyCastle-shaped {@code catch} block catches NOTHING and the
     * error escapes to whatever sits above. This distinction is what reversed
     * the first key-wrap ruling on 2026-08-31.
     */
    CHECKED_DIVERGENCE,

    /**
     * Both ACCEPTED and produced DIFFERENT output. No exception-level survey
     * can see this; see the class note above.
     */
    SILENT_DIVERGENCE,

    /**
     * Exactly one side refused. An accept/reject disagreement, which no
     * exception-type mapping can fix. Megan's ruling of 2026-08-31 scopes
     * these: OpenSSL wins. Reported, never silently reconciled.
     */
    DECISION_DIVERGENCE,

    /** BouncyCastle serves no comparable transformation; nothing to compare. */
    BC_ABSENT,

    /**
     * The cell's POSITIVE baseline failed on one or both sides, so the fault
     * was never validly applied. Recorded rather than dropped: a cell that
     * measured nothing must never read as agreement.
     */
    NO_BASELINE,

    /**
     * Live BouncyCastle disagrees with a BouncyCastle type TRANSCRIBED into a
     * pinned test. Produced by a different comparison from every verdict above
     * - see {@link ExceptionParity#classifyPinDrift} - and fires when a bcprov
     * bump moves the reference out from under a pin.
     */
    PIN_DRIFT
}
