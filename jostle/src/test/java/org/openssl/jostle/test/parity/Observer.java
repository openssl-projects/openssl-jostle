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

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.NoSuchPaddingException;

/**
 * Runs a call and records what happened. The only way an {@link Observation} of
 * a live provider is ever created.
 *
 * <p>Catches {@link Throwable}, not {@link Exception}: an {@code Error} escaping
 * a provider is itself a finding, and letting it propagate would abort the
 * survey rather than record the cell.
 */
public final class Observer
{
    private Observer()
    {
    }

    /** What a call under observation does. */
    public interface Call
    {
        /** @return bytes to compare, or null when the call produces nothing comparable. */
        byte[] run() throws Throwable;
    }

    /** A call whose answer IS a boolean - a {@code Signature.verify}. */
    public interface BooleanCall
    {
        boolean run() throws Throwable;
    }

    /**
     * Observe one call.
     *
     * <p>A {@code NoSuchAlgorithm}/{@code NoSuchPadding} failure is reported as
     * {@link Observation#absent()} rather than as a refusal: "this provider does
     * not serve the transformation" is not an answer to "how does it refuse bad
     * input", and folding the two together would fabricate divergences wherever
     * BouncyCastle simply has no such name.
     */
    public static Observation observe(Call call)
    {
        try
        {
            byte[] out = call.run();
            return out == null ? Observation.acceptedNoOutput() : Observation.accepted(out);
        }
        catch (NoSuchAlgorithmException | NoSuchPaddingException | NoSuchProviderException absent)
        {
            return Observation.absent();
        }
        catch (Throwable t)
        {
            return Observation.threw(t);
        }
    }

    /**
     * Observe a verification.
     *
     * <p>Separate from {@link #observe} because a verify reports refusal by
     * RETURNING false, and a returned false must not be recorded as an accept.
     * Folding the two would make a correct rejection and a wrongly-accepted
     * forgery the same observation - the one distinction the whole surface
     * exists to measure.
     */
    public static Observation observeVerify(BooleanCall call)
    {
        try
        {
            return Observation.returned(call.run());
        }
        catch (NoSuchAlgorithmException | NoSuchPaddingException | NoSuchProviderException absent)
        {
            return Observation.absent();
        }
        catch (Throwable t)
        {
            return Observation.threw(t);
        }
    }
}
