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

import java.security.Provider;
import java.security.Security;

/**
 * Finds the JDK's own provider for a service, or reports that there is none.
 *
 * <p>The third column. DISCOVERED rather than named: hard-coding "SunEC" or
 * "SunJCE" per algorithm would be a transcribed table of exactly the kind these
 * surveys exist to avoid, and it would go stale the first time the JDK moved an
 * algorithm between its providers.
 *
 * <p>JSL and BC are excluded by name because they are the two providers under
 * comparison; everything else installed is the JDK's own.
 */
public final class JdkComparator
{
    private JdkComparator()
    {
    }

    /**
     * The first installed provider other than JSL and BC that serves
     * {@code type}/{@code algorithm}, or null when the JDK serves neither.
     *
     * <p>A null answer is recorded as {@link Observation#absent()} and lands the
     * cell in the UNATTRIBUTED or UNCOMPARED population - never as a refusal,
     * which would fabricate a divergence out of an algorithm the JDK simply
     * does not implement.
     */
    public static Provider forService(String type, String algorithm)
    {
        for (Provider p : Security.getProviders())
        {
            String n = p.getName();
            if ("JSL".equals(n) || "JSLFIPS".equals(n) || "BC".equals(n) || "BCFIPS".equals(n))
            {
                continue;
            }
            if (p.getService(type, algorithm) != null)
            {
                return p;
            }
        }
        return null;
    }
}
