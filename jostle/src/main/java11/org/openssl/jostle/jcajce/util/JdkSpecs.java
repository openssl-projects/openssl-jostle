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

package org.openssl.jostle.jcajce.util;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.NamedParameterSpec;

public final class JdkSpecs
{
    private JdkSpecs()
    {
    }

    /** Java 11+ override: reads {@code java.security.spec.NamedParameterSpec}, which enters the platform at 11. */
    public static String namedParameterSpecName(AlgorithmParameterSpec spec)
    {
        return spec instanceof NamedParameterSpec ? ((NamedParameterSpec) spec).getName() : null;
    }
}
