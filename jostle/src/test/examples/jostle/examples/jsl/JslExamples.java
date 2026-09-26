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

package jostle.examples.jsl;

import org.junit.jupiter.api.BeforeAll;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import java.security.Security;

/**
 * Every JSL example below runs as a JUnit test against the built jar, from a package outside the jar, so it
 * uses only the exported API. Each example assumes this one-time setup, which registers the provider under
 * the name "JSL"; the examples then name it in every `getInstance` call.
 */
public abstract class JslExamples
{
    /**
     * Register JSL once per JVM.
     */
    @BeforeAll
    public static void addProvider()
    {
        if (Security.getProvider("JSL") == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }
}
