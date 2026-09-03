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

package org.openssl.jostle.test.multirelease;

import java.security.CodeSource;

/**
 * Answers "is the {@code javaN/} override actually LOADED?" — which is NOT the
 * same question as "does this JDK have the API the override needs".
 *
 * <h2>Why the distinction is load-bearing</h2>
 *
 * <p>A multi-release override is served only from a jar carrying
 * {@code META-INF/versions/N}. The base {@code :jostle:test} task runs against
 * raw {@code sourceSets.main.output} class directories — there is no jar on its
 * classpath — so it loads the Java 8 BASELINE copy whatever JDK it runs on. The
 * {@code unitTestNN} / {@code integrationTestNN} tasks set
 * {@code classpath = files(jar.archiveFile)} and therefore do get the override.
 *
 * <p>So a test that gates on API presence ({@code NamedParameterSpec} exists
 * from 11) is asking about the JDK when the behaviour is decided by the
 * CLASSPATH. Measured 2026-09-02, one probe per cell:
 *
 * <pre>
 *   JDK  classpath  apiPresent  fromJar  override in effect
 *   8    jar        false       true     no
 *   11   jar        true        true     YES
 *   11   classes    true        false    no
 *   25   jar        true        true     YES
 *   25   classes    true        false    no
 * </pre>
 *
 * <p>{@code apiPresent && fromJar} predicts all five; either alone does not —
 * apiPresent is true in four cells including two where the baseline runs, and
 * fromJar is true on JDK 8 where {@code META-INF/versions} is ignored entirely.
 *
 * <p>This exists because two committed tests gated on API presence and so
 * FAILED on the base leg while passing on all five jar legs — the classes-vs-jar
 * leg dimension. A test using this helper must assert BOTH branches (the
 * override's behaviour when active, the baseline's when not), per
 * "assert the CONTRACT, not one environment's answer" in testing.md.
 */
public final class MultiReleaseOverrides
{
    private MultiReleaseOverrides()
    {
    }

    /**
     * True when {@code impl} was loaded from a jar AND {@code requiredApiClass}
     * exists — i.e. the {@code javaN/} override for {@code impl} is the copy in
     * effect.
     *
     * @param impl             a class that has a {@code javaN/} override.
     * @param requiredApiClass the JDK API the override needs, e.g.
     *                         {@code java.security.spec.NamedParameterSpec}.
     */
    public static boolean overrideActive(Class<?> impl, String requiredApiClass)
    {
        return loadedFromJar(impl) && classPresent(requiredApiClass);
    }

    /** True when the class came from a jar rather than a class directory. */
    public static boolean loadedFromJar(Class<?> impl)
    {
        if (impl.getProtectionDomain() == null)
        {
            return false;
        }
        CodeSource cs = impl.getProtectionDomain().getCodeSource();
        if (cs == null || cs.getLocation() == null)
        {
            return false;
        }
        return cs.getLocation().toString().endsWith(".jar");
    }

    /** True when the named class is resolvable on this JDK. */
    public static boolean classPresent(String name)
    {
        try
        {
            Class.forName(name);
            return true;
        }
        catch (Throwable absent)
        {
            return false;
        }
    }
}
