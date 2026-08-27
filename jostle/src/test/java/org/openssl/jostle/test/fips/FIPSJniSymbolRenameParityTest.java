/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.fips;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Every {@code native} method on a {@code *FIPSJNI} class must have a
 * {@code #define} rename in {@code interface/fips/jni/}.
 *
 * <p><b>Why.</b> JNI binds by a symbol derived from the declaring CLASS name,
 * so the FIPS classes need their own exports. The FIPS JNI tree gets them by
 * {@code #define}-renaming the base names and {@code #include}-ing the base
 * glue. Add a native method without extending the rename list and two things
 * happen at once, neither of them a compile error:
 *
 * <ol>
 * <li>the FIPS class's symbol does not exist, so the first call to it is an
 *     {@code UnsatisfiedLinkError} at runtime; and</li>
 * <li>the FIPS library exports the symbol under the BASE class's name, which
 *     the base library also exports — a genuine base/FIPS symbol collision of
 *     exactly the kind {@code native-code.md} calls the dangerous axis,
 *     because the loader may bind either.</li>
 * </ol>
 *
 * <p>This shipped: {@code SpecFIPSJNI.ni_getKeyProvider} was added to
 * {@code fips/jni/spec_ni_jni.c} but not to {@code spec_fips_jni.c}'s rename
 * list, and the FIPS library exported
 * {@code Java_..._jcajce_spec_SpecJNI_ni_1getKeyProvider} alongside the base
 * library's copy of the same name. The FFI half of the same change was
 * correct, so {@code FIPSLibraryLookupParityTest} — which probes FFI entry
 * points — stayed green. This test is its JNI counterpart.
 *
 * <p><b>Gradle does not track {@code interface/} as a test-task input</b>, so
 * a run after a C-only edit is served UP-TO-DATE and this guard does not
 * execute — the same shape as the {@code TEST_FIPS_LIB} caching trap in
 * testing.md. Falsifying it, or re-checking it after editing a rename list,
 * needs {@code --rerun}. (Observed: removing the {@code getKeyProvider} define
 * and re-running produced BUILD SUCCESSFUL in 270ms with no test executed.)
 * The full two-pass gate rebuilds native and reruns, so CI is unaffected.
 *
 * <p><b>Source-level, deliberately.</b> The equivalent runtime check would
 * need the built library and could not probe an overloaded method without
 * reconstructing its full JNI signature. The rename list is the thing that
 * actually goes missing, so checking the source catches it earlier, on any
 * platform, and without a native build.
 */
public class FIPSJniSymbolRenameParityTest
{
    /**
     * Classes whose FIPS glue is purpose-written rather than a rename
     * re-include, so no {@code #define} is expected.
     *
     * <p>{@code OpenSSLFIPSJNI} is the standing example: {@code native-code.md}
     * records why the FIPS tree writes its own {@code openssl_fips_jni.c}
     * instead of re-including the base file — the re-include would drag in
     * {@code set_openssl_module}, which installs a NON-FIPS lib ctx as the FIPS
     * global.
     */
    private static final Set<String> PURPOSE_WRITTEN_GLUE = new LinkedHashSet<String>(
            java.util.Arrays.asList("OpenSSLFIPSJNI"));

    /**
     * Classes present only in an operations-test build. Their symbols are
     * compiled out of a release library, and their glue is conditional, so the
     * rename list legitimately does not carry them.
     */
    private static final Set<String> OPS_ONLY = new LinkedHashSet<String>(
            java.util.Arrays.asList("OperationsTestFIPSJNI"));

    private static final Pattern NATIVE_METHOD = Pattern.compile(
            "\\bnative\\s+[\\w.$<>\\[\\]]+(?:\\s*\\[\\s*\\])*\\s+(\\w+)\\s*\\(");

    @Test
    public void everyFipsJniNativeHasARenameDefine() throws IOException
    {
        Path javaDir = resolve("jostle/src/main/java/org/openssl/jostle/jcajce/provider/fips",
                "src/main/java/org/openssl/jostle/jcajce/provider/fips");
        Path jniDir = resolve("interface/fips/jni", "../interface/fips/jni");

        Assumptions.assumeTrue(javaDir != null && jniDir != null,
                "source tree not reachable from the working directory ("
                        + Paths.get("").toAbsolutePath() + ") — this guard is source-level "
                        + "and only runs from a checkout");

        StringBuilder allDefines = new StringBuilder();
        for (Path c : listFiles(jniDir, ".c"))
        {
            allDefines.append(read(c)).append('\n');
        }
        String defines = allDefines.toString();

        List<String> missing = new ArrayList<String>();
        int checked = 0;

        for (Path java : listFiles(javaDir, "FIPSJNI.java"))
        {
            String cls = java.getFileName().toString().replace(".java", "");
            if (PURPOSE_WRITTEN_GLUE.contains(cls) || OPS_ONLY.contains(cls))
            {
                continue;
            }
            String src = stripCommentsAndStrings(read(java));

            Set<String> methods = new LinkedHashSet<String>();
            Matcher m = NATIVE_METHOD.matcher(src);
            while (m.find())
            {
                methods.add(m.group(1));
            }

            for (String method : methods)
            {
                // JNI mangling: '_' in an identifier becomes "_1". An
                // overloaded method additionally carries "__<signature>", so
                // the target is matched as a PREFIX.
                String target = "Java_org_openssl_jostle_jcajce_provider_fips_" + cls + "_"
                        + method.replace("_", "_1");
                checked++;
                if (!defines.contains(target))
                {
                    missing.add(cls + "." + method + "  (expected a #define whose replacement "
                            + "starts " + target + ")");
                }
            }
        }

        Assertions.assertTrue(checked > 0,
                "no native methods were examined — the guard is vacuous");
        Assertions.assertTrue(missing.isEmpty(),
                "a *FIPSJNI native method has no #define rename in interface/fips/jni/, so the "
                        + "FIPS library exports it under the BASE class's name — an "
                        + "UnsatisfiedLinkError for the FIPS class and a symbol collision with "
                        + "the base library:\n  " + String.join("\n  ", missing));
    }

    /**
     * Strip comments and string literals before matching.
     *
     * <p>Required in both directions, per the source-guard rule in
     * testing.md: Javadoc on these classes discusses {@code native} methods in
     * prose, and a message string can contain something that looks like a
     * declaration. Every source lint in this repo needed this.
     */
    private static String stripCommentsAndStrings(String src)
    {
        String s = src.replaceAll("(?s)/\\*.*?\\*/", " ");
        s = s.replaceAll("(?m)//.*$", " ");
        s = s.replaceAll("\"(\\\\.|[^\"\\\\])*\"", "\"\"");
        return s;
    }

    private static Path resolve(String... candidates)
    {
        for (String c : candidates)
        {
            Path p = Paths.get(c);
            if (Files.isDirectory(p))
            {
                return p.toAbsolutePath().normalize();
            }
        }
        return null;
    }

    private static List<Path> listFiles(Path dir, String suffix)
    {
        final List<Path> out = new ArrayList<Path>();
        try (java.util.stream.Stream<Path> walk = Files.walk(dir, 1))
        {
            walk.filter(p -> p.getFileName().toString().endsWith(suffix)).forEach(out::add);
        }
        catch (IOException e)
        {
            throw new UncheckedIOException(e);
        }
        java.util.Collections.sort(out);
        return out;
    }

    private static String read(Path path)
    {
        try
        {
            return new String(Files.readAllBytes(path), StandardCharsets.UTF_8);
        }
        catch (IOException e)
        {
            throw new UncheckedIOException(e);
        }
    }
}
