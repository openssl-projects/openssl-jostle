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

package org.openssl.jostle.test.provider;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * D50/C47: production never reads an {@code AlgorithmParameterSpec}
 * reflectively, and never carries a {@code org.bouncycastle} string literal.
 * Only Jostle's own spec types and, from their multi-release entry level,
 * the matching JDK standard type ({@code NamedParameterSpec} at java11,
 * {@code EdDSAParameterSpec} at java15) are accepted, by {@code instanceof}
 * — see C43-C46.
 *
 * <p>Comments are stripped before matching in both directions (a Javadoc
 * mentioning reflection or BouncyCastle reads exactly like a live
 * reference); for the reflection check, string-literal CONTENTS are also
 * stripped, since a message string naming a method is not a reflective call.
 * For the {@code org.bouncycastle} check the opposite holds — string
 * literals are exactly what is being searched, so they are preserved.
 *
 * <p>Allowlists are empty except for one exact carve-out: {@code Loader.java}
 * is the one production file permitted a single {@code Class.forName(...)}
 * call (it loads the FFI implementation class by name at runtime, per
 * {@code Loader.interfaceType}). Every other reflective entry point has no
 * legitimate production use.
 */
public class NoReflectiveSpecAccessInProductionTest
{
    private static final Pattern IMPORT_REFLECT = Pattern.compile("import\\s+java\\.lang\\.reflect");

    /**
     * A preceding dot is required: a reflective call is always invoked on an
     * object reference (a {@code Class}, or in {@code setAccessible}'s case
     * an {@code AccessibleObject}), whereas a method DECLARATION of the same
     * name (e.g. overriding {@code java.security.Provider.Service.newInstance})
     * never has one. Measured false positive without the dot requirement:
     * {@code JostleProvider}'s {@code public Object newInstance(...)}
     * override.
     */
    private static final Pattern REFLECTIVE_CALL = Pattern.compile(
            "\\.\\s*(getMethod|getDeclaredMethod|getMethods|getDeclaredMethods|getField|getDeclaredField"
                    + "|getConstructor|getDeclaredConstructor|setAccessible|newInstance)\\s*\\(");

    /**
     * {@code java.security.spec.EllipticCurve.getField()} (the curve's finite
     * field) collides in name with reflective {@code Class.getField}/
     * {@code getDeclaredField}. Measured: every {@code getField(}/
     * {@code getDeclaredField(} call in production is one of these five EC
     * sites, always immediately preceded by {@code .getCurve()} — the one
     * shape excluded below.
     */
    private static final Pattern EC_GET_CURVE_PREFIX = Pattern.compile("getCurve\\(\\)\\s*$");

    private static final Pattern CLASS_FOR_NAME = Pattern.compile("\\bClass\\.forName\\s*\\(");

    @Test
    public void noReflectionInProduction() throws IOException
    {
        List<Path> roots = UnpinnedServiceResolutionParityTest.mainSourceRoots();
        Assertions.assertFalse(roots.isEmpty(),
                "no production source roots found — the guard would pass vacuously");

        List<String> findings = new ArrayList<String>();
        int scanned = 0;
        boolean sawJava25 = false;
        int classForNameInLoader = 0;

        for (Path root : roots)
        {
            for (Path file : ProductionSourceLint.javaSourcesUnder(root))
            {
                scanned++;
                if (root.toString().contains("java25"))
                {
                    sawJava25 = true;
                }
                String path = file.toString();
                boolean isLoader = path.replace(java.io.File.separatorChar, '/')
                        .endsWith("java/org/openssl/jostle/Loader.java");
                String source = new String(Files.readAllBytes(file), StandardCharsets.UTF_8);

                findings.addAll(findReflectiveIssues(source, path, isLoader));

                if (isLoader)
                {
                    classForNameInLoader += countMatches(CLASS_FOR_NAME, ProductionSourceLint.stripCode(source));
                }
            }
        }

        Assertions.assertTrue(scanned > 100,
                "only " + scanned + " production sources scanned — the walk is not reaching the tree");
        Assertions.assertTrue(sawJava25,
                "no java25 source file was scanned — a source-set root was dropped from mainSourceRoots()");
        Assertions.assertEquals(1, classForNameInLoader,
                "Loader.java must carry exactly one Class.forName( call — found " + classForNameInLoader
                        + "; a second probe here must fail the build, not silently pass");

        Assertions.assertTrue(findings.isEmpty(),
                "production code reads a spec reflectively (" + findings.size() + "):\n  "
                        + String.join("\n  ", findings)
                        + "\n\nOnly Jostle's own spec types and the matching JDK standard type (by instanceof,"
                        + " at their multi-release entry level) are accepted. There is no allowlist for this"
                        + " guard beyond Loader.java's single Class.forName use.");
    }

    @Test
    public void noBouncyCastleLiteralsInProduction() throws IOException
    {
        List<Path> roots = UnpinnedServiceResolutionParityTest.mainSourceRoots();
        Assertions.assertFalse(roots.isEmpty(),
                "no production source roots found — the guard would pass vacuously");

        List<String> findings = new ArrayList<String>();
        int scanned = 0;
        boolean sawJava25 = false;

        for (Path root : roots)
        {
            for (Path file : ProductionSourceLint.javaSourcesUnder(root))
            {
                scanned++;
                if (root.toString().contains("java25"))
                {
                    sawJava25 = true;
                }
                String source = new String(Files.readAllBytes(file), StandardCharsets.UTF_8);
                findings.addAll(findBouncyCastleLiterals(source, file.toString()));
            }
        }

        Assertions.assertTrue(scanned > 100,
                "only " + scanned + " production sources scanned — the walk is not reaching the tree");
        Assertions.assertTrue(sawJava25,
                "no java25 source file was scanned — a source-set root was dropped from mainSourceRoots()");

        Assertions.assertTrue(findings.isEmpty(),
                "production code carries an org.bouncycastle string literal (" + findings.size() + "):\n  "
                        + String.join("\n  ", findings)
                        + "\n\nProduction reads only Jostle's own spec types; there is no allowlist for this"
                        + " guard — a parity-doc reference belongs in a comment, not a live literal.");
    }

    /**
     * Falsify both matchers in both directions: they must fire on a live
     * reference and stay silent on comments and on longer identifiers that
     * merely contain a forbidden token.
     */
    @Test
    public void matchersFalsifiedBothWays()
    {
        Assertions.assertEquals(1,
                findReflectiveIssues("x.getMethod(\"foo\");", "inCode", false).size(),
                "a live getMethod( call must be caught exactly once");

        Assertions.assertTrue(
                findReflectiveIssues("/* x.getMethod(\"foo\"); */", "inBlockComment", false).isEmpty(),
                "a block comment must not be scanned");

        Assertions.assertTrue(
                findReflectiveIssues("// x.getMethod(\"foo\");", "inLineComment", false).isEmpty(),
                "a line comment must not be scanned");

        Assertions.assertTrue(
                findReflectiveIssues("x.getMethodology(\"foo\");", "lookalike", false).isEmpty(),
                "getMethodology( must not match getMethod( without the call boundary");

        Assertions.assertEquals(1,
                findBouncyCastleLiterals("String s = \"org.bouncycastle.Foo\";", "inCode").size(),
                "a live org.bouncycastle string literal must be caught exactly once");

        Assertions.assertTrue(
                findBouncyCastleLiterals("/** org.bouncycastle.Foo */", "inJavadoc").isEmpty(),
                "a javadoc mention must not be scanned");

        Assertions.assertEquals(1,
                findReflectiveIssues("Class.forName(\"x\");", "nonLoaderLabel", false).size(),
                "Class.forName( outside Loader.java must be reported as a finding");

        Assertions.assertTrue(
                findReflectiveIssues("public Object newInstance(Object x) { return null; }", "declaration", false)
                        .isEmpty(),
                "a method DECLARATION named newInstance (no preceding dot) must not be flagged — "
                        + "this is the JostleProvider.Service override, not a reflective call");

        Assertions.assertTrue(
                findReflectiveIssues("int n = spec.getCurve().getField().getFieldSize();", "ecFiniteField", false)
                        .isEmpty(),
                "EllipticCurve.getField() (immediately after .getCurve()) must not be flagged");

        Assertions.assertEquals(1,
                findReflectiveIssues("clazz.getField(\"x\");", "genuineGetField", false).size(),
                "a genuine reflective getField( call, not preceded by .getCurve(), must still be flagged");
    }

    private static List<String> findReflectiveIssues(String source, String path, boolean isLoader)
    {
        List<String> out = new ArrayList<String>();
        String code = ProductionSourceLint.stripCode(source);

        if (IMPORT_REFLECT.matcher(code).find())
        {
            out.add(path + ": imports java.lang.reflect");
        }

        Matcher rc = REFLECTIVE_CALL.matcher(code);
        while (rc.find())
        {
            String methodName = rc.group(1);
            boolean isEcFiniteField = ("getField".equals(methodName) || "getDeclaredField".equals(methodName))
                    && EC_GET_CURVE_PREFIX.matcher(code.substring(Math.max(0, rc.start() - 20), rc.start())).find();
            if (isEcFiniteField)
            {
                continue;
            }
            out.add(path + ": reflective call " + rc.group() + " at offset " + rc.start());
        }

        Matcher cfn = CLASS_FOR_NAME.matcher(code);
        while (cfn.find())
        {
            if (!isLoader)
            {
                out.add(path + ": Class.forName( outside Loader.java at offset " + cfn.start());
            }
        }

        return out;
    }

    private static List<String> findBouncyCastleLiterals(String source, String path)
    {
        List<String> out = new ArrayList<String>();
        String noComments = ProductionSourceLint.stripComments(source);

        Matcher lit = ProductionSourceLint.STRING_LITERAL.matcher(noComments);
        while (lit.find())
        {
            String literal = lit.group();
            if (literal.contains("org.bouncycastle"))
            {
                out.add(path + ": " + literal + " at offset " + lit.start());
            }
        }

        return out;
    }

    private static int countMatches(Pattern p, String body)
    {
        Matcher m = p.matcher(body);
        int n = 0;
        while (m.find())
        {
            n++;
        }
        return n;
    }
}
