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
 * Production code never names a JDK provider — no service is ever resolved
 * from a non-Jostle provider.
 *
 * <p>Comments are stripped before matching (a Javadoc mentioning a JDK
 * provider by name reads exactly like a live reference); string literals are
 * NOT stripped, because the whole point is to catch a literal like
 * {@code "SunEC"} appearing as a provider-name argument.
 *
 * <p>Allowlist is empty: naming a JDK provider in production has no
 * legitimate case, so there is nothing to allow.
 */
public class NoJdkProviderNamesInProductionTest
{
    private static final Pattern BLOCK_COMMENT = Pattern.compile("/\\*.*?\\*/", Pattern.DOTALL);
    private static final Pattern LINE_COMMENT = Pattern.compile("//[^\\n]*");
    private static final Pattern STRING_LITERAL = Pattern.compile("\"(\\\\.|[^\"\\\\])*\"");

    private static final Pattern FORBIDDEN_NAME = Pattern.compile(
            "\\b(SUN|SunEC|SunJCE|SunRsaSign|SunJSSE|SunPKCS11|SunJGSS|SunSASL|XMLDSig|SunPCSC|JdkLDAP|JdkSASL|Apple)\\b");

    @Test
    public void productionCodeNamesNoJdkProvider() throws IOException
    {
        List<Path> roots = UnpinnedServiceResolutionParityTest.mainSourceRoots();
        Assertions.assertFalse(roots.isEmpty(),
                "no production source roots found — the guard would pass vacuously");

        List<String> findings = new ArrayList<String>();
        int scanned = 0;
        boolean sawJava25 = false;

        for (Path root : roots)
        {
            for (Path file : javaSourcesUnder(root))
            {
                scanned++;
                if (root.toString().contains("java25"))
                {
                    sawJava25 = true;
                }
                String cls = file.getFileName().toString();
                String source = new String(Files.readAllBytes(file), StandardCharsets.UTF_8);
                findings.addAll(findForbiddenNames(source, cls));
            }
        }

        Assertions.assertTrue(scanned > 100,
                "only " + scanned + " production sources scanned — the walk is not reaching the tree");
        // A dropped source-set root (e.g. java25, which carries the FFI
        // bindings) must not pass vacuously — assert we actually reached it.
        Assertions.assertTrue(sawJava25,
                "no java25 source file was scanned — a source-set root was dropped from mainSourceRoots()");

        Assertions.assertTrue(findings.isEmpty(),
                "production code names a JDK provider (" + findings.size() + "):\n  "
                        + String.join("\n  ", findings)
                        + "\n\nProduction code never resolves a service from a non-Jostle provider. Remove the"
                        + " reference; there is no allowlist for this guard.");
    }

    /**
     * Falsify the matcher itself in both directions: it must fire on a live
     * reference and stay silent on comments and on longer identifiers that
     * merely contain a forbidden token.
     */
    @Test
    public void matcherFiresOnLiveReferenceAndStaysSilentOnLookalikes()
    {
        List<String> inCode = findForbiddenNames(
                "CertificateFactory.getInstance(\"X.509\", \"SUN\");", "inCode");
        Assertions.assertEquals(1, inCode.size(),
                "a live SUN provider-name literal must be caught exactly once: " + inCode);

        List<String> inBlockComment = findForbiddenNames(
                "/* CertificateFactory.getInstance(\"X.509\", \"SUN\"); */", "inBlockComment");
        Assertions.assertTrue(inBlockComment.isEmpty(),
                "a block comment must not be scanned: " + inBlockComment);

        List<String> inLineComment = findForbiddenNames(
                "// CertificateFactory.getInstance(\"X.509\", \"SUN\");", "inLineComment");
        Assertions.assertTrue(inLineComment.isEmpty(),
                "a line comment must not be scanned: " + inLineComment);

        List<String> sunset = findForbiddenNames("String s = \"SUNSET\";", "sunset");
        Assertions.assertTrue(sunset.isEmpty(),
                "SUNSET must not match SUN without a word boundary: " + sunset);

        List<String> applet = findForbiddenNames("String s = \"Applet\";", "applet");
        Assertions.assertTrue(applet.isEmpty(),
                "Applet must not match Apple without a word boundary: " + applet);
    }

    private static List<String> findForbiddenNames(String source, String label)
    {
        List<String> out = new ArrayList<String>();
        String noComments = stripComments(source);

        Matcher lit = STRING_LITERAL.matcher(noComments);
        while (lit.find())
        {
            String literal = lit.group();
            if (FORBIDDEN_NAME.matcher(literal).find())
            {
                out.add(label + ": JDK provider name in string literal " + literal
                        + " at offset " + lit.start());
            }
        }
        return out;
    }

    private static String stripComments(String body)
    {
        return LINE_COMMENT.matcher(BLOCK_COMMENT.matcher(body).replaceAll(" ")).replaceAll(" ");
    }

    private static List<Path> javaSourcesUnder(Path root) throws IOException
    {
        final List<Path> out = new ArrayList<Path>();
        try (java.util.stream.Stream<Path> walk = Files.walk(root))
        {
            walk.filter(p -> p.getFileName().toString().endsWith(".java")).forEach(out::add);
        }
        return out;
    }
}
