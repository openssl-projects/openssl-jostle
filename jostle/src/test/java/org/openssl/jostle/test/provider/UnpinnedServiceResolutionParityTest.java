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
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Production code must not resolve a JCA service without naming the provider.
 *
 * <p>MT-18 removed seven such sites; this is what stops the eighth. An
 * unpinned {@code getInstance(alg)} takes whatever the {@code Security} search
 * order offers — measured on a bare JVM, <b>seven of the twenty
 * {@code AlgorithmParameters} names Jostle itself registers resolve to SunJCE,
 * SUN or SunEC</b>, because the JDK's providers sit ahead of Jostle.
 *
 * <p><b>What a green run does NOT mean.</b> This closes "resolved from the
 * registry". It does not close "pinned to the WRONG provider" — the matcher
 * decides pinned-ness by counting top-level arguments, so a {@code String}
 * provider name and a {@code Provider} object are indistinguishable to it.
 * That is MT-16's name-versus-instance distinction, and it is the same
 * designed blind spot {@code ProviderPinningParityTest} has. Only a
 * behavioural test against a selectively-incapable provider instance can close
 * the second question.
 *
 * <p>A runtime test cannot be the guard here. {@code jostle/build.gradle} puts
 * BouncyCastle on the TEST runtime classpath and production has no such
 * dependency, so a delegation can be satisfied in tests by a provider that is
 * absent in production — which is exactly how one of MT-18's findings stayed
 * hidden. The defect is visible in the source and nowhere else, so the guard
 * reads the source.
 */
public class UnpinnedServiceResolutionParityTest
{
    private static final Pattern BLOCK_COMMENT = Pattern.compile("/\\*.*?\\*/", Pattern.DOTALL);
    private static final Pattern LINE_COMMENT = Pattern.compile("//[^\\n]*");
    private static final Pattern STRING_LITERAL = Pattern.compile("\"(\\\\.|[^\"\\\\])*\"");

    /** JCA types whose {@code getInstance} consults the provider registry. */
    private static final String TYPES =
            "MessageDigest|Cipher|Signature|KeyFactory|KeyPairGenerator|KeyGenerator|Mac"
                    + "|SecureRandom|AlgorithmParameters|AlgorithmParameterGenerator|KeyAgreement"
                    + "|SecretKeyFactory|CertificateFactory|KeyStore|KeyManagerFactory|TrustManagerFactory";

    /**
     * A {@code getInstance(...)} whose argument list has no top-level comma —
     * i.e. one argument, so no provider. Nested calls are permitted inside the
     * single argument, which is why the capture excludes commas but allows
     * parentheses to be counted rather than matched.
     */
    private static final Pattern GET_INSTANCE =
            Pattern.compile("\\b(" + TYPES + ")\\s*\\.\\s*getInstance\\s*\\(");

    private static final Pattern PROVIDER_WALK =
            Pattern.compile("Security\\s*\\.\\s*getProviders\\s*\\(");

    /**
     * Sanctioned unpinned resolutions, each with the reason it is allowed.
     * Keyed by {@code <SimpleClassName>:<algorithm-or-shape>} so a carve-out
     * cannot silently widen to the whole file.
     */
    private static final Set<String> ALLOWED = Collections.unmodifiableSet(new HashSet<String>(Arrays.asList(
            // Megan's ruling: CONSUMING a platform JCA service as a client is
            // fine; any conforming DRBG is acceptable and Jostle registers no
            // competing "DRBG".
            "ThreadLocalSecureRandomProvider:SecureRandom",
            // MT-14's unbound realm: a directly-constructed SPI has no provider
            // instance, so name resolution is the maximum pinning available.
            // Resolves Jostle-by-name only and throws if no Jostle provider is
            // registered, so no foreign provider can serve through it.
            "JostleAlgorithmParameters:AlgorithmParameters",
            // Same unbound realm, reached from the generators' null-provider
            // constructors.
            "DHAlgorithmParameterGenerator:AlgorithmParameters",
            "DSAAlgorithmParameterGenerator:AlgorithmParameters"
    )));

    @Test
    public void productionCodeNeverResolvesAServiceWithoutNamingTheProvider() throws IOException
    {
        List<Path> roots = mainSourceRoots();
        Assertions.assertFalse(roots.isEmpty(),
                "no production source roots found — the guard would pass vacuously");

        List<String> findings = new ArrayList<String>();
        int scanned = 0;

        for (Path root : roots)
        {
            for (Path file : javaSourcesUnder(root))
            {
                scanned++;
                String cls = file.getFileName().toString().replace(".java", "");
                String code = strip(new String(Files.readAllBytes(file), StandardCharsets.UTF_8));

                Matcher m = GET_INSTANCE.matcher(code);
                while (m.find())
                {
                    if (hasProviderArgument(code, m.end()))
                    {
                        continue;
                    }
                    if (ALLOWED.contains(cls + ":" + m.group(1)))
                    {
                        continue;
                    }
                    findings.add(cls + ": unpinned " + m.group(1) + ".getInstance(...) at offset " + m.start());
                }

                Matcher w = PROVIDER_WALK.matcher(code);
                while (w.find())
                {
                    if (ALLOWED.contains(cls + ":Security.getProviders"))
                    {
                        continue;
                    }
                    findings.add(cls + ": Security.getProviders() walk at offset " + w.start());
                }
            }
        }

        Assertions.assertTrue(scanned > 100,
                "only " + scanned + " production sources scanned — the walk is not reaching the tree");

        Assertions.assertTrue(findings.isEmpty(),
                "production code resolving a JCA service without naming the provider ("
                        + findings.size() + "):\n  " + String.join("\n  ", findings)
                        + "\n\nPin it: getInstance(alg, providerInstance) reads the provider OBJECT and never"
                        + " consults the Security registry. If the site genuinely cannot pin, add it to"
                        + " ALLOWED with the reason.");
    }

    /**
     * Does the argument list starting at {@code open} carry a second top-level
     * argument? Counts nesting so {@code getInstance(f(a, b))} reads as one.
     */
    private static boolean hasProviderArgument(String code, int open)
    {
        int depth = 1;
        for (int i = open; i < code.length(); i++)
        {
            char c = code.charAt(i);
            if (c == '(')
            {
                depth++;
            }
            else if (c == ')')
            {
                if (--depth == 0)
                {
                    return false;
                }
            }
            else if (c == ',' && depth == 1)
            {
                return true;
            }
        }
        return false;
    }

    private static String strip(String body)
    {
        String noComments = LINE_COMMENT.matcher(
                BLOCK_COMMENT.matcher(body).replaceAll(" ")).replaceAll(" ");
        return STRING_LITERAL.matcher(noComments).replaceAll("\"\"");
    }

    private static List<Path> mainSourceRoots()
    {
        String[] bases = {"src/main", "jostle/src/main"};
        String[] levels = {"java", "java9", "java11", "java15", "java17", "java21", "java25"};
        List<Path> found = new ArrayList<Path>();
        for (String base : bases)
        {
            for (String level : levels)
            {
                Path p = Paths.get(base, level, "org", "openssl", "jostle");
                if (Files.isDirectory(p))
                {
                    found.add(p.toAbsolutePath().normalize());
                }
            }
        }
        return found;
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
