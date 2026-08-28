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
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Source-level parity guard: every FIPS NI class inheriting
 * {@code DefaultServiceNI} must override {@code providerName()} and answer
 * {@code JostleFIPSProvider.PROVIDER_NAME}.
 *
 * <p>The default is the BASE provider, so a missing override reports "JSL"
 * while running in the FIPS library — and stays invisible until something
 * READS the value. Before MT-12 exactly the six classes with a consumer had
 * the override and the other 28 did not, so the next family to grow one would
 * have shipped wrong. Only a source lint can cover the inert ones.
 *
 * <p>Out of scope: {@code OpenSSLFIPS*} and {@code OperationsTestFIPS*} do not
 * inherit {@code DefaultServiceNI}, so there is nothing to override.
 * {@link #theExcludedClassesReallyAreNotServiceNis()} re-derives that from the
 * interface sources rather than trusting the list.
 */
public class FIPSProviderNameParityTest
{
    /** Not {@code DefaultServiceNI}. Consulted before any shape detection. */
    private static final Set<String> NOT_SERVICE_NIS = new HashSet<String>(Arrays.asList(
            "OpenSSLFIPSJNI", "OpenSSLFIPSFFI",
            "OperationsTestFIPSJNI", "OperationsTestFIPSFFI"));

    private static final Pattern OVERRIDE = Pattern.compile(
            "public\\s+String\\s+providerName\\s*\\(\\s*\\)\\s*\\{\\s*"
                    + "return\\s+JostleFIPSProvider\\.PROVIDER_NAME\\s*;\\s*\\}");

    /** {@code class}/{@code interface} X extends|implements Y — the walk crosses both. */
    private static final Pattern DECLARES = Pattern.compile(
            "\\b(?:class|interface)\\s+(\\w+)\\s+(?:extends|implements)\\s+(\\w+)");

    private static final Pattern BLOCK_COMMENT = Pattern.compile("/\\*.*?\\*/", Pattern.DOTALL);
    private static final Pattern LINE_COMMENT = Pattern.compile("//[^\\n]*");
    private static final Pattern STRING_LITERAL = Pattern.compile("\"(\\\\.|[^\"\\\\])*\"");

    @Test
    public void everyFipsNiClassOverridesProviderName()
    {
        TreeMap<String, Path> classes = fipsNiSources();
        Assumptions.assumeFalse(classes.isEmpty(),
                "no FIPS NI source directory reachable from " + Paths.get("").toAbsolutePath()
                        + " — source-level lint, skipped rather than failed");

        List<String> missing = new ArrayList<String>();
        int checked = 0;

        for (java.util.Map.Entry<String, Path> e : classes.entrySet())
        {
            if (NOT_SERVICE_NIS.contains(e.getKey()))
            {
                continue;
            }
            checked++;
            // Strip comments and literals: correct classes quote providerName()
            // in Javadoc, which reads like the code being matched.
            if (!OVERRIDE.matcher(strip(read(e.getValue()))).find())
            {
                missing.add(e.getKey());
            }
        }

        Assertions.assertTrue(checked >= 24,
                "only " + checked + " FIPS NI classes scanned — the guard is not looking where "
                        + "it thinks and would pass vacuously");

        Assertions.assertTrue(missing.isEmpty(),
                "these FIPS NI classes inherit DefaultServiceNI.providerName(), which DEFAULTS to "
                        + "JostleProvider.PROVIDER_NAME — so they report \"JSL\" while running in "
                        + "the FIPS interface library, and providerManagesEntropy() (derived from "
                        + "it) answers false under JSLFIPS. Add the override returning "
                        + "JostleFIPSProvider.PROVIDER_NAME (MT-12):\n  "
                        + String.join("\n  ", missing));
    }

    /** A family added to one bridge only is a gap the per-file check cannot see. */
    @Test
    public void theTwoBridgesCarryTheSameNiClasses()
    {
        TreeMap<String, Path> classes = fipsNiSources();
        Assumptions.assumeFalse(classes.isEmpty(), "no FIPS NI source directory reachable");

        Set<String> jni = new TreeSet<String>();
        Set<String> ffi = new TreeSet<String>();
        for (String name : classes.keySet())
        {
            if (name.endsWith("FIPSJNI"))
            {
                jni.add(name.substring(0, name.length() - "FIPSJNI".length()));
            }
            else
            {
                ffi.add(name.substring(0, name.length() - "FIPSFFI".length()));
            }
        }

        Assertions.assertTrue(jni.size() >= 14, "only " + jni.size() + " FIPS JNI NI classes found");
        Assertions.assertEquals(jni, ffi,
                "the FIPS JNI and FFI bridges must carry the same NI families; a family present "
                        + "in one only is either an unfinished port or a stale file");
    }

    /**
     * Vacuity guard on {@link #NOT_SERVICE_NIS}: re-derive each exclusion from
     * the interface it names, so a stale one cannot hide a real miss.
     */
    @Test
    public void theExcludedClassesReallyAreNotServiceNis()
    {
        TreeMap<String, Path> classes = fipsNiSources();
        Assumptions.assumeFalse(classes.isEmpty(), "no FIPS NI source directory reachable");

        List<String> unjustified = new ArrayList<String>();
        int examined = 0;

        for (String excluded : NOT_SERVICE_NIS)
        {
            Path source = classes.get(excluded);
            Assertions.assertNotNull(source,
                    excluded + " is excluded but no such FIPS NI source exists — stale entry");

            // Walk the chain: an FFI class names its base FFI class, not the NI.
            // One link would leave every *FIPSFFI entry checked only via its twin.
            List<String> chain = new ArrayList<String>();
            String current = excluded;
            Path currentSource = source;
            boolean serviceNi = false;
            for (int hop = 0; hop < 8 && currentSource != null; hop++)
            {
                String body = strip(read(currentSource));
                Matcher m = DECLARES.matcher(body);
                if (!m.find())
                {
                    break;
                }
                String superType = m.group(2);
                chain.add(current + " -> " + superType);
                if ("DefaultServiceNI".equals(superType) || body.contains("DefaultServiceNI"))
                {
                    serviceNi = true;
                    break;
                }
                current = superType;
                currentSource = findTypeSource(superType);
            }

            Assertions.assertFalse(chain.isEmpty(),
                    "cannot read the class declaration of " + excluded);
            examined++;

            if (serviceNi)
            {
                unjustified.add(excluded + ": " + String.join(", ", chain)
                        + " (now reaches DefaultServiceNI)");
            }
        }

        Assertions.assertEquals(NOT_SERVICE_NIS.size(), examined,
                "not every exclusion was examined");
        Assertions.assertTrue(unjustified.isEmpty(),
                "these are excluded from the providerName() guard on the grounds that they are "
                        + "not DefaultServiceNI implementations, but their supertype now names "
                        + "DefaultServiceNI. Remove the exclusion and add the override:\n  "
                        + String.join("\n  ", unjustified));
    }

    /** Simple name -> source path, for every {@code *FIPSJNI} / {@code *FIPSFFI}. */
    private static TreeMap<String, Path> fipsNiSources()
    {
        TreeMap<String, Path> out = new TreeMap<String, Path>();
        for (Path dir : fipsPackageDirs())
        {
            for (Path p : javaSourcesUnder(dir))
            {
                String name = p.getFileName().toString();
                if (name.endsWith("FIPSJNI.java") || name.endsWith("FIPSFFI.java"))
                {
                    out.put(name.substring(0, name.length() - ".java".length()), p);
                }
            }
        }
        return out;
    }

    private static List<Path> fipsPackageDirs()
    {
        String pkg = "org/openssl/jostle/jcajce/provider/fips";
        String[] bases = {"src/main", "jostle/src/main"};
        String[] levels = {"java", "java9", "java11", "java15", "java17", "java21", "java25"};
        List<Path> found = new ArrayList<Path>();
        for (String base : bases)
        {
            for (String level : levels)
            {
                Path p = Paths.get(base, level).resolve(pkg);
                if (Files.isDirectory(p))
                {
                    found.add(p.toAbsolutePath().normalize());
                }
            }
        }
        return found;
    }

    /** Locate {@code <simpleName>.java} anywhere under the main source tree. */
    private static Path findTypeSource(String simpleName)
    {
        String[] bases = {"src/main", "jostle/src/main"};
        for (String base : bases)
        {
            Path root = Paths.get(base);
            if (!Files.isDirectory(root))
            {
                continue;
            }
            try (java.util.stream.Stream<Path> walk = Files.walk(root))
            {
                java.util.Optional<Path> hit = walk
                        .filter(p -> p.getFileName().toString().equals(simpleName + ".java"))
                        .findFirst();
                if (hit.isPresent())
                {
                    return hit.get();
                }
            }
            catch (IOException e)
            {
                throw new UncheckedIOException(e);
            }
        }
        return null;
    }

    private static String strip(String body)
    {
        String s = LINE_COMMENT.matcher(BLOCK_COMMENT.matcher(body).replaceAll(" ")).replaceAll(" ");
        return STRING_LITERAL.matcher(s).replaceAll("\"\"");
    }

    private static List<Path> javaSourcesUnder(Path root)
    {
        final List<Path> out = new ArrayList<Path>();
        try (java.util.stream.Stream<Path> walk = Files.walk(root))
        {
            walk.filter(p -> p.getFileName().toString().endsWith(".java")).forEach(out::add);
        }
        catch (IOException e)
        {
            throw new UncheckedIOException(e);
        }
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
