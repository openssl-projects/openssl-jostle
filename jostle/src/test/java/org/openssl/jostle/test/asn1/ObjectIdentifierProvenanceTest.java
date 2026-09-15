/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.asn1;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Provenance for every object identifier the provider names.
 *
 * <p>Three independent checks. Each constant's computed value is compared
 * against the dotted literal in its own javadoc, which is the human-written
 * oracle a branch typo cannot reach; then against BouncyCastle 1.86's field of
 * the same class and field name, which is an oracle we do not own; and finally
 * a source lint requires that no dotted literal survives outside this package.
 *
 * <p>The lint reads every main source set as text, so it sees the {@code javaN}
 * override trees that {@code checkstyleMain} cannot — {@code build.gradle} sets
 * {@code sourceSets = [project.sourceSets.main]} and the overrides are separate
 * source sets.
 */
public class ObjectIdentifierProvenanceTest
{
    /** Our interfaces, and where BouncyCastle 1.86 keeps the same-named class. */
    private static final Map<String, String> BC_CLASSES = new LinkedHashMap<String, String>();

    static
    {
        BC_CLASSES.put("PKCSObjectIdentifiers", "org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers");
        BC_CLASSES.put("X9ObjectIdentifiers", "org.bouncycastle.asn1.x9.X9ObjectIdentifiers");
        BC_CLASSES.put("SECObjectIdentifiers", "org.bouncycastle.asn1.sec.SECObjectIdentifiers");
        BC_CLASSES.put("NISTObjectIdentifiers", "org.bouncycastle.asn1.nist.NISTObjectIdentifiers");
        BC_CLASSES.put("GMObjectIdentifiers", "org.bouncycastle.asn1.gm.GMObjectIdentifiers");
        BC_CLASSES.put("CryptoProObjectIdentifiers", "org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers");
        BC_CLASSES.put("OIWObjectIdentifiers", "org.bouncycastle.internal.asn1.oiw.OIWObjectIdentifiers");
        BC_CLASSES.put("MiscObjectIdentifiers", "org.bouncycastle.internal.asn1.misc.MiscObjectIdentifiers");
        BC_CLASSES.put("ISOIECObjectIdentifiers", "org.bouncycastle.internal.asn1.iso.ISOIECObjectIdentifiers");
        BC_CLASSES.put("KISAObjectIdentifiers", "org.bouncycastle.internal.asn1.kisa.KISAObjectIdentifiers");
        BC_CLASSES.put("EdECObjectIdentifiers", "org.bouncycastle.internal.asn1.edec.EdECObjectIdentifiers");
        BC_CLASSES.put("NSRIObjectIdentifiers", "org.bouncycastle.internal.asn1.nsri.NSRIObjectIdentifiers");
        BC_CLASSES.put("NTTObjectIdentifiers", "org.bouncycastle.internal.asn1.ntt.NTTObjectIdentifiers");
        // Ours groups the id-ce arcs in one class; BouncyCastle keeps them as
        // fields of Extension under DIFFERENT names, so this entry needs the
        // alias map below. Without the entry the nineteen new constants were
        // covered by the literal lint alone -- neither the javadoc-vs-computed
        // check nor the BouncyCastle oracle saw them, which is exactly the
        // "not seeing the package" shape the vacuity floors exist for.
        BC_CLASSES.put("X509ObjectIdentifiers", "org.bouncycastle.asn1.x509.Extension");
    }

    /**
     * {@code OurClass.ourField -> BouncyCastle's field name}, for the one class
     * whose names deliberately do not follow BouncyCastle's.
     *
     * <p>Read from the tagged clone at {@code r1rv86},
     * {@code core/src/main/java/org/bouncycastle/asn1/x509/Extension.java},
     * lines 36-136 -- through the ref, not the working tree.
     */
    private static final Map<String, String> BC_FIELD_ALIASES = new LinkedHashMap<String, String>();

    static
    {
        BC_FIELD_ALIASES.put("X509ObjectIdentifiers.id_ce_keyUsage", "keyUsage");
        BC_FIELD_ALIASES.put("X509ObjectIdentifiers.id_ce_subjectAltName", "subjectAlternativeName");
        BC_FIELD_ALIASES.put("X509ObjectIdentifiers.id_ce_issuerAltName", "issuerAlternativeName");
        BC_FIELD_ALIASES.put("X509ObjectIdentifiers.id_ce_basicConstraints", "basicConstraints");
        BC_FIELD_ALIASES.put("X509ObjectIdentifiers.id_ce_cRLNumber", "cRLNumber");
        BC_FIELD_ALIASES.put("X509ObjectIdentifiers.id_ce_cRLReasons", "reasonCode");
        BC_FIELD_ALIASES.put("X509ObjectIdentifiers.id_ce_invalidityDate", "invalidityDate");
        BC_FIELD_ALIASES.put("X509ObjectIdentifiers.id_ce_deltaCRLIndicator", "deltaCRLIndicator");
        BC_FIELD_ALIASES.put("X509ObjectIdentifiers.id_ce_issuingDistributionPoint", "issuingDistributionPoint");
        BC_FIELD_ALIASES.put("X509ObjectIdentifiers.id_ce_certificateIssuer", "certificateIssuer");
        BC_FIELD_ALIASES.put("X509ObjectIdentifiers.id_ce_nameConstraints", "nameConstraints");
        BC_FIELD_ALIASES.put("X509ObjectIdentifiers.id_ce_cRLDistributionPoints", "cRLDistributionPoints");
        BC_FIELD_ALIASES.put("X509ObjectIdentifiers.id_ce_certificatePolicies", "certificatePolicies");
        BC_FIELD_ALIASES.put("X509ObjectIdentifiers.id_ce_policyMappings", "policyMappings");
        BC_FIELD_ALIASES.put("X509ObjectIdentifiers.id_ce_authorityKeyIdentifier", "authorityKeyIdentifier");
        BC_FIELD_ALIASES.put("X509ObjectIdentifiers.id_ce_policyConstraints", "policyConstraints");
        BC_FIELD_ALIASES.put("X509ObjectIdentifiers.id_ce_extKeyUsage", "extendedKeyUsage");
        BC_FIELD_ALIASES.put("X509ObjectIdentifiers.id_ce_freshestCRL", "freshestCRL");
        BC_FIELD_ALIASES.put("X509ObjectIdentifiers.id_ce_inhibitAnyPolicy", "inhibitAnyPolicy");
    }

    /**
     * Constants with NO BouncyCastle field this check can read, each with the
     * reason. An entry here is not "unchecked": see the reason.
     */
    private static final Map<String, String> BC_UNREADABLE = new LinkedHashMap<String, String>();

    static
    {
        // BouncyCastle's own id_ce is PACKAGE-PRIVATE (r1rv86,
        // core/src/main/java/org/bouncycastle/asn1/x509/X509ObjectIdentifiers.java:144
        // -- "static final", no "public"), so getField cannot reach it and
        // setAccessible across a module boundary is not a reasonable thing for
        // a lint to do. Its value is implied rather than unverified: all
        // nineteen id-ce constants BRANCH from it and all nineteen are compared
        // against BouncyCastle above, so a wrong id_ce fails nineteen rows.
        BC_UNREADABLE.put("X509ObjectIdentifiers.id_ce", "BouncyCastle's id_ce is package-private");
    }

    private static final String OIDS_PACKAGE = "org/openssl/jostle/util/asn1/oids";

    /** A dotted identifier inside a Java string literal. */
    private static final Pattern LITERAL = Pattern.compile("\"([0-2](?:\\.[0-9]+){2,})\"");

    /** The first dotted identifier in a javadoc block. */
    private static final Pattern DOC_OID = Pattern.compile("([0-2](?:\\.[0-9]+){2,})");

    /**
     * A constant's computed value must equal the dotted identifier its own
     * javadoc states. The javadoc is written by hand and the value is computed
     * through a chain of {@code branch} calls, so a mistyped branch shows up
     * here and nowhere else.
     */
    @Test
    public void everyConstantMatchesTheOidInItsJavadoc()
        throws Exception
    {
        Path oids = findOidsPackage();
        Assertions.assertNotNull(oids,
                "the oids package is not reachable from the working directory ("
                        + Paths.get("").toAbsolutePath() + ") -- Gradle runs from jostle/, so "
                        + "this is a broken reader, not an absent tree; a skip here would go unread");

        List<String> problems = new ArrayList<String>();
        int checked = 0;

        for (String simpleName : BC_CLASSES.keySet())
        {
            Path source = oids.resolve(simpleName + ".java");
            Assertions.assertTrue(Files.exists(source), "missing source: " + source);

            Map<String, String> documented = documentedOids(source);
            Class<?> ours = Class.forName("org.openssl.jostle.util.asn1.oids." + simpleName);
            Field[] fields = ours.getDeclaredFields();

            Assertions.assertTrue(fields.length > 0, simpleName + " declares no constants");
            Assertions.assertEquals(fields.length, documented.size(),
                    simpleName + ": every constant needs a javadoc carrying its dotted identifier");

            for (Field f : fields)
            {
                String doc = documented.get(f.getName());
                if (doc == null)
                {
                    problems.add(simpleName + "." + f.getName() + " has no dotted identifier in its javadoc");
                    continue;
                }
                String actual = idOf(f.get(null));
                if (!doc.equals(actual))
                {
                    problems.add(simpleName + "." + f.getName()
                            + ": javadoc says " + doc + ", the constant computes " + actual);
                }
                checked++;
            }
        }

        Assertions.assertTrue(problems.isEmpty(), "javadoc disagrees with the computed value:\n  "
                + String.join("\n  ", problems));
        // Vacuity: a run that examined nothing must fail, not pass.
        Assertions.assertTrue(checked >= 200,
                "only " + checked + " constants examined -- the reader is not seeing the package");
    }

    /**
     * Every constant must equal BouncyCastle 1.86's field of the same class and
     * field name. Field names follow BouncyCastle deliberately so this
     * comparison needs no translation table.
     */
    @Test
    public void everyConstantAgreesWithBouncyCastle()
        throws Exception
    {
        List<String> problems = new ArrayList<String>();
        java.util.Set<String> aliasesSeen = new java.util.LinkedHashSet<String>();
        java.util.Set<String> unreadableSeen = new java.util.LinkedHashSet<String>();
        int checked = 0;

        for (Map.Entry<String, String> e : BC_CLASSES.entrySet())
        {
            Class<?> ours = Class.forName("org.openssl.jostle.util.asn1.oids." + e.getKey());
            Class<?> theirs = Class.forName(e.getValue());

            for (Field f : ours.getDeclaredFields())
            {
                String qualified = e.getKey() + "." + f.getName();
                if (BC_UNREADABLE.containsKey(qualified))
                {
                    unreadableSeen.add(qualified);
                    continue;
                }
                String bcName = BC_FIELD_ALIASES.get(qualified);
                if (bcName != null)
                {
                    aliasesSeen.add(qualified);
                }
                else
                {
                    bcName = f.getName();
                }
                Field bc;
                try
                {
                    bc = theirs.getField(bcName);
                }
                catch (NoSuchFieldException missing)
                {
                    problems.add(qualified + " has no field \"" + bcName + "\" in " + e.getValue());
                    continue;
                }
                String mine = idOf(f.get(null));
                String bcId = idOf(bc.get(null));
                if (!mine.equals(bcId))
                {
                    problems.add(e.getKey() + "." + f.getName()
                            + ": ours " + mine + ", BouncyCastle " + bcId);
                }
                checked++;
            }
        }

        Assertions.assertTrue(problems.isEmpty(), "disagreement with BouncyCastle 1.86:\n  "
                + String.join("\n  ", problems));
        Assertions.assertTrue(checked >= 200,
                "only " + checked + " constants compared -- the sweep is not reaching the package");

        // An alias or an exemption that matches nothing reads exactly like a
        // justified one, so every entry must have been CONSUMED this run.
        Assertions.assertEquals(BC_FIELD_ALIASES.keySet(), aliasesSeen,
                "stale or unconsumed BouncyCastle field aliases -- an entry matching no field of"
                        + " ours has outlived the constant it translated");
        Assertions.assertEquals(BC_UNREADABLE.keySet(), unreadableSeen,
                "stale BC_UNREADABLE entries -- delete any whose constant is gone");
    }

    /**
     * No dotted identifier may be written as a literal in main source outside
     * the oids package. Comments are exempt: a comment cannot hold a constant,
     * and quoting an identifier while explaining one is legitimate.
     */
    @Test
    public void noOidLiteralSurvivesOutsideTheOidsPackage()
        throws IOException
    {
        Path mainRoot = findMainRoot();
        Assertions.assertNotNull(mainRoot,
                "src/main is not reachable from the working directory ("
                        + Paths.get("").toAbsolutePath() + ") -- Gradle runs from jostle/, so "
                        + "this is a broken reader, not an absent tree; a skip here would go unread");

        List<Path> sources;
        try (Stream<Path> walk = Files.walk(mainRoot))
        {
            sources = walk.filter(p -> p.toString().endsWith(".java"))
                    .sorted()
                    .collect(Collectors.toList());
        }

        // Vacuity: a walk that found almost nothing is a broken reader, not a
        // clean tree. The count is a floor, not the exact number, so adding a
        // class does not fail the lint.
        Assertions.assertTrue(sources.size() >= 300,
                "walked only " + sources.size() + " sources under " + mainRoot
                        + " -- the lint is not reading the tree");

        List<String> violations = new ArrayList<String>();
        for (Path source : sources)
        {
            String normalised = source.toString().replace('\\', '/');
            if (normalised.contains(OIDS_PACKAGE))
            {
                continue;
            }
            List<String> lines = Files.readAllLines(source, Charset.forName("UTF-8"));
            for (int i = 0; i < lines.size(); i++)
            {
                String line = lines.get(i);
                Matcher m = LITERAL.matcher(line);
                while (m.find())
                {
                    if (inComment(line, m.start()))
                    {
                        continue;
                    }
                    violations.add(mainRoot.relativize(source) + ":" + (i + 1)
                            + "  \"" + m.group(1) + "\"");
                }
            }
        }

        Assertions.assertTrue(violations.isEmpty(),
                "object identifiers must be named by a constant in "
                        + "org.openssl.jostle.util.asn1.oids, with its source in the javadoc:\n  "
                        + String.join("\n  ", violations));
    }

    /** Source sets this lint must reach, asserted so a new one cannot go unread. */
    @Test
    public void theLintReadsEveryMainSourceSet()
        throws IOException
    {
        Path mainRoot = findMainRoot();
        Assertions.assertNotNull(mainRoot, "src/main is not reachable");

        for (String set : Arrays.asList("java", "java9", "java11", "java15", "java17", "java21", "java25"))
        {
            Path dir = mainRoot.resolve(set);
            Assertions.assertTrue(Files.isDirectory(dir),
                    "source set " + set + " is missing -- update this list, or the lint "
                            + "silently stops covering a tree");
        }
    }

    private static boolean inComment(String line, int at)
    {
        String before = line.substring(0, at);
        String trimmed = line.trim();
        if (trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("/*"))
        {
            return true;
        }
        return before.contains("//");
    }

    private static Map<String, String> documentedOids(Path source)
        throws IOException
    {
        List<String> lines = Files.readAllLines(source, Charset.forName("UTF-8"));
        Map<String, String> out = new LinkedHashMap<String, String>();
        String pending = null;
        for (String line : lines)
        {
            String trimmed = line.trim();
            if (trimmed.startsWith("*") || trimmed.startsWith("/**"))
            {
                Matcher m = DOC_OID.matcher(trimmed);
                if (m.find())
                {
                    pending = m.group(1);
                }
                continue;
            }
            int at = trimmed.indexOf("ASN1ObjectIdentifier ");
            if (at >= 0 && pending != null)
            {
                String rest = trimmed.substring(at + "ASN1ObjectIdentifier ".length());
                int end = rest.indexOf(' ');
                if (end > 0)
                {
                    out.put(rest.substring(0, end), pending);
                }
                pending = null;
            }
        }
        return out;
    }

    private static String idOf(Object oid)
        throws Exception
    {
        Method getId = oid.getClass().getMethod("getId");
        return (String) getId.invoke(oid);
    }

    private static Path findMainRoot()
    {
        return firstDirectory("src/main", "jostle/src/main");
    }

    private static Path findOidsPackage()
    {
        return firstDirectory("src/main/java/" + OIDS_PACKAGE, "jostle/src/main/java/" + OIDS_PACKAGE);
    }

    private static Path firstDirectory(String... candidates)
    {
        for (String candidate : candidates)
        {
            Path path = Paths.get(candidate);
            if (Files.isDirectory(path))
            {
                return path.toAbsolutePath().normalize();
            }
        }
        return null;
    }
}
