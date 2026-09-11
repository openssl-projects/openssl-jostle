/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.provider;

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
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Source-level parity guard: inside {@code jcajce/provider/**}, a JCA
 * {@code getInstance} for a CRYPTOGRAPHIC service must name a provider, and
 * must not hard-code {@code JostleProvider.PROVIDER_NAME}.
 *
 * <h2>Why this cannot be a behavioural test</h2>
 *
 * SHA-256 is SHA-256 whoever computes it, and JSL's AES-KW produces the same
 * bytes as JSLFIPS's. So every round-trip and every BouncyCastle-agreement
 * test passes identically whether the work happened inside the FIPS module or
 * in SUN. {@code FIPSModuleIsActuallyUsedTest} cannot reach it either: that
 * sweeps {@code getServices()} and asks OpenSSL which provider implements each
 * registered NAME, and it cannot see a provider resolved inside an SPI body.
 * A structural lint is the only falsifiable guard for this property — the same
 * reasoning as {@code FIPSLibraryLookupParityTest} and
 * {@code NativeReferenceParityTest}.
 *
 * <h2>What it caught (MT-5)</h2>
 *
 * Two shapes, both live:
 * <ol>
 * <li><b>No provider at all.</b> {@code MessageDigest.getInstance(name)} in
 *     {@code MLKEMKTSCipherSpi}, {@code RSAKEMCipherSpi} and — the one the
 *     work item had not spotted — {@code KeyAgreementKDF}, whose X9.42/X9.63
 *     KDF derives the KEK from a DH/ECDH shared secret and is reached from
 *     JSLFIPS-registered key agreements. JCA resolves those against the
 *     installed provider list in order, normally SUN.</li>
 * <li><b>The WRONG provider, explicitly.</b>
 *     {@code Cipher.getInstance(oid, JostleProvider.PROVIDER_NAME)} for the
 *     AES key wrap in both KTS ciphers — classes that serve BOTH providers, so
 *     a JSLFIPS wrap key-wrapped the CEK in the base library.</li>
 * </ol>
 *
 * <h2>Scope</h2>
 *
 * {@code AlgorithmParameters} is exempt BY TYPE, not by file: it encodes and
 * decodes public ASN.1 parameters and performs no cryptography, so there is no
 * operation for a module to own. If an {@code AlgorithmParameters} ever does
 * cryptography it is misnamed, and that is the bug to fix.
 */
public class ProviderPinningParityTest
{
    /** JCA types whose {@code getInstance} performs or keys cryptography. */
    private static final String CRYPTO_TYPES =
            "MessageDigest|Mac|Cipher|SecretKeyFactory|KeyFactory|KeyAgreement"
                    + "|Signature|KeyGenerator|KeyPairGenerator|SecureRandom"
                    + "|AlgorithmParameters";

    private static final Pattern CALL = Pattern.compile(
            "\\b(" + CRYPTO_TYPES + ")\\s*\\.\\s*getInstance\\s*\\(([^;]*?)\\)", Pattern.DOTALL);

    private static final Pattern BLOCK_COMMENT = Pattern.compile("/\\*.*?\\*/", Pattern.DOTALL);
    private static final Pattern LINE_COMMENT = Pattern.compile("//[^\\n]*");
    /** Handles escaped quotes, so a literal containing \" does not run on. */
    private static final Pattern STRING_LITERAL = Pattern.compile("\"(\\\\.|[^\"\\\\])*\"");

    /**
     * Sanctioned exceptions, each with the reason it is sound. An entry here
     * is a claim that the pin is CORRECT, not that the check is inconvenient.
     */
    /**
     * File-level exemptions. EMPTY since 2026-09-11: {@code KSServiceSPI.java}
     * was the only entry, on the grounds that "JSL-only by construction, so
     * naming JSL is correct here". That answered WHICH provider and not
     * name-versus-instance, and the gap it left was measurable — a KeyStore
     * obtained from the JSL provider OBJECT could not read back its own
     * entries once the name was unregistered. The SPI now carries the
     * instance, so the exemption is gone rather than reworded.
     */
    private static final Set<String> EXEMPT_FILES = Collections.<String>emptySet();

    /**
     * Sites that legitimately name NO provider, keyed
     * {@code <SimpleClassName>:<type>} so a carve-out cannot widen to a file.
     *
     * <p>{@code AlgorithmParameters} used to be exempt BY TYPE here, on the
     * grounds that it is ASN.1 codec work rather than cryptography. True, and
     * it is also why MT-89's cross-provider CCM crossing was invisible to this
     * guard. The type is now in scope; measured, the exemption was covering
     * exactly these two sites and nothing else.
     */
    private static final Set<String> ALLOWED_UNPINNED =
            Collections.unmodifiableSet(new HashSet<String>(Arrays.asList(
                    // MT-14's unbound realm, reached only from the generators'
                    // null-provider constructors: there is no instance to pin
                    // and the objects are public parameter codecs carrying no
                    // key material. UnpinnedServiceResolutionParityTest owns
                    // the sanction and records the measurement.
                    "DHAlgorithmParameterGenerator:AlgorithmParameters",
                    "DSAAlgorithmParameterGenerator:AlgorithmParameters")));

    /**
     * Sites that legitimately hard-code the base provider's NAME, same key
     * shape. Each is an unbound-realm FALLBACK sitting beside an
     * instance-pinned arm, and
     * {@code ProviderInstancePinningParityTest} owns them: it counts the
     * sanctioned sites and additionally requires the bound arm to still
     * exist, which a file-level exemption here could not do. That is why
     * {@code KSServiceSPI.java} is no longer exempt as a file.
     */
    private static final Set<String> ALLOWED_BASE_NAME =
            Collections.unmodifiableSet(new HashSet<String>(Arrays.asList(
                    "KSServiceSPI:KeyFactory")));

    @Test
    public void everyCryptoGetInstanceNamesItsOwnProvider()
    {
        List<Path> roots = providerSourceRoots();
        Assumptions.assumeFalse(roots.isEmpty(),
                "no provider source root reachable from " + Paths.get("").toAbsolutePath()
                        + " — this guard is a source-level lint and is skipped, not failed, "
                        + "when there is no source tree to read");

        List<String> unpinned = new ArrayList<String>();
        List<String> hardPinned = new ArrayList<String>();
        int scanned = 0;
        int callsChecked = 0;

        for (Path root : roots)
        {
            for (Path source : javaSourcesUnder(root))
            {
                String name = source.getFileName().toString();
                if (EXEMPT_FILES.contains(name))
                {
                    continue;
                }
                scanned++;

                String code = stripComments(read(source));
                Matcher m = CALL.matcher(code);
                while (m.find())
                {
                    callsChecked++;
                    String args = m.group(2);
                    String where = name + ":" + (code.substring(0, m.start()).split("\n", -1).length)
                            + "  " + m.group(1) + ".getInstance(" + oneLine(args) + ")";

                    if (args.contains("JostleProvider.PROVIDER_NAME"))
                    {
                        if (!ALLOWED_BASE_NAME.contains(name.replace(".java", "") + ":" + m.group(1)))
                        {
                            hardPinned.add(where);
                        }
                    }
                    else if (!namesAProvider(args)
                            && !ALLOWED_UNPINNED.contains(name.replace(".java", "") + ":" + m.group(1)))
                    {
                        unpinned.add(where);
                    }
                }
            }
        }

        Assertions.assertTrue(scanned > 30,
                "only " + scanned + " provider sources scanned — the guard is not looking where "
                        + "it thinks and would pass vacuously");
        Assertions.assertTrue(callsChecked > 5,
                "only " + callsChecked + " getInstance calls seen — the pattern has probably drifted");

        Assertions.assertTrue(unpinned.isEmpty(),
                "these getInstance calls name NO provider, so JCA resolves them against the "
                        + "installed provider list — normally SUN. Under JSLFIPS that performs "
                        + "the operation outside the FIPS module, and no behavioural test can "
                        + "see it. Pass the provider the SPI belongs to, sourced from "
                        + "construction:\n  " + String.join("\n  ", unpinned));

        Assertions.assertTrue(hardPinned.isEmpty(),
                "these getInstance calls hard-code JostleProvider.PROVIDER_NAME. A class that "
                        + "serves BOTH providers names the wrong one for half its instances — "
                        + "a JSLFIPS operation performed in the base library. Take the provider "
                        + "name by constructor, as the NI already is:\n  "
                        + String.join("\n  ", hardPinned));
    }

    /** Does the argument list name a provider (a String or a Provider object)? */
    private static boolean namesAProvider(String args)
    {
        int depth = 0;
        int commas = 0;
        for (int i = 0; i != args.length(); i++)
        {
            char c = args.charAt(i);
            if (c == '(' || c == '[')
            {
                depth++;
            }
            else if (c == ')' || c == ']')
            {
                depth--;
            }
            else if (c == ',' && depth == 0)
            {
                commas++;
            }
        }
        // getInstance(algorithm) is one argument; every provider-naming
        // overload takes a second.
        return commas >= 1;
    }

    /**
     * Strip comments AND string literals before matching.
     *
     * <p>Both are load-bearing, and both were learned by getting it wrong.
     * Javadoc explaining a provider boundary reads exactly like code crossing
     * it. And an exception message such as
     * {@code "use KeyFactory.getInstance(\"DSA\")"} is source text that looks
     * like an unpinned call but is a string — the first version of this lint
     * flagged {@code DSAKeyPairGenerator} and {@code SLHDSAKeyPairGenerator}
     * for exactly that, and a guard that cries wolf gets exempted into
     * uselessness.
     */
    private static String stripComments(String body)
    {
        String noComments = LINE_COMMENT.matcher(
                BLOCK_COMMENT.matcher(body).replaceAll(" ")).replaceAll(" ");
        return STRING_LITERAL.matcher(noComments).replaceAll("\"\"");
    }

    private static String oneLine(String s)
    {
        String j = s.replaceAll("\\s+", " ").trim();
        return j.length() > 70 ? j.substring(0, 70) + "..." : j;
    }

    private static List<Path> providerSourceRoots()
    {
        String pkg = "org/openssl/jostle/jcajce/provider";
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
