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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Production code names a provider by INSTANCE, not by name.
 *
 * <p>{@code UnpinnedServiceResolutionParityTest} closes "named no provider".
 * This closes the next question, "named it how" — the one that lint cannot
 * see, because it decides pinned-ness by counting arguments and a {@code
 * String} name is indistinguishable from a {@code Provider} object to it.
 *
 * <p>A name is re-resolvable. {@code removeProvider} plus {@code addProvider}
 * swaps which instance answers to it, and {@code getInstance(alg, Provider)}
 * never required registration at all. Measured on one PKITS certificate
 * before MT-99: a factory obtained from the JSL provider OBJECT returned a
 * {@code sun.security.rsa.RSAPublicKeyImpl} once the name was unregistered,
 * and returned a key its own provider then REFUSED when a second instance
 * held the name. MT-89 was the same shape at CCM parameters, MT-16 at the KTS
 * ciphers' inner wrap.
 *
 * <h2>What a green run does NOT mean</h2>
 *
 * The matcher reads the argument TEXT. A site that assigns a name to a local
 * and passes the local — {@code String p = ...; getInstance(alg, p)} — is
 * flagged (the text is not instance-shaped) rather than missed, which is the
 * safe direction; but a site that assigns a PROVIDER to a local named
 * something else is also flagged, and the fix is to add the spelling to
 * {@link #INSTANCE_SHAPED} deliberately, not to widen {@link #ALLOWED}. This
 * guard says nothing about whether the instance named is the RIGHT one; only
 * a behavioural test against a selectively-incapable instance does that.
 *
 * <h2>Scope, both decisions deliberate</h2>
 *
 * <ol>
 * <li><b>A site with no second argument is SKIPPED, not flagged.</b> That is
 *     {@code UnpinnedServiceResolutionParityTest}'s question, and it carries
 *     its own sanctions for the two unbound parameter generators. Reading a
 *     green run here as covering both is the mistake this paragraph exists to
 *     prevent.</li>
 * <li><b>The {@code verify} arm is scoped to {@code jcajce/provider/cert/}.</b>
 *     Certificate and CRL verification is the only JCA surface in this tree
 *     whose second argument is a provider, and the scope is measured rather
 *     than assumed: a bare {@code .verify(} over all of {@code src/main}
 *     matches 17 sites, of which 13 are NI calls shaped
 *     {@code verify(ref.getReference(), sigBytes)} in the six signature SPIs
 *     and their {@code javaN} copies. A new certificate wrapper outside that
 *     package needs the scope widened, and
 *     {@link #VERIFY_SITES_FLOOR} is what makes the arm fail rather than
 *     quietly cover nothing if the package moves.</li>
 * </ol>
 *
 * <p><b>Every {@link #ALLOWED} entry carries the NUMBER of sites it sanctions,
 * and the count must match exactly.</b> Too few and the sanction has outlived
 * the code it sanctioned, which reads exactly like a justified one and is how
 * an exemption list becomes folklore. Too many and a NEW name-based site has
 * taken cover under an existing entry — found while falsifying this guard:
 * turning {@code KeyAgreementKDF}'s instance resolution back to a name
 * produces a site whose text is identical to the sanctioned fallback, and a
 * presence-only check passes. A text-keyed lint cannot tell two identical
 * sites apart, so it counts them.
 */
public class ProviderInstancePinningParityTest
{
    private static final Pattern BLOCK_COMMENT = Pattern.compile("/\\*.*?\\*/", Pattern.DOTALL);
    private static final Pattern LINE_COMMENT = Pattern.compile("//[^\\n]*");

    /**
     * JCA types whose {@code getInstance} takes a provider, plus Jostle's own
     * name-resolving helper so its unbound call stays visible here.
     */
    private static final String TYPES =
            "MessageDigest|Cipher|Signature|KeyFactory|KeyPairGenerator|KeyGenerator|Mac"
                    + "|SecureRandom|AlgorithmParameters|AlgorithmParameterGenerator|KeyAgreement"
                    + "|SecretKeyFactory|CertificateFactory|CertPathBuilder|CertPathValidator"
                    + "|KeyStore|KeyManagerFactory|TrustManagerFactory"
                    + "|JostleAlgorithmParameters";

    private static final Pattern GET_INSTANCE =
            Pattern.compile("\\b(" + TYPES + ")\\s*\\.\\s*getInstance\\s*\\(");

    private static final Pattern VERIFY = Pattern.compile("\\.\\s*verify\\s*\\(");

    /** Only this package's {@code verify} takes a provider — see the scope note. */
    private static final String VERIFY_SCOPE = "/jcajce/provider/cert/";

    /** JSLKeyX509Certificate's three provider-taking verify sites, plus room. */
    private static final int VERIFY_SITES_FLOOR = 4;

    /**
     * Argument texts that ARE a provider instance. All four are measured in
     * use; adding a spelling here is a deliberate act, not a workaround for a
     * flagged site.
     */
    private static final List<String> INSTANCE_SHAPED = Collections.unmodifiableList(
            Arrays.asList("providerInstance", "ownProvider", "provider", "this",
                    // ProviderBinding holds the one fact; instance() is the
                    // instance arm of a binding, name() its unbound fallback.
                    "binding.instance()"));

    /**
     * Sanctioned name-based resolutions: key is
     * {@code <SimpleClassName>:<call>:<normalised provider argument>}. The
     * ARGUMENT is part of the key on purpose — {@code JSLKeyX509Certificate}
     * has an instance-pinned KeyFactory beside a name fallback, and a
     * class-and-type key would sanction both.
     */
    private static final Map<String, Sanction> ALLOWED = allowed();

    /** How many sites an entry sanctions, and why they are sound. */
    private static final class Sanction
    {
        private final int sites;
        /**
         * For a FALLBACK entry, the {@code <class>:<call>} that must carry an
         * instance-shaped resolution, or the reason has stopped being true.
         * Without it a one-for-one substitution — delete the instance arm,
         * keep the name arm — leaves the sanctioned count unchanged and the
         * guard blind; measured, that is exactly what the MT-99 falsification
         * did to {@code JSLKeyX509Certificate} and the count check missed it.
         *
         * <p>Named EXPLICITLY rather than derived from the entry's own key,
         * because the two are not always the same call: the block ciphers'
         * fallback goes through {@code JostleAlgorithmParameters} while their
         * bound arm calls {@code AlgorithmParameters} directly. Deriving it
         * flagged both of those correct sites — the over-firing half of the
         * both-directions rule, caught by reading every line of the sabotaged
         * run rather than only the one I expected.
         */
        private final String boundSibling;
        private final String reason;

        private Sanction(int sites, String boundSibling, String reason)
        {
            this.sites = sites;
            this.boundSibling = boundSibling;
            this.reason = reason;
        }
    }

    private static Map<String, Sanction> allowed()
    {
        Map<String, Sanction> m = new LinkedHashMap<String, Sanction>();

        // Deliberately FOREIGN: the name is the correct reference, because we
        // want whichever object answers to it rather than one of ours.
        add(m, "X509CertificateFactorySpi:CertificateFactory:\"SUN\"", 1,
                "the JDK's X.509 parser; naming SUN also stops us recursing into this factory"
                        + " when JSL sorts first in the search order");
        add(m, "ECKeyFactorySpi:KeyFactory:\"SunEC\"", 1,
                "so the encoded bytes do not vary with the caller's installed provider list");

        // MT-14's unbound realm: a directly-constructed SPI has no instance,
        // so its own provider BY NAME is the maximum pinning available. Each
        // resolves to that provider or nowhere - never to the other one.
        add(m, "JostleAlgorithmParameters:AlgorithmParameters:providerName", 1,
                "unbound realm; the cross-Jostle fallback was removed by MT-97");
        addFallback(m, "BlockCipherSpi:JostleAlgorithmParameters:blockCipherNi.providerName()", 2, "BlockCipherSpi:AlgorithmParameters",
                "unbound arm only, java and java9; the bound arm above it pins the instance");
        addFallback(m, "CCMCipherSpi:JostleAlgorithmParameters:cipherNI.providerName()", 2, "CCMCipherSpi:AlgorithmParameters",
                "unbound arm only, java and java9; the bound arm above it pins the instance");
        addFallback(m, "JSLKeyX509Certificate:KeyFactory:binding.name()", 1, "JSLKeyX509Certificate:KeyFactory",
                "reached only from the factory's public name-only constructor");
        addFallback(m, "JSLKeyX509Certificate:verify:binding.name()", 1, "JSLKeyX509Certificate:verify",
                "reached only from the factory's public name-only constructor");
        addFallback(m, "KeyAgreementKDF:MessageDigest:providerName", 1, "KeyAgreementKDF:MessageDigest",
                "reached only from the agreement SPIs' convenience constructor");
        addFallback(m, "KSServiceSPI:KeyFactory:binding.name()", 2, "KSServiceSPI:KeyFactory",
                "unbound arm only, java and java9; the KeyStore is registered by JSL alone");
        addFallback(m, "KSServiceSPI:CertificateFactory:binding.name()", 2, "KSServiceSPI:CertificateFactory",
                "unbound arm only, java and java9; the KeyStore is registered by JSL alone");
        addFallback(m, "JostleCertPathBuilderSpi:CertificateFactory:binding.name()", 1,
                "JostleCertPathBuilderSpi:CertificateFactory",
                "unbound arm only, and CertPathBuilder is registered by JSL alone, so this names"
                        + " the SPI's own provider rather than crossing to another");

        // The caller's own choice.
        add(m, "JSLKeyX509Certificate:verify:sigProvider", 2,
                "the two-argument verify overloads; the caller named a provider and we honour it");

        // Not a provider argument at all.
        add(m, "ThreadLocalSecureRandomProvider:SecureRandom:DrbgParameters.instantiation", 2,
                "SecureRandom.getInstance(String, AlgorithmParameterSpec) - the second argument is"
                        + " a spec, not a provider. Whether it should name one is the sibling"
                        + " lint's question and it already sanctions this site");

        return Collections.unmodifiableMap(m);
    }

    private static void add(Map<String, Sanction> m, String key, int sites, String reason)
    {
        m.put(key, new Sanction(sites, null, reason));
    }

    /** A fallback entry: {@code boundSibling} must pin an instance somewhere. */
    private static void addFallback(Map<String, Sanction> m, String key, int sites,
                                    String boundSibling, String reason)
    {
        m.put(key, new Sanction(sites, boundSibling, reason));
    }

    @Test
    public void everyResolvedServiceNamesItsProviderByInstance() throws IOException
    {
        List<Path> roots = mainSourceRoots();
        Assertions.assertFalse(roots.isEmpty(),
                "no production source roots found — the guard would pass vacuously");

        List<String> findings = new ArrayList<String>();
        Map<String, Integer> allowedHits = new LinkedHashMap<String, Integer>();
        java.util.Set<String> boundSites = new java.util.HashSet<String>();
        int scanned = 0;
        int considered = 0;
        int verifySites = 0;

        for (Path root : roots)
        {
            for (Path file : javaSourcesUnder(root))
            {
                scanned++;
                String cls = file.getFileName().toString().replace(".java", "");
                String code = stripComments(new String(Files.readAllBytes(file), StandardCharsets.UTF_8));
                boolean certPackage = file.toString().replace('\\', '/').contains(VERIFY_SCOPE);

                Matcher m = GET_INSTANCE.matcher(code);
                while (m.find())
                {
                    List<String> args = argumentsAt(code, m.end());
                    if (args.size() < 2)
                    {
                        // Owned by UnpinnedServiceResolutionParityTest.
                        continue;
                    }
                    considered++;
                    check(cls, m.group(1), args.get(1), findings, allowedHits, boundSites);
                }

                if (!certPackage)
                {
                    continue;
                }
                Matcher v = VERIFY.matcher(code);
                while (v.find())
                {
                    List<String> args = argumentsAt(code, v.end());
                    if (args.size() < 2)
                    {
                        continue;
                    }
                    verifySites++;
                    considered++;
                    check(cls, "verify", args.get(1), findings, allowedHits, boundSites);
                }
            }
        }

        Assertions.assertTrue(scanned > 100,
                "only " + scanned + " production sources scanned — the walk is not reaching the tree");
        Assertions.assertTrue(considered > 20,
                "only " + considered + " provider-taking calls seen — the pattern has drifted");
        Assertions.assertTrue(verifySites >= VERIFY_SITES_FLOOR,
                "the verify arm found " + verifySites + " sites under " + VERIFY_SCOPE
                        + ", fewer than the " + VERIFY_SITES_FLOOR + " known ones — the scope is"
                        + " looking in the wrong place and would report 0 findings from nowhere");

        Assertions.assertTrue(findings.isEmpty(),
                "these resolutions name their provider by NAME where an instance is reachable ("
                        + findings.size() + "):\n  " + String.join("\n  ", findings)
                        + "\n\nA name is re-resolvable: removeProvider plus addProvider swaps which"
                        + " instance answers to it, so the service can come from an instance the"
                        + " caller never asked for, and a key it decodes is then refused by the"
                        + " caller's own provider. Pass the provider the SPI belongs to, sourced"
                        + " from construction. If the site genuinely cannot, add it to ALLOWED"
                        + " with the reason.");

        List<String> miscounted = new ArrayList<String>();
        for (Map.Entry<String, Sanction> e : ALLOWED.entrySet())
        {
            Integer seen = allowedHits.get(e.getKey());
            int actual = seen == null ? 0 : seen;
            if (actual != e.getValue().sites)
            {
                miscounted.add(e.getKey() + "  sanctioned=" + e.getValue().sites
                        + " found=" + actual + "  (" + e.getValue().reason + ")");
            }
            else if (e.getValue().boundSibling != null
                    && !boundSites.contains(e.getValue().boundSibling))
            {
                miscounted.add(e.getKey() + "  sanctioned as a FALLBACK but "
                        + e.getValue().boundSibling + " pins no instance anywhere — the bound arm"
                        + " is gone, so the reason (" + e.getValue().reason + ") is no longer true");
            }
        }
        Assertions.assertTrue(miscounted.isEmpty(),
                "these ALLOWED entries do not sanction the number of sites they claim ("
                        + miscounted.size() + "):\n  " + String.join("\n  ", miscounted)
                        + "\n\nFewer means the sanction has outlived the code it sanctioned, and a"
                        + " stale sanction reads exactly like a justified one. MORE means a new"
                        + " name-based site has taken cover under an existing entry, which is the"
                        + " defect this guard exists to catch. Fix the code, or change the count"
                        + " deliberately and say why.");
    }

    private static void check(String cls, String call, String rawArg,
                              List<String> findings, Map<String, Integer> allowedHits,
                              java.util.Set<String> boundSites)
    {
        String arg = normalise(rawArg);
        if (INSTANCE_SHAPED.contains(arg))
        {
            boundSites.add(cls + ":" + call);
            return;
        }
        String key = cls + ":" + call + ":" + arg;
        if (ALLOWED.containsKey(key))
        {
            Integer seen = allowedHits.get(key);
            allowedHits.put(key, seen == null ? 1 : seen + 1);
            return;
        }
        findings.add(key);
    }

    /**
     * Collapse whitespace, and drop the argument list of a call that HAS
     * arguments so a multi-line expression keys stably. A zero-argument call
     * keeps its {@code ()}, since that is part of how the site reads.
     */
    private static String normalise(String arg)
    {
        String s = String.join(" ", arg.trim().split("\\s+"));
        int open = s.indexOf('(');
        if (open >= 0 && !s.substring(open).replaceAll("\\s", "").startsWith("()"))
        {
            s = s.substring(0, open).trim();
        }
        return s;
    }

    /** Top-level arguments of the list opening at {@code open}. */
    private static List<String> argumentsAt(String code, int open)
    {
        List<String> out = new ArrayList<String>();
        StringBuilder cur = new StringBuilder();
        int depth = 1;
        for (int i = open; i < code.length(); i++)
        {
            char c = code.charAt(i);
            if (c == '(' || c == '[')
            {
                depth++;
            }
            else if (c == ')' || c == ']')
            {
                depth--;
                if (depth == 0)
                {
                    out.add(cur.toString());
                    return out;
                }
            }
            else if (c == ',' && depth == 1)
            {
                out.add(cur.toString());
                cur.setLength(0);
                continue;
            }
            cur.append(c);
        }
        return out;
    }

    /**
     * Comments only. String literals are KEPT, unlike the sibling lint: two of
     * the sanctioned arguments ARE literals ("SUN", "SunEC"), so blanking them
     * would make those sites unkeyable. The cost is that a getInstance written
     * inside a message literal would be seen; measured, there are two such
     * literals in the tree (DSAKeyPairGenerator, SLHDSAKeyPairGenerator) and
     * neither has a second argument, so both fall into the skip above.
     */
    private static String stripComments(String body)
    {
        return LINE_COMMENT.matcher(BLOCK_COMMENT.matcher(body).replaceAll(" ")).replaceAll(" ");
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
