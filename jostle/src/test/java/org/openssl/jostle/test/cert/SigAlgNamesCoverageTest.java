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

package org.openssl.jostle.test.cert;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import java.lang.reflect.Method;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * {@code SigAlgNames} covers every signature OID this provider can put in a
 * certificate, and spells each one the way the JDK does.
 *
 * <p>The table is a hand-written transcription of 16 rows, and its miss
 * behaviour is SILENT: {@code nameFor} returns the OID itself, so a registered
 * algorithm absent from the table makes {@code getSigAlgName()} report
 * {@code "1.2.840.113549.1.1.11"} where every other provider reports
 * {@code "SHA256withRSA"}. Nothing fails; a caller switching on the name just
 * stops matching. That is precisely the drift a transcribed table invites.
 *
 * <p><b>Both halves are derived, not listed.</b> The OIDs come from
 * {@code getServices()} plus the provider's own alias entries, so a newly
 * registered signature algorithm is covered the day it is registered; the
 * expected spellings come from whichever JDK provider registers the same alias,
 * which cannot share a source with our table. A hand-written list on either
 * side would be a second transcription checking the first.
 */
public class SigAlgNamesCoverageTest
{
    private static final String ALIAS_PREFIX = "Alg.Alias.Signature.";

    /**
     * The rows where our spelling DELIBERATELY differs from the JDK's, mapped
     * to the JDK's spelling so the divergence is pinned from both sides.
     *
     * <p>The truncated SHA-512s are a disjoint naming domain rather than a
     * casing difference: BouncyCastle takes {@code SHA512(224)} and refuses
     * {@code SHA-512/224}, OpenSSL the exact reverse, so no single string
     * serves both and we keep our own. Recorded in the guides.
     *
     * <p>Pinning the JDK's side too is what makes this safe to sanction: a JDK
     * that MOVED to our spelling would fail here rather than leaving a
     * permanent exemption for a divergence that had gone away.
     */
    private static final Map<String, String> DIVERGENT_SPELLING = divergent();

    private static Map<String, String> divergent()
    {
        Map<String, String> m = new LinkedHashMap<String, String>();
        m.put("1.2.840.113549.1.1.15", "SHA512/224withRSA");
        m.put("1.2.840.113549.1.1.16", "SHA512/256withRSA");
        return java.util.Collections.unmodifiableMap(m);
    }


    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    @Test
    public void everyRegisteredSignatureOidIsInTheTableAndSpelledAsTheJdkDoes()
        throws Exception
    {
        Provider jsl = Security.getProvider(JostleProvider.PROVIDER_NAME);
        Assertions.assertNotNull(jsl);

        Map<String, String> ourOids = signatureOidAliases(jsl);
        Assertions.assertTrue(ourOids.size() >= 10,
                "only " + ourOids.size() + " signature OID aliases found on " + jsl.getName()
                        + " — the alias sweep is not reading the provider, and a zero-finding"
                        + " run would read as full coverage");

        Method nameFor = nameForMethod();

        Map<String, String> jdk = jdkSignatureOidAliases();
        Assertions.assertTrue(jdk.size() >= 5,
                "only " + jdk.size() + " JDK signature OID aliases found — without them this"
                        + " test compares our table against nothing");

        List<String> missing = new ArrayList<String>();
        List<String> misspelled = new ArrayList<String>();
        List<String> unusable = new ArrayList<String>();
        java.util.Set<String> divergentSeen = new java.util.LinkedHashSet<String>();
        int comparedAgainstJdk = 0;

        for (Map.Entry<String, String> e : ourOids.entrySet())
        {
            String oid = e.getKey();
            String ours = (String) nameFor.invoke(null, oid, null);
            if (oid.equals(ours))
            {
                // The silent-miss shape: the table handed the OID straight back.
                missing.add(oid + " (registered here as " + e.getValue() + ")");
                continue;
            }
            // Every entry must be a name our OWN provider answers to, which is
            // what makes arm (c) safe where there is no JDK oracle at all.
            try
            {
                java.security.Signature.getInstance(ours, jsl);
            }
            catch (java.security.NoSuchAlgorithmException noSuch)
            {
                unusable.add(oid + " -> \"" + ours + "\", which " + jsl.getName()
                        + " does not serve");
            }

            String theirs = jdk.get(oid);
            if (theirs != null)
            {
                String sanctioned = DIVERGENT_SPELLING.get(oid);
                if (sanctioned != null)
                {
                    divergentSeen.add(oid);
                    if (!sanctioned.equals(theirs))
                    {
                        misspelled.add(oid + ": the JDK now spells it \"" + theirs
                                + "\", not \"" + sanctioned + "\" — the sanctioned divergence has"
                                + " moved and must be re-decided, not re-pinned");
                    }
                    continue;
                }
                comparedAgainstJdk++;
                if (!theirs.equals(ours))
                {
                    misspelled.add(oid + ": ours \"" + ours + "\", the JDK \"" + theirs + "\"");
                }
            }
        }

        Assertions.assertTrue(missing.isEmpty(),
                "these signature OIDs are registered by " + jsl.getName() + " but absent from"
                        + " SigAlgNames, so getSigAlgName() reports the raw OID ("
                        + missing.size() + "):\n  " + String.join("\n  ", missing));
        Assertions.assertTrue(unusable.isEmpty(),
                "SigAlgNames names an algorithm this provider cannot resolve, so getSigAlgName()"
                        + " reports something Signature.getInstance rejects (" + unusable.size()
                        + "):\n  " + String.join("\n  ", unusable));
        Assertions.assertTrue(misspelled.isEmpty(),
                "SigAlgNames disagrees with the JDK's EXACT spelling, case included ("
                        + misspelled.size() + "):\n  "
                        + String.join("\n  ", misspelled));
        Assertions.assertEquals(DIVERGENT_SPELLING.keySet(), divergentSeen,
                "a sanctioned spelling divergence matched no registered OID — it has outlived the"
                        + " algorithm it sanctioned and must be deleted");
        Assertions.assertTrue(comparedAgainstJdk >= 5,
                "only " + comparedAgainstJdk + " of our OIDs were checked against a JDK provider"
                        + " — the oracle is not being reached, so the spellings are unverified");
    }

    /** {@code OID -> the algorithm it aliases}, for one provider's Signatures. */
    private static Map<String, String> signatureOidAliases(Provider p)
    {
        Map<String, String> out = new TreeMap<String, String>();
        for (Object k : p.keySet())
        {
            String key = (String) k;
            if (!key.startsWith(ALIAS_PREFIX))
            {
                continue;
            }
            String alias = key.substring(ALIAS_PREFIX.length());
            if (alias.startsWith("OID."))
            {
                alias = alias.substring(4);
            }
            if (isDottedOid(alias))
            {
                out.put(alias, String.valueOf(p.get(k)));
            }
        }
        return out;
    }

    /**
     * The same map from every provider that is NOT one of ours — the oracle.
     * First registration wins, which is JCA's own resolution order.
     */
    private static Map<String, String> jdkSignatureOidAliases()
    {
        Map<String, String> out = new LinkedHashMap<String, String>();
        for (Provider p : Security.getProviders())
        {
            if (p.getName().startsWith("JSL"))
            {
                continue;
            }
            for (Map.Entry<String, String> e : signatureOidAliases(p).entrySet())
            {
                if (!out.containsKey(e.getKey()))
                {
                    out.put(e.getKey(), e.getValue());
                }
            }
        }
        return out;
    }

    private static boolean isDottedOid(String s)
    {
        if (s.isEmpty() || !Character.isDigit(s.charAt(0)) || s.indexOf('.') < 0)
        {
            return false;
        }
        for (int i = 0; i != s.length(); i++)
        {
            char c = s.charAt(i);
            if (c != '.' && (c < '0' || c > '9'))
            {
                return false;
            }
        }
        return true;
    }

    /** SigAlgNames is package-private; the certificate is its only public route. */
    private static Method nameForMethod() throws Exception
    {
        Class<?> c = Class.forName("org.openssl.jostle.jcajce.provider.cert.SigAlgNames");
        Method m = c.getDeclaredMethod("nameFor", String.class, byte[].class);
        m.setAccessible(true);
        return m;
    }

    /**
     * A genuinely FOREIGN OID — one this provider does not register — still
     * falls back to the dotted form, which is what the JDK does for an
     * algorithm it does not know. The fallback is the table's contract for
     * unknown input, not a symptom of a missing row, so it is pinned
     * separately from the coverage assertion above.
     */
    @Test
    public void anUnregisteredOidFallsBackToItsDottedForm() throws Exception
    {
        Provider jsl = Security.getProvider(JostleProvider.PROVIDER_NAME);
        String foreign = "1.2.3.4.5.6.7.8.9";
        Assertions.assertFalse(signatureOidAliases(jsl).containsKey(foreign),
                "vacuity guard: the probe OID must genuinely be one we do not register");

        Assertions.assertEquals(foreign, nameForMethod().invoke(null, foreign, null),
                "an unknown OID must come back as itself");
        Assertions.assertNull(nameForMethod().invoke(null, null, null),
                "a null OID must stay null rather than becoming the string \"null\"");
    }
}
