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
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * Every object identifier the provider answers to must answer to BOTH of its
 * lookup spellings: bare ({@code "1.2.840.113549.1.1.1"}) and JCA's
 * {@code "OID."}-prefixed form. BouncyCastle registers both, and a caller
 * holding an OID from a certificate or a CMS structure may reasonably spell it
 * either way.
 * <p>
 * Measured before this was centralised in {@code JostleProvider.putAlias}: 86
 * of 175 OIDs on JSL, and 75 of 114 on JSLFIPS, resolved by the bare spelling
 * only — {@code getInstance("OID." + oid)} threw
 * {@code NoSuchAlgorithmException}. The cause was that two {@code addAlias}
 * overloads disagreed about what an OID alias means (the
 * {@code ASN1ObjectIdentifier} one emitted both forms, the {@code String} one
 * emitted the bare form) and every caller used the {@code String} overload.
 * The same disagreement existed one layer up between the two
 * {@code addAlgorithmImplementation} overloads, for services whose PRIMARY
 * name is an OID.
 * <p>
 * <b>Discovered, not listed.</b> The OIDs come from the provider's own
 * registration table each run, so a family registered tomorrow is covered
 * without editing this test — which is the point, since the defect this
 * guards was introduced by ordinary registrations that each looked fine. A
 * hand-written list would have to be extended by exactly the person who is
 * most likely to forget.
 * <p>
 * Both spellings must also resolve to the SAME implementation: a spelling that
 * resolves somewhere else is worse than one that does not resolve at all.
 */
public class OidSpellingParityTest
{
    /**
     * Non-vacuity floor. Measured 175 on JSL; a run finding materially fewer
     * means discovery broke and the sweep is asserting nothing. The floor is
     * deliberately per-provider — JSLFIPS registers a smaller surface, so a
     * shared threshold would either pass vacuously there or fail spuriously.
     */
    private static final int MIN_OIDS = 150;

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    @Test
    public void everyOidResolvesUnderBothSpellings()
    {
        assertBothSpellings(Security.getProvider(JostleProvider.PROVIDER_NAME), MIN_OIDS);
    }

    /**
     * Shared by {@code FIPSOidSpellingParityTest}, which runs the identical
     * sweep over JSLFIPS. The two providers build their surfaces from separate
     * {@code Prov*} trees, so neither run says anything about the other.
     */
    public static void assertBothSpellings(Provider provider, int minOids)
    {
        Assertions.assertNotNull(provider, "provider not registered");

        Set<String> pairs = discoverOidServices(provider);
        Assertions.assertTrue(pairs.size() >= minOids,
                "discovery found only " + pairs.size() + " OID-named services for "
                        + provider.getName() + ", expected at least " + minOids
                        + " — the sweep is vacuous");

        List<String> bareOnly = new ArrayList<String>();
        List<String> prefixedOnly = new ArrayList<String>();
        List<String> disagree = new ArrayList<String>();

        for (String pair : pairs)
        {
            int sp = pair.indexOf(' ');
            String type = pair.substring(0, sp);
            String oid = pair.substring(sp + 1);

            Provider.Service bare = provider.getService(type, oid);
            Provider.Service prefixed = provider.getService(type, "OID." + oid);

            if (bare != null && prefixed == null)
            {
                bareOnly.add(pair);
            }
            else if (bare == null && prefixed != null)
            {
                prefixedOnly.add(pair);
            }
            else if (bare != null && !bare.getClassName().equals(prefixed.getClassName()))
            {
                disagree.add(pair + " (" + bare.getClassName()
                        + " vs " + prefixed.getClassName() + ")");
            }
        }

        Assertions.assertEquals(0, bareOnly.size(),
                provider.getName() + ": OIDs resolving by the bare spelling only, so "
                        + "getInstance(\"OID.\" + oid) throws: " + bareOnly);
        Assertions.assertEquals(0, prefixedOnly.size(),
                provider.getName() + ": OIDs resolving by the \"OID.\"-prefixed spelling "
                        + "only, so getInstance(oid) throws: " + prefixedOnly);
        Assertions.assertEquals(0, disagree.size(),
                provider.getName() + ": the two spellings resolve to DIFFERENT "
                        + "implementations: " + disagree);
    }

    /**
     * Every {@code (type, oid)} the provider mentions at all — as a primary
     * service name, or as an alias in either spelling. Collecting from all
     * three sources matters: an earlier version of this sweep read only
     * {@code Alg.Alias.} entries and therefore could not see services whose
     * primary name IS an OID, reporting the canonical spelling as missing.
     */
    private static Set<String> discoverOidServices(Provider provider)
    {
        Set<String> pairs = new TreeSet<String>();
        for (Object key : provider.keySet())
        {
            String k = (String) key;
            String rest;
            if (k.startsWith("Alg.Alias."))
            {
                rest = k.substring("Alg.Alias.".length());
            }
            else if (k.startsWith("Alg."))
            {
                continue;   // attribute entries, not services
            }
            else
            {
                rest = k;
            }

            int dot = rest.indexOf('.');
            if (dot < 0)
            {
                continue;
            }
            String type = rest.substring(0, dot);
            String name = rest.substring(dot + 1);
            if (name.startsWith("OID."))
            {
                name = name.substring("OID.".length());
            }
            if (name.matches("\\d+(\\.\\d+)+"))
            {
                pairs.add(type + " " + name);
            }
        }
        return pairs;
    }
}
