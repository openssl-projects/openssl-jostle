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
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * MT-72b: an OID that JSL serves must also be served by JSLFIPS wherever JSLFIPS
 * serves the same algorithm under its NAME.
 *
 * <h2>The gap this exists to close</h2>
 *
 * <p>{@code OidSpellingParityTest} and {@code FIPSOidSpellingParityTest} compare
 * the bare and {@code OID.}-prefixed spellings <b>within one provider</b>.
 * Nothing compared the OID SET of one provider against the other, so a
 * registration added to {@code ProvAES} and not to {@code ProvFIPSAES} was
 * invisible to the whole guard family — which is exactly what happened to the
 * AES-CCM and PBKDF2 OIDs in commit {@code 81fe329}.
 *
 * <h2>Why "where JSLFIPS serves the algorithm by name" is the right condition</h2>
 *
 * <p>The two providers legitimately serve different algorithm SETS — the FIPS
 * module decides what is fetchable, so ChaCha20, OCB and the memory-hard KDFs
 * are absent from JSLFIPS by design. Requiring OID parity outright would fail on
 * every one of those. The defect being caught is narrower and sharper: JSLFIPS
 * serves the algorithm, a caller can reach it by NAME, and cannot reach it by
 * the OID that CMS and PKCS#8 actually resolve with.
 */
public class FIPSOidCrossProviderParityTest
{
    /**
     * Vacuity floor. JSL carries ~175 OID-addressable names and JSLFIPS serves
     * most of the same algorithms, so a run that considers fewer than this has
     * a broken discovery rather than a clean surface.
     */
    private static final int MIN_PAIRS_CONSIDERED = 40;

    /**
     * Pinned exceptions: an OID JSL serves, whose algorithm JSLFIPS also serves
     * by name, that JSLFIPS deliberately does NOT serve by OID. Each entry needs
     * a measured reason. Empty today — every known case is a defect, not a
     * decision.
     */
    private static final Set<String> PINNED = Collections.unmodifiableSet(new TreeSet<String>());

    private static Provider jsl;
    private static Provider fips;

    @BeforeAll
    public static void setUp()
    {
        fips = FIPSTestUtil.assumeFipsProvider();
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        jsl = Security.getProvider(JostleProvider.PROVIDER_NAME);
    }

    @Test
    public void everyJslOidIsServedByFipsWhereFipsServesTheAlgorithm()
    {
        // A Set, not a List: the bare and OID.-prefixed spellings of one alias
        // are two property entries for the SAME (type, OID) row.
        Set<String> missing = new TreeSet<String>();
        Set<String> stale = new TreeSet<String>();
        Set<String> seen = new TreeSet<String>();
        int considered = 0;

        // ---- Arm A: OIDs registered as ALIASES.
        //
        // The primary comes from the PROPERTY VALUE, not from
        // getService(...).getAlgorithm(): JostleProvider.getService is custom and
        // returns a Service whose algorithm is the name you ASKED for, so the
        // alias -> primary link is invisible through it. Measured, and it is why
        // the first version of this guard passed against a tree with four known
        // missing rows.
        for (Map.Entry<Object, Object> e : jsl.entrySet())
        {
            String k = String.valueOf(e.getKey());
            if (!k.startsWith("Alg.Alias."))
            {
                continue;
            }
            String rest = k.substring("Alg.Alias.".length());
            int dot = rest.indexOf('.');
            if (dot < 0)
            {
                continue;
            }
            String type = rest.substring(0, dot);
            String oid = stripOidPrefix(rest.substring(dot + 1));
            if (!isOid(oid))
            {
                continue;
            }
            String primary = String.valueOf(e.getValue());
            if (isOid(primary))
            {
                continue;   // self-alias of an OID primary; Arm B judges those
            }
            if (fips.getService(type, primary) == null)
            {
                continue;   // JSLFIPS does not serve the algorithm at all
            }
            if (seen.add(type + " " + oid))
            {
                considered++;
                record(type, oid, primary, missing, stale);
            }
        }

        // ---- Arm B: OIDs registered as PRIMARIES.
        //
        // There is no algorithm NAME to compare, so the link is the SPI class:
        // if JSLFIPS registers any service of the same type backed by the same
        // class, it implements that family and should answer the OID.
        Map<String, Set<String>> fipsClasses = new TreeMap<String, Set<String>>();
        for (Provider.Service s : fips.getServices())
        {
            fipsClasses.computeIfAbsent(s.getType(), x -> new TreeSet<String>()).add(s.getClassName());
        }
        for (Provider.Service s : jsl.getServices())
        {
            String oid = s.getAlgorithm();
            if (!isOid(oid))
            {
                continue;
            }
            Set<String> classes = fipsClasses.get(s.getType());
            if (classes == null || !classes.contains(s.getClassName()))
            {
                continue;   // JSLFIPS has no service of this type backed by that SPI
            }
            if (seen.add(s.getType() + " " + oid))
            {
                considered++;
                record(s.getType(), oid, shortName(s.getClassName()), missing, stale);
            }
        }

        Assertions.assertTrue(considered >= MIN_PAIRS_CONSIDERED,
                "VACUOUS: only " + considered + " (type, OID) pairs were considered, expected at least "
                        + MIN_PAIRS_CONSIDERED + " - discovery is broken, not the surface");

        Assertions.assertTrue(stale.isEmpty(),
                "PINNED lists rows JSLFIPS now serves; delete them:\n  " + String.join("\n  ", stale));

        Assertions.assertTrue(missing.isEmpty(),
                "JSLFIPS serves these algorithms but not by the OID that CMS / PKCS#8 resolves with ("
                        + missing.size() + " of " + considered + " considered):\n  "
                        + String.join("\n  ", missing));
    }

    /**
     * NEGATIVE CONTROL for Arm B, pinned rather than remembered.
     *
     * <p>Arm B links an OID primary to JSLFIPS by SPI CLASS, which is a looser
     * link than a name. If it over-fired, every OID backed by a widely-used SPI
     * would be reported. {@code id-aes128-GCM} is the discriminating case: it is
     * an OID primary backed by {@code AESBlockCipherSpi} — a class JSLFIPS uses
     * for many services — and JSLFIPS DOES serve the OID. It must therefore be
     * considered and found present, never reported.
     */
    @Test
    public void armBDoesNotOverFireOnAnOidBothProvidersServe()
    {
        String gcm = "2.16.840.1.101.3.4.1.6";
        Provider.Service jslSvc = jsl.getService("Cipher", gcm);
        Assertions.assertNotNull(jslSvc, "precondition: JSL serves Cipher " + gcm);
        Assertions.assertEquals("AESBlockCipherSpi", shortName(jslSvc.getClassName()),
                "precondition: the control must be backed by a widely-shared SPI, or it controls nothing");
        Assertions.assertNotNull(fips.getService("Cipher", gcm),
                "JSLFIPS serves this OID, so the cross-provider guard must not report it");
    }

    private void record(String type, String oid, String via, Set<String> missing, Set<String> stale)
    {
        String row = type + " " + oid;
        boolean served = fips.getService(type, oid) != null;
        if (PINNED.contains(row))
        {
            if (served)
            {
                stale.add(row);
            }
            return;
        }
        if (!served)
        {
            missing.add(row + "   (JSLFIPS serves " + via + ")");
        }
    }

    private static String shortName(String className)
    {
        return className.substring(className.lastIndexOf('.') + 1);
    }

    private static boolean isOid(String s)
    {
        return s.matches("\\d+(\\.\\d+)+");
    }

    private static String stripOidPrefix(String name)
    {
        return name.startsWith("OID.") ? name.substring("OID.".length()) : name;
    }

}
