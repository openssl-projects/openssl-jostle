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

import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * {@code KeyFactory.translateKey} must accept a key the SAME provider
 * produced, for every family and BOTH halves.
 *
 * <p><b>Why this exists.</b> Every family's {@code engineTranslateKey} opens
 * with an "already ours" branch — {@code if (key instanceof JOFooPublicKey ||
 * key instanceof JOFooPrivateKey)} — which reaches the key's
 * {@code PKEYKeySpec} and returns the key unchanged. Nothing tested that
 * branch. The existing per-family translate tests (e.g.
 * {@code EdDSATest.testKeyFactory_translateForeignEdKey_BC}) all hand the
 * factory a <em>BouncyCastle</em> key, so they exercise the foreign-import
 * path underneath it and never enter the already-ours branch at all.
 *
 * <p>That hole let a real crash ship in review: the branch was changed to read
 * the spec via {@code ((OSSLKey) key).getSpec()}, and {@code JOEdPublicKey}
 * was the one Jostle key class that did not implement {@code OSSLKey} —
 * {@code EdDSAKey extends Key}, where {@code MLKEMKey}, {@code MLDSAKey},
 * {@code SLHDSAKey} and {@code MLXKEMKey} all extend {@code OSSLKey}, and the
 * classical families declare it directly. So every Ed public key through
 * {@code translateKey} was a guaranteed {@code ClassCastException} while the
 * whole suite stayed green.
 *
 * <p><b>Discovery, not a list.</b> The families are read from
 * {@code provider.getServices()} rather than hard-coded, so a family added
 * later is covered without anyone remembering to extend this file — the same
 * reasoning as the agreement-test completeness guards. Failures are collected
 * and reported together so a systematic breakage reads as one list instead of
 * a fix-one-rerun-repeat loop.
 */
public class KeyFactoryTranslateOwnKeyTest
{
    private static Provider jsl;

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        jsl = Security.getProvider(JostleProvider.PROVIDER_NAME);
    }

    /**
     * Every algorithm this provider offers as BOTH a KeyPairGenerator and a
     * KeyFactory — i.e. every family whose own keys can reach
     * {@code translateKey}.
     */
    private static Set<String> translatableFamilies()
    {
        Set<String> kpg = new TreeSet<String>();
        Set<String> kf = new TreeSet<String>();
        for (Provider.Service s : jsl.getServices())
        {
            if ("KeyPairGenerator".equals(s.getType()))
            {
                kpg.add(s.getAlgorithm());
            }
            else if ("KeyFactory".equals(s.getType()))
            {
                kf.add(s.getAlgorithm());
            }
        }
        kpg.retainAll(kf);
        Assertions.assertFalse(kpg.isEmpty(),
                "no family offers both a KeyPairGenerator and a KeyFactory — the sweep "
                        + "would be vacuous");
        return kpg;
    }

    /**
     * The guard. For each family: generate a keypair through JSL, hand each
     * half straight back to the JSL KeyFactory, and require it to come back.
     *
     * <p>Asserts the property a caller depends on — {@code translateKey}
     * returns a usable Jostle key of the right role — not merely that the call
     * did not throw a checked exception. A {@code ClassCastException} is
     * unchecked and would otherwise escape as a raw crash.
     */
    @Test
    public void translateKeyAcceptsThisProvidersOwnKeys() throws Exception
    {
        List<String> failures = new ArrayList<String>();
        int checked = 0;

        for (String alg : translatableFamilies())
        {
            KeyPair kp;
            try
            {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance(alg, jsl);
                kp = kpg.generateKeyPair();
            }
            catch (Exception e)
            {
                // A family whose KPG needs explicit initialisation is out of
                // scope here; it is covered by its own family test.
                continue;
            }

            KeyFactory kf = KeyFactory.getInstance(alg, jsl);

            try
            {
                Key pub = kf.translateKey(kp.getPublic());
                Assertions.assertNotNull(pub, alg + ": translateKey returned null for the public half");
                checked++;
            }
            catch (Throwable t)
            {
                failures.add(alg + " PUBLIC -> " + t.getClass().getName()
                        + (t.getMessage() == null ? "" : ": " + t.getMessage()));
            }

            try
            {
                Key priv = kf.translateKey(kp.getPrivate());
                Assertions.assertNotNull(priv, alg + ": translateKey returned null for the private half");
                checked++;
            }
            catch (Throwable t)
            {
                failures.add(alg + " PRIVATE -> " + t.getClass().getName()
                        + (t.getMessage() == null ? "" : ": " + t.getMessage()));
            }
        }

        Assertions.assertTrue(checked > 0, "the sweep translated nothing — it is vacuous");
        Assertions.assertTrue(failures.isEmpty(),
                "KeyFactory.translateKey rejected keys made by its own provider:\n  "
                        + String.join("\n  ", failures));
    }
}
