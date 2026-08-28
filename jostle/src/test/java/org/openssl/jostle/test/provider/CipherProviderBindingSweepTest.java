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

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * MT-10, wiring half: EVERY registered Cipher whose {@code engineUnwrap} can
 * reconstruct an asymmetric key must carry the provider instance that
 * registered it.
 *
 * <h2>Why the behavioural tests are not enough</h2>
 *
 * {@link UnwrappedKeyBindingTest} drives three transformations, which proves
 * the MECHANISM in all three SPI classes. It says nothing about the other
 * sixty-odd registration sites: one {@code Prov*} lambda that forgot its
 * {@code provider} argument produces an SPI that fails only when somebody
 * actually unwraps an asymmetric key through THAT transformation. Nothing in
 * the suite does, so the miss would sit there.
 *
 * <p>This is the MT-14 {@code ProvFIPSXDH} lesson in cipher clothing: two
 * registrations kept the old constructor through the flip, and the symptom
 * appeared several files from the cause. Enumeration is the answer — a longer
 * hand list would have the same blind spot, one entry further along.
 *
 * <p>So this sweep asks the provider what it registered rather than being
 * told. It constructs each Cipher service and inspects the SPI. End-to-end
 * unwrap through all of them is unnecessary: the behavioural tests prove the
 * mechanism, this proves the wiring.
 *
 * <h2>Classification</h2>
 *
 * An SPI is only required to be bound if it can actually return an asymmetric
 * key, so the sweep first asks whether the class overrides
 * {@code engineUnwrap} at all. Those that do not (CCM, for one) inherit
 * {@code CipherSpi}'s {@code UnsupportedOperationException} and have no
 * surface to protect.
 *
 * <p>An overriding class the sweep does not recognise is a FAILURE, not a
 * skip. A new unwrapping Cipher must be classified deliberately — defaulting
 * to "probably fine" is how the original defect survived.
 */
public class CipherProviderBindingSweepTest
{
    /**
     * Classes that override {@code engineUnwrap} and are deliberately NOT
     * required to carry a provider instance. An entry is a claim with a
     * reason, not a way to quieten the sweep.
     *
     * <p>Both entries are the KTS ciphers, and their reason is the same: they
     * do not reconstruct a key themselves. They derive a KEK and delegate the
     * whole unwrap — {@code wrappedKeyType} included, so the asymmetric arms
     * do reach it — to an inner AES key-wrap {@code Cipher} obtained as
     * {@code Cipher.getInstance(oid, providerName)}. MT-5 pinned that lookup
     * by NAME, so their asymmetric-unwrap surface is name-pinned rather than
     * instance-pinned.
     *
     * <p><b>That is a narrower version of the same gap MT-10 closes, recorded
     * rather than fixed.</b> Converting MT-5's name pins to instance pins is a
     * separate decision with its own blast radius (it also moves the KDF
     * digest lookups), and it is logged as a follow-up in
     * {@code reviews/STATUS.md}. It is not silently blessed: this comment is
     * the record, and removing an entry from here is how the follow-up gets
     * closed.
     */
    private static final Set<String> NAME_PINNED_BY_MT5 = Collections.unmodifiableSet(
            new HashSet<String>(Arrays.asList(
                    "RSAKEMCipherSpi",
                    "MLKEMKTSCipherSpi")));

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

    @Test
    public void everyRegisteredUnwrappingCipherIsBoundToItsProvider() throws Exception
    {
        // Measured 48 / 45 today; the floors leave headroom for registration
        // churn while still failing loudly if the sweep stops finding things.
        sweep(jsl, 40, 40);
    }

    // -----------------------------------------------------------------
    // shared with the FIPS twin
    // -----------------------------------------------------------------

    /**
     * Runs the sweep over one provider. Public and static so
     * {@code FIPSCipherProviderBindingSweepTest} drives the identical logic
     * against JSLFIPS — the two providers register different sets through
     * different {@code Prov*} files, so a defect in one is invisible to the
     * other.
     */
    public static void sweep(Provider provider, int minCipherServices, int minBound)
        throws Exception
    {
        List<String> unbound = new ArrayList<String>();
        List<String> unclassified = new ArrayList<String>();
        List<String> unconstructible = new ArrayList<String>();
        Set<String> namePinned = new TreeSet<String>();
        int cipherServices = 0;
        int unwrapping = 0;
        int bound = 0;

        for (Provider.Service svc : provider.getServices())
        {
            if (!"Cipher".equals(svc.getType()))
            {
                continue;
            }
            cipherServices++;

            Object spi;
            try
            {
                spi = svc.newInstance(null);
            }
            catch (Exception e)
            {
                unconstructible.add(svc.getAlgorithm() + " (" + e + ")");
                continue;
            }

            if (!overridesEngineUnwrap(spi.getClass()))
            {
                continue;
            }
            unwrapping++;

            String simpleName = spi.getClass().getSimpleName();

            //
            // The explicit classification is consulted FIRST, and that
            // ordering is load-bearing. Both KTS ciphers happen to hold a
            // bound RSAKeyFactorySpi, so shape detection reported them as
            // bound — while the field governing their UNWRAP is the inner
            // Cipher they resolve by provider NAME. Sniffing a shape that is
            // not the one in the path is exactly the matcher trap the guides
            // warn about, and the first version of this sweep fell into it:
            // it printed namePinned=[] and counted both as fine.
            //
            if (NAME_PINNED_BY_MT5.contains(simpleName))
            {
                namePinned.add(simpleName);
                continue;
            }

            Binding b = bindingOf(spi);
            if (!b.recognised)
            {
                unclassified.add(svc.getAlgorithm() + " -> " + spi.getClass().getName());
                continue;
            }

            if (b.provider != provider)
            {
                unbound.add(provider.getName() + " / " + svc.getAlgorithm() + " -> " + simpleName
                        + " carries " + (b.provider == null ? "no provider" : b.provider.getName()));
            }
            else
            {
                bound++;
            }
        }

        Assertions.assertTrue(unconstructible.isEmpty(),
                "these Cipher services could not be constructed, so the sweep could not inspect "
                        + "them:\n  " + String.join("\n  ", unconstructible));

        Assertions.assertTrue(unclassified.isEmpty(),
                "these Cipher SPIs override engineUnwrap but the sweep does not know how they "
                        + "record their provider. A new unwrapping Cipher must be classified "
                        + "deliberately: either give it a providerInstance field / a bound "
                        + "KeyFactory, or add it to NAME_PINNED_BY_MT5 with the reason it is "
                        + "sound:\n  " + String.join("\n  ", unclassified));

        Assertions.assertTrue(unbound.isEmpty(),
                "these registrations do not pass their provider instance, so an asymmetric "
                        + "unwrap through them reconstructs the key via JCA order (MT-10). Audit "
                        + "the matching new <Spi>(...) in the Prov class for a trailing provider "
                        + "argument:\n  " + String.join("\n  ", unbound));

        // Non-vacuity. Without these the sweep passes just as happily when
        // getServices() returns nothing or when the engineUnwrap probe stops
        // matching, which is the failure mode a structural guard is prone to.
        System.out.println(provider.getName() + " sweep: cipherServices=" + cipherServices
                + " unwrapping=" + unwrapping + " bound=" + bound + " namePinned=" + namePinned);
        Assertions.assertTrue(cipherServices >= minCipherServices,
                provider.getName() + ": only " + cipherServices + " Cipher services seen (expected "
                        + "at least " + minCipherServices + ") — the sweep is not looking where it "
                        + "thinks");
        Assertions.assertTrue(bound >= minBound,
                provider.getName() + ": only " + bound + " bound SPIs seen out of " + unwrapping
                        + " unwrapping ones (expected at least " + minBound + "); the rest were "
                        + namePinned);
    }

    /**
     * Does {@code type}, or any ancestor below {@code javax.crypto.CipherSpi},
     * declare {@code engineUnwrap}? Only such a class can return a key at all.
     */
    private static boolean overridesEngineUnwrap(Class<?> type)
    {
        for (Class<?> c = type; c != null && c != javax.crypto.CipherSpi.class; c = c.getSuperclass())
        {
            for (Method m : c.getDeclaredMethods())
            {
                if ("engineUnwrap".equals(m.getName()) && m.getParameterTypes().length == 3)
                {
                    return true;
                }
            }
        }
        return false;
    }

    /** {@code recognised} separates "no such shape" from "shape present, value null". */
    private static final class Binding
    {
        private final boolean recognised;
        private final Provider provider;

        private Binding(boolean recognised, Provider provider)
        {
            this.recognised = recognised;
            this.provider = provider;
        }
    }

    /**
     * The two shapes an unwrapping SPI uses to record its provider.
     *
     * <p>Read by reflection deliberately: {@code BlockCipherSpi} is
     * package-private and {@code ownProviderInstance()} is package-private in
     * {@code provider.rsa}, so a test outside those packages cannot name
     * either. Matching on the shape rather than the type also means a future
     * SPI that follows either convention is covered with no edit here.
     */
    private static Binding bindingOf(Object spi) throws Exception
    {
        // Shape 1: a Provider field named providerInstance (BlockCipherSpi
        // and everything that extends it).
        for (Class<?> c = spi.getClass(); c != null; c = c.getSuperclass())
        {
            for (Field f : c.getDeclaredFields())
            {
                if ("providerInstance".equals(f.getName())
                        && Provider.class.isAssignableFrom(f.getType()))
                {
                    f.setAccessible(true);
                    return new Binding(true, (Provider) f.get(spi));
                }
            }
        }

        // Shape 2: a bound KeyFactory SPI exposing ownProviderInstance()
        // (RSAOAEPCipherSpi, RSAPKCS1CipherSpi).
        for (Class<?> c = spi.getClass(); c != null; c = c.getSuperclass())
        {
            for (Field f : c.getDeclaredFields())
            {
                if (!"keyFactory".equals(f.getName()))
                {
                    continue;
                }
                f.setAccessible(true);
                Object kf = f.get(spi);
                if (kf == null)
                {
                    continue;
                }
                Method m = kf.getClass().getDeclaredMethod("ownProviderInstance");
                m.setAccessible(true);
                return new Binding(true, (Provider) m.invoke(kf));
            }
        }

        return new Binding(false, null);
    }
}
