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
     * <p><b>Empty since MT-16, and that is the whole point of it.</b> It held
     * the two KTS ciphers, {@code RSAKEMCipherSpi} and
     * {@code MLKEMKTSCipherSpi}: they reconstruct no key themselves but
     * delegate the whole unwrap — {@code wrappedKeyType} included, so the
     * asymmetric arms do reach it — to an inner AES key-wrap {@code Cipher},
     * which MT-5 obtained as {@code Cipher.getInstance(oid, providerName)}.
     * MT-16 converted that pin, and the KDF digest beside it, to the provider
     * INSTANCE, so both now satisfy the ordinary bound-KeyFactory shape and
     * the sweep enforces them like everything else.
     *
     * <p>The set stays, empty, for the next such class — and the branch that
     * consults it stays FIRST, for the reason recorded at that branch.
     */
    private static final Set<String> NAME_PINNED_BY_MT5 = Collections.unmodifiableSet(
            new HashSet<String>(Arrays.<String>asList()));

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
        sweep(jsl, 40, 45);
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
            // ordering is load-bearing even now the set is empty. Both KTS
            // ciphers held a bound RSAKeyFactorySpi while their UNWRAP still
            // ran through a name-resolved inner Cipher, so shape detection
            // reported them bound on a field that was not in the path — the
            // matcher trap the guides warn about, which the first version of
            // this sweep fell into: it printed namePinned=[] and counted both
            // as fine. MT-16 made that field the real one, but the next
            // name-pinned class would repeat the trap, so the order stands.
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
