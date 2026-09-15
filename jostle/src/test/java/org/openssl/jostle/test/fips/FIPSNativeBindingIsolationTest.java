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

package org.openssl.jostle.test.fips;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.DefaultServiceNI;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.security.Provider;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

/**
 * No JSLFIPS service holds a BASE native binding, and no JSL service holds a
 * FIPS one.
 *
 * <p>This is the general form of a defect found in the X.509 work: the
 * CertificateFactory SPI read {@code NISelector.X509NI} in its constructor, so
 * the FIPS provider drove the BASE interface library. It surfaced as a JVM
 * abort only because a FIPS-only run leaves the base lib ctx uninitialised —
 * on a JVM where both are initialised the same wiring parses in the wrong
 * library and returns keys from the wrong provider with NO symptom, because
 * mainline and the module compute identical bytes. No functional test can tell
 * them apart. That is why this guard is structural and why it runs on the
 * ordinary unit legs rather than only the FIPS leg: it must not depend on the
 * abort, which was luck.
 *
 * <p><b>Gated PER METHOD, deliberately, and listed in
 * {@code FIPSTestGateParityTest}'s EXEMPT with this reason.</b> The mirror
 * cell is over the BASE provider and must run on the ordinary non-FIPS legs —
 * it is the control, and a wrongly-wired base provider is exactly as possible
 * there. A class-level gate would skip the control everywhere it can still
 * run. Only the FIPS cell gates itself.
 *
 * <p>Lives in the {@code fips} test package rather than {@code parity}
 * because {@code FIPSTestUtil} is package-private — the same constraint that
 * has already moved one test in this tree. The guard is a parity guard by
 * nature, not by directory.
 *
 * <p>Base and FIPS bindings are DISTINCT TYPES — {@code MDServiceFFI} against
 * {@code MDServiceFIPSFFI} — so "which library does this object reach" is
 * decidable from the class alone.
 *
 * <p><b>What this does NOT catch:</b> a base binding reached through a STATIC
 * read at call time rather than held in a field, since nothing is then
 * reachable from the SPI instance to walk. Measured across all 67 classes the
 * {@code ProvFIPS*} registrars name: 62 base-selector reads, every one inside
 * a constructor, and ZERO in a field initialiser or method body. So no such
 * site exists today and the companion source lint is not yet needed. Note the
 * count alone would not have caught the X.509 defect either — that read was in
 * a constructor too, and benign only until a FIPS registration called that
 * constructor. The field walk is what decides it, which is why it is the
 * guard.
 */
public class FIPSNativeBindingIsolationTest
{
    /** Below these the walk is not measuring anything and must fail. */
    private static final int MIN_SERVICES = 20;
    private static final int MIN_BINDINGS_SEEN = 20;
    private static final int MAX_DEPTH = 6;

    private static boolean isBinding(Object o)
    {
        return o instanceof DefaultServiceNI;
    }

    /**
     * A binding's library, decided from its class name. The implementation
     * classes are {@code XServiceJNI} / {@code XServiceFFI} for the base and
     * {@code XServiceFIPSJNI} / {@code XServiceFIPSFFI} for the module, so the
     * presence of FIPS in the simple name is the discriminator — and the two
     * are different types, never the same object configured differently.
     */
    private static boolean isFipsBinding(Object o)
    {
        return o.getClass().getSimpleName().contains("FIPS");
    }

    private static final class Found
    {
        final String service;
        final String path;
        final String binding;

        Found(String service, String path, String binding)
        {
            this.service = service;
            this.path = path;
            this.binding = binding;
        }

        public String toString()
        {
            return service + " -> " + path + " = " + binding;
        }
    }

    private int bindingsSeen;

    private void walk(String service, Object root, boolean wantFips, List<Found> wrong)
    {
        Map<Object, Boolean> seen = new IdentityHashMap<Object, Boolean>();
        Deque<Object[]> queue = new ArrayDeque<Object[]>();
        queue.add(new Object[]{root, root.getClass().getSimpleName(), Integer.valueOf(0)});

        while (!queue.isEmpty())
        {
            Object[] item = queue.poll();
            Object o = item[0];
            String path = (String) item[1];
            int depth = ((Integer) item[2]).intValue();

            if (o == null || depth > MAX_DEPTH || seen.put(o, Boolean.TRUE) != null)
            {
                continue;
            }
            if (isBinding(o))
            {
                bindingsSeen++;
                if (isFipsBinding(o) != wantFips)
                {
                    wrong.add(new Found(service, path, o.getClass().getName()));
                }
                // A binding holds no further provider state worth walking.
                continue;
            }
            // Only our own objects: walking the JDK's would be unbounded and
            // could not hold one of our bindings anyway.
            if (!o.getClass().getName().startsWith("org.openssl.jostle."))
            {
                continue;
            }
            for (Class<?> c = o.getClass(); c != null && c != Object.class; c = c.getSuperclass())
            {
                for (Field f : c.getDeclaredFields())
                {
                    if (Modifier.isStatic(f.getModifiers()))
                    {
                        continue;
                    }
                    try
                    {
                        f.setAccessible(true);
                        Object v = f.get(o);
                        if (v != null)
                        {
                            queue.add(new Object[]{v, path + "." + f.getName(), Integer.valueOf(depth + 1)});
                        }
                    }
                    catch (RuntimeException | IllegalAccessException inaccessible)
                    {
                        // A field we cannot read cannot be walked; that is a
                        // gap in coverage, not a failure, and the vacuity
                        // floor is what keeps the walk honest overall.
                    }
                }
            }
        }
    }

    private void assertNoForeignBindings(Provider provider, boolean wantFips)
    {
        List<Found> wrong = new ArrayList<Found>();
        int constructed = 0;
        bindingsSeen = 0;

        for (Provider.Service s : new TreeSet<Provider.Service>(
                java.util.Comparator.comparing(x -> x.getType() + "." + x.getAlgorithm()))
        {
            {
                addAll(provider.getServices());
            }
        })
        {
            Object spi;
            try
            {
                spi = s.newInstance(null);
            }
            catch (Exception notConstructible)
            {
                // Some services need a parameter; the smoke test owns that
                // contract. Skipping one here only reduces coverage, and the
                // floor below catches a wholesale failure to construct.
                continue;
            }
            if (spi == null)
            {
                continue;
            }
            constructed++;
            walk(s.getType() + "." + s.getAlgorithm(), spi, wantFips, wrong);
        }

        Assertions.assertTrue(constructed >= MIN_SERVICES,
                "only " + constructed + " services constructed for " + provider.getName()
                        + "; the walk is not measuring the surface");
        Assertions.assertTrue(bindingsSeen >= MIN_BINDINGS_SEEN,
                "only " + bindingsSeen + " native bindings reached for " + provider.getName()
                        + "; a walk that finds none would report clean whatever the wiring");

        if (!wrong.isEmpty())
        {
            StringBuilder sb = new StringBuilder(provider.getName())
                    .append(" holds ").append(wrong.size())
                    .append(wantFips ? " BASE" : " FIPS").append(" native binding(s):");
            for (Found f : wrong)
            {
                sb.append("\n  ").append(f);
            }
            Assertions.fail(sb.toString());
        }
    }

    @Test
    public void noFipsServiceHoldsABaseNativeBinding()
        throws Exception
    {
        // Returns the configured provider and skips when the module is absent.
        assertNoForeignBindings(FIPSTestUtil.assumeFipsProvider(), true);
    }

    @Test
    public void noBaseServiceHoldsAFipsNativeBinding()
    {
        assertNoForeignBindings(new JostleProvider(), false);
    }
}
