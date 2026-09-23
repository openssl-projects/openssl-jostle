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

package org.openssl.jostle.test.disposal;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.disposal.DisposalDaemon;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import java.lang.ref.WeakReference;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.BooleanSupplier;

/**
 * The reconciliation: every handle registered for disposal is disposed, once a
 * collection has been forced.
 *
 * <p>Per-value counts, not a total. A total balances while the wrong handle
 * leaks and another is freed twice; a set hides a leak at a reused address.
 *
 * <p>Exceeding the cap FAILS. A test that skipped here would report the same
 * green as one where the daemon ran, which is the failure this whole item
 * exists to make visible. The single {@code Assumption} is a sentinel that never
 * clears, which is what {@code -XX:+DisableExplicitGC} produces.
 */
public class DisposalReconciliationIntegrationTest
{
    /** Instances per family. */
    static final int K = 4;

    private DisposalRecorder recorder;

    @BeforeAll
    public static void beforeAll()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    protected Provider provider()
    {
        return Security.getProvider(JostleProvider.PROVIDER_NAME);
    }

    /**
     * The fewest families the hierarchy resolution may reach on this provider.
     * Measured: JSL reaches 17. A resolution that reaches fewer is broken, not a
     * smaller provider.
     */
    protected int minimumFamiliesReached()
    {
        return 17;
    }

    @AfterEach
    public void removeRecorder()
    {
        if (recorder != null)
        {
            DisposalDaemon.removeListener(recorder);
            recorder = null;
        }
    }

    private static WeakReference<Object> sentinel(Object[] holder)
    {
        holder[0] = new Object();
        return new WeakReference<Object>(holder[0]);
    }

    /**
     * Drives K instances of every family, in its OWN frame: the drivers hold the
     * key-pair cache, and a stale local slot in the frame that runs the drain
     * would keep it reachable. Returns the drivers that failed.
     */
    private static List<String> drive(Provider provider, List<String> modes) throws Exception
    {
        List<String> broken = new ArrayList<String>();
        for (DisposalFamilies.Driver d : DisposalFamilies.drivers(provider))
        {
            for (int i = 0; i < K; i++)
            {
                try
                {
                    Object used = d.driveOnce();
                    Assertions.assertNotNull(used, d + " returned nothing to drop");
                }
                catch (Throwable t)
                {
                    broken.add(d + ": " + t);
                    break;
                }
            }
            modes.add(d.family() + "=" + (d.detail().isEmpty() ? "-" : d.detail()));
        }
        return broken;
    }

    @Test
    public void everyRegisteredHandleIsDisposed() throws Exception
    {
        Provider provider = provider();
        Map<String, String> reached = DisposalFamilies.familiesOf(provider);
        Assertions.assertTrue(reached.size() >= minimumFamiliesReached(),
                "the hierarchy resolution reached only " + reached.size()
                        + " families on " + provider.getName() + ": " + reached.keySet());

        Object[] holder = new Object[1];
        final WeakReference<Object> sentinel = sentinel(holder);

        // Lazily populated process-lifetime caches (DSA parameters, for one) look
        // like leaks in the measured window, so one pass runs before recording.
        List<String> warmModes = new ArrayList<String>();
        List<String> modes = new ArrayList<String>();
        drive(provider, warmModes);
        recorder = new DisposalRecorder();
        DisposalDaemon.addListener(recorder);
        List<String> broken = drive(provider, modes);
        final int driverCount = modes.size();

        Assertions.assertTrue(driverCount > 0, "no family drivers were built");
        Assertions.assertTrue(broken.isEmpty(),
                "family drivers failed, so this cell measured less than it claims:\n  "
                        + String.join("\n  ", broken));

        holder[0] = null;

        int cycles = DisposalDrain.drain(new BooleanSupplier()
        {
            public boolean getAsBoolean()
            {
                return sentinel.get() == null && recorder.isDrained();
            }
        });

        Assumptions.assumeTrue(sentinel.get() == null,
                "the sentinel never cleared, so this JVM does not honour System.gc()"
                        + " (-XX:+DisableExplicitGC); jvm="
                        + System.getProperty("java.version"));

        System.out.println("[disposal] provider=" + provider.getName()
                + " families=" + reached.size()
                + " drivers=" + driverCount + " K=" + K
                + " registered=" + recorder.registeredCount()
                + " reusedValues=" + recorder.reusedCount()
                + " cycles=" + cycles + " capWas=" + DisposalDrain.CAP
                + " modes=" + modes);

        Set<Long> missing = recorder.missing();
        Assertions.assertTrue(missing.isEmpty(),
                missing.size() + " of " + recorder.registeredCount()
                        + " registered handles were never disposed after " + cycles
                        + " collection cycles: " + recorder.describe(missing));

        Assertions.assertEquals(0, recorder.failedCount(),
                "disposers failed: " + recorder.failures());

        Assertions.assertTrue(recorder.registeredCount() >= driverCount * K,
                "expected at least one handle per instance driven, registered="
                        + recorder.registeredCount() + " driven=" + (driverCount * K));
    }

    /**
     * The positive control: a handle that is STILL HELD must be reported missing
     * by its own value. Without it the reconciliation passes on a JVM that never
     * collects, a listener that records nothing, and a loop that exits early.
     */
    @Test
    public void aHeldHandleIsReportedMissingByValue() throws Exception
    {
        Provider provider = provider();

        recorder = new DisposalRecorder();
        DisposalDaemon.addListener(recorder);

        // One instance, held for the whole cell. Its handle must not drain.
        MessageDigest held = MessageDigest.getInstance(
                DisposalFamilies.familiesOf(provider).get("MDServiceSPI"), provider);
        held.update(new byte[16]);
        held.digest();

        Object[] holder = new Object[1];
        final WeakReference<Object> sentinel = sentinel(holder);
        holder[0] = null;

        DisposalDrain.drain(new BooleanSupplier()
        {
            public boolean getAsBoolean()
            {
                return sentinel.get() == null;
            }
        });
        Assumptions.assumeTrue(sentinel.get() == null,
                "the sentinel never cleared, so this JVM does not honour System.gc()");

        Set<Long> missing = recorder.missing();
        Assertions.assertEquals(1, recorder.registeredCount(),
                "expected exactly one handle to have been registered, got "
                        + recorder.registeredCount());
        Assertions.assertEquals(1, missing.size(),
                "the held handle was reported disposed, so this instrument cannot see a leak");
        Assertions.assertEquals(recorder.registeredHandles(), missing,
                "the missing handle is not the one that was held");

        // Keep it reachable past the assertions, or the JVM may collect it early.
        Assertions.assertNotNull(held);
    }

    /**
     * A family with no driver is a family whose handles nothing in this suite
     * drops, so its disposal is unmeasured. The family list is read from the
     * SOURCE tree, the technique {@code NativeReferenceParityTest} uses, so a
     * new family reddens this by name rather than silently going uncovered.
     *
     * <p>A source family is exempt only when the LOADED hierarchy of every
     * registered service misses it: that is the same resolution the drivers
     * use, so a family registered through a subclass cannot slip past.
     */
    @Test
    public void everyNativeReferenceFamilyHasADriver() throws Exception
    {
        Set<String> inSource = DisposalSources.nativeReferenceFamilies();
        Assertions.assertTrue(inSource.size() >= 15,
                "only " + inSource.size() + " NativeReference subclasses found in the source"
                        + " tree, which is fewer than a correct scan can reach");

        Set<String> driven = new LinkedHashSet<String>();
        for (DisposalFamilies.Driver d : DisposalFamilies.drivers(provider()))
        {
            driven.add(d.family());
        }

        Set<String> reached = new LinkedHashSet<String>(
                DisposalFamilies.familiesOf(provider()).keySet());
        Assertions.assertTrue(reached.size() >= minimumFamiliesReached(),
                "the hierarchy resolution reached only " + reached.size() + " families: " + reached);

        List<String> uncovered = new ArrayList<String>();
        for (String family : inSource)
        {
            if (driven.contains(family))
            {
                continue;
            }
            // Not in any registered service's hierarchy: this provider cannot drive it.
            if (!reached.contains(family) && !family.equals("PKEYKeySpec"))
            {
                continue;
            }
            uncovered.add(family);
        }
        Assertions.assertTrue(uncovered.isEmpty(),
                "NativeReference families this provider registers but no driver exercises: "
                        + uncovered);

        List<String> stale = new ArrayList<String>();
        for (String family : driven)
        {
            if (!inSource.contains(family))
            {
                stale.add(family);
            }
        }
        Assertions.assertTrue(stale.isEmpty(),
                "drivers name classes that are not NativeReference subclasses: " + stale);

        List<String> unresolvable = new ArrayList<String>();
        for (String family : reached)
        {
            if (!inSource.contains(family))
            {
                unresolvable.add(family);
            }
        }
        Assertions.assertTrue(unresolvable.isEmpty(),
                "the hierarchy resolution named families the source scan does not: " + unresolvable);
    }
}
