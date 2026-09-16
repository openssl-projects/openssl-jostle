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

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.provider.dh.DHAlgorithmParameterGenerator;
import org.openssl.jostle.jcajce.provider.dh.DHAlgorithmParameters;
import org.openssl.jostle.jcajce.provider.dh.DHServiceNI;
import org.openssl.jostle.jcajce.provider.dsa.DSAAlgorithmParameterGenerator;
import org.openssl.jostle.jcajce.provider.dsa.DSAAlgorithmParameters;
import org.openssl.jostle.jcajce.provider.dsa.DSAServiceNI;
import org.openssl.jostle.jcajce.spec.SpecNI;

import java.security.AlgorithmParameters;
import java.security.Provider;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.Security;

/**
 * The unbound DH / DSA {@code AlgorithmParameterGenerator}s (constructed
 * directly, with a null provider — never through {@code getInstance}) pin
 * their own provider by NAME in {@code engineGenerateParameters}, never
 * registry order.
 *
 * <p>Before this fix the unbound arm called
 * {@code AlgorithmParameters.getInstance("DH")} / {@code ("DSA")} with no
 * provider argument, so a foreign provider registered ahead of {@code JSL}
 * answered instead. This reproduces that ordering with a pseudo provider —
 * the same shape {@code DHAlgorithmParametersRecursionTest} uses — mapping
 * {@code AlgorithmParameters.DH}/{@code DSA} to Jostle's own codec classes
 * under a foreign name, inserted at registry position 1 ahead of
 * {@code JSL}. The pseudo answers with a genuinely working codec (Jostle's
 * own {@code resolveDelegate} skips itself by package and delegates to the
 * platform codec), so the ternary's registry-order fallback can complete an
 * {@code init()} rather than merely resolve a class — proving the wrong
 * PROVIDER was chosen, not merely a broken one.
 *
 * <p>Registry snapshot/restore skeleton copied from
 * {@code RSAPSSWithoutJdkProvidersTest}, including its SHA1PRNG witness;
 * this class does not empty the registry (the pseudo's delegate needs the
 * platform DH/DSA codec present).
 */
public class UnboundParameterGeneratorPinningRegressionTest
{
    private static final String PSEUDO = "JOSTLE_PSEUDO_APG";

    /** Small sizes per the plan: DH 512 is served on JSL; DSA 1024. */
    private static final int DH_BITS = 512;
    private static final int DSA_BITS = 1024;

    private Provider[] original;

    @BeforeEach
    public void snapshotTheRegistry()
    {
        original = Security.getProviders();
    }

    @AfterEach
    public void restoreTheRegistry()
    {
        if (original == null)
        {
            return;
        }

        for (Provider installed : Security.getProviders())
        {
            Security.removeProvider(installed.getName());
        }
        for (int i = 0; i < original.length; i++)
        {
            Security.insertProviderAt(original[i], i + 1);
        }

        Provider[] restored = Security.getProviders();
        Assertions.assertEquals(original.length, restored.length,
                "provider count not restored: the next class in this JVM will see a different registry");
        for (int i = 0; i < original.length; i++)
        {
            Assertions.assertEquals(original[i].getName(), restored[i].getName(),
                    "provider at position " + i + " not restored");
        }

        Assertions.assertDoesNotThrow(
                () -> java.security.SecureRandom.getInstance("SHA1PRNG"),
                "SHA1PRNG is unavailable after the restore");
    }

    /**
     * Exposes the protected {@code AlgorithmParameterGeneratorSpi} methods so
     * this test — outside the SPI's package, and deliberately NOT going
     * through {@code AlgorithmParameterGenerator.getInstance} (that would
     * bind a provider and defeat the whole point of the unbound realm) — can
     * drive the direct-construction path.
     */
    private static final class ExposedDH extends DHAlgorithmParameterGenerator
    {
        ExposedDH(DHServiceNI ni, SpecNI specNI)
        {
            super(ni, specNI);
        }

        AlgorithmParameters generate(int bits) throws Exception
        {
            engineInit(bits, new SecureRandom());
            return engineGenerateParameters();
        }
    }

    private static final class ExposedDSA extends DSAAlgorithmParameterGenerator
    {
        ExposedDSA(DSAServiceNI ni, SpecNI specNI)
        {
            super(ni, specNI);
        }

        AlgorithmParameters generate(int bits) throws Exception
        {
            engineInit(bits, new SecureRandom());
            return engineGenerateParameters();
        }
    }

    @Test
    public void unboundGeneratorsPinTheirOwnProviderByNameNeverRegistryOrder() throws Exception
    {
        Provider pseudo = new Provider(PSEUDO, 1.0, "unbound APG pinning regression")
        {
        };
        pseudo.put("AlgorithmParameters.DH", DHAlgorithmParameters.class.getName());
        pseudo.put("AlgorithmParameters.DSA", DSAAlgorithmParameters.class.getName());
        Security.removeProvider(PSEUDO);
        Security.insertProviderAt(pseudo, 1);

        // Appended LAST: strictly lower registry precedence than the pseudo,
        // so an unqualified getInstance("DH")/("DSA") resolves to the pseudo
        // before the fix.
        Security.removeProvider(JostleProvider.PROVIDER_NAME);
        Security.addProvider(new JostleProvider());

        ExposedDH dhGen = new ExposedDH(NISelector.DHServiceNI, NISelector.SpecNI);
        AlgorithmParameters dhParams = dhGen.generate(DH_BITS);
        Assertions.assertEquals(JostleProvider.PROVIDER_NAME, dhParams.getProvider().getName(),
                "unbound DH generator must pin its own provider by name, never registry order");

        ExposedDSA dsaGen = new ExposedDSA(NISelector.DSAServiceNI, NISelector.SpecNI);
        AlgorithmParameters dsaParams = dsaGen.generate(DSA_BITS);
        Assertions.assertEquals(JostleProvider.PROVIDER_NAME, dsaParams.getProvider().getName(),
                "unbound DSA generator must pin its own provider by name, never registry order");

        // Remove JSL entirely: the pinned name resolves nowhere, so both
        // generators must refuse typed rather than silently answer from the
        // pseudo (or any other provider still registered).
        Security.removeProvider(JostleProvider.PROVIDER_NAME);

        ExposedDH dhGenAfterRemoval = new ExposedDH(NISelector.DHServiceNI, NISelector.SpecNI);
        Assertions.assertThrows(ProviderException.class, () -> dhGenAfterRemoval.generate(DH_BITS),
                "with JSL unregistered the unbound DH generator must not silently answer from another provider");

        ExposedDSA dsaGenAfterRemoval = new ExposedDSA(NISelector.DSAServiceNI, NISelector.SpecNI);
        Assertions.assertThrows(ProviderException.class, () -> dsaGenAfterRemoval.generate(DSA_BITS),
                "with JSL unregistered the unbound DSA generator must not silently answer from another provider");
    }
}
