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
import org.openssl.jostle.Loader;
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;

import java.util.Locale;

/**
 * Behaviour-lock over the FIPS interface-library selection. Two properties are
 * pinned once the FIPS provider (and hence the lazy FIPS interface load) has
 * been triggered:
 *
 * <ol>
 *     <li>The library actually loaded for the FIPS provider is the
 *     fips-suffixed one (interface_fips_jni / interface_fips_ffi), not the base
 *     non-FIPS interface library - i.e. {@link Loader#getFipsInterfaceLibPath()}
 *     names a lib whose name contains "fips".</li>
 *     <li>The resolved {@link FIPSNISelector} implementations match the active
 *     bridge flavour: under FFI ({@link Loader#isFFI()}) every impl class's
 *     simple name ends with "FFI", otherwise "JNI". The FIPS JNI and FIPS FFI
 *     bridges are separate compile units, so this guards against the selector
 *     handing back a mismatched flavour.</li>
 * </ol>
 *
 * <p>Gated on TEST_FIPS_LIB; skipped when unset. Touching a
 * {@code FIPSNISelector} field forces the selector's static initialiser, which
 * runs {@link Loader#loadFipsInterface()} - so referencing the selector below
 * is what triggers the FIPS interface load these tests observe.
 */
public class FIPSInterfaceSelectionTest
{
    /**
     * Class-level gate: the whole class skips when TEST_FIPS_LIB is unset.
     * Gating here rather than per test method fails closed, so a test added
     * later is gated automatically.
     */
    @BeforeAll
    static void before()
    {
        FIPSTestUtil.assumeFipsProvider();
    }

    /**
     * The FIPS interface library that loaded is the fips-suffixed one, and the
     * resolved NI impls match the active JNI/FFI bridge flavour.
     */
    @Test
    public void fipsNiSelectorHonoursInterfaceOverrideAndLoadsFipsSuffixedLib()
    {
        // Touch a selector field: forces FIPSNISelector's static init, which
        // calls Loader.loadFipsInterface() - the load these assertions observe.
        Object mdImpl = FIPSNISelector.MDServiceNI;

        Assertions.assertTrue(Loader.isFipsLoadSuccessful(),
                "FIPS interface load must have succeeded: " + Loader.getFipsMessage());

        String libPath = Loader.getFipsInterfaceLibPath();
        Assertions.assertNotNull(libPath,
                "FIPS interface lib path must be set after a successful load");
        Assertions.assertTrue(libPath.toLowerCase(Locale.ROOT).contains("fips"),
                "FIPS interface lib must be the fips-suffixed library, was: " + libPath);

        String expectedSuffix = Loader.isFFI() ? "FFI" : "JNI";

        assertImplFlavour(FIPSNISelector.OpenSSLFIPSNI, expectedSuffix);
        assertImplFlavour(mdImpl, expectedSuffix);
        assertImplFlavour(FIPSNISelector.BlockCipherNI, expectedSuffix);
        assertImplFlavour(FIPSNISelector.CCMCipherNI, expectedSuffix);
        assertImplFlavour(FIPSNISelector.MacServiceNI, expectedSuffix);
        assertImplFlavour(FIPSNISelector.RandServiceNI, expectedSuffix);
        assertImplFlavour(FIPSNISelector.SpecNI, expectedSuffix);
        assertImplFlavour(FIPSNISelector.Asn1NI, expectedSuffix);
        assertImplFlavour(FIPSNISelector.RSAServiceNI, expectedSuffix);
        assertImplFlavour(FIPSNISelector.RSAOAEPCipherNI, expectedSuffix);
        assertImplFlavour(FIPSNISelector.RSAPKCS1CipherNI, expectedSuffix);
        assertImplFlavour(FIPSNISelector.ECServiceNI, expectedSuffix);
        assertImplFlavour(FIPSNISelector.DSAServiceNI, expectedSuffix);
        assertImplFlavour(FIPSNISelector.DHServiceNI, expectedSuffix);
        assertImplFlavour(FIPSNISelector.XECServiceNI, expectedSuffix);
        assertImplFlavour(FIPSNISelector.KdfNI, expectedSuffix);
        assertImplFlavour(FIPSNISelector.OperationsTestNI, expectedSuffix);
    }

    private static void assertImplFlavour(Object impl, String expectedSuffix)
    {
        Assertions.assertNotNull(impl, "FIPS NI impl must be resolved");
        String simpleName = impl.getClass().getSimpleName();
        Assertions.assertTrue(simpleName.endsWith(expectedSuffix),
                "FIPS NI impl " + simpleName + " must match active interface flavour "
                        + expectedSuffix);
    }
}
