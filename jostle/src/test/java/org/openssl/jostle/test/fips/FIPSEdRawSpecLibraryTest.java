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
import org.openssl.jostle.jcajce.spec.EdDSAPublicKeySpec;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;

/**
 * MT-15: the Ed KeyFactory's RAW key-spec paths allocated through the
 * instance's SpecNI but recorded the BASE one.
 *
 * <pre>
 *   PKEYKeySpec pkeySpec = new PKEYKeySpec(specNI.allocate(), osslKeyType);
 * </pre>
 *
 * <p>{@code specNI.allocate()} allocates through this SPI's library — the FIPS
 * one under JSLFIPS — while the convenience overload
 * {@code PKEYKeySpec(long, OSSLKeyType)} delegates to
 * {@code this(NISelector.SpecNI, ref, type)}, the BASE library. So a
 * JSLFIPS-created Ed key from a raw spec recorded the wrong library.
 *
 * <p>{@code PKEYKeySpec.Disposer} states the invariant this breaks, two files
 * away: <i>"The NI that allocated the PKEY frees it - a FIPS-allocated key
 * must be disposed through the FIPS interface library."</i> Disposal, name
 * lookup and the key-provider read all route through the recorded NI.
 *
 * <p>Pinned with the key-level accessor MT-14 added, which is the only tool
 * that can see this: nothing about the key's VALUE is wrong, so no round-trip
 * or agreement test can detect it.
 */
public class FIPSEdRawSpecLibraryTest
{
    private static Provider jsl;
    private static Provider fips;

    @BeforeAll
    static void before()
    {
        fips = FIPSTestUtil.assumeFipsProvider();
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        jsl = Security.getProvider(JostleProvider.PROVIDER_NAME);
        fipsServesEd25519 = fips.getService("KeyFactory", "ED25519") != null;
    }

    /**
     * Whether the loaded module serves Ed25519 at all. 3.1.2 refuses it; the
     * 3.5.x modules serve it.
     *
     * <p><b>Not an assumption.</b> This was a class-level
     * {@code Assumptions.assumeTrue}, which made the whole class skip
     * wholesale on 3.1.2 — and a FIPS class where {@code tests == skipped} is
     * exactly what {@code verify-results.py} fails the matrix on, because it
     * cannot tell a legitimate capability gate from a suite that never ran.
     * It failed the gate for that reason, correctly.
     *
     * <p>The fix is the rule from testing.md: where two supported
     * environments disagree, assert the CONTRACT rather than one
     * environment's answer. So each test below probes and asserts BOTH
     * branches — the recorded-SpecNI property where Ed25519 is served, and
     * the all-or-nothing absence of the family where it is not. Neither
     * module produces a skip, and neither leaves the class asserting nothing.
     */
    private static boolean fipsServesEd25519;

    /**
     * Where the module refuses Ed25519, the refusal must be COMPLETE.
     *
     * <p><b>Enumerated, not name-listed.</b> The first version queried
     * ED25519/ED448 against three service types. That cannot express
     * "complete": {@code ProvFIPSED} also registers {@code ED} (KeyFactory,
     * KeyPairGenerator), {@code EDDSA}, {@code ED25519PH}, {@code ED25519CTX},
     * {@code ED448PH} and OID aliases, so a partial registration leaving, say,
     * {@code Signature ED25519PH} alive while keymgmt is refused would have
     * passed. A guard against partial registration cannot be defeated by a
     * name nobody thought to list, so it reads the registered set instead.
     *
     * <p>The {@code ED} prefix is safe as a family matcher here: every
     * {@code ED*} algorithm across the whole FIPS registrar is Ed-family
     * (checked — the set is ED, ED25519, ED25519CTX, ED25519PH, ED448,
     * ED448PH, EDDSA), and the two Ed OIDs are matched explicitly since an
     * alias name carries no {@code ED} prefix.
     */
    private static void assertEd25519AbsentEntirely()
    {
        java.util.List<String> present = new java.util.ArrayList<String>();
        for (Provider.Service svc : fips.getServices())
        {
            String alg = svc.getAlgorithm().toUpperCase(java.util.Locale.ROOT);
            if (alg.startsWith("ED") || ED_OIDS.contains(alg))
            {
                present.add(svc.getType() + "/" + svc.getAlgorithm());
            }
        }
        // Aliases are registered inside the same gated blocks as their
        // canonical names, so canonical-absent implies alias-absent; the OIDs
        // are probed directly anyway, since they are the one form the prefix
        // match cannot see.
        for (String oid : ED_OIDS)
        {
            for (String type : new String[]{"KeyFactory", "KeyPairGenerator", "Signature"})
            {
                if (fips.getService(type, oid) != null)
                {
                    present.add(type + "/" + oid);
                }
            }
        }
        Assertions.assertTrue(present.isEmpty(),
                "the module does not serve an Ed25519 KeyFactory, so JSLFIPS must register no "
                        + "EdDSA service at all — a partial registration is unusable. Present: "
                        + present);
    }

    /** The Ed OIDs, which carry no ED prefix and so need explicit probing. */
    private static final java.util.List<String> ED_OIDS = java.util.Arrays.asList(
            "1.3.101.112", "1.3.101.113");

    /**
     * A key built through the RAW spec path must RECORD the SpecNI that
     * allocated it, because that is what disposal routes through.
     *
     * <p><b>Why this, and not the key-provider read.</b> The obvious assertion
     * — that {@code getKeyProvider} answers "fips" for a JSLFIPS raw-spec key
     * — was written first and PASSED on the broken tree. It does not
     * discriminate: {@code EVP_PKEY_get0_provider} reads a field on the key
     * itself, so either library answers correctly for a handle the other
     * allocated. Shipping it would have been an assertion that never could
     * have failed.
     *
     * <p>The recorded SpecNI is the property that actually matters. It is what
     * {@code PKEYKeySpec.Disposer} calls {@code dispose} on, and the invariant
     * is stated there: <i>"The NI that allocated the PKEY frees it - a
     * FIPS-allocated key must be disposed through the FIPS interface
     * library."</i> A mismatch is a cross-library free.
     */
    @Test
    public void rawSpecKeysRecordTheAllocatingSpecNi() throws Exception
    {
        byte[] raw = rawPublicBytes();

        Assertions.assertSame(
                org.openssl.jostle.jcajce.provider.NISelector.SpecNI,
                specNiOfRawSpecKey(jsl, raw),
                "a JSL raw-spec Ed key must record the BASE SpecNI");

        if (!fipsServesEd25519)
        {
            // The JSL half above still ran, so this test is never vacuous.
            assertEd25519AbsentEntirely();
            return;
        }

        Assertions.assertSame(
                org.openssl.jostle.jcajce.provider.fips.FIPSNISelector.SpecNI,
                specNiOfRawSpecKey(fips, raw),
                "a JSLFIPS raw-spec Ed key must record the FIPS SpecNI. Failing here means "
                        + "EdKeyFactorySpi allocated through the FIPS library but recorded the "
                        + "base one, so disposal frees across libraries — see MT-15.");
    }

    /**
     * Control: the X509 path was always correct (it uses the explicit
     * three-argument constructor), so it must pass in both phases. Without it
     * a broken harness would look like the defect.
     */
    @Test
    public void encodedPathAlreadyRecordsTheAllocatingLibrary() throws Exception
    {
        if (!fipsServesEd25519)
        {
            assertEd25519AbsentEntirely();
            return;
        }
        KeyPair kp = KeyPairGenerator.getInstance("ED25519", jsl).generateKeyPair();
        PublicKey viaFips = KeyFactory.getInstance("ED25519", fips)
                .generatePublic(new java.security.spec.X509EncodedKeySpec(kp.getPublic().getEncoded()));

        // Asserted with the PIN'S OWN instrument — the recorded SpecNI — not
        // with getKeyProvider. A control that measures something else cannot
        // tell you the instrument is broken: if the recorded-SpecNI read were
        // silently wrong, a getKeyProvider-based control would stay green and
        // the pin's failure would look like the defect returning.
        Assertions.assertSame(
                org.openssl.jostle.jcajce.provider.fips.FIPSNISelector.SpecNI,
                ((org.openssl.jostle.jcajce.interfaces.OSSLKey) viaFips).getSpec().getSpecNI(),
                "the X509 path uses the explicit constructor and was never affected");

        // Kept alongside as a second, independent reading: the module really
        // is the one holding the key, not merely the NI we recorded.
        Assertions.assertEquals("fips", providerOf(viaFips),
                "the X509-path key must also be SERVED by the FIPS module");
    }

    private static byte[] rawPublicBytes() throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance("ED25519", jsl).generateKeyPair();
        // Raw bytes via the KeyFactory's own raw spec, so the test does not
        // depend on which getter name the key interface exposes.
        return KeyFactory.getInstance("ED25519", jsl)
                .getKeySpec(kp.getPublic(), EdDSAPublicKeySpec.class).getPublicData();
    }

    private static org.openssl.jostle.jcajce.spec.SpecNI specNiOfRawSpecKey(Provider p, byte[] raw)
            throws Exception
    {
        PublicKey key = KeyFactory.getInstance("ED25519", p)
                .generatePublic(new EdDSAPublicKeySpec(
                        org.openssl.jostle.jcajce.spec.EdDSAParameterSpec.ED25519, raw));
        return ((org.openssl.jostle.jcajce.interfaces.OSSLKey) key).getSpec().getSpecNI();
    }

    /**
     * Reached through {@code OSSLKey}, like every other family.
     *
     * <p>This used reflection, with a comment saying Ed key classes were the
     * one family that did not implement {@code OSSLKey}. That was true and is
     * no longer: {@code JOEdPublicKey} declared only {@code EdDSAPublicKey}
     * (because {@code EdDSAKey extends Key}, where {@code MLKEMKey} and the
     * other PQC key interfaces extend {@code OSSLKey}), and it was fixed when
     * the MT-14 acceptance checks began casting to {@code OSSLKey} and turned
     * that gap into a guaranteed {@code ClassCastException} through
     * {@code translateKey}.
     */
    private static String providerOf(java.security.Key key)
    {
        PKEYKeySpec spec = ((org.openssl.jostle.jcajce.interfaces.OSSLKey) key).getSpec();
        return spec.getSpecNI().getKeyProvider(spec.getReference());
    }
}
