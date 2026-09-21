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

package org.openssl.jostle.jcajce.provider.bcfks;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.BCFKSLoadStoreParameter;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.test.util.ProviderSurfaceGuard;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.SortedSet;

/**
 * The BCFKS surface through the FIPS provider: JSLFIPS against JSL, and
 * JSLFIPS against BouncyCastle, over the same writer-option and entry-type
 * table the base class drives.
 *
 * <p>Neither class substitutes for the other. This one drives the FIPS
 * interface library and the module's own lib ctx, and its registered set is
 * JSLFIPS's, so a base-only registration is invisible here and a FIPS-only
 * defect is invisible there.
 */
public class FIPSBcFKSAgreementTest
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
    private static final SecureRandom RANDOM = new SecureRandom();

    @BeforeEach
    void assumeFips()
    {
        Assumptions.assumeFalse(TestUtil.skipFipsTests(),
                "TEST_FIPS_LIB not set (full path to the FIPS module library)");
        // Register as well as gate: a cell that only gated reached
        // getInstance with JSLFIPS unregistered.
        TestUtil.addFipsProvider();
    }

    private static Provider fips()
    {
        return TestUtil.addFipsProvider();
    }

    private static String fipsName()
    {
        return JostleFIPSProvider.PROVIDER_NAME;
    }

    private static String jslName()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        return JostleProvider.PROVIDER_NAME;
    }

    private static String bcName()
    {
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        return BC;
    }

    private static Certificate certificate() throws Exception
    {
        return CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(BcFKSFixtures.TRUSTED_CERT_DATA));
    }

    private static char[] password()
    {
        byte[] bytes = new byte[16];
        RANDOM.nextBytes(bytes);
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes)
        {
            sb.append((char) ('a' + (b & 0x0F)));
        }
        return sb.toString().toCharArray();
    }

    // ---- The completeness guard over JSLFIPS's own registered set ----------

    @Test
    public void everyRegisteredBcfksNameIsDrivenOnTheFipsProvider() throws Exception
    {
        Provider provider = fips();
        SortedSet<String> registered = ProviderSurfaceGuard.registeredSurface(provider,
                "org.openssl.jostle.jcajce.provider.", new String[]{"KeyStore"});
        Assertions.assertFalse(registered.isEmpty(),
                "no KeyStore services discovered on JSLFIPS, so this guard would pass vacuously");
        Assertions.assertTrue(registered.contains("KeyStore.BCFKS"),
                "BCFKS is absent from the JSLFIPS KeyStore surface: " + registered);

        SortedSet<String> names = BcFKSAgreementTest.bcfksNames(provider);
        Assertions.assertFalse(names.isEmpty(),
                "no registered name resolves to the BCFKS SPI on JSLFIPS");

        Certificate certificate = certificate();
        char[] password = password();
        List<String> failures = new ArrayList<String>();
        for (String name : names)
        {
            try
            {
                KeyStore store = KeyStore.getInstance(name, fipsName());
                store.load(null, null);
                store.setCertificateEntry("cert", certificate);
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                store.store(out, password);

                KeyStore viaBc = KeyStore.getInstance("BCFKS", bcName());
                viaBc.load(new ByteArrayInputStream(out.toByteArray()), password);
                Assertions.assertEquals(1, viaBc.size(), name);
            }
            catch (Throwable t)
            {
                failures.add(name + " -> " + t.getClass().getSimpleName() + ": " + t.getMessage());
            }
        }
        Assertions.assertTrue(failures.isEmpty(),
                "registered BCFKS names that could not be driven on JSLFIPS (" + failures.size()
                        + " of " + names.size() + "):\n  " + String.join("\n  ", failures));
    }

    // ---- The writer-option matrix ------------------------------------------

    /**
     * Each option is driven on JSLFIPS and the store read back by JSLFIPS, JSL
     * and BouncyCastle. A row the module cannot serve is asserted REFUSED with
     * its own message, never skipped -- an absent row and a refused row look
     * the same in a green run otherwise.
     */
    @Test
    public void everyWriterOptionEitherInteroperatesOrIsRefusedTyped() throws Exception
    {
        Map<String, BcFKSWriterOptions.Option> options = BcFKSWriterOptions.options();
        Assertions.assertFalse(options.isEmpty(), "the writer-option table is empty");

        Certificate certificate = certificate();
        List<String> failures = new ArrayList<String>();
        int served = 0;
        int refused = 0;
        for (BcFKSWriterOptions.Option option : options.values())
        {
            char[] password = password();
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            KeyStore store = KeyStore.getInstance("BCFKS", fipsName());
            store.load(null, null);
            store.setCertificateEntry("cert", certificate);

            if (!option.servedOnFips)
            {
                try
                {
                    store.store(option.configure.apply(
                            new BCFKSLoadStoreParameter.Builder(out, password)).build());
                    failures.add(option.name + ": expected a typed refusal on JSLFIPS, but the"
                            + " write succeeded");
                }
                catch (IOException e)
                {
                    if (!option.fipsRefusal.equals(e.getMessage()))
                    {
                        failures.add(option.name + ": refused with \"" + e.getMessage()
                                + "\", expected \"" + option.fipsRefusal + "\"");
                    }
                    else
                    {
                        refused++;
                    }
                }
                catch (Throwable t)
                {
                    failures.add(option.name + ": refused with " + t.getClass().getName()
                            + " rather than a typed IOException");
                }
                continue;
            }

            try
            {
                store.store(option.configure.apply(
                        new BCFKSLoadStoreParameter.Builder(out, password)).build());
                byte[] written = out.toByteArray();

                for (String reader : new String[]{fipsName(), jslName(), bcName()})
                {
                    KeyStore back = KeyStore.getInstance("BCFKS", reader);
                    back.load(new ByteArrayInputStream(written), password);
                    Assertions.assertEquals(1, back.size(), option.name + " read by " + reader);
                }
                served++;
            }
            catch (Throwable t)
            {
                failures.add(option.name + " -> " + t.getClass().getSimpleName() + ": " + t.getMessage());
            }
        }
        Assertions.assertTrue(failures.isEmpty(),
                "writer options that did not behave (" + failures.size() + " of " + options.size()
                        + "):\n  " + String.join("\n  ", failures));
        Assertions.assertTrue(served > 0, "no option was served, so the interop half is vacuous");
        Assertions.assertTrue(refused > 0,
                "no option was refused, so the impossible-cell half is vacuous -- scrypt is the"
                        + " row that must refuse here");
    }

    @Test
    public void everyEntryTypeRoundTripsOnTheFipsProvider() throws Exception
    {
        Map<Integer, BcFKSWriterOptions.EntryType> types =
                BcFKSWriterOptions.entryTypes(fipsName());
        Assertions.assertFalse(types.isEmpty(), "the entry-type table is empty");

        Certificate certificate = certificate();
        List<String> failures = new ArrayList<String>();
        for (BcFKSWriterOptions.EntryType type : types.values())
        {
            char[] password = password();
            try
            {
                KeyStore store = KeyStore.getInstance("BCFKS", fipsName());
                store.load(null, null);
                type.setter.set(store, certificate, password);
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                store.store(out, password);

                KeyStore back = KeyStore.getInstance("BCFKS", fipsName());
                back.load(new ByteArrayInputStream(out.toByteArray()), password);
                Assertions.assertEquals(1, back.size(), type.name);

                KeyStore viaBc = KeyStore.getInstance("BCFKS", bcName());
                viaBc.load(new ByteArrayInputStream(out.toByteArray()), password);
                Assertions.assertTrue(viaBc.containsAlias(type.alias), type.name);
            }
            catch (Throwable t)
            {
                failures.add(type.name + " -> " + t.getClass().getSimpleName() + ": " + t.getMessage());
            }
        }
        Assertions.assertTrue(failures.isEmpty(),
                "entry types that did not round-trip on JSLFIPS (" + failures.size() + " of "
                        + types.size() + "):\n  " + String.join("\n  ", failures));
    }

    // ---- A store crossing between the two providers ------------------------

    /**
     * A store is a FILE, so it crosses between the providers freely -- unlike a
     * key OBJECT, which belongs to its creating provider instance. Both
     * directions, because a reader and a writer are different code.
     */
    @Test
    public void storesCrossBetweenTheTwoProvidersBothDirections() throws Exception
    {
        Certificate certificate = certificate();
        char[] password = password();

        KeyStore written = KeyStore.getInstance("BCFKS", fipsName());
        written.load(null, null);
        written.setCertificateEntry("cert", certificate);
        ByteArrayOutputStream fromFips = new ByteArrayOutputStream();
        written.store(fromFips, password);

        KeyStore readByBase = KeyStore.getInstance("BCFKS", jslName());
        readByBase.load(new ByteArrayInputStream(fromFips.toByteArray()), password);
        Assertions.assertArrayEquals(certificate.getEncoded(),
                readByBase.getCertificate("cert").getEncoded());

        KeyStore base = KeyStore.getInstance("BCFKS", jslName());
        base.load(null, null);
        base.setCertificateEntry("cert", certificate);
        ByteArrayOutputStream fromBase = new ByteArrayOutputStream();
        base.store(fromBase, password);

        KeyStore readByFips = KeyStore.getInstance("BCFKS", fipsName());
        readByFips.load(new ByteArrayInputStream(fromBase.toByteArray()), password);
        Assertions.assertArrayEquals(certificate.getEncoded(),
                readByFips.getCertificate("cert").getEncoded());
    }

    /**
     * A scrypt store the base provider writes is refused by the FIPS provider
     * with its own message, and the SAME bytes load on JSL. Both halves, so a
     * refusal that had become unconditional would fail the second one.
     */
    @Test
    public void aScryptStoreIsRefusedUnderFipsAndLoadsOnTheBaseProvider() throws Exception
    {
        Certificate certificate = certificate();
        char[] password = password();

        KeyStore base = KeyStore.getInstance("BCFKS", jslName());
        base.load(null, null);
        base.setCertificateEntry("cert", certificate);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        base.store(new BCFKSLoadStoreParameter.Builder(out, password)
                .withStorePBKDFConfig(
                        new BCFKSLoadStoreParameter.ScryptConfig.Builder(1024, 8, 1).build())
                .build());
        byte[] scryptStore = out.toByteArray();

        KeyStore underFips = KeyStore.getInstance("BCFKS", fipsName());
        IOException e = Assertions.assertThrows(IOException.class,
                () -> underFips.load(new ByteArrayInputStream(scryptStore), password));
        Assertions.assertEquals("BCFKS store uses scrypt, which this provider does not serve",
                e.getMessage());

        KeyStore underBase = KeyStore.getInstance("BCFKS", jslName());
        underBase.load(new ByteArrayInputStream(scryptStore), password);
        Assertions.assertEquals(1, underBase.size(),
                "the same bytes must load on the base provider, or the refusal above says nothing"
                        + " about scrypt in particular");
    }

    // ---- SignatureCheck, including the module-dependent DSA arm ------------

    /**
     * Every SignatureCheck algorithm, with the signing key generated through
     * JSL and imported into JSLFIPS as an encoding -- the sanctioned crossing,
     * and the only one that works on a module refusing DSA generation.
     *
     * <p>The DSA rows are module-dependent and BOTH branches are asserted: the
     * 3.1.2 module signs, and the 3.5.x module refuses with a typed message.
     * Pinning either answer alone would be wrong against the other module.
     */
    @Test
    public void signatureCheckAlgorithmsAgreeWithWhatTheModuleWillSign() throws Exception
    {
        Certificate certificate = certificate();
        List<String> failures = new ArrayList<String>();
        BCFKSLoadStoreParameter.SignatureAlgorithm[] algorithms =
                BCFKSLoadStoreParameter.SignatureAlgorithm.values();
        Assertions.assertTrue(algorithms.length > 0, "no signature algorithms are declared");

        int signed = 0;
        for (BCFKSLoadStoreParameter.SignatureAlgorithm algorithm : algorithms)
        {
            String keyAlgorithm = BcFKSWriterOptions.keyAlgorithmFor(algorithm);
            char[] password = password();
            try
            {
                KeyPair pair = crossedSigningPair(keyAlgorithm);
                KeyStore store = KeyStore.getInstance("BCFKS", fipsName());
                store.load(null, null);
                store.setCertificateEntry("cert", certificate);
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                try
                {
                    store.store(new BCFKSLoadStoreParameter.Builder(out, pair.getPrivate())
                            .withStoreSignatureAlgorithm(algorithm).build());
                }
                catch (IOException e)
                {
                    // The module refuses to SIGN with this key type. Typed and
                    // self-naming, or it is a defect rather than a capability.
                    if (e.getMessage() == null
                            || !e.getMessage().startsWith("BCFKS KeyStore: unable to sign store:"))
                    {
                        failures.add(algorithm + ": refused with \"" + e.getMessage()
                                + "\", which does not name the signing capability");
                    }
                    continue;
                }

                KeyStore back = KeyStore.getInstance("BCFKS", fipsName());
                back.load(new BCFKSLoadStoreParameter.Builder(
                        new ByteArrayInputStream(out.toByteArray()), pair.getPublic()).build());
                Assertions.assertEquals(1, back.size(), algorithm.name());
                signed++;
            }
            catch (Throwable t)
            {
                failures.add(algorithm + " -> " + t.getClass().getSimpleName() + ": " + t.getMessage());
            }
        }
        Assertions.assertTrue(failures.isEmpty(),
                "signature-check algorithms that misbehaved (" + failures.size() + " of "
                        + algorithms.length + "):\n  " + String.join("\n  ", failures));
        Assertions.assertTrue(signed > 0,
                "no signature algorithm signed at all, so the accepting half is vacuous");
    }

    /**
     * A signing key made by JSL and decoded through the FIPS provider's own
     * KeyFactory. Generating through JSLFIPS would fail on a module that
     * refuses DSA generation, and would then be measuring generation rather
     * than signing.
     */
    private static KeyPair crossedSigningPair(String keyAlgorithm) throws Exception
    {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(keyAlgorithm, jslName());
        if ("EC".equals(keyAlgorithm))
        {
            generator.initialize(new ECGenParameterSpec("secp256r1"));
        }
        else
        {
            generator.initialize(2048);
        }
        KeyPair generated = generator.generateKeyPair();

        KeyFactory factory = KeyFactory.getInstance(keyAlgorithm, fipsName());
        PrivateKey privateKey = factory.generatePrivate(
                new PKCS8EncodedKeySpec(generated.getPrivate().getEncoded()));
        PublicKey publicKey = factory.generatePublic(
                new X509EncodedKeySpec(generated.getPublic().getEncoded()));
        return new KeyPair(publicKey, privateKey);
    }
}
