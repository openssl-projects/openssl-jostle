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
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.BCFKSLoadStoreParameter;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.test.util.ProviderSurfaceGuard;
import org.openssl.jostle.util.asn1.Der;

import javax.crypto.SecretKey;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Provider;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.SortedSet;
import java.util.TreeSet;

/**
 * BCFKS stores written by this provider are read by BouncyCastle and the other
 * way round, over every writer option and every entry type.
 *
 * <p>Interop here is file-level by design: the implementation shares no type
 * with BouncyCastle, so only a store one writes and the other reads can show
 * that the two agree. Cells where they do NOT agree are pinned in both halves
 * and labelled, so a bcprov release that changes its half reddens by name.
 */
public class BcFKSAgreementTest
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static Provider jsl;
    private static Certificate certificate;

    @BeforeAll
    static void before() throws Exception
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        jsl = Security.getProvider(JostleProvider.PROVIDER_NAME);
        Assertions.assertNotNull(jsl, "the base provider did not register");
        Assertions.assertNotNull(Security.getProvider(BC),
                "BouncyCastle is not registered, so every cell here would compare us with ourselves");
        certificate = CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(BcFKSFixtures.TRUSTED_CERT_DATA));
    }

    private static String jslName()
    {
        return JostleProvider.PROVIDER_NAME;
    }

    /** A fresh password per cell, so no cell can pass on a value another set up. */
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

    // ---- The completeness guard --------------------------------------------

    /**
     * Every KeyStore name this SPI is registered under is driven, aliases
     * included. The vacuity check asks for the TYPE-QUALIFIED name, because
     * asking for {@code BCFKS} alone answers false on a provider serving it.
     */
    @Test
    public void everyRegisteredBcfksNameIsDriven() throws Exception
    {
        SortedSet<String> registered = ProviderSurfaceGuard.registeredSurface(jsl,
                "org.openssl.jostle.jcajce.provider.", new String[]{"KeyStore"});
        Assertions.assertFalse(registered.isEmpty(),
                "no KeyStore services discovered, so this guard would pass vacuously");
        Assertions.assertTrue(registered.contains("KeyStore.BCFKS"),
                "BCFKS is absent from the registered KeyStore surface: " + registered);

        SortedSet<String> bcfksNames = bcfksNames(jsl);
        Assertions.assertFalse(bcfksNames.isEmpty(),
                "no registered name resolves to the BCFKS SPI, so the sweep below drives nothing");

        char[] password = password();
        List<String> failures = new ArrayList<String>();
        for (String name : bcfksNames)
        {
            try
            {
                KeyStore store = KeyStore.getInstance(name, jslName());
                store.load(null, null);
                store.setCertificateEntry("cert", certificate);
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                store.store(out, password);

                KeyStore back = KeyStore.getInstance("BCFKS", BC);
                back.load(new ByteArrayInputStream(out.toByteArray()), password);
                Assertions.assertEquals(1, back.size(), name);
            }
            catch (Throwable t)
            {
                failures.add(name + " -> " + t.getClass().getSimpleName() + ": " + t.getMessage());
            }
        }
        Assertions.assertTrue(failures.isEmpty(),
                "registered BCFKS names that could not be driven (" + failures.size() + " of "
                        + bcfksNames.size() + "):\n  " + String.join("\n  ", failures));
    }

    /** Every registered name, primary or alias, whose SPI class is the BCFKS one. */
    static SortedSet<String> bcfksNames(Provider provider)
    {
        Map<String, String> classNames = ProviderSurfaceGuard.registeredClassNames(provider,
                "org.openssl.jostle.jcajce.provider.", new String[]{"KeyStore"});
        SortedSet<String> out = new TreeSet<String>();
        for (Map.Entry<String, String> entry : classNames.entrySet())
        {
            if (BcFKSKeyStoreSpi.class.getName().equals(entry.getValue()))
            {
                out.add(entry.getKey().substring("KeyStore.".length()));
            }
        }
        return out;
    }

    // ---- The writer-option matrix, both directions -------------------------

    @Test
    public void everyWriterOptionRoundTripsThroughBouncyCastleBothDirections() throws Exception
    {
        Map<String, BcFKSWriterOptions.Option> options = BcFKSWriterOptions.options();
        Assertions.assertFalse(options.isEmpty(), "the writer-option table is empty");

        List<String> failures = new ArrayList<String>();
        java.util.Set<String> distinctBcStores = new java.util.HashSet<String>();
        for (BcFKSWriterOptions.Option option : options.values())
        {
            char[] password = password();
            byte[] written;
            try
            {
                KeyStore store = KeyStore.getInstance("BCFKS", jslName());
                store.load(null, null);
                store.setCertificateEntry("cert", certificate);
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                store.store(option.configure.apply(
                        new BCFKSLoadStoreParameter.Builder(out, password)).build());
                written = out.toByteArray();
            }
            catch (Throwable t)
            {
                failures.add(option.name + ": write failed -- " + t.getClass().getSimpleName()
                        + ": " + t.getMessage());
                continue;
            }

            try
            {
                KeyStore viaBc = KeyStore.getInstance("BCFKS", BC);
                viaBc.load(new ByteArrayInputStream(written), password);
                Assertions.assertEquals(1, viaBc.size(), option.name);
                Assertions.assertArrayEquals(certificate.getEncoded(),
                        viaBc.getCertificate("cert").getEncoded(), option.name);
            }
            catch (Throwable t)
            {
                failures.add(option.name + ": BouncyCastle could not read our store -- "
                        + t.getClass().getSimpleName() + ": " + t.getMessage());
            }

            // The other direction drives BouncyCastle's writer with the SAME
            // option, through its own builder. Letting BC default here would
            // write one identical store for every row.
            try
            {
                KeyStore bcStore = KeyStore.getInstance("BCFKS", BC);
                bcStore.load(null, null);
                bcStore.setCertificateEntry("cert", certificate);
                ByteArrayOutputStream bcOut = new ByteArrayOutputStream();
                bcStore.store(option.configureBc.apply(
                        new org.bouncycastle.jcajce.BCFKSLoadStoreParameter.Builder(bcOut, password))
                        .build());

                KeyStore back = KeyStore.getInstance("BCFKS", jslName());
                back.load(new ByteArrayInputStream(bcOut.toByteArray()), password);
                Assertions.assertEquals(1, back.size(), option.name);
                Assertions.assertArrayEquals(certificate.getEncoded(),
                        back.getCertificate("cert").getEncoded(), option.name);

                // Both writers, given the same option, must choose the same
                // algorithms. Without this the BC column is wired but never
                // checked -- a row pointed at the wrong value would still
                // write a store we read perfectly well.
                Assertions.assertEquals(storeShape(written), storeShape(bcOut.toByteArray()),
                        option.name + ": the two writers disagree on what this option means");
                distinctBcStores.add(storeShape(bcOut.toByteArray()));
            }
            catch (Throwable t)
            {
                failures.add(option.name + ": we could not read BouncyCastle's store -- "
                        + t.getClass().getSimpleName() + ": " + t.getMessage());
            }
        }
        Assertions.assertTrue(failures.isEmpty(),
                "writer options that did not interoperate (" + failures.size() + " of "
                        + options.size() + "):\n  " + String.join("\n  ", failures));
        Assertions.assertTrue(distinctBcStores.size() > 1,
                "every row produced the same BouncyCastle store, so the BC column is inert and"
                        + " that direction is testing one option " + options.size() + " times");
    }

    /**
     * Every writer option the API offers has a row in the table. Re-derived
     * from the enums each run, so a row cannot be deleted and leave the sweep
     * above simply testing less -- which is what a deleted row does, silently,
     * to a sweep that only iterates the table.
     */
    @Test
    public void everyWriterOptionTheApiOffersHasATableRow()
    {
        Map<String, BcFKSWriterOptions.Option> options = BcFKSWriterOptions.options();
        List<String> missing = new ArrayList<String>();

        for (BCFKSLoadStoreParameter.EncryptionAlgorithm algorithm
                : BCFKSLoadStoreParameter.EncryptionAlgorithm.values())
        {
            require(options, "encryption " + algorithm, missing);
        }
        for (BCFKSLoadStoreParameter.MacAlgorithm algorithm
                : BCFKSLoadStoreParameter.MacAlgorithm.values())
        {
            require(options, "mac " + algorithm, missing);
        }
        for (BCFKSLoadStoreParameter.PBKDF2Config.PRF prf
                : BCFKSLoadStoreParameter.PBKDF2Config.PRF.values())
        {
            require(options, "pbkdf2 prf " + prf, missing);
        }
        // The two rows with no enum to derive them from, named so deleting
        // either fails here rather than shrinking the sweep.
        require(options, "default", missing);
        require(options, "scrypt N=1024 r=8 p=1", missing);

        Assertions.assertTrue(missing.isEmpty(),
                "writer options the API offers with no row in the table (" + missing.size()
                        + "):\n  " + String.join("\n  ", missing));

        int expected = BCFKSLoadStoreParameter.EncryptionAlgorithm.values().length
                + BCFKSLoadStoreParameter.MacAlgorithm.values().length
                + BCFKSLoadStoreParameter.PBKDF2Config.PRF.values().length + 2;
        Assertions.assertEquals(expected, options.size(),
                "the table carries a row the API does not offer, or has lost one");
    }

    private static void require(Map<String, BcFKSWriterOptions.Option> options, String name,
                                List<String> missing)
    {
        if (!options.containsKey(name))
        {
            missing.add(name);
        }
    }

    @Test
    public void everyEntryTypeRoundTripsThroughBouncyCastle() throws Exception
    {
        Map<Integer, BcFKSWriterOptions.EntryType> types =
                BcFKSWriterOptions.entryTypes(jslName());
        Assertions.assertFalse(types.isEmpty(), "the entry-type table is empty");

        List<String> failures = new ArrayList<String>();
        for (BcFKSWriterOptions.EntryType type : types.values())
        {
            char[] password = password();
            try
            {
                KeyStore store = KeyStore.getInstance("BCFKS", jslName());
                store.load(null, null);
                type.setter.set(store, certificate, password);
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                store.store(out, password);

                KeyStore viaBc = KeyStore.getInstance("BCFKS", BC);
                viaBc.load(new ByteArrayInputStream(out.toByteArray()), password);
                Assertions.assertEquals(1, viaBc.size(), type.name);
                Assertions.assertTrue(viaBc.containsAlias(type.alias), type.name);

                KeyStore back = KeyStore.getInstance("BCFKS", jslName());
                back.load(new ByteArrayInputStream(out.toByteArray()), password);
                Assertions.assertEquals(1, back.size(), type.name);
            }
            catch (Throwable t)
            {
                failures.add(type.name + " -> " + t.getClass().getSimpleName() + ": " + t.getMessage());
            }
        }
        Assertions.assertTrue(failures.isEmpty(),
                "entry types that did not round-trip (" + failures.size() + " of " + types.size()
                        + "):\n  " + String.join("\n  ", failures));
    }

    @Test
    public void everySignatureCheckAlgorithmRoundTrips() throws Exception
    {
        List<String> failures = new ArrayList<String>();
        BCFKSLoadStoreParameter.SignatureAlgorithm[] algorithms =
                BCFKSLoadStoreParameter.SignatureAlgorithm.values();
        Assertions.assertTrue(algorithms.length > 0, "no signature algorithms are declared");

        for (BCFKSLoadStoreParameter.SignatureAlgorithm algorithm : algorithms)
        {
            try
            {
                KeyPair pair = signingPair(BcFKSWriterOptions.keyAlgorithmFor(algorithm));
                KeyStore store = KeyStore.getInstance("BCFKS", jslName());
                store.load(null, null);
                store.setCertificateEntry("cert", certificate);
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                store.store(new BCFKSLoadStoreParameter.Builder(out, pair.getPrivate())
                        .withStoreSignatureAlgorithm(algorithm).build());

                KeyStore back = KeyStore.getInstance("BCFKS", jslName());
                back.load(new BCFKSLoadStoreParameter.Builder(
                        new ByteArrayInputStream(out.toByteArray()), pair.getPublic()).build());
                Assertions.assertEquals(1, back.size(), algorithm.name());
            }
            catch (Throwable t)
            {
                failures.add(algorithm + " -> " + t.getClass().getSimpleName() + ": " + t.getMessage());
            }
        }
        Assertions.assertTrue(failures.isEmpty(),
                "signature-check algorithms that did not round-trip (" + failures.size() + " of "
                        + algorithms.length + "):\n  " + String.join("\n  ", failures));
    }

    private static KeyPair signingPair(String keyAlgorithm) throws Exception
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
        return generator.generateKeyPair();
    }

    /**
     * A store's identifying shape: the algorithm identifiers its writer chose,
     * including the PBKDF2 PRF. Without the PRF the two prf rows and the
     * default row share a shape, so a check built on it reaches neither.
     */
    private static String storeShape(byte[] store) throws Exception
    {
        BcFKSFormat.ObjectStore parsed = BcFKSFormat.parseObjectStore(store);
        BcFKSFormat.EncryptedObjectStoreData encrypted =
                BcFKSFormat.parseEncryptedObjectStoreData(parsed.storeDataRaw);
        Der.Pbes2Params pbes2 =
                new Der.Reader(encrypted.encryptionAlgorithm.parameters).readPbes2Params("PBES2-params");

        String prf = "no-prf";
        if (BcFKSLimitDriver.PBKDF2_OID.equals(pbes2.keyDerivationFunc.oid))
        {
            Der.Pbkdf2Params params = new Der.Reader(pbes2.keyDerivationFunc.parameters)
                    .readPbkdf2Params("PBKDF2-params");
            prf = params.prf == null ? "default-prf" : params.prf.oid;
        }
        return pbes2.encryptionScheme.oid + "|" + pbes2.keyDerivationFunc.oid + "|" + prf + "|"
                + parsed.integrityCheck.pbkdMac.macAlgorithm.oid;
    }

    // ---- Parity: the same bytes, the same exception TYPE -------------------

    /**
     * Both providers refuse the same malformed stores with the same exception
     * type. Messages stay ours; the type is what a caller's catch block binds
     * to, so the type is what parity means here.
     */
    @Test
    public void malformedStoresAreRefusedWithTheSameTypeAsBouncyCastle() throws Exception
    {
        char[] password = password();
        byte[] store = BcFKSLimitDriver.minimalStore(jslName(), password);
        Map<String, BcFKSLimitDriver.Malformation> table =
                BcFKSLimitDriver.namedMalformations(store, password);
        Assertions.assertFalse(table.isEmpty(), "the malformation table is empty");

        List<String> divergent = new ArrayList<String>();
        int agreed = 0;
        for (BcFKSLimitDriver.Malformation malformation : table.values())
        {
            if (DIVERGENT_MALFORMATIONS.contains(malformation.name))
            {
                continue;
            }
            BcFKSLimitDriver.Outcome ours =
                    BcFKSLimitDriver.load(jslName(), malformation.bytes, malformation.password);
            BcFKSLimitDriver.Outcome theirs =
                    BcFKSLimitDriver.load(BC, malformation.bytes, malformation.password);
            if (ours.type != theirs.type)
            {
                divergent.add(malformation.name + ": ours " + ours + ", BouncyCastle " + theirs);
            }
            else
            {
                agreed++;
            }
        }
        Assertions.assertTrue(agreed > 0, "no malformation was compared, so this cell is vacuous");
        Assertions.assertTrue(divergent.isEmpty(),
                "malformations where the two providers' exception TYPE differs, and which are not"
                        + " listed as known divergences (" + divergent.size() + "):\n  "
                        + String.join("\n  ", divergent));
    }

    /**
     * The malformations where the two deliberately disagree. Each has its own
     * cell below pinning BOTH halves; listing the name here keeps the sweep
     * above honest rather than letting a divergence hide in it.
     */
    private static final List<String> DIVERGENT_MALFORMATIONS = java.util.Arrays.asList(
            "trailing zero byte after the outer SEQUENCE",
            "trailing NULL TLV after the outer SEQUENCE",
            "indefinite length on the outer SEQUENCE",
            "non-minimal long-form outer length",
            "zero-length input",
            "an integrity-check iteration count of zero",
            "an unrecognised MAC algorithm OID");

    @Test
    public void everyListedDivergenceIsStillADivergence() throws Exception
    {
        char[] password = password();
        byte[] store = BcFKSLimitDriver.minimalStore(jslName(), password);
        Map<String, BcFKSLimitDriver.Malformation> table =
                BcFKSLimitDriver.namedMalformations(store, password);

        List<String> stale = new ArrayList<String>();
        for (String name : DIVERGENT_MALFORMATIONS)
        {
            BcFKSLimitDriver.Malformation malformation = table.get(name);
            if (malformation == null)
            {
                stale.add(name + ": no malformation of this name exists any more");
                continue;
            }
            BcFKSLimitDriver.Outcome ours =
                    BcFKSLimitDriver.load(jslName(), malformation.bytes, malformation.password);
            BcFKSLimitDriver.Outcome theirs =
                    BcFKSLimitDriver.load(BC, malformation.bytes, malformation.password);
            if (ours.type == theirs.type)
            {
                stale.add(name + ": both providers now answer " + ours.type
                        + ", so this entry is stale and the row belongs in the parity sweep");
            }
        }
        Assertions.assertTrue(stale.isEmpty(),
                "divergence entries that have outlived their reason (" + stale.size() + "):\n  "
                        + String.join("\n  ", stale));
    }

    /**
     * We refuse trailing bytes after the outer SEQUENCE and an indefinite
     * length; BouncyCastle accepts both. Ours is the stricter reading and the
     * correct one for a blob decode -- a store is one object, not a stream.
     * If a bcprov release starts refusing these, this cell reddens: delete the
     * line for whichever half changed rather than loosening ours.
     */
    @Test
    public void weRefuseTrailingBytesAndIndefiniteLengthWhereBouncyCastleAccepts() throws Exception
    {
        assertWeRefuseWhereBouncyCastleAccepts("trailing zero byte after the outer SEQUENCE");
        assertWeRefuseWhereBouncyCastleAccepts("indefinite length on the outer SEQUENCE");
    }

    /**
     * The malformation named in the table, refused by us and accepted by
     * BouncyCastle. Taking the bytes from the table rather than rebuilding them
     * keeps a divergence cell and the table it names from drifting apart.
     */
    private void assertWeRefuseWhereBouncyCastleAccepts(String name) throws Exception
    {
        char[] password = password();
        byte[] store = BcFKSLimitDriver.minimalStore(jslName(), password);
        BcFKSLimitDriver.Malformation malformation =
                BcFKSLimitDriver.namedMalformations(store, password).get(name);
        Assertions.assertNotNull(malformation, "no malformation named " + name);

        Assertions.assertEquals(IOException.class,
                BcFKSLimitDriver.load(jslName(), malformation.bytes, malformation.password).type, name);
        Assertions.assertTrue(
                BcFKSLimitDriver.load(BC, malformation.bytes, malformation.password).accepted(),
                "BouncyCastle now refuses " + name + "; this divergence has closed");
    }

    /**
     * A non-minimal long-form length: we refuse, BouncyCastle accepts. Same
     * class as the indefinite-length divergence above -- DER admits one
     * encoding of a length and BouncyCastle reads BER here.
     */
    @Test
    public void weRefuseANonMinimalLengthWhereBouncyCastleAccepts() throws Exception
    {
        assertWeRefuseWhereBouncyCastleAccepts("non-minimal long-form outer length");
    }

    /**
     * A design difference, not a defect on either side: the MAC algorithm OID
     * comes from the store bytes, so an unknown one is a malformed-store
     * refusal and takes this surface's single type for hostile input. We wrap
     * it as an IOException carrying the cause; BouncyCastle lets the more
     * specific NoSuchAlgorithmException out. Both are declared on
     * {@code KeyStore.load}.
     */
    @Test
    public void anUnknownMacAlgorithmOidIsAnIoExceptionForUsAndNotForBouncyCastle() throws Exception
    {
        char[] password = password();
        byte[] store = BcFKSLimitDriver.minimalStore(jslName(), password);
        BcFKSLimitDriver.Malformation malformation = BcFKSLimitDriver
                .namedMalformations(store, password).get("an unrecognised MAC algorithm OID");
        Assertions.assertNotNull(malformation, "the malformation table no longer carries this row");

        BcFKSLimitDriver.Outcome ours =
                BcFKSLimitDriver.load(jslName(), malformation.bytes, malformation.password);
        Assertions.assertEquals(IOException.class, ours.type);
        Assertions.assertTrue(ours.message.contains("cannot set up MAC calculation"), ours.message);

        BcFKSLimitDriver.Outcome theirs =
                BcFKSLimitDriver.load(BC, malformation.bytes, malformation.password);
        Assertions.assertEquals(java.security.NoSuchAlgorithmException.class, theirs.type,
                "BouncyCastle no longer lets NoSuchAlgorithmException out here");
    }

    /**
     * Zero-length input and a zero iteration count: we refuse typed, BouncyCastle
     * raises an unchecked exception from a method declared to throw
     * {@link IOException}. Ours is correct; BC's is a defect on their side, so
     * this cell reddens when they fix it and the line should then be deleted.
     */
    @Test
    public void weRefuseTypedWhereBouncyCastleRaisesAnUncheckedException() throws Exception
    {
        char[] password = password();
        byte[] store = BcFKSLimitDriver.minimalStore(jslName(), password);

        BcFKSLimitDriver.Outcome ourEmpty = BcFKSLimitDriver.load(jslName(), new byte[0], password);
        Assertions.assertEquals(IOException.class, ourEmpty.type);
        BcFKSLimitDriver.Outcome theirEmpty = BcFKSLimitDriver.load(BC, new byte[0], password);
        Assertions.assertEquals(NullPointerException.class, theirEmpty.type,
                "BouncyCastle no longer NPEs on empty input; delete this half of the divergence");

        byte[] zeroIterations = BcFKSLimitDriver.spliceAt(store,
                BcFKSLimitDriver.macIterationCount(store).start, Der.integer(0));
        BcFKSLimitDriver.Outcome ourZero = BcFKSLimitDriver.load(jslName(), zeroIterations, password);
        Assertions.assertEquals(IOException.class, ourZero.type);
        Assertions.assertEquals("BCFKS KeyStore: invalid iteration count", ourZero.message);
        BcFKSLimitDriver.Outcome theirZero = BcFKSLimitDriver.load(BC, zeroIterations, password);
        Assertions.assertEquals(IllegalArgumentException.class, theirZero.type,
                "BouncyCastle no longer raises IllegalArgumentException on a zero iteration count;"
                        + " delete this half of the divergence");
    }

    /**
     * Entry-level divergences, reached through a forged MAC-valid store because
     * the MAC check answers everything otherwise. Ours are all typed JCA
     * exceptions; several of BouncyCastle's are raw.
     */
    @Test
    public void entryLevelRefusalsDivergeFromBouncyCastleInOurFavour() throws Exception
    {
        char[] password = password();
        BcFKSKeyStoreSpi spi = new BcFKSKeyStoreSpi(jsl,
                org.openssl.jostle.jcajce.provider.NISelector.KdfNI,
                org.openssl.jostle.jcajce.provider.NISelector.MemoryHardKdfNI,
                org.openssl.jostle.jcajce.provider.NISelector.Asn1NI,
                org.openssl.jostle.jcajce.provider.NISelector.SpecNI);

        // getKey on a certificate entry: the JCA contract says null.
        byte[] certificateEntry = BcFKSLimitDriver.forge(jsl, spi, password,
                BcFKSLimitDriver.entry(BcFKSFormat.ObjectData.TYPE_CERTIFICATE, "c", new byte[]{1}));
        KeyStore ours = KeyStore.getInstance("BCFKS", jslName());
        ours.load(new ByteArrayInputStream(certificateEntry), password);
        Assertions.assertNull(ours.getKey("c", password),
                "the JCA contract answers null for getKey on a certificate entry");

        KeyStore theirs = KeyStore.getInstance("BCFKS", BC);
        theirs.load(new ByteArrayInputStream(certificateEntry), password);
        Assertions.assertThrows(UnrecoverableKeyException.class, () -> theirs.getKey("c", password),
                "BouncyCastle no longer throws for getKey on a certificate entry;"
                        + " delete this half of the divergence");

        // Junk key payloads: ours typed, BouncyCastle raw.
        byte[] junkKey = BcFKSLimitDriver.forge(jsl, spi, password,
                BcFKSLimitDriver.entry(BcFKSFormat.ObjectData.TYPE_SECRET_KEY, "k",
                        new byte[]{1, 2, 3}));
        KeyStore oursJunk = KeyStore.getInstance("BCFKS", jslName());
        oursJunk.load(new ByteArrayInputStream(junkKey), password);
        Assertions.assertThrows(UnrecoverableKeyException.class,
                () -> oursJunk.getKey("k", password));

        KeyStore theirsJunk = KeyStore.getInstance("BCFKS", BC);
        theirsJunk.load(new ByteArrayInputStream(junkKey), password);
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> theirsJunk.getKey("k", password),
                "BouncyCastle now refuses a junk key payload typed; delete this half");
    }

    // ---- Parity over the whole cut sweep -----------------------------------

    /**
     * Every length-consistent cut driven through BOTH providers. One
     * disagreement is expected and named; a second would mean a real change.
     */
    @Test
    public void everyCutIsRefusedWithTheSameTypeExceptTheEmptyOne() throws Exception
    {
        char[] password = password();
        byte[] store = BcFKSLimitDriver.minimalStore(jslName(), password);
        SortedSet<Integer> cuts = BcFKSLimitDriver.cutOffsets(store);
        Assertions.assertFalse(cuts.isEmpty(), "no cut offsets were generated");

        List<String> divergent = new ArrayList<String>();
        int agreed = 0;
        for (int cut : cuts)
        {
            byte[] bytes = BcFKSLimitDriver.cutAt(store, cut);
            BcFKSLimitDriver.Outcome ours = BcFKSLimitDriver.load(jslName(), bytes, password);
            BcFKSLimitDriver.Outcome theirs = BcFKSLimitDriver.load(BC, bytes, password);
            if (ours.type == theirs.type)
            {
                agreed++;
            }
            else
            {
                divergent.add("cut " + cut + " (" + bytes.length + " bytes): ours " + ours.type
                        + ", BouncyCastle " + theirs.type);
            }
        }
        Assertions.assertTrue(agreed > 0, "no cut was compared, so this cell is vacuous");
        Assertions.assertEquals(1, divergent.size(),
                "expected exactly one cut where the two providers' type differs -- the empty one,"
                        + " where BouncyCastle NPEs -- but found " + divergent.size() + ":\n  "
                        + String.join("\n  ", divergent));
        Assertions.assertTrue(divergent.get(0).startsWith("cut 0 "),
                "the single divergent cut is no longer the empty one: " + divergent.get(0));
    }

    // ---- BouncyCastle's own recorded stores --------------------------------

    /**
     * Stores BouncyCastle wrote, committed as fixtures. A recorded artefact is
     * a weaker witness than driving BouncyCastle live, so these sit beside the
     * live cells rather than standing for them -- but they pin the wire format
     * against a release that is no longer on the classpath.
     */
    @Test
    public void recordedBouncyCastleStoresStillLoad() throws Exception
    {
        KeyStore kwp = KeyStore.getInstance("BCFKS", jslName());
        kwp.load(new ByteArrayInputStream(BcFKSFixtures.KWP_KEY_STORE),
                BcFKSKeyStoreSpiTest.testPassword);
        Assertions.assertEquals(4, kwp.size());

        KeyStore legacyScrypt = KeyStore.getInstance("BCFKS", jslName());
        legacyScrypt.load(new ByteArrayInputStream(BcFKSFixtures.LEGACY_SCRYPT_KEY_STORE),
                "hello world".toCharArray());
        Assertions.assertEquals(1, legacyScrypt.size());

        KeyStore noPassword = KeyStore.getInstance("BCFKS", jslName());
        noPassword.load(new ByteArrayInputStream(BcFKSFixtures.OLD_KEY_STORE_NO_PW), new char[0]);
        Assertions.assertEquals(1, noPassword.size());

        KeyStore withPassword = KeyStore.getInstance("BCFKS", jslName());
        withPassword.load(new ByteArrayInputStream(BcFKSFixtures.OLD_KEY_STORE),
                BcFKSKeyStoreSpiTest.testPassword);
        Assertions.assertEquals(1, withPassword.size());
        Assertions.assertEquals(2, withPassword.getCertificateChain("privkey").length);

        // Signature-checked rather than MAC-checked: with no MAC to settle the
        // scrypt parallelization convention, this reaches the retry at store
        // decryption instead.
        PublicKey verificationKey = KeyFactory.getInstance("EC", jslName())
                .generatePublic(new X509EncodedKeySpec(BcFKSFixtures.LEGACY_SCRYPT_SIGNED_KEY_STORE_PUB));
        KeyStore signed = KeyStore.getInstance("BCFKS", jslName());
        signed.load(new BCFKSLoadStoreParameter.Builder(
                new ByteArrayInputStream(BcFKSFixtures.LEGACY_SCRYPT_SIGNED_KEY_STORE),
                verificationKey).build());
        Assertions.assertArrayEquals(hex("000102030405060708090a0b0c0d0e0f"),
                signed.getKey("seckey", BcFKSKeyStoreSpiTest.testPassword).getEncoded());
    }

    // ---- Cells moved here because they compare us with BouncyCastle --------

    private static KeyStore fixtureStore() throws Exception
    {
        KeyStore store = KeyStore.getInstance("BCFKS", jslName());
        store.load(new ByteArrayInputStream(BcFKSFixtures.KWP_KEY_STORE),
                BcFKSKeyStoreSpiTest.testPassword);
        return store;
    }

    private static KeyStore freshStore(char[] storePassword) throws Exception
    {
        KeyStore store = KeyStore.getInstance("BCFKS", jslName());
        store.load(null, storePassword);
        return store;
    }

    private static byte[] hex(String s)
    {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++)
        {
            out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    /**
     * BouncyCastle answers getCreationDate with the ENTRY's lastModifiedDate,
     * not the store's creation date. Measured against the installed release
     * rather than a recorded date, so a change on their side reddens here.
     */
    @Test
    public void creationDateMatchesBouncyCastlePerEntry() throws Exception
    {
        KeyStore ours = fixtureStore();
        KeyStore theirs = KeyStore.getInstance("BCFKS", BC);
        theirs.load(new ByteArrayInputStream(BcFKSFixtures.KWP_KEY_STORE),
                BcFKSKeyStoreSpiTest.testPassword);

        for (String alias : new String[]{"secret2", "secret1", "privkey", "trusted"})
        {
            Assertions.assertEquals(theirs.getCreationDate(alias), ours.getCreationDate(alias), alias);
        }
    }

    /** The store-encryption CCM tag length a writer chose, read back off the wire. */
    private static int storeEncryptionCcmIcvBytes(byte[] storeBytes) throws Exception
    {
        BcFKSFormat.ObjectStore store = BcFKSFormat.parseObjectStore(storeBytes);
        BcFKSFormat.EncryptedObjectStoreData encrypted =
                BcFKSFormat.parseEncryptedObjectStoreData(store.storeDataRaw);
        Der.Pbes2Params pbes2 =
                new Der.Reader(encrypted.encryptionAlgorithm.parameters).readPbes2Params("PBES2-params");
        return new Der.Reader(pbes2.encryptionScheme.parameters)
                .readCcmParameters("CCMParameters").icvBytes;
    }

    /**
     * A divergence in what each writer CHOOSES, both halves pinned: BouncyCastle
     * takes its Cipher's default 8-octet CCM tag where we write 16. Neither is
     * wrong and both are read by the other, which the two assertions below show.
     */
    @Test
    public void bcWritesAnEightOctetCcmTagWhereWeWriteSixteen() throws Exception
    {
        char[] password = password();
        KeyStore theirs = KeyStore.getInstance("BCFKS", BC);
        theirs.load(null, password);
        theirs.setCertificateEntry("cert", certificate);
        ByteArrayOutputStream theirOut = new ByteArrayOutputStream();
        theirs.store(theirOut, password);
        Assertions.assertEquals(8, storeEncryptionCcmIcvBytes(theirOut.toByteArray()),
                "BouncyCastle no longer writes an 8-octet CCM tag; this divergence has closed");

        KeyStore ours = freshStore(password);
        ours.setCertificateEntry("cert", certificate);
        ByteArrayOutputStream ourOut = new ByteArrayOutputStream();
        ours.store(ourOut, password);
        Assertions.assertEquals(16, storeEncryptionCcmIcvBytes(ourOut.toByteArray()));

        // Each reads the other, so the divergence is a choice and not a break.
        KeyStore weReadTheirs = KeyStore.getInstance("BCFKS", jslName());
        weReadTheirs.load(new ByteArrayInputStream(theirOut.toByteArray()), password);
        Assertions.assertEquals(1, weReadTheirs.size());

        KeyStore theyReadOurs = KeyStore.getInstance("BCFKS", BC);
        theyReadOurs.load(new ByteArrayInputStream(ourOut.toByteArray()), password);
        Assertions.assertEquals(1, theyReadOurs.size());
    }

    /** A wrong per-ENTRY password is UnrecoverableKeyException on both sides. */
    @Test
    public void wrongPerKeyPasswordFailsUnrecoverableOnBothSides() throws Exception
    {
        KeyStore source = fixtureStore();
        PrivateKey privateKey =
                (PrivateKey) source.getKey("privkey", BcFKSKeyStoreSpiTest.testPassword);
        Certificate[] chain = source.getCertificateChain("privkey");

        char[] storePassword = password();
        char[] keyPassword = password();
        char[] wrongKeyPassword = password();

        KeyStore fresh = freshStore(storePassword);
        fresh.setKeyEntry("mykey", privateKey, keyPassword, chain);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        fresh.store(out, storePassword);

        KeyStore ours = KeyStore.getInstance("BCFKS", jslName());
        ours.load(new ByteArrayInputStream(out.toByteArray()), storePassword);
        Assertions.assertThrows(UnrecoverableKeyException.class,
                () -> ours.getKey("mykey", wrongKeyPassword));

        KeyStore theirs = KeyStore.getInstance("BCFKS", BC);
        theirs.load(new ByteArrayInputStream(out.toByteArray()), storePassword);
        Assertions.assertThrows(UnrecoverableKeyException.class,
                () -> theirs.getKey("mykey", wrongKeyPassword));
    }

    private static Class<? extends Throwable> setKeyEntryRefusal(KeyStore store, Key key,
                                                                 char[] password, Certificate[] chain)
    {
        try
        {
            store.setKeyEntry("x", key, password, chain);
        }
        catch (Exception e)
        {
            return e.getClass();
        }
        return Assertions.fail(store.getProvider().getName()
                + " did not refuse an entry it should have refused");
    }

    private static Class<? extends Throwable> setCertificateEntryRefusal(KeyStore store, String alias,
                                                                        Certificate cert)
    {
        try
        {
            store.setCertificateEntry(alias, cert);
        }
        catch (Exception e)
        {
            return e.getClass();
        }
        return Assertions.fail(store.getProvider().getName()
                + " did not refuse an entry it should have refused");
    }

    /**
     * The three setter-side refusals, each asserting BOTH sides' type. These
     * are write-path refusals rather than load-path ones, so no malformed-store
     * cell reaches them.
     */
    @Test
    public void setterRefusalsCarryTheSameTypeAsBouncyCastle() throws Exception
    {
        KeyStore source = fixtureStore();
        PrivateKey privateKey =
                (PrivateKey) source.getKey("privkey", BcFKSKeyStoreSpiTest.testPassword);
        SecretKey secret = (SecretKey) source.getKey("secret1", "secretPwd1".toCharArray());
        Certificate trusted = source.getCertificate("trusted");
        char[] password = password();

        KeyStore ours = freshStore(password);
        KeyStore theirs = KeyStore.getInstance("BCFKS", BC);
        theirs.load(null, password);
        Assertions.assertEquals(setKeyEntryRefusal(theirs, privateKey, password, null),
                setKeyEntryRefusal(ours, privateKey, password, null),
                "a private key with no certificate chain");

        KeyStore oursChain = freshStore(password);
        KeyStore theirsChain = KeyStore.getInstance("BCFKS", BC);
        theirsChain.load(null, password);
        Certificate[] chain = new Certificate[]{trusted};
        Assertions.assertEquals(setKeyEntryRefusal(theirsChain, secret, password, chain),
                setKeyEntryRefusal(oursChain, secret, password, chain),
                "a secret key with a certificate chain");

        KeyStore oursOver = freshStore(password);
        oursOver.setKeyEntry("k", secret, password, null);
        KeyStore theirsOver = KeyStore.getInstance("BCFKS", BC);
        theirsOver.load(null, password);
        theirsOver.setKeyEntry("k", secret, password, null);
        Assertions.assertEquals(setCertificateEntryRefusal(theirsOver, "k", trusted),
                setCertificateEntryRefusal(oursOver, "k", trusted),
                "a certificate over an existing key alias");
    }
}
