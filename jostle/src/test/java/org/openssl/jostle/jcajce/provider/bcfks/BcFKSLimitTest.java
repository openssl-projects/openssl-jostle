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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.provider.kdf.BytePasswordKdf;
import org.openssl.jostle.util.asn1.Der;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.UnrecoverableKeyException;

/**
 * The BCFKS store's input-validation edges, driven with hostile bytes through
 * the base provider.
 *
 * <p>Every declared bound is probed at the bound and at bound plus one, and a
 * counting KDF proves the refusal happened BEFORE the derivation rather than
 * after it: wall time cannot tell a cheap derivation from no derivation.
 */
public class BcFKSLimitTest
{
    private static final char[] PASSWORD = "bcfks limit password".toCharArray();
    private static Provider jsl;

    @BeforeAll
    static void registerProvider()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        jsl = Security.getProvider(JostleProvider.PROVIDER_NAME);
        Assertions.assertNotNull(jsl, "the base provider did not register");
    }

    private static String provider()
    {
        return JostleProvider.PROVIDER_NAME;
    }

    private static byte[] store() throws Exception
    {
        return BcFKSLimitDriver.minimalStore(provider(), PASSWORD);
    }

    /** An SPI whose KDF calls are counted, so "did it derive" is answered by a number. */
    private static BcFKSKeyStoreSpi countingSpi(BcFKSLimitDriver.CountingKdfNI kdf,
                                                 BcFKSLimitDriver.CountingMemoryHardKdfNI memoryHard)
    {
        return new BcFKSKeyStoreSpi(jsl, kdf, memoryHard, NISelector.Asn1NI, NISelector.SpecNI);
    }

    // ---- The cut sweep -----------------------------------------------------

    /**
     * Cutting the store at every TLV boundary AND re-encoding the enclosing
     * lengths, so the cut reaches an inner decoder instead of stopping at the
     * outer length check.
     */
    @Test
    public void everyLengthConsistentCutIsRefusedTyped() throws Exception
    {
        BcFKSLimitDriver.assertEveryCutIsRefusedTyped(provider(), store(), PASSWORD);
    }

    /**
     * Raw truncation is a weaker probe than the cut above, kept to pin that
     * weakness: the outer length check answers at almost every offset, so this
     * is one check exercised many times rather than coverage.
     */
    @Test
    public void rawTruncationAlwaysStopsAtTheOuterLengthCheck() throws Exception
    {
        byte[] store = store();
        int reachedOuterCheck = 0;
        for (int length = 4; length < store.length; length++)
        {
            BcFKSLimitDriver.Outcome outcome = BcFKSLimitDriver.load(provider(),
                    java.util.Arrays.copyOf(store, length), PASSWORD);
            Assertions.assertEquals(IOException.class, outcome.type,
                    "raw truncation to " + length + " bytes -> " + outcome);
            if ("truncated content in ObjectStore".equals(outcome.message))
            {
                reachedOuterCheck++;
            }
        }
        Assertions.assertEquals(store.length - 4, reachedOuterCheck,
                "raw truncation no longer stops uniformly at the outer length check, so this cell"
                        + " has stopped measuring what it documents");
    }

    // ---- The named-malformation table --------------------------------------

    @Test
    public void everyNamedMalformationIsRefusedWithItsOwnMessage() throws Exception
    {
        BcFKSLimitDriver.assertEveryMalformationIsRefused(provider(), store(), PASSWORD, true);
    }

    /**
     * The property the whole class exists for, asserted once over every input
     * it builds: a caller handing this store arbitrary bytes gets a typed
     * refusal, never an unchecked throwable out of a method declared to throw
     * {@link IOException}.
     */
    @Test
    public void noUncheckedThrowableEscapesLoadOverTheWholeHostileSet() throws Exception
    {
        BcFKSLimitDriver.assertNoUncheckedThrowableEscapesLoad(provider(), store(), PASSWORD);
    }

    // ---- Trailing bytes, every blob decoder --------------------------------

    /**
     * A blob decoder consumes its input exactly. One object followed by a NULL
     * TLV is trailing garbage at every one of these entry points -- the
     * stream-reading contract, which permits a following object, belongs to the
     * certificate factory and not here.
     */
    @Test
    public void everyBlobDecoderRefusesTrailingBytes() throws Exception
    {
        BcFKSLimitDriver.assertEveryBlobDecoderRefusesTrailingBytes(store());
    }

    // ---- Bounds, at the bound and one past it ------------------------------

    @Test
    public void iterationCountFloorAndCapRefuseBeforeAnyDerivation() throws Exception
    {
        BcFKSLimitDriver.CountingKdfNI kdf = new BcFKSLimitDriver.CountingKdfNI(NISelector.KdfNI);
        BcFKSKeyStoreSpi spi = countingSpi(kdf,
                new BcFKSLimitDriver.CountingMemoryHardKdfNI(NISelector.MemoryHardKdfNI));

        int before = kdf.pbkdf2Calls.get();
        IOException zero = Assertions.assertThrows(IOException.class,
                () -> spi.deriveKey(BcFKSLimitDriver.pbkdf2(0, Integer.valueOf(32)),
                        BytePasswordKdf.PURPOSE_INTEGRITY_CHECK, PASSWORD, null, false));
        Assertions.assertEquals("BCFKS KeyStore: invalid iteration count", zero.getMessage());
        Assertions.assertEquals(before, kdf.pbkdf2Calls.get(),
                "a zero iteration count reached the KDF instead of being refused before it");

        long cap = BcFKSKeyStoreSpi.DEFAULT_MAX_IT_COUNT;
        IOException past = Assertions.assertThrows(IOException.class,
                () -> spi.deriveKey(BcFKSLimitDriver.pbkdf2((int) (cap + 1), Integer.valueOf(32)),
                        BytePasswordKdf.PURPOSE_INTEGRITY_CHECK, PASSWORD, null, false));
        Assertions.assertEquals("BCFKS KeyStore: iteration count (" + (cap + 1) + ") greater than " + cap,
                past.getMessage());
        Assertions.assertEquals(before, kdf.pbkdf2Calls.get(),
                "an over-cap iteration count reached the KDF instead of being refused before it");

        // The bound itself is accepted. Driven under a lowered property rather
        // than at the default, which is a real multi-second derivation; the
        // property is the documented override and the same code path.
        String property = BcFKSKeyStoreSpi.MAX_IT_COUNT_PROPERTY;
        String previous = System.getProperty(property);
        try
        {
            System.setProperty(property, "16");
            byte[] key = spi.deriveKey(BcFKSLimitDriver.pbkdf2(16, Integer.valueOf(32)),
                    BytePasswordKdf.PURPOSE_INTEGRITY_CHECK, PASSWORD, null, false);
            Assertions.assertEquals(32, key.length);
            Assertions.assertEquals(before + 1, kdf.pbkdf2Calls.get(),
                    "the at-bound derivation did not run, so the accepting half proves nothing");

            IOException overLowered = Assertions.assertThrows(IOException.class,
                    () -> spi.deriveKey(BcFKSLimitDriver.pbkdf2(17, Integer.valueOf(32)),
                            BytePasswordKdf.PURPOSE_INTEGRITY_CHECK, PASSWORD, null, false));
            Assertions.assertEquals("BCFKS KeyStore: iteration count (17) greater than 16",
                    overLowered.getMessage());
            Assertions.assertEquals(before + 1, kdf.pbkdf2Calls.get());
        }
        finally
        {
            restore(property, previous);
        }
    }

    @Test
    public void emptySaltIsRefusedOnBothKdfPathsBeforeAnyDerivation() throws Exception
    {
        BcFKSLimitDriver.CountingKdfNI kdf = new BcFKSLimitDriver.CountingKdfNI(NISelector.KdfNI);
        BcFKSLimitDriver.CountingMemoryHardKdfNI memoryHard =
                new BcFKSLimitDriver.CountingMemoryHardKdfNI(NISelector.MemoryHardKdfNI);
        BcFKSKeyStoreSpi spi = countingSpi(kdf, memoryHard);

        byte[] pbkdf2Params = Der.pbkdf2Params(new byte[0], 2048, Integer.valueOf(32),
                Der.algorithmIdentifier(BcFKSLimitDriver.HMAC_SHA512_OID, Der.nullValue()));
        IOException pbkdf2 = Assertions.assertThrows(IOException.class,
                () -> spi.deriveKey(
                        BcFKSLimitDriver.algorithmIdentifier(BcFKSLimitDriver.PBKDF2_OID, pbkdf2Params),
                        BytePasswordKdf.PURPOSE_INTEGRITY_CHECK, PASSWORD, null, false));
        Assertions.assertEquals("BCFKS KeyStore: empty salt", pbkdf2.getMessage());
        Assertions.assertEquals(0, kdf.pbkdf2Calls.get(),
                "an empty salt reached the PBKDF2 derivation");

        byte[] scryptParams = Der.scryptParams(new byte[0], 1024, 8, 1, Integer.valueOf(32));
        IOException scrypt = Assertions.assertThrows(IOException.class,
                () -> spi.deriveKey(
                        BcFKSLimitDriver.algorithmIdentifier(BcFKSLimitDriver.SCRYPT_OID, scryptParams),
                        BytePasswordKdf.PURPOSE_INTEGRITY_CHECK, PASSWORD, null, false));
        Assertions.assertEquals("BCFKS KeyStore: empty salt", scrypt.getMessage());
        Assertions.assertEquals(0, memoryHard.scryptCalls.get(),
                "an empty salt reached the scrypt derivation");

        // The same two paths accept a non-empty salt, so the refusal above is
        // about the salt and not about the whole parameter set.
        Assertions.assertEquals(32, spi.deriveKey(BcFKSLimitDriver.pbkdf2(2048, Integer.valueOf(32)),
                BytePasswordKdf.PURPOSE_INTEGRITY_CHECK, PASSWORD, null, false).length);
        Assertions.assertEquals(32, spi.deriveKey(BcFKSLimitDriver.scrypt(1024, 8, 1, Integer.valueOf(32)),
                BytePasswordKdf.PURPOSE_INTEGRITY_CHECK, PASSWORD, null, false).length);
        Assertions.assertEquals(1, kdf.pbkdf2Calls.get());
        Assertions.assertEquals(1, memoryHard.scryptCalls.get());
    }

    @Test
    public void keyLengthFloorAndCapRefuseBeforeAnyDerivation() throws Exception
    {
        BcFKSLimitDriver.CountingKdfNI kdf = new BcFKSLimitDriver.CountingKdfNI(NISelector.KdfNI);
        BcFKSKeyStoreSpi spi = countingSpi(kdf,
                new BcFKSLimitDriver.CountingMemoryHardKdfNI(NISelector.MemoryHardKdfNI));

        IOException zero = Assertions.assertThrows(IOException.class,
                () -> spi.deriveKey(BcFKSLimitDriver.pbkdf2(2048, Integer.valueOf(0)),
                        BytePasswordKdf.PURPOSE_INTEGRITY_CHECK, PASSWORD, null, false));
        Assertions.assertEquals("BCFKS KeyStore: invalid keyLength", zero.getMessage());

        // 1024 is the cap; it is private, so the bound is written here and the
        // message is required to name the same number, which is what makes the
        // literal answerable rather than a second source of truth.
        byte[] atCap = spi.deriveKey(BcFKSLimitDriver.pbkdf2(1, Integer.valueOf(1024)),
                BytePasswordKdf.PURPOSE_INTEGRITY_CHECK, PASSWORD, null, false);
        Assertions.assertEquals(1024, atCap.length);

        IOException past = Assertions.assertThrows(IOException.class,
                () -> spi.deriveKey(BcFKSLimitDriver.pbkdf2(1, Integer.valueOf(1025)),
                        BytePasswordKdf.PURPOSE_INTEGRITY_CHECK, PASSWORD, null, false));
        Assertions.assertEquals("BCFKS KeyStore: keyLength (1025) greater than 1024", past.getMessage());
        Assertions.assertEquals(1, kdf.pbkdf2Calls.get(),
                "only the at-cap derivation should have run");
    }

    @Test
    public void scryptBlockSizeAndMemoryBoundsRefuseBeforeAnyDerivation() throws Exception
    {
        BcFKSLimitDriver.CountingMemoryHardKdfNI memoryHard =
                new BcFKSLimitDriver.CountingMemoryHardKdfNI(NISelector.MemoryHardKdfNI);
        BcFKSKeyStoreSpi spi = countingSpi(
                new BcFKSLimitDriver.CountingKdfNI(NISelector.KdfNI), memoryHard);

        byte[] atBlockCap = spi.deriveKey(BcFKSLimitDriver.scrypt(2, 1024, 1, Integer.valueOf(32)),
                BytePasswordKdf.PURPOSE_INTEGRITY_CHECK, PASSWORD, null, false);
        Assertions.assertEquals(32, atBlockCap.length);
        Assertions.assertEquals(1, memoryHard.scryptCalls.get());

        IOException pastBlock = Assertions.assertThrows(IOException.class,
                () -> spi.deriveKey(BcFKSLimitDriver.scrypt(2, 1025, 1, Integer.valueOf(32)),
                        BytePasswordKdf.PURPOSE_INTEGRITY_CHECK, PASSWORD, null, false));
        Assertions.assertEquals("BCFKS KeyStore: scrypt block size (1025) greater than 1024",
                pastBlock.getMessage());

        IOException zeroBlock = Assertions.assertThrows(IOException.class,
                () -> spi.deriveKey(BcFKSLimitDriver.scrypt(2, 0, 1, Integer.valueOf(32)),
                        BytePasswordKdf.PURPOSE_INTEGRITY_CHECK, PASSWORD, null, false));
        Assertions.assertEquals("BCFKS KeyStore: invalid scrypt parameters", zeroBlock.getMessage());

        // The memory cap bounds N and the parallelization parameter against the
        // same figure, so both directions are probed.
        long maxCost = BcFKSKeyStoreSpi.DEFAULT_MAX_SCRYPT_MEMORY / (128L * 8);
        IOException pastCost = Assertions.assertThrows(IOException.class,
                () -> spi.deriveKey(BcFKSLimitDriver.scrypt(maxCost + 1, 8, 1, Integer.valueOf(32)),
                        BytePasswordKdf.PURPOSE_INTEGRITY_CHECK, PASSWORD, null, false));
        Assertions.assertTrue(pastCost.getMessage().contains("scrypt cost parameters require more than"),
                pastCost.getMessage());

        IOException pastParallel = Assertions.assertThrows(IOException.class,
                () -> spi.deriveKey(BcFKSLimitDriver.scrypt(2, 8, (int) Math.min(maxCost + 1,
                                Integer.MAX_VALUE), Integer.valueOf(32)),
                        BytePasswordKdf.PURPOSE_INTEGRITY_CHECK, PASSWORD, null, false));
        Assertions.assertTrue(pastParallel.getMessage().contains("scrypt cost parameters require more than"),
                pastParallel.getMessage());

        Assertions.assertEquals(1, memoryHard.scryptCalls.get(),
                "an out-of-range scrypt parameter reached the derivation");

        // The at-cap accept, under a lowered property: at the default it is a
        // real one-gibibyte derivation.
        String property = BcFKSKeyStoreSpi.MAX_SCRYPT_MEMORY_PROPERTY;
        String previous = System.getProperty(property);
        try
        {
            System.setProperty(property, "1048576");
            byte[] key = spi.deriveKey(BcFKSLimitDriver.scrypt(1024, 8, 1, Integer.valueOf(32)),
                    BytePasswordKdf.PURPOSE_INTEGRITY_CHECK, PASSWORD, null, false);
            Assertions.assertEquals(32, key.length);
            Assertions.assertEquals(2, memoryHard.scryptCalls.get());

            IOException overLowered = Assertions.assertThrows(IOException.class,
                    () -> spi.deriveKey(BcFKSLimitDriver.scrypt(1025, 8, 1, Integer.valueOf(32)),
                            BytePasswordKdf.PURPOSE_INTEGRITY_CHECK, PASSWORD, null, false));
            Assertions.assertEquals("BCFKS KeyStore: scrypt cost parameters require more than 1048576 bytes",
                    overLowered.getMessage());
            Assertions.assertEquals(2, memoryHard.scryptCalls.get());
        }
        finally
        {
            restore(property, previous);
        }
    }

    @Test
    public void wholeStoreCeilingIsEnforcedBeforeAnyDecoding() throws Exception
    {
        int ceiling = BcFKSFormat.DEFAULT_MAX_STORE_BYTES;
        Assertions.assertEquals(ceiling,
                BcFKSFormat.readWholeStore(new ByteArrayInputStream(new byte[ceiling])).length);

        IOException past = Assertions.assertThrows(IOException.class,
                () -> BcFKSFormat.readWholeStore(new ByteArrayInputStream(new byte[ceiling + 1])));
        Assertions.assertEquals("BCFKS store exceeds the " + ceiling + "-byte ceiling", past.getMessage());
    }

    /**
     * No bound on nesting depth is declared, and none is needed: the reader
     * hands back a sub-reader rather than recursing, and every container loop
     * is iterative. Asserted rather than assumed, because a future decoder that
     * recursed on input structure would be a stack-overflow reachable from a
     * caller's bytes and nothing else here would notice.
     */
    @Test
    public void deeplyNestedInputIsRefusedTypedRatherThanOverflowingTheStack() throws Exception
    {
        byte[] nested = nestedOf(100_000);
        IOException e = Assertions.assertThrows(IOException.class,
                () -> BcFKSFormat.parseObjectStore(nested));
        Assertions.assertTrue(e.getMessage().contains("storeData has 1 fields"), e.getMessage());
    }

    private static byte[] nestedOf(int depth)
    {
        byte[] nested = Der.sequence();
        for (int i = 0; i < depth; i++)
        {
            nested = Der.sequence(nested);
        }
        return nested;
    }

    // ---- The plain ObjectStoreData decoder ---------------------------------

    /**
     * Reached at the format surface on purpose: {@code engineStore} always
     * encrypts the store data, so no store this implementation writes can carry
     * a plain {@code ObjectStoreData} for {@code engineLoad} to decode.
     */
    @Test
    public void onlyVersionOneIsAcceptedByThePlainStoreDataDecoder() throws Exception
    {
        byte[] algorithmIdentifier =
                Der.algorithmIdentifier(BcFKSLimitDriver.HMAC_SHA512_OID, Der.nullValue());
        byte[] good = BcFKSFormat.writeObjectStoreData(algorithmIdentifier,
                BcFKSLimitDriver.FIXED_DATE, BcFKSLimitDriver.FIXED_DATE, new byte[0][], null);
        Assertions.assertEquals(1, BcFKSFormat.parseObjectStoreData(good).version);

        for (int version : new int[]{0, 2, 127, 255, 65535})
        {
            byte[] der = Der.sequence(Der.integer(version), algorithmIdentifier,
                    Der.generalizedTime(BcFKSLimitDriver.FIXED_DATE),
                    Der.generalizedTime(BcFKSLimitDriver.FIXED_DATE), Der.sequence());
            IOException e = Assertions.assertThrows(IOException.class,
                    () -> BcFKSFormat.parseObjectStoreData(der));
            Assertions.assertEquals("ObjectStoreData version " + version
                    + " is not supported (expected 1)", e.getMessage());
        }

        byte[] negative = Der.sequence(Der.integer(java.math.BigInteger.valueOf(-1)),
                algorithmIdentifier, Der.generalizedTime(BcFKSLimitDriver.FIXED_DATE),
                Der.generalizedTime(BcFKSLimitDriver.FIXED_DATE), Der.sequence());
        IOException e = Assertions.assertThrows(IOException.class,
                () -> BcFKSFormat.parseObjectStoreData(negative));
        Assertions.assertEquals("negative INTEGER in version", e.getMessage());
    }

    // ---- Forged, MAC-valid stores ------------------------------------------

    /**
     * A store whose MAC verifies but whose entries this implementation would
     * never write. Without forging one, every such cell is answered by the MAC
     * check and the dispatch below is never reached.
     */
    @Test
    public void unknownEntryTypesLoadAndThenRefuseTypedAtGetKey() throws Exception
    {
        BcFKSKeyStoreSpi spi = new BcFKSKeyStoreSpi(jsl, NISelector.KdfNI,
                NISelector.MemoryHardKdfNI, NISelector.Asn1NI, NISelector.SpecNI);

        int[] unknownTypes = {6, 7, 9, 127, 32767};
        for (int type : unknownTypes)
        {
            byte[] forged = BcFKSLimitDriver.forge(jsl, spi, PASSWORD,
                    BcFKSLimitDriver.entry(type, "a", new byte[]{1, 2, 3}));
            KeyStore store = KeyStore.getInstance("BCFKS", provider());
            store.load(new ByteArrayInputStream(forged), PASSWORD);

            Assertions.assertEquals(1, store.size(), "entry type " + type);
            Assertions.assertFalse(store.isKeyEntry("a"), "entry type " + type);
            Assertions.assertFalse(store.isCertificateEntry("a"), "entry type " + type);

            UnrecoverableKeyException e = Assertions.assertThrows(UnrecoverableKeyException.class,
                    () -> store.getKey("a", PASSWORD), "entry type " + type);
            Assertions.assertEquals("BCFKS KeyStore unable to recover key (a): type not recognized",
                    e.getMessage());
            Assertions.assertNull(store.getCertificate("a"), "entry type " + type);
        }
    }

    @Test
    public void malformedEntryPayloadsRefuseTypedAtGetKey() throws Exception
    {
        BcFKSKeyStoreSpi spi = new BcFKSKeyStoreSpi(jsl, NISelector.KdfNI,
                NISelector.MemoryHardKdfNI, NISelector.Asn1NI, NISelector.SpecNI);

        int[] keyTypes = {BcFKSFormat.ObjectData.TYPE_PRIVATE_KEY,
                BcFKSFormat.ObjectData.TYPE_SECRET_KEY, BcFKSFormat.ObjectData.TYPE_PBKDF_KEY};
        for (int type : keyTypes)
        {
            byte[] forged = BcFKSLimitDriver.forge(jsl, spi, PASSWORD,
                    BcFKSLimitDriver.entry(type, "k", new byte[]{1, 2, 3}));
            KeyStore store = KeyStore.getInstance("BCFKS", provider());
            store.load(new ByteArrayInputStream(forged), PASSWORD);

            UnrecoverableKeyException e = Assertions.assertThrows(UnrecoverableKeyException.class,
                    () -> store.getKey("k", PASSWORD), "entry type " + type);
            Assertions.assertTrue(e.getMessage().startsWith("BCFKS KeyStore unable to recover key (k):"),
                    e.getMessage());
        }
    }

    @Test
    public void duplicateAndEmptyAliasesLoadWithoutAnUncheckedThrowable() throws Exception
    {
        BcFKSKeyStoreSpi spi = new BcFKSKeyStoreSpi(jsl, NISelector.KdfNI,
                NISelector.MemoryHardKdfNI, NISelector.Asn1NI, NISelector.SpecNI);

        byte[] duplicate = BcFKSLimitDriver.forge(jsl, spi, PASSWORD,
                BcFKSLimitDriver.entry(BcFKSFormat.ObjectData.TYPE_CERTIFICATE, "dup", new byte[]{1}),
                BcFKSLimitDriver.entry(BcFKSFormat.ObjectData.TYPE_SECRET_KEY, "dup", new byte[]{2}));
        KeyStore duplicateStore = KeyStore.getInstance("BCFKS", provider());
        duplicateStore.load(new ByteArrayInputStream(duplicate), PASSWORD);
        Assertions.assertEquals(1, duplicateStore.size(),
                "two entries sharing an alias must collapse to one, last written winning");
        Assertions.assertThrows(UnrecoverableKeyException.class,
                () -> duplicateStore.getKey("dup", PASSWORD));

        byte[] empty = BcFKSLimitDriver.forge(jsl, spi, PASSWORD,
                BcFKSLimitDriver.entry(BcFKSFormat.ObjectData.TYPE_CERTIFICATE, "", new byte[]{1}));
        KeyStore emptyStore = KeyStore.getInstance("BCFKS", provider());
        emptyStore.load(new ByteArrayInputStream(empty), PASSWORD);
        Assertions.assertEquals(1, emptyStore.size());
        Assertions.assertTrue(emptyStore.isCertificateEntry(""));
    }

    @Test
    public void aStoreOfManyEntriesLoadsWithoutUnboundedCost() throws Exception
    {
        BcFKSKeyStoreSpi spi = new BcFKSKeyStoreSpi(jsl, NISelector.KdfNI,
                NISelector.MemoryHardKdfNI, NISelector.Asn1NI, NISelector.SpecNI);

        byte[][] entries = new byte[1000][];
        for (int i = 0; i < entries.length; i++)
        {
            entries[i] = BcFKSLimitDriver.entry(BcFKSFormat.ObjectData.TYPE_CERTIFICATE,
                    "a" + i, new byte[]{1});
        }
        byte[] forged = BcFKSLimitDriver.forge(jsl, spi, PASSWORD, entries);
        KeyStore store = KeyStore.getInstance("BCFKS", provider());
        store.load(new ByteArrayInputStream(forged), PASSWORD);
        Assertions.assertEquals(entries.length, store.size());
    }

    private static void restore(String property, String previous)
    {
        if (previous == null)
        {
            System.clearProperty(property);
        }
        else
        {
            System.setProperty(property, previous);
        }
    }
}
