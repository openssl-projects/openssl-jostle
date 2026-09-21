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
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.BCFKSLoadStoreParameter;
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.jcajce.provider.kdf.BytePasswordKdf;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.util.asn1.Der;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.Provider;

/**
 * The same hostile inputs as {@link BcFKSLimitTest}, driven through the FIPS
 * provider so the FIPS interface library and its own lib ctx answer them, plus
 * the one arm that exists only here: scrypt is not served, and both the write
 * and the read must refuse typed rather than reach into the base library.
 */
public class FIPSBcFKSLimitTest
{
    private static final char[] PASSWORD = "fips bcfks limit password".toCharArray();

    @BeforeEach
    void assumeFips()
    {
        Assumptions.assumeFalse(TestUtil.skipFipsTests(),
                "TEST_FIPS_LIB not set (full path to the FIPS module library)");
        // Register as well as gate: only the cells that built an SPI
        // registered JSLFIPS as a side effect, so results depended on order.
        TestUtil.addFipsProvider();
    }

    private static Provider provider()
    {
        return TestUtil.addFipsProvider();
    }

    private static String providerName()
    {
        return JostleFIPSProvider.PROVIDER_NAME;
    }

    private static byte[] store() throws Exception
    {
        return BcFKSLimitDriver.minimalStore(providerName(), PASSWORD);
    }

    /**
     * The FIPS SPI as the registrar builds it: {@code memoryHardKdfNI} is null,
     * which is what gives the typed scrypt refusal instead of a reach into the
     * base library.
     */
    private static BcFKSKeyStoreSpi fipsSpi(BcFKSLimitDriver.CountingKdfNI kdf)
    {
        return new BcFKSKeyStoreSpi(provider(), kdf, null,
                FIPSNISelector.Asn1NI, FIPSNISelector.SpecNI);
    }

    // ---- The shared families, through the FIPS library ---------------------

    @Test
    public void everyLengthConsistentCutIsRefusedTyped() throws Exception
    {
        BcFKSLimitDriver.assertEveryCutIsRefusedTyped(providerName(), store(), PASSWORD);
    }

    @Test
    public void everyNamedMalformationIsRefusedWithItsOwnMessage() throws Exception
    {
        BcFKSLimitDriver.assertEveryMalformationIsRefused(providerName(), store(), PASSWORD, false);
    }

    @Test
    public void noUncheckedThrowableEscapesLoadOverTheWholeHostileSet() throws Exception
    {
        BcFKSLimitDriver.assertNoUncheckedThrowableEscapesLoad(providerName(), store(), PASSWORD);
    }

    // ---- Bounds, through the FIPS KDF --------------------------------------

    @Test
    public void iterationCountFloorAndCapRefuseBeforeAnyDerivation() throws Exception
    {
        BcFKSLimitDriver.CountingKdfNI kdf = new BcFKSLimitDriver.CountingKdfNI(FIPSNISelector.KdfNI);
        BcFKSKeyStoreSpi spi = fipsSpi(kdf);

        IOException zero = Assertions.assertThrows(IOException.class,
                () -> spi.deriveKey(BcFKSLimitDriver.pbkdf2(0, Integer.valueOf(32)),
                        BytePasswordKdf.PURPOSE_INTEGRITY_CHECK, PASSWORD, null, false));
        Assertions.assertEquals("BCFKS KeyStore: invalid iteration count", zero.getMessage());
        Assertions.assertEquals(0, kdf.pbkdf2Calls.get(),
                "a zero iteration count reached the FIPS KDF instead of being refused before it");

        long cap = BcFKSKeyStoreSpi.DEFAULT_MAX_IT_COUNT;
        IOException past = Assertions.assertThrows(IOException.class,
                () -> spi.deriveKey(BcFKSLimitDriver.pbkdf2((int) (cap + 1), Integer.valueOf(32)),
                        BytePasswordKdf.PURPOSE_INTEGRITY_CHECK, PASSWORD, null, false));
        Assertions.assertEquals("BCFKS KeyStore: iteration count (" + (cap + 1) + ") greater than " + cap,
                past.getMessage());
        Assertions.assertEquals(0, kdf.pbkdf2Calls.get(),
                "an over-cap iteration count reached the FIPS KDF");

        // A usable count still derives, so the two refusals above are about the
        // bound rather than about the FIPS KDF refusing everything.
        Assertions.assertEquals(32, spi.deriveKey(BcFKSLimitDriver.pbkdf2(2048, Integer.valueOf(32)),
                BytePasswordKdf.PURPOSE_INTEGRITY_CHECK, PASSWORD, null, false).length);
        Assertions.assertEquals(1, kdf.pbkdf2Calls.get());
    }

    @Test
    public void emptySaltIsRefusedBeforeAnyDerivation() throws Exception
    {
        BcFKSLimitDriver.CountingKdfNI kdf = new BcFKSLimitDriver.CountingKdfNI(FIPSNISelector.KdfNI);
        BcFKSKeyStoreSpi spi = fipsSpi(kdf);

        byte[] params = Der.pbkdf2Params(new byte[0], 2048, Integer.valueOf(32),
                Der.algorithmIdentifier(BcFKSLimitDriver.HMAC_SHA512_OID, Der.nullValue()));
        IOException e = Assertions.assertThrows(IOException.class,
                () -> spi.deriveKey(
                        BcFKSLimitDriver.algorithmIdentifier(BcFKSLimitDriver.PBKDF2_OID, params),
                        BytePasswordKdf.PURPOSE_INTEGRITY_CHECK, PASSWORD, null, false));
        Assertions.assertEquals("BCFKS KeyStore: empty salt", e.getMessage());
        Assertions.assertEquals(0, kdf.pbkdf2Calls.get(), "an empty salt reached the FIPS KDF");
    }

    @Test
    public void everyBlobDecoderRefusesTrailingBytes() throws Exception
    {
        BcFKSLimitDriver.assertEveryBlobDecoderRefusesTrailingBytes(store());
    }

    // ---- The arm that exists only here: scrypt is not served ---------------

    /**
     * The module has no scrypt, so the registrar passes a null memory-hard NI.
     * Both directions must refuse typed: a read of a scrypt store, and a write
     * that asks for one. Reaching into the base library for either would be
     * correct-looking crypto performed outside the module.
     */
    @Test
    public void scryptIsRefusedTypedOnBothDirectionsAndNeverDerives() throws Exception
    {
        BcFKSLimitDriver.CountingKdfNI kdf = new BcFKSLimitDriver.CountingKdfNI(FIPSNISelector.KdfNI);
        BcFKSKeyStoreSpi spi = fipsSpi(kdf);

        IOException read = Assertions.assertThrows(IOException.class,
                () -> spi.deriveKey(BcFKSLimitDriver.scrypt(1024, 8, 1, Integer.valueOf(32)),
                        BytePasswordKdf.PURPOSE_INTEGRITY_CHECK, PASSWORD, null, false));
        Assertions.assertEquals("BCFKS store uses scrypt, which this provider does not serve",
                read.getMessage());
        Assertions.assertEquals(0, kdf.pbkdf2Calls.get(),
                "the scrypt refusal should not have consumed the PBKDF2 path either");

        KeyStore store = KeyStore.getInstance("BCFKS", providerName());
        store.load(null, null);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        IOException write = Assertions.assertThrows(IOException.class,
                () -> store.store(new BCFKSLoadStoreParameter.Builder(out, PASSWORD)
                        .withStorePBKDFConfig(
                                new BCFKSLoadStoreParameter.ScryptConfig.Builder(1024, 8, 1).build())
                        .build()));
        Assertions.assertEquals("BCFKS store cannot write scrypt, which this provider does not serve",
                write.getMessage());
        Assertions.assertEquals(0, out.size(),
                "a refused write must leave nothing on the stream");
    }

    /**
     * The refusal above is about scrypt and not about the FIPS provider
     * refusing every configured KDF: PBKDF2 with the same shape writes and
     * reads back.
     */
    @Test
    public void pbkdf2StillWritesAndReadsOnTheFipsProvider() throws Exception
    {
        KeyStore store = KeyStore.getInstance("BCFKS", providerName());
        store.load(null, null);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        store.store(new BCFKSLoadStoreParameter.Builder(out, PASSWORD)
                .withStorePBKDFConfig(new BCFKSLoadStoreParameter.PBKDF2Config.Builder()
                        .withIterationCount(2048).build())
                .build());
        Assertions.assertTrue(out.size() > 0, "nothing was written");

        KeyStore back = KeyStore.getInstance("BCFKS", providerName());
        back.load(new ByteArrayInputStream(out.toByteArray()), PASSWORD);
        Assertions.assertEquals(0, back.size());
    }
}
