/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.ks;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.provider.ks.KSServiceNI;
import org.openssl.jostle.test.TestUtil;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStoreException;
import java.security.Security;

/**
 * NI-layer input-validation tests for the PKCS#12 KeyStore. Calls the
 * {@code KSServiceNI} default-method wrappers directly so the C bridge layer's
 * null / range checks surface as the JCE-friendly exceptions the higher layers
 * rely on. Runs under both {@code integrationTest25JNI} and
 * {@code integrationTest25FFI} (which select the JNI / FFI {@code KSServiceNI}
 * via the loader property), proving the two bridges reject identical inputs
 * with identical error codes.
 *
 * <p>The exception <em>type</em> a test catches depends on how the NI default
 * method wraps the bridge code:
 * <ul>
 *   <li>{@code store} / {@code load} wrap via {@code handleIoErrors} -&gt;
 *       {@link IOException} (cause carries the underlying type, message
 *       preserved);</li>
 *   <li>{@code getKey} / {@code setKey} / {@code getCertificateChain} /
 *       {@code setCertificateChain} / {@code setCertificateEntry} /
 *       {@code deleteEntry} / {@code getAliases} / {@code getCreationDate} wrap
 *       via {@code handleKeyStoreErrors} -&gt; {@link KeyStoreException};</li>
 *   <li>{@code allocateKeyStore} / {@code containsAlias} / {@code size} /
 *       {@code isKeyEntry} / {@code isCertificateEntry} go through
 *       {@code handleErrors} and surface the raw {@link IllegalArgumentException}
 *       / {@link NullPointerException}.</li>
 * </ul>
 * Each catch block pins the message text per the testing.md "Pin the exception
 * message in OPS / Limit-test catch blocks" rule.
 */
public class KSServiceLimitTest
{
    // Valid store profile (AES-256-CBC keys, AES-128-CBC certs, HMAC-SHA256 MAC).
    private static final int KEY_PBE = 3;
    private static final int CERT_PBE = 2;
    private static final int MAC_SCHEME = 1;
    private static final int MAC_DIGEST = 2;
    private static final int PBE_ITER = 2048;
    private static final int MAC_ITER = 2048;

    private static final byte[] PASSWORD = "changeit".getBytes(StandardCharsets.UTF_8);
    private static final byte[] DUMMY_KEY = {0x01};

    private final KSServiceNI ni = NISelector.KSServiceNI;
    private long validRef = 0L;

    @BeforeAll
    public static void beforeAll()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    @BeforeEach
    public void allocateValidRef()
    {
        validRef = ni.allocateKeyStore("PKCS12");
    }

    @AfterEach
    public void disposeValidRef()
    {
        if (validRef != 0L)
        {
            ni.dispose(validRef);
            validRef = 0L;
        }
    }

    // -----------------------------------------------------------------
    // allocateKeyStore
    // -----------------------------------------------------------------

    @Test
    public void allocateKeyStore_nullType()
    {
        try
        {
            ni.allocateKeyStore(null);
            Assertions.fail();
        }
        catch (NullPointerException e)
        {
            Assertions.assertEquals("key store type is null", e.getMessage());
        }
    }

    @Test
    public void allocateKeyStore_unsupportedType()
    {
        try
        {
            ni.allocateKeyStore("NOT-A-REAL-KEYSTORE-TYPE");
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("key store type is not supported", e.getMessage());
        }
    }

    // -----------------------------------------------------------------
    // store -- IOException wrapper
    // -----------------------------------------------------------------

    @Test
    public void store_negativePbeIter()
    {
        try
        {
            ni.store(validRef, PASSWORD, KEY_PBE, CERT_PBE, MAC_SCHEME, MAC_DIGEST,
                    -1, MAC_ITER, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (IOException e)
        {
            Assertions.assertEquals("key store PBE iteration count is negative", e.getMessage());
        }
    }

    // Integer.MIN_VALUE is redundant with store_negativePbeIter for the current
    // native check: pbe_iter is signed end-to-end and validated with `< 0`
    // before use (no abs/negate, never cast to an unsigned type), so both -1 and
    // MIN_VALUE hit the identical branch. Kept deliberately as a forward-guard --
    // if the count ever gains an abs()/clamp, MIN_VALUE defeats it where -1 does
    // not -- not as a distinct path under today's implementation.
    @Test
    public void store_minValuePbeIter()
    {
        try
        {
            ni.store(validRef, PASSWORD, KEY_PBE, CERT_PBE, MAC_SCHEME, MAC_DIGEST,
                    Integer.MIN_VALUE, MAC_ITER, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (IOException e)
        {
            Assertions.assertEquals("key store PBE iteration count is negative", e.getMessage());
        }
    }

    @Test
    public void store_negativeMacIter()
    {
        try
        {
            ni.store(validRef, PASSWORD, KEY_PBE, CERT_PBE, MAC_SCHEME, MAC_DIGEST,
                    PBE_ITER, -1, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (IOException e)
        {
            Assertions.assertEquals("key store MAC iteration count is negative", e.getMessage());
        }
    }

    // Forward-guard like store_minValuePbeIter: redundant with the -1 case under
    // today's signed `mac_iter < 0` check, retained to catch a future abs/clamp.
    @Test
    public void store_minValueMacIter()
    {
        try
        {
            ni.store(validRef, PASSWORD, KEY_PBE, CERT_PBE, MAC_SCHEME, MAC_DIGEST,
                    PBE_ITER, Integer.MIN_VALUE, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (IOException e)
        {
            Assertions.assertEquals("key store MAC iteration count is negative", e.getMessage());
        }
    }

    @Test
    public void store_nullRandSource()
    {
        try
        {
            ni.store(validRef, PASSWORD, KEY_PBE, CERT_PBE, MAC_SCHEME, MAC_DIGEST,
                    PBE_ITER, MAC_ITER, null);
            Assertions.fail();
        }
        catch (IOException e)
        {
            Assertions.assertEquals("supplied random source was null", e.getMessage());
        }
    }

    @Test
    public void store_nullCtx()
    {
        try
        {
            ni.store(0L, PASSWORD, KEY_PBE, CERT_PBE, MAC_SCHEME, MAC_DIGEST,
                    PBE_ITER, MAC_ITER, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (IOException e)
        {
            Assertions.assertEquals("key store context is null", e.getMessage());
        }
    }

    // -----------------------------------------------------------------
    // load -- IOException wrapper
    // -----------------------------------------------------------------

    @Test
    public void load_nullCtx()
    {
        try
        {
            ni.load(0L, new byte[] {0x01}, PASSWORD);
            Assertions.fail();
        }
        catch (IOException e)
        {
            Assertions.assertEquals("key store context is null", e.getMessage());
        }
    }

    // -----------------------------------------------------------------
    // getKey -- KeyStoreException wrapper
    // -----------------------------------------------------------------

    @Test
    public void getKey_nullCtx()
    {
        try
        {
            ni.getKey(0L, "alias", PASSWORD);
            Assertions.fail();
        }
        catch (KeyStoreException e)
        {
            Assertions.assertEquals("key store context is null", e.getMessage());
        }
    }

    @Test
    public void getKey_nullAlias()
    {
        try
        {
            ni.getKey(validRef, null, PASSWORD);
            Assertions.fail();
        }
        catch (KeyStoreException e)
        {
            Assertions.assertEquals("key store alias is null", e.getMessage());
        }
    }

    // -----------------------------------------------------------------
    // setKey -- KeyStoreException wrapper
    // -----------------------------------------------------------------

    @Test
    public void setKey_nullCtx()
    {
        try
        {
            ni.setKey(0L, "alias", DUMMY_KEY, PASSWORD);
            Assertions.fail();
        }
        catch (KeyStoreException e)
        {
            Assertions.assertEquals("key store context is null", e.getMessage());
        }
    }

    @Test
    public void setKey_nullAlias()
    {
        try
        {
            ni.setKey(validRef, null, DUMMY_KEY, PASSWORD);
            Assertions.fail();
        }
        catch (KeyStoreException e)
        {
            Assertions.assertEquals("key store alias is null", e.getMessage());
        }
    }

    @Test
    public void setKey_nullKey()
    {
        try
        {
            ni.setKey(validRef, "alias", null, PASSWORD);
            Assertions.fail();
        }
        catch (KeyStoreException e)
        {
            Assertions.assertEquals("key store key is null", e.getMessage());
        }
    }

    // -----------------------------------------------------------------
    // getCertificateChain -- KeyStoreException wrapper
    // -----------------------------------------------------------------

    @Test
    public void getCertificateChain_nullCtx()
    {
        try
        {
            ni.getCertificateChain(0L, "alias");
            Assertions.fail();
        }
        catch (KeyStoreException e)
        {
            Assertions.assertEquals("key store context is null", e.getMessage());
        }
    }

    @Test
    public void getCertificateChain_nullAlias()
    {
        try
        {
            ni.getCertificateChain(validRef, null);
            Assertions.fail();
        }
        catch (KeyStoreException e)
        {
            Assertions.assertEquals("key store alias is null", e.getMessage());
        }
    }

    // -----------------------------------------------------------------
    // setCertificateChain -- KeyStoreException wrapper
    // -----------------------------------------------------------------

    @Test
    public void setCertificateChain_nullCtx()
    {
        try
        {
            ni.setCertificateChain(0L, "alias", new byte[] {0x01});
            Assertions.fail();
        }
        catch (KeyStoreException e)
        {
            Assertions.assertEquals("key store context is null", e.getMessage());
        }
    }

    @Test
    public void setCertificateChain_nullAlias()
    {
        try
        {
            ni.setCertificateChain(validRef, null, new byte[] {0x01});
            Assertions.fail();
        }
        catch (KeyStoreException e)
        {
            Assertions.assertEquals("key store alias is null", e.getMessage());
        }
    }

    // -----------------------------------------------------------------
    // setCertificateEntry -- KeyStoreException wrapper
    // -----------------------------------------------------------------

    @Test
    public void setCertificateEntry_nullCtx()
    {
        try
        {
            ni.setCertificateEntry(0L, "alias", new byte[] {0x01});
            Assertions.fail();
        }
        catch (KeyStoreException e)
        {
            Assertions.assertEquals("key store context is null", e.getMessage());
        }
    }

    @Test
    public void setCertificateEntry_nullAlias()
    {
        try
        {
            ni.setCertificateEntry(validRef, null, new byte[] {0x01});
            Assertions.fail();
        }
        catch (KeyStoreException e)
        {
            Assertions.assertEquals("key store alias is null", e.getMessage());
        }
    }

    // -----------------------------------------------------------------
    // deleteEntry -- KeyStoreException wrapper
    // -----------------------------------------------------------------

    @Test
    public void deleteEntry_nullCtx()
    {
        try
        {
            ni.deleteEntry(0L, "alias");
            Assertions.fail();
        }
        catch (KeyStoreException e)
        {
            Assertions.assertEquals("key store context is null", e.getMessage());
        }
    }

    @Test
    public void deleteEntry_nullAlias()
    {
        try
        {
            ni.deleteEntry(validRef, null);
            Assertions.fail();
        }
        catch (KeyStoreException e)
        {
            Assertions.assertEquals("key store alias is null", e.getMessage());
        }
    }

    // -----------------------------------------------------------------
    // getAliases -- KeyStoreException wrapper
    // -----------------------------------------------------------------

    @Test
    public void getAliases_nullCtx()
    {
        try
        {
            ni.getAliases(0L);
            Assertions.fail();
        }
        catch (KeyStoreException e)
        {
            Assertions.assertEquals("key store context is null", e.getMessage());
        }
    }

    // -----------------------------------------------------------------
    // containsAlias -- raw handleErrors
    // -----------------------------------------------------------------

    @Test
    public void containsAlias_nullCtx()
    {
        try
        {
            ni.containsAlias(0L, "alias");
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("key store context is null", e.getMessage());
        }
    }

    @Test
    public void containsAlias_nullAlias()
    {
        try
        {
            ni.containsAlias(validRef, null);
            Assertions.fail();
        }
        catch (NullPointerException e)
        {
            Assertions.assertEquals("key store alias is null", e.getMessage());
        }
    }

    // -----------------------------------------------------------------
    // size -- raw handleErrors
    // -----------------------------------------------------------------

    @Test
    public void size_nullCtx()
    {
        try
        {
            ni.size(0L);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("key store context is null", e.getMessage());
        }
    }

    // -----------------------------------------------------------------
    // isKeyEntry -- raw handleErrors
    // -----------------------------------------------------------------

    @Test
    public void isKeyEntry_nullCtx()
    {
        try
        {
            ni.isKeyEntry(0L, "alias");
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("key store context is null", e.getMessage());
        }
    }

    @Test
    public void isKeyEntry_nullAlias()
    {
        try
        {
            ni.isKeyEntry(validRef, null);
            Assertions.fail();
        }
        catch (NullPointerException e)
        {
            Assertions.assertEquals("key store alias is null", e.getMessage());
        }
    }

    // -----------------------------------------------------------------
    // isCertificateEntry -- raw handleErrors
    // -----------------------------------------------------------------

    @Test
    public void isCertificateEntry_nullCtx()
    {
        try
        {
            ni.isCertificateEntry(0L, "alias");
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("key store context is null", e.getMessage());
        }
    }

    @Test
    public void isCertificateEntry_nullAlias()
    {
        try
        {
            ni.isCertificateEntry(validRef, null);
            Assertions.fail();
        }
        catch (NullPointerException e)
        {
            Assertions.assertEquals("key store alias is null", e.getMessage());
        }
    }

    // -----------------------------------------------------------------
    // getCreationDate -- KeyStoreException wrapper
    // -----------------------------------------------------------------

    @Test
    public void getCreationDate_nullCtx()
    {
        try
        {
            ni.getCreationDate(0L, "alias");
            Assertions.fail();
        }
        catch (KeyStoreException e)
        {
            Assertions.assertEquals("key store context is null", e.getMessage());
        }
    }

    @Test
    public void getCreationDate_nullAlias()
    {
        try
        {
            ni.getCreationDate(validRef, null);
            Assertions.fail();
        }
        catch (KeyStoreException e)
        {
            Assertions.assertEquals("key store alias is null", e.getMessage());
        }
    }
}
