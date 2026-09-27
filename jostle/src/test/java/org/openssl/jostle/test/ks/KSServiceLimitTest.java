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
 * {@code integrationTest25FFM} (which select the JNI / FFM {@code KSServiceNI}
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
                    -1, MAC_ITER, KSServiceNI.SECRET_FORM_RFC7292, TestUtil.RNDSrc);
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
                    Integer.MIN_VALUE, MAC_ITER, KSServiceNI.SECRET_FORM_RFC7292, TestUtil.RNDSrc);
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
                    PBE_ITER, -1, KSServiceNI.SECRET_FORM_RFC7292, TestUtil.RNDSrc);
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
                    PBE_ITER, Integer.MIN_VALUE, KSServiceNI.SECRET_FORM_RFC7292, TestUtil.RNDSrc);
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
                    PBE_ITER, MAC_ITER, KSServiceNI.SECRET_FORM_RFC7292, null);
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
                    PBE_ITER, MAC_ITER, KSServiceNI.SECRET_FORM_RFC7292, TestUtil.RNDSrc);
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

    // -----------------------------------------------------------------
    // Secret-key entries (PKCS#12 secretBag)
    // -----------------------------------------------------------------

    private static final String RFC_AES128 = "2.16.840.1.101.3.4.1.2";
    private static final String SUN_AES = "2.16.840.1.101.3.4.1";
    private static final byte[] SECRET = new byte[16];

    static
    {
        new java.security.SecureRandom().nextBytes(SECRET);
    }

    private void assertSetSecretRefused(long ref, String alias, byte[] key, String rfcOid, String sunOid,
                                        String message)
    {
        KeyStoreException e = Assertions.assertThrows(KeyStoreException.class,
                () -> ni.setSecretKey(ref, alias, key, rfcOid, sunOid, PASSWORD));
        Assertions.assertEquals(message, e.getMessage());
    }

    private byte[] storeWith(long ref, byte[] password, int certPbe, int form)
        throws Exception
    {
        return ni.store(ref, password, KEY_PBE, certPbe, MAC_SCHEME, MAC_DIGEST,
                PBE_ITER, MAC_ITER, form, TestUtil.RNDSrc);
    }

    /** The (OID, key) pair a getSecretKey DER carries. */
    private static Object[] decode(byte[] der)
    {
        org.bouncycastle.asn1.ASN1Sequence seq = org.bouncycastle.asn1.ASN1Sequence.getInstance(der);
        Assertions.assertEquals(2, seq.size());
        return new Object[]{
                org.bouncycastle.asn1.ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0)).getId(),
                org.bouncycastle.asn1.ASN1OctetString.getInstance(seq.getObjectAt(1)).getOctets()};
    }

    @Test
    public void setSecret_nullCtx()
    {
        assertSetSecretRefused(0L, "s", SECRET, RFC_AES128, SUN_AES, "key store context is null");
    }

    @Test
    public void setSecret_nullAlias()
    {
        assertSetSecretRefused(validRef, null, SECRET, RFC_AES128, SUN_AES, "key store alias is null");
    }

    @Test
    public void setSecret_nullKey()
    {
        assertSetSecretRefused(validRef, "s", null, RFC_AES128, SUN_AES, "key store key is null");
    }

    @Test
    public void setSecret_nullOids()
    {
        assertSetSecretRefused(validRef, "s", SECRET, null, SUN_AES, "key store secret key algorithm OID is null");
        assertSetSecretRefused(validRef, "s", SECRET, RFC_AES128, null, "key store secret key algorithm OID is null");
    }

    @Test
    public void setSecret_emptyKey()
    {
        assertSetSecretRefused(validRef, "s", new byte[0], RFC_AES128, SUN_AES,
                "key store secret key is empty");
    }

    /** The stated bound is exact: 8192 bytes is held and read back, 8193 is refused. */
    @Test
    public void setSecret_lengthBoundary()
        throws Exception
    {
        assertSetSecretRefused(validRef, "s", new byte[KSServiceNI.SECRET_MAX_LEN + 1], RFC_AES128, SUN_AES,
                "key store secret key is longer than 8192 bytes");
        byte[] max = new byte[KSServiceNI.SECRET_MAX_LEN];
        new java.security.SecureRandom().nextBytes(max);
        ni.setSecretKey(validRef, "s", max, RFC_AES128, SUN_AES, PASSWORD);
        Assertions.assertArrayEquals(max, (byte[]) decode(ni.getSecretKey(validRef, "s", PASSWORD))[1]);
    }

    /**
     * Both OIDs must be dotted; the RFC 7292 one must also be known to OpenSSL, since that bag is written from
     * it, while the SunJCE one may be any dotted OID.
     */
    @Test
    public void setSecret_oidValidation()
        throws Exception
    {
        String invalid = "key store secret key algorithm OID is not valid";
        assertSetSecretRefused(validRef, "s", SECRET, "not.an.oid", SUN_AES, invalid);
        assertSetSecretRefused(validRef, "s", SECRET, "AES", SUN_AES, invalid);
        assertSetSecretRefused(validRef, "s", SECRET, "1.2.3.4.5.6.7", SUN_AES, invalid);
        assertSetSecretRefused(validRef, "s", SECRET, RFC_AES128, "not.an.oid", invalid);
        Assertions.assertFalse(ni.containsAlias(validRef, "s"), "a refused set left an entry");
        ni.setSecretKey(validRef, "s", SECRET, RFC_AES128, "1.2.3.4.5.6.7", PASSWORD);
        Assertions.assertTrue(ni.isSecretKeyEntry(validRef, "s"));
    }

    @Test
    public void getSecret_nullCtxAndAlias()
    {
        KeyStoreException e = Assertions.assertThrows(KeyStoreException.class,
                () -> ni.getSecretKey(0L, "s", PASSWORD));
        Assertions.assertEquals("key store context is null", e.getMessage());
        e = Assertions.assertThrows(KeyStoreException.class, () -> ni.getSecretKey(validRef, null, PASSWORD));
        Assertions.assertEquals("key store alias is null", e.getMessage());
    }

    /** The DER is exactly SEQUENCE { the RFC 7292 OID, the key }; an absent alias gives null. */
    @Test
    public void getSecret_shapeAndAbsence()
        throws Exception
    {
        Assertions.assertNull(ni.getSecretKey(validRef, "s", PASSWORD));
        ni.setSecretKey(validRef, "s", SECRET, RFC_AES128, SUN_AES, PASSWORD);
        Object[] got = decode(ni.getSecretKey(validRef, "s", PASSWORD));
        Assertions.assertEquals(RFC_AES128, got[0]);
        Assertions.assertArrayEquals(SECRET, (byte[]) got[1]);
    }

    @Test
    public void getSecret_wrongPasswordRefused()
        throws Exception
    {
        ni.setSecretKey(validRef, "s", SECRET, RFC_AES128, SUN_AES, PASSWORD);
        KeyStoreException e = Assertions.assertThrows(KeyStoreException.class,
                () -> ni.getSecretKey(validRef, "s", "wrong".getBytes(StandardCharsets.UTF_8)));
        Assertions.assertEquals("unable to decode key store private key", e.getMessage());
    }

    @Test
    public void isSecretEntry_nullCtxAlias_andEntryKinds()
        throws Exception
    {
        IllegalArgumentException c = Assertions.assertThrows(IllegalArgumentException.class,
                () -> ni.isSecretKeyEntry(0L, "s"));
        Assertions.assertEquals("key store context is null", c.getMessage());
        NullPointerException a = Assertions.assertThrows(NullPointerException.class,
                () -> ni.isSecretKeyEntry(validRef, null));
        Assertions.assertEquals("key store alias is null", a.getMessage());

        Assertions.assertFalse(ni.isSecretKeyEntry(validRef, "s"));
        ni.setSecretKey(validRef, "s", SECRET, RFC_AES128, SUN_AES, PASSWORD);
        Assertions.assertTrue(ni.isSecretKeyEntry(validRef, "s"));
        Assertions.assertTrue(ni.isKeyEntry(validRef, "s"), "a secret entry is a key entry");
        Assertions.assertFalse(ni.isCertificateEntry(validRef, "s"));
    }

    /**
     * RFC 7292 form: the bag carries no per-entry protection, so after a load the key comes back whatever
     * password getSecretKey is given, and under the RFC OID.
     */
    @Test
    public void rfcForm_roundTrip_anyPasswordAfterLoad()
        throws Exception
    {
        ni.setSecretKey(validRef, "s", SECRET, RFC_AES128, SUN_AES, PASSWORD);
        byte[] p12 = storeWith(validRef, PASSWORD, CERT_PBE, KSServiceNI.SECRET_FORM_RFC7292);
        long loaded = ni.allocateKeyStore("PKCS12");
        try
        {
            ni.load(loaded, p12, PASSWORD);
            Assertions.assertTrue(ni.isSecretKeyEntry(loaded, "s"));
            for (byte[] pw : new byte[][]{PASSWORD, "wrong".getBytes(StandardCharsets.UTF_8), null})
            {
                Object[] got = decode(ni.getSecretKey(loaded, "s", pw));
                Assertions.assertEquals(RFC_AES128, got[0]);
                Assertions.assertArrayEquals(SECRET, (byte[]) got[1]);
            }
        }
        finally
        {
            ni.dispose(loaded);
        }
    }

    /**
     * SunJCE form: the bag is encrypted under the entry password, the load decrypts it with the store password,
     * and afterwards the entry keeps that password, so a wrong one is refused. The OID read back is SunJCE's.
     */
    @Test
    public void sunForm_roundTrip_passwordRequiredAfterLoad()
        throws Exception
    {
        ni.setSecretKey(validRef, "s", SECRET, RFC_AES128, SUN_AES, PASSWORD);
        byte[] p12 = storeWith(validRef, PASSWORD, CERT_PBE, KSServiceNI.SECRET_FORM_SUNJCE);
        long loaded = ni.allocateKeyStore("PKCS12");
        try
        {
            ni.load(loaded, p12, PASSWORD);
            Object[] got = decode(ni.getSecretKey(loaded, "s", PASSWORD));
            Assertions.assertEquals(SUN_AES, got[0]);
            Assertions.assertArrayEquals(SECRET, (byte[]) got[1]);
            KeyStoreException e = Assertions.assertThrows(KeyStoreException.class,
                    () -> ni.getSecretKey(loaded, "s", "wrong".getBytes(StandardCharsets.UTF_8)));
            Assertions.assertEquals("unable to decode key store private key", e.getMessage());
        }
        finally
        {
            ni.dispose(loaded);
        }
    }

    /** A SunJCE-form bag under an entry password other than the store password cannot be read back. */
    @Test
    public void sunForm_entryPasswordOtherThanStorePassword_loadFails()
        throws Exception
    {
        ni.setSecretKey(validRef, "s", SECRET, RFC_AES128, SUN_AES, "entry".getBytes(StandardCharsets.UTF_8));
        byte[] p12 = storeWith(validRef, PASSWORD, CERT_PBE, KSServiceNI.SECRET_FORM_SUNJCE);
        long loaded = ni.allocateKeyStore("PKCS12");
        try
        {
            java.io.IOException e = Assertions.assertThrows(java.io.IOException.class,
                    () -> ni.load(loaded, p12, PASSWORD));
            Assertions.assertEquals("key store load failed", e.getMessage());
        }
        finally
        {
            ni.dispose(loaded);
        }
    }

    /** The RFC 7292 bag holds the raw key, so it is never written into a cleartext safe; the SunJCE bag can be. */
    @Test
    public void rfcForm_cleartextCertificateSafeRefused()
        throws Exception
    {
        ni.setSecretKey(validRef, "s", SECRET, RFC_AES128, SUN_AES, PASSWORD);
        java.io.IOException e = Assertions.assertThrows(java.io.IOException.class,
                () -> storeWith(validRef, PASSWORD, 0, KSServiceNI.SECRET_FORM_RFC7292));
        Assertions.assertEquals("key store store failed", e.getMessage());
        Assertions.assertNotNull(storeWith(validRef, PASSWORD, 0, KSServiceNI.SECRET_FORM_SUNJCE));
    }

    @Test
    public void store_invalidSecretForm()
        throws Exception
    {
        ni.setSecretKey(validRef, "s", SECRET, RFC_AES128, SUN_AES, PASSWORD);
        for (int form : new int[]{-1, 2, Integer.MIN_VALUE})
        {
            java.io.IOException e = Assertions.assertThrows(java.io.IOException.class,
                    () -> storeWith(validRef, PASSWORD, CERT_PBE, form), "form " + form);
            Assertions.assertEquals("key store store failed", e.getMessage());
        }
    }

    /**
     * An OID OpenSSL does not know can arrive from a SunJCE-form file; the RFC 7292 form, whose bag is built
     * from a NID, then refuses to write it, while the SunJCE form still can.
     */
    @Test
    public void unknownOidReadFromSunForm_cannotBeWrittenAsRfc()
        throws Exception
    {
        ni.setSecretKey(validRef, "s", SECRET, RFC_AES128, "1.2.3.4.5.6.7", PASSWORD);
        byte[] p12 = storeWith(validRef, PASSWORD, CERT_PBE, KSServiceNI.SECRET_FORM_SUNJCE);
        long loaded = ni.allocateKeyStore("PKCS12");
        try
        {
            ni.load(loaded, p12, PASSWORD);
            Assertions.assertEquals("1.2.3.4.5.6.7", decode(ni.getSecretKey(loaded, "s", PASSWORD))[0]);
            java.io.IOException e = Assertions.assertThrows(java.io.IOException.class,
                    () -> storeWith(loaded, PASSWORD, CERT_PBE, KSServiceNI.SECRET_FORM_RFC7292));
            Assertions.assertEquals("key store store failed", e.getMessage());
            Assertions.assertNotNull(storeWith(loaded, PASSWORD, CERT_PBE, KSServiceNI.SECRET_FORM_SUNJCE));
        }
        finally
        {
            ni.dispose(loaded);
        }
    }

    // -----------------------------------------------------------------
    // setSecretKeyOids: replaces only the two OIDs of an existing secret entry
    // -----------------------------------------------------------------

    private static final String RFC_AES256 = "2.16.840.1.101.3.4.1.42";
    private static final String NOT_SECRET = "key store alias holds no secret key";

    private void assertSetOidsRefused(long ref, String alias, String rfcOid, String sunOid, String message)
    {
        KeyStoreException e = Assertions.assertThrows(KeyStoreException.class,
                () -> ni.setSecretKeyOids(ref, alias, rfcOid, sunOid));
        Assertions.assertEquals(message, e.getMessage());
    }

    @Test
    public void setSecretOids_nullArguments()
    {
        assertSetOidsRefused(0L, "s", RFC_AES128, SUN_AES, "key store context is null");
        assertSetOidsRefused(validRef, null, RFC_AES128, SUN_AES, "key store alias is null");
        assertSetOidsRefused(validRef, "s", null, SUN_AES, "key store secret key algorithm OID is null");
        assertSetOidsRefused(validRef, "s", RFC_AES128, null, "key store secret key algorithm OID is null");
    }

    /** Refused for an absent alias, a private-key entry and a certificate entry: only a secret entry has OIDs. */
    @Test
    public void setSecretOids_aliasHoldsNoSecret()
        throws Exception
    {
        assertSetOidsRefused(validRef, "absent", RFC_AES128, SUN_AES, NOT_SECRET);

        java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator.getInstance("RSA",
                JostleProvider.PROVIDER_NAME);
        kpg.initialize(2048);
        java.security.KeyPair pair = kpg.generateKeyPair();
        ni.setKey(validRef, "k", pair.getPrivate().getEncoded(), PASSWORD);
        assertSetOidsRefused(validRef, "k", RFC_AES128, SUN_AES, NOT_SECRET);

        org.bouncycastle.asn1.x500.X500Name name = new org.bouncycastle.asn1.x500.X500Name("CN=Jostle KS Limit");
        java.util.Date now = new java.util.Date();
        org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder builder =
                new org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(name, java.math.BigInteger.ONE,
                        new java.util.Date(now.getTime() - 3600_000L), new java.util.Date(now.getTime() + 3600_000L),
                        name, pair.getPublic());
        org.bouncycastle.operator.ContentSigner signer =
                new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256withRSA").build(pair.getPrivate());
        ni.setCertificateEntry(validRef, "c", builder.build(signer).getEncoded());
        assertSetOidsRefused(validRef, "c", RFC_AES128, SUN_AES, NOT_SECRET);
    }

    /** The same OID rules as setSecretKey, and a refused call leaves the entry's OIDs as they were. */
    @Test
    public void setSecretOids_oidValidationLeavesOidsUnchanged()
        throws Exception
    {
        ni.setSecretKey(validRef, "s", SECRET, RFC_AES128, SUN_AES, PASSWORD);
        String invalid = "key store secret key algorithm OID is not valid";
        assertSetOidsRefused(validRef, "s", "not.an.oid", SUN_AES, invalid);
        assertSetOidsRefused(validRef, "s", "AES", SUN_AES, invalid);
        assertSetOidsRefused(validRef, "s", "1.2.3.4.5.6.7", SUN_AES, invalid);
        assertSetOidsRefused(validRef, "s", RFC_AES128, "not.an.oid", invalid);
        Assertions.assertEquals(RFC_AES128, decode(ni.getSecretKey(validRef, "s", PASSWORD))[0]);

        ni.setSecretKeyOids(validRef, "s", RFC_AES256, "1.2.3.4.5.6.7");
        Object[] got = decode(ni.getSecretKey(validRef, "s", PASSWORD));
        Assertions.assertEquals(RFC_AES256, got[0]);
        Assertions.assertArrayEquals(SECRET, (byte[]) got[1], "the key must be unchanged");
    }

    /** A session-set entry keeps its password rule: a wrong password is refused before and after. */
    @Test
    public void setSecretOids_keepsThePasswordRule()
        throws Exception
    {
        ni.setSecretKey(validRef, "s", SECRET, RFC_AES128, SUN_AES, PASSWORD);
        byte[] wrong = "wrong".getBytes(StandardCharsets.UTF_8);
        Assertions.assertThrows(KeyStoreException.class, () -> ni.getSecretKey(validRef, "s", wrong));
        ni.setSecretKeyOids(validRef, "s", RFC_AES256, SUN_AES);
        KeyStoreException e = Assertions.assertThrows(KeyStoreException.class,
                () -> ni.getSecretKey(validRef, "s", wrong));
        Assertions.assertEquals("unable to decode key store private key", e.getMessage());
    }

    /** An RFC-loaded entry keeps its any-password rule: a wrong password returns the key before and after. */
    @Test
    public void setSecretOids_keepsTheAnyPasswordRule()
        throws Exception
    {
        ni.setSecretKey(validRef, "s", SECRET, RFC_AES128, SUN_AES, PASSWORD);
        byte[] p12 = storeWith(validRef, PASSWORD, CERT_PBE, KSServiceNI.SECRET_FORM_RFC7292);
        long loaded = ni.allocateKeyStore("PKCS12");
        try
        {
            ni.load(loaded, p12, PASSWORD);
            byte[] wrong = "wrong".getBytes(StandardCharsets.UTF_8);
            Assertions.assertArrayEquals(SECRET, (byte[]) decode(ni.getSecretKey(loaded, "s", wrong))[1]);
            ni.setSecretKeyOids(loaded, "s", RFC_AES256, SUN_AES);
            Object[] got = decode(ni.getSecretKey(loaded, "s", wrong));
            Assertions.assertEquals(RFC_AES256, got[0]);
            Assertions.assertArrayEquals(SECRET, (byte[]) got[1]);
        }
        finally
        {
            ni.dispose(loaded);
        }
    }
}
