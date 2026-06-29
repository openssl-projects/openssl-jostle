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

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.Loader;
import org.openssl.jostle.jcajce.provider.AccessException;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.provider.ks.KSServiceNI;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.test.crypto.TestNISelector;
import org.openssl.jostle.util.ops.OperationsTestNI;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStoreException;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * Fault-injection tests for the PKCS#12 KeyStore JNI bridge. Every
 * {@code OPS_FAILED_ACCESS_*} / {@code OPS_INT32_OVERFLOW_*} site in
 * {@code interface/jni/ks_jni.c} is driven once: a single flag is set, the
 * matching {@code KSServiceNI} call is made, and the resulting typed exception
 * and message are asserted (the C error code -&gt; exception mapping in
 * {@code DefaultServiceNI} / the {@code KSServiceNI} wrappers).
 *
 * <p>All tests are guarded by {@link OperationsTestNI#opsTestAvailable()} (so
 * they no-op on a release native build) and by
 * {@code Assumptions.assumeFalse(Loader.isFFI())}: every instrumented site is a
 * JNI {@code GetStringUTFChars}/{@code GetByteArrayElements}/{@code NewByteArray}
 * fault or the JNI {@code int32} overflow guard, none of which exist on the FFI
 * bridge.
 */
public class KSServiceOpsTest
{
    private static final int KEY_PBE = 3;
    private static final int CERT_PBE = 2;
    private static final int MAC_SCHEME = 1;
    private static final int MAC_DIGEST = 2;
    private static final int PBE_ITER = 2048;
    private static final int MAC_ITER = 2048;

    private static final byte[] PASSWORD = "changeit".getBytes(StandardCharsets.UTF_8);
    private static final byte[] DUMMY = {0x01};

    private final KSServiceNI ni = NISelector.KSServiceNI;
    private final OperationsTestNI operationsTestNI = TestNISelector.getOperationsTestNI();
    private long validRef = 0L;

    // Generated once, before any OPS flag is set. RSA keygen and certificate
    // signing draw entropy through the OPS-instrumented up-call, so producing
    // this material while a flag is active would corrupt the generation rather
    // than the bridge site under test. Computing it in @BeforeAll keeps every
    // per-test setKey/setCertificateEntry feed flag-free.
    private static byte[] keyPkcs8;
    private static byte[] certDer;

    @BeforeAll
    public static void beforeAll()
        throws Exception
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        keyPkcs8 = rsaPkcs8();
        certDer = selfSignedCertDer();
    }

    @BeforeEach
    public void beforeEach()
    {
        if (operationsTestNI.opsTestAvailable())
        {
            operationsTestNI.resetFlags();
        }
        if (!Loader.isFFI())
        {
            validRef = ni.allocateKeyStore("PKCS12");
        }
    }

    @AfterEach
    public void afterEach()
    {
        if (operationsTestNI.opsTestAvailable())
        {
            operationsTestNI.resetFlags();
        }
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
    public void allocateKeyStore_failedAccessName()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());
        try
        {
            // Exercises interface/jni/ks_jni.c:41
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            ni.allocateKeyStore("PKCS12");
            Assertions.fail();
        }
        catch (IllegalStateException e)
        {
            Assertions.assertEquals("unable to access name", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    // -----------------------------------------------------------------
    // load
    // -----------------------------------------------------------------

    @Test
    public void load_failedAccessInput()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());
        try
        {
            // Exercises interface/jni/ks_jni.c:80
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            ni.load(validRef, DUMMY, PASSWORD);
            Assertions.fail();
        }
        catch (Exception e)
        {
            Assertions.assertEquals("unable to access input array", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void load_failedAccessPassword()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());
        try
        {
            // Exercises interface/jni/ks_jni.c:85
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_2);
            ni.load(validRef, DUMMY, PASSWORD);
            Assertions.fail();
        }
        catch (Exception e)
        {
            Assertions.assertEquals("unable to access key array", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    // ks_load OpenSSL-call failure arms (interface/util/ks.c), now reachable
    // without leaks since ks_load was refactored to a single goto-exit. Both
    // load a VALID keystore so the only thing failing is the OPS-forced call.

    @Test
    public void load_opensslErrorAtParse()
        throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());
        byte[] encoded = buildValidKeystore();
        try
        {
            // Exercises interface/util/ks.c:539
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_4);
            ni.load(validRef, encoded, PASSWORD);
            Assertions.fail();
        }
        catch (Exception e)
        {
            Assertions.assertEquals("key store load failed", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void load_opensslErrorAtUnpackAuthsafes()
        throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());
        byte[] encoded = buildValidKeystore();
        try
        {
            // Exercises interface/util/ks.c:565
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_5);
            ni.load(validRef, encoded, PASSWORD);
            Assertions.fail();
        }
        catch (Exception e)
        {
            Assertions.assertEquals("key store load failed", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    // -----------------------------------------------------------------
    // store
    // -----------------------------------------------------------------

    @Test
    public void store_failedAccessPassword()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());
        try
        {
            // Exercises interface/jni/ks_jni.c:125
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            ni.store(validRef, PASSWORD, KEY_PBE, CERT_PBE, MAC_SCHEME, MAC_DIGEST,
                    PBE_ITER, MAC_ITER, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (Exception e)
        {
            Assertions.assertEquals("unable to access key array", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    // The following three drive the OpenSSL-call failure arms of ks_store
    // (interface/util/ks.c), instrumented with OPS_OPENSSL_ERROR_*. ks_store is
    // shared util compiled into both bridges; these run via JNI (the file's
    // convention) which exercises the same util code path. ks_load is NOT
    // instrumented: its early-return cleanup (vs ks_store's single goto-end)
    // would leak the just-succeeded handle on an OPS-forced failure branch, so
    // instrumenting it needs an early-return -> goto-exit refactor first.

    @Test
    public void store_opensslErrorAtAddKey()
        throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());
        ni.setKey(validRef, "k", keyPkcs8, PASSWORD);
        try
        {
            // Exercises interface/util/ks.c:707
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            ni.store(validRef, PASSWORD, KEY_PBE, CERT_PBE, MAC_SCHEME, MAC_DIGEST,
                    PBE_ITER, MAC_ITER, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (Exception e)
        {
            Assertions.assertEquals("key store store failed", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void store_opensslErrorAtAddSafes()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());
        try
        {
            // Exercises interface/util/ks.c:752
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            ni.store(validRef, PASSWORD, KEY_PBE, CERT_PBE, MAC_SCHEME, MAC_DIGEST,
                    PBE_ITER, MAC_ITER, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (Exception e)
        {
            Assertions.assertEquals("key store store failed", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void store_opensslErrorAtSerialize()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());
        try
        {
            // Exercises interface/util/ks.c:777
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_3);
            ni.store(validRef, PASSWORD, KEY_PBE, CERT_PBE, MAC_SCHEME, MAC_DIGEST,
                    PBE_ITER, MAC_ITER, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (Exception e)
        {
            Assertions.assertEquals("key store store failed", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    // NOTE: the store int32-overflow guard (interface/jni/ks_jni.c:149) is
    // intentionally NOT covered here. Reaching it requires ks_store to succeed,
    // which draws PKCS#12 salts through the entropy up-call -- and that up-call
    // (interface/jni/rand_upcall_jni.c:67) checks the SAME OPS_INT32_OVERFLOW_1
    // flag, so setting it fails the entropy draw before line 149 is reached.
    // The guard is unreachable in isolation via OPS; the analogous reachable
    // int32 guards (getKey:218, getCertificateChain:334, getAliases:495) cover
    // the same code shape on non-entropy paths.

    // -----------------------------------------------------------------
    // getKey
    // -----------------------------------------------------------------

    @Test
    public void getKey_failedAccessAlias()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());
        try
        {
            // Exercises interface/jni/ks_jni.c:202
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            ni.getKey(validRef, "alias", PASSWORD);
            Assertions.fail();
        }
        catch (KeyStoreException e)
        {
            Assertions.assertEquals("unable to access key store alias", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void getKey_failedAccessPassword()
        throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());
        ni.setKey(validRef, "k", keyPkcs8, PASSWORD);
        try
        {
            // Exercises interface/jni/ks_jni.c:207
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_2);
            ni.getKey(validRef, "k", PASSWORD);
            Assertions.fail();
        }
        catch (KeyStoreException e)
        {
            Assertions.assertEquals("unable to access key array", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void getKey_int32Overflow()
        throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());
        ni.setKey(validRef, "k", keyPkcs8, PASSWORD);
        try
        {
            // Exercises interface/jni/ks_jni.c:218
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_2);
            ni.getKey(validRef, "k", PASSWORD);
            Assertions.fail();
        }
        catch (KeyStoreException e)
        {
            Assertions.assertEquals("output too long int32", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    // -----------------------------------------------------------------
    // setKey
    // -----------------------------------------------------------------

    @Test
    public void setKey_failedAccessAlias()
        throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());
        try
        {
            // Exercises interface/jni/ks_jni.c:264
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            ni.setKey(validRef, "alias", keyPkcs8, PASSWORD);
            Assertions.fail();
        }
        catch (KeyStoreException e)
        {
            Assertions.assertEquals("unable to access key store alias", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void setKey_failedAccessKey()
        throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());
        try
        {
            // Exercises interface/jni/ks_jni.c:273
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_2);
            ni.setKey(validRef, "alias", keyPkcs8, PASSWORD);
            Assertions.fail();
        }
        catch (KeyStoreException e)
        {
            Assertions.assertEquals("unable to access key store key", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void setKey_failedAccessPassword()
        throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());
        try
        {
            // Exercises interface/jni/ks_jni.c:278
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_3);
            ni.setKey(validRef, "alias", keyPkcs8, PASSWORD);
            Assertions.fail();
        }
        catch (KeyStoreException e)
        {
            Assertions.assertEquals("unable to access key array", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    // -----------------------------------------------------------------
    // getCertificateChain
    // -----------------------------------------------------------------

    @Test
    public void getCertificateChain_failedAccessAlias()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());
        try
        {
            // Exercises interface/jni/ks_jni.c:324
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            ni.getCertificateChain(validRef, "alias");
            Assertions.fail();
        }
        catch (KeyStoreException e)
        {
            Assertions.assertEquals("unable to access key store alias", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void getCertificateChain_int32Overflow()
        throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());
        ni.setCertificateEntry(validRef, "c", certDer);
        try
        {
            // Exercises interface/jni/ks_jni.c:334
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_2);
            ni.getCertificateChain(validRef, "c");
            Assertions.fail();
        }
        catch (KeyStoreException e)
        {
            Assertions.assertEquals("output too long int32", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    // -----------------------------------------------------------------
    // setCertificateChain
    // -----------------------------------------------------------------

    @Test
    public void setCertificateChain_failedAccessAlias()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());
        try
        {
            // Exercises interface/jni/ks_jni.c:377
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            ni.setCertificateChain(validRef, "alias", DUMMY);
            Assertions.fail();
        }
        catch (KeyStoreException e)
        {
            Assertions.assertEquals("unable to access key store alias", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void setCertificateChain_failedAccessInput()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());
        try
        {
            // Exercises interface/jni/ks_jni.c:382
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_2);
            ni.setCertificateChain(validRef, "alias", DUMMY);
            Assertions.fail();
        }
        catch (KeyStoreException e)
        {
            Assertions.assertEquals("unable to access input array", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    // -----------------------------------------------------------------
    // setCertificateEntry
    // -----------------------------------------------------------------

    @Test
    public void setCertificateEntry_failedAccessAlias()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());
        try
        {
            // Exercises interface/jni/ks_jni.c:417
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            ni.setCertificateEntry(validRef, "alias", DUMMY);
            Assertions.fail();
        }
        catch (KeyStoreException e)
        {
            Assertions.assertEquals("unable to access key store alias", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void setCertificateEntry_failedAccessInput()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());
        try
        {
            // Exercises interface/jni/ks_jni.c:422
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_2);
            ni.setCertificateEntry(validRef, "alias", DUMMY);
            Assertions.fail();
        }
        catch (KeyStoreException e)
        {
            Assertions.assertEquals("unable to access input array", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    // -----------------------------------------------------------------
    // deleteEntry
    // -----------------------------------------------------------------

    @Test
    public void deleteEntry_failedAccessAlias()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());
        try
        {
            // Exercises interface/jni/ks_jni.c:454
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            ni.deleteEntry(validRef, "alias");
            Assertions.fail();
        }
        catch (KeyStoreException e)
        {
            Assertions.assertEquals("unable to access key store alias", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    // -----------------------------------------------------------------
    // getAliases
    // -----------------------------------------------------------------

    @Test
    public void getAliases_int32Overflow()
        throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());
        ni.setKey(validRef, "k", keyPkcs8, PASSWORD);
        try
        {
            // Exercises interface/jni/ks_jni.c:495
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_1);
            ni.getAliases(validRef);
            Assertions.fail();
        }
        catch (KeyStoreException e)
        {
            Assertions.assertEquals("output too long int32", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    // -----------------------------------------------------------------
    // containsAlias
    // -----------------------------------------------------------------

    @Test
    public void containsAlias_failedAccessAlias()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());
        try
        {
            // Exercises interface/jni/ks_jni.c:532
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            ni.containsAlias(validRef, "alias");
            Assertions.fail();
        }
        catch (AccessException e)
        {
            Assertions.assertEquals("unable to access key store alias", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    // -----------------------------------------------------------------
    // isKeyEntry
    // -----------------------------------------------------------------

    @Test
    public void isKeyEntry_failedAccessAlias()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());
        try
        {
            // Exercises interface/jni/ks_jni.c:576
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            ni.isKeyEntry(validRef, "alias");
            Assertions.fail();
        }
        catch (AccessException e)
        {
            Assertions.assertEquals("unable to access key store alias", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    // -----------------------------------------------------------------
    // isCertificateEntry
    // -----------------------------------------------------------------

    @Test
    public void isCertificateEntry_failedAccessAlias()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());
        try
        {
            // Exercises interface/jni/ks_jni.c:607
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            ni.isCertificateEntry(validRef, "alias");
            Assertions.fail();
        }
        catch (AccessException e)
        {
            Assertions.assertEquals("unable to access key store alias", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    // -----------------------------------------------------------------
    // getCreationDate
    // -----------------------------------------------------------------

    @Test
    public void getCreationDate_failedAccessAlias()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());
        try
        {
            // Exercises interface/jni/ks_jni.c:648
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            ni.getCreationDate(validRef, "alias");
            Assertions.fail();
        }
        catch (KeyStoreException e)
        {
            Assertions.assertEquals("unable to access key store alias", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    // -----------------------------------------------------------------
    // helpers
    // -----------------------------------------------------------------

    // Builds a valid single-key keystore (no OPS flag active) for the load
    // fault-injection tests to then fail on a forced OpenSSL-call error.
    private byte[] buildValidKeystore()
        throws Exception
    {
        long ref = ni.allocateKeyStore("PKCS12");
        try
        {
            ni.setKey(ref, "k", keyPkcs8, PASSWORD);
            return ni.store(ref, PASSWORD, KEY_PBE, CERT_PBE, MAC_SCHEME, MAC_DIGEST,
                    PBE_ITER, MAC_ITER, TestUtil.RNDSrc);
        }
        finally
        {
            ni.dispose(ref);
        }
    }

    private static byte[] rsaPkcs8()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", JostleProvider.PROVIDER_NAME);
        kpg.initialize(2048);
        return kpg.generateKeyPair().getPrivate().getEncoded();
    }

    private static byte[] selfSignedCertDer()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", JostleProvider.PROVIDER_NAME);
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();
        X500Name name = new X500Name("CN=Jostle KS Ops Test");
        Date notBefore = new Date(System.currentTimeMillis() - 3600_000L);
        Date notAfter = new Date(System.currentTimeMillis() + 3600_000L);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                name, BigInteger.ONE, notBefore, notAfter, name, keyPair.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(keyPair.getPrivate());
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(builder.build(signer));
        return cert.getEncoded();
    }
}
