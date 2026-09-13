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

package org.openssl.jostle.test.module;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.NotSerializableException;
import java.io.ObjectOutputStream;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;

/**
 * Behaviour of the packages module-info USED to open to java.base, measured
 * under a module. The seven clauses are gone; these cells are what proves
 * nothing depended on them.
 *
 * <p>No clause was load-bearing, and no {@code opens} qualified to
 * java.base can be: {@code Method.setAccessible} (java.base/java/lang/
 * reflect/Method.java:175) calls {@code checkCanSetAccessible}, which returns
 * true for a java.base caller at AccessibleObject.java:301 on JDK 25 — before
 * the {@code isExported} and {@code isOpen} tests at :309 and :324. Same line
 * at :294 on JDK 11, :311 on 17, :339 on 21. All seven of jostle's opens were
 * qualified to java.base, and all seven are now removed.
 * MT-96 in reviews/misc-tasks-plan.md carries the measurement.
 *
 * <p>These cells pin what a caller sees, not the clauses.
 */
public class ModuleOpensTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;

    @BeforeAll
    public static void setUp()
    {
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    /**
     * {@code SecureRandomSpi implements Serializable}, so serialisation
     * reaches the SPI's private {@code writeObject}
     * (ObjectStreamClass.java:1391), which refuses: a native RNG handle
     * cannot be serialised. The message is pinned; asserting success would
     * pass against default field serialisation writing a useless object.
     */
    @Test
    public void serialisingASecureRandomIsRefusedWithANamedMessage() throws Exception
    {
        SecureRandom sr = SecureRandom.getInstance("DEFAULT", JSL);
        sr.nextBytes(new byte[16]);

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        UnsupportedOperationException thrown = Assertions.assertThrows(
                UnsupportedOperationException.class,
                () ->
                {
                    try (ObjectOutputStream oos = new ObjectOutputStream(bos))
                    {
                        oos.writeObject(sr);
                    }
                },
                "the refusal did not reach the caller");
        Assertions.assertEquals("writeObject not implemented on native rand", thrown.getMessage());
    }

    /**
     * The three PQ packages that have no other reflective consumer:
     * {@code provider.mldsa}, {@code provider.mlkem}, {@code provider.slhdsa}.
     *
     * <p>{@code java.security.Key} extends {@code Serializable}, so writing one
     * makes java.base walk the key's declared fields — reflection INTO the
     * package, which is the only thing a removed {@code opens} could have
     * broken. It does not break: the walk reaches the NI service field and
     * refuses because that field's type is not serialisable.
     *
     * <p>Pinning {@code NotSerializableException} is what makes this a witness.
     * An {@code InaccessibleObjectException} is what a genuinely-needed
     * {@code opens} would produce, and it would fail here by type.
     *
     * <p>The refused class is named per BRIDGE — {@code ...ServiceFFI} or
     * {@code ...ServiceJNI} by leg — so the assertion pins its PACKAGE, which
     * is the part under test, and not the bridge, which is not.
     */
    @Test
    public void serialisingAPqKeyRefusesOnItsNativeFieldNotOnAccess() throws Exception
    {
        String[] algs = {"ML-DSA-44", "ML-KEM-512", "SLH-DSA-SHA2-128S"};
        String[] packages = {
                "org.openssl.jostle.jcajce.provider.mldsa",
                "org.openssl.jostle.jcajce.provider.mlkem",
                "org.openssl.jostle.jcajce.provider.slhdsa"};
        Assertions.assertEquals(algs.length, packages.length, "vacuity: the table must be square");

        int driven = 0;
        for (int i = 0; i < algs.length; i++)
        {
            PublicKey k = KeyPairGenerator.getInstance(algs[i], JSL).generateKeyPair().getPublic();
            Assertions.assertEquals(packages[i], k.getClass().getPackageName(),
                    algs[i] + ": the key must come from the package under test");

            NotSerializableException thrown = Assertions.assertThrows(
                    NotSerializableException.class,
                    () ->
                    {
                        try (ObjectOutputStream oos = new ObjectOutputStream(new ByteArrayOutputStream()))
                        {
                            oos.writeObject(k);
                        }
                    },
                    algs[i] + ": expected the field-level refusal, not an access failure");

            Assertions.assertTrue(thrown.getMessage().startsWith(packages[i] + "."),
                    algs[i] + ": the refusal must name a class in " + packages[i]
                            + ", got " + thrown.getMessage());
            driven++;
        }
        Assertions.assertEquals(3, driven, "all three packages must have been driven");
    }

    /** PKCS12 under a module, both directions: a store that cannot be loaded is not a keystore. */
    @Test
    public void aPkcs12KeystoreStoresAndLoadsBack() throws Exception
    {
        char[] password = "module-leg".toCharArray();

        KeyStore out = KeyStore.getInstance("PKCS12", JSL);
        out.load(null, password);
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        out.store(bos, password);
        Assertions.assertTrue(bos.size() > 0, "an empty PKCS12 was written");

        KeyStore back = KeyStore.getInstance("PKCS12", JSL);
        back.load(new ByteArrayInputStream(bos.toByteArray()), password);
        Assertions.assertEquals(0, back.size());
    }
}
