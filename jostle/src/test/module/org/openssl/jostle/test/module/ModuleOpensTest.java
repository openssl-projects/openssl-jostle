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
import java.io.ObjectOutputStream;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Security;

/**
 * Behaviour of the two packages module-info opens to java.base, measured
 * under a module.
 *
 * <p>Neither clause is load-bearing, and no {@code opens} qualified to
 * java.base can be: {@code Method.setAccessible} (java.base/java/lang/
 * reflect/Method.java:175) calls {@code checkCanSetAccessible}, which returns
 * true for a java.base caller at AccessibleObject.java:301 on JDK 25 — before
 * the {@code isExported} and {@code isOpen} tests at :309 and :324. Same line
 * at :294 on JDK 11, :311 on 17, :339 on 21. All seven of jostle's opens are
 * qualified to java.base. Deleting two and re-running confirmed it.
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
