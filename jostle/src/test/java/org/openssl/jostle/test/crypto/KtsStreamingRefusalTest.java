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

package org.openssl.jostle.test.crypto;

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;

/**
 * MT-37: the two KTS ciphers have no streaming surface.
 *
 * <p>MT-37 excluded them from the chunking sweep on the ground that
 * {@code update()} is not in their contract. The exclusion is pinned here so the
 * claim cannot rot.
 *
 * <p>Every call below is made on a cipher initialised in a state a KTS caller
 * can actually reach. An earlier version called them UNINITIALISED, which throws
 * for every cipher in every provider — an AES cipher satisfied it unchanged.
 */
public class KtsStreamingRefusalTest
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

    private static KTSParameterSpec kts()
    {
        return new KTSParameterSpec.Builder("AES", 256)
                .withKdfAlgorithm(new AlgorithmIdentifier(X9ObjectIdentifiers.id_kdf_kdf3,
                        new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256)))
                .build();
    }

    private static KeyPair rsaPair() throws Exception
    {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA", JSL);
        g.initialize(2048);
        return g.generateKeyPair();
    }

    private static KeyPair mlKemPair() throws Exception
    {
        return KeyPairGenerator.getInstance("ML-KEM-768", JSL).generateKeyPair();
    }

    /**
     * After a real WRAP_MODE init, the streaming surface is refused. Type only:
     * the thrower is the JDK framework and its text differs across 8 to 25.
     */
    private static void assertNoStreamingSurface(String transformation, KeyPair kp) throws Exception
    {
        final byte[] in = new byte[32];
        final byte[] out = new byte[512];

        Cipher a = Cipher.getInstance(transformation, JSL);
        a.init(Cipher.WRAP_MODE, kp.getPublic(), kts());
        Assertions.assertThrows(IllegalStateException.class,
                () -> a.update(in, 0, in.length), transformation + ": update");
        Cipher b = Cipher.getInstance(transformation, JSL);
        b.init(Cipher.WRAP_MODE, kp.getPublic(), kts());
        Assertions.assertThrows(IllegalStateException.class,
                () -> b.update(in, 0, in.length, out, 0), transformation + ": update into");
        Cipher c = Cipher.getInstance(transformation, JSL);
        c.init(Cipher.WRAP_MODE, kp.getPublic(), kts());
        Assertions.assertThrows(IllegalStateException.class,
                () -> c.doFinal(in, 0, in.length), transformation + ": doFinal");
        Cipher d = Cipher.getInstance(transformation, JSL);
        d.init(Cipher.WRAP_MODE, kp.getPublic(), kts());
        Assertions.assertThrows(IllegalStateException.class,
                () -> d.doFinal(in, 0, in.length, out, 0), transformation + ": doFinal into");
    }

    /** The mode refusal is ours, so its message is asserted exactly. */
    private static void assertEncryptModeRefused(String transformation, KeyPair kp,
                                                 String expected) throws Exception
    {
        Cipher c = Cipher.getInstance(transformation, JSL);
        InvalidAlgorithmParameterException e = Assertions.assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> c.init(Cipher.ENCRYPT_MODE, kp.getPublic(), kts()),
                transformation + ": ENCRYPT_MODE must be refused");
        Assertions.assertEquals(expected, e.getMessage(), transformation + ": mode refusal message");
    }

    /** Distinct from the mode refusal: this overload refuses in EVERY mode. */
    private static void assertNoParamsInitRefused(String transformation) throws Exception
    {
        Cipher c = Cipher.getInstance(transformation, JSL);
        InvalidKeyException e = Assertions.assertThrows(InvalidKeyException.class,
                () -> c.init(Cipher.WRAP_MODE, (Key) null),
                transformation + ": the no-params init must be refused");
        Assertions.assertTrue(String.valueOf(e.getMessage()).contains("KTSParameterSpec"),
                transformation + ": must name what is required, got: " + e.getMessage());
    }

    @Test
    public void mlKemKtsHasNoStreamingSurface() throws Exception
    {
        KeyPair kp = mlKemPair();
        assertNoStreamingSurface("ML-KEM", kp);
        assertEncryptModeRefused("ML-KEM", kp, "ML-KEM KTS cipher only supports WRAP_MODE/UNWRAP_MODE");
        assertNoParamsInitRefused("ML-KEM");
    }

    @Test
    public void rsaKtsHasNoStreamingSurface() throws Exception
    {
        KeyPair kp = rsaPair();
        assertNoStreamingSurface("RSA-KTS-KEM-KWS", kp);
        assertEncryptModeRefused("RSA-KTS-KEM-KWS", kp,
                "RSA-KTS-KEM-KWS only supports WRAP_MODE/UNWRAP_MODE");
        assertNoParamsInitRefused("RSA-KTS-KEM-KWS");
    }

    /**
     * The control that makes the above non-vacuous: a cipher WITH a streaming
     * surface, initialised, does not throw. Without it, an assertion that every
     * cipher satisfies reads exactly like one only KTS satisfies.
     */
    @Test
    public void anOrdinaryCipherDoesNotRefuseTheStreamingSurface() throws Exception
    {
        byte[] k = new byte[16];
        new java.security.SecureRandom().nextBytes(k);
        Cipher c = Cipher.getInstance("AES/ECB/NoPadding", JSL);
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(k, "AES"));
        Assertions.assertNotNull(c.update(new byte[16], 0, 16),
                "an ordinary block cipher must accept update() — otherwise the KTS "
                        + "assertions above prove nothing about KTS");
    }
}
