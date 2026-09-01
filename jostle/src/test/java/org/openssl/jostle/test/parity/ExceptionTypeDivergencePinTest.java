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

package org.openssl.jostle.test.parity;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Security;

/**
 * Divergences from BouncyCastle that are DELIBERATE, pinned in both halves.
 *
 * <p>The standing rule is to match BouncyCastle's exception type for the same
 * refusal, because callers write their catch blocks against BC. It has one
 * boundary, added after the MT-31 survey measured two cases where BC is the
 * non-canonical side: <b>match BouncyCastle UNLESS BouncyCastle diverges from
 * the JCE contract.</b> Where BC is wrong, JCE-canonical wins and the
 * divergence is pinned here.
 *
 * <p><b>Both halves are asserted deliberately.</b> A pin that recorded only our
 * type would let a future BC-parity sweep "fix" the divergence without ever
 * meeting the reason it exists. Asserting BC's half too means such a sweep must
 * first delete a test that explains itself.
 *
 * <p><b>The BC half is measured LIVE, and a bcprov bump that moves BC will fail
 * this loudly. That is the pin's second job, not fragility</b> - if the
 * reference moves we want to know, because the reason for the divergence may
 * have moved with it.
 */
public class ExceptionTypeDivergencePinTest
{
    @BeforeAll
    public static void setUp()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private static Throwable initWith(String provider, java.security.Key key,
                                      java.security.spec.AlgorithmParameterSpec ps)
    {
        try
        {
            Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding", provider);
            c.init(Cipher.ENCRYPT_MODE, key, ps);
            return null;
        }
        catch (Throwable t)
        {
            return t;
        }
    }

    /**
     * A short key is an InvalidKeyException for us and an
     * InvalidAlgorithmParameterException for BouncyCastle.
     *
     * <p>We are the JCE-canonical side: {@code InvalidKeyException} is the type
     * the contract names for a bad key, and it is also what triggers the JCE's
     * next-provider fallback. BC reports it as a parameter problem because its
     * key-length check happens inside its parameter handling - both messages
     * name the key length, so the disagreement is about the TYPE, not about
     * what was wrong.
     *
     * <p>Matching BC here would make us less correct, so we do not.
     */
    @Test
    public void shortKey_weAreJceCanonicalAndBouncyCastleIsNot()
    {
        byte[] shortKey = new byte[15];          // one byte under AES-128
        IvParameterSpec iv = new IvParameterSpec(new byte[16]);

        Throwable ours = initWith(JostleProvider.PROVIDER_NAME,
                new SecretKeySpec(shortKey, "AES"), iv);
        Throwable bc = initWith(BouncyCastleProvider.PROVIDER_NAME,
                new SecretKeySpec(shortKey, "AES"), iv);

        Assertions.assertNotNull(ours, "a 15-byte AES key must be refused");
        Assertions.assertNotNull(bc, "BouncyCastle must refuse it too");

        Assertions.assertEquals(InvalidKeyException.class, ours.getClass(),
                "ours must stay the JCE-canonical type for a bad key");
        Assertions.assertEquals(InvalidAlgorithmParameterException.class, bc.getClass(),
                "BouncyCastle's half of the pin: if this fails, BC has MOVED -"
                        + " re-evaluate whether the divergence still has a reason");
    }

    /**
     * An unrelated AlgorithmParameterSpec is refused by us and silently ignored
     * by BouncyCastle.
     *
     * <p>A decision divergence, not a type one, and it is decided in our Java
     * layer rather than in OpenSSL - so the OpenSSL-wins rule does not dispose
     * of it. We keep ours: silently discarding a caller's parameters is worse
     * than refusing them, because the caller believes they took effect.
     */
    @Test
    public void foreignParameterSpec_weRefuseWhereBouncyCastleIgnores()
    {
        byte[] key = new byte[16];
        PBEParameterSpec foreign = new PBEParameterSpec(new byte[8], 1000);

        Throwable ours = initWith(JostleProvider.PROVIDER_NAME,
                new SecretKeySpec(key, "AES"), foreign);
        Throwable bc = initWith(BouncyCastleProvider.PROVIDER_NAME,
                new SecretKeySpec(key, "AES"), foreign);

        Assertions.assertNotNull(ours, "a PBEParameterSpec on AES must be refused");
        Assertions.assertEquals(InvalidAlgorithmParameterException.class, ours.getClass(),
                "ours must be the JCE-canonical parameter refusal");
        Assertions.assertNull(bc,
                "BouncyCastle's half of the pin: it ACCEPTS the foreign spec."
                        + " If this fails, BC has started refusing and the"
                        + " divergence may be over");
    }
}
