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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;

/**
 * MT-52 and MT-54: the KeyPairGenerator and SecretKeyFactory halves of the
 * init-surface arc.
 *
 * <h2>Two fixes here brought us into line with our OWN correct siblings</h2>
 *
 * <p>Neither was a new policy. {@code MLXKEMKeyGenerator} already guarded a
 * null spec while {@code MLKEMKeyGenerator} raised a raw NPE;
 * {@code HKDFSecretKeyFactory} already answered {@code "unsupported KeySpec
 * null"} while {@code PBKDF2SecretKeyFactory} raised one too. Both siblings are
 * asserted alongside the fixed classes so the pair cannot drift back apart.
 *
 * <h2>Ed25519's size check replaces a comment that claimed a parity it lacked</h2>
 *
 * <p>{@code EdDSAKeyPairGenerator.initialize(int, SecureRandom)} ignored the
 * size, with a comment saying it "mirrors XECKeyPairGenerator" - which
 * validates. The two references disagree slightly and the SUPERSET is taken:
 * the JDK accepts Ed25519 at 255 (the field size), BouncyCastle at 255 and 256
 * (the encoded length in bits). Both name the same key, so refusing either
 * would reject a caller that one reference tells to use.
 */
public class InitSurfaceContractTest
{
    private static Provider jsl;

    @BeforeAll
    public static void setUp()
    {
        jsl = Security.getProvider(JostleProvider.PROVIDER_NAME);
        if (jsl == null)
        {
            jsl = new JostleProvider();
            Security.addProvider(jsl);
        }
    }

    @Test
    public void edwardsGeneratorsRefuseAMeaninglessKeySize() throws Exception
    {
        List<String> failures = new ArrayList<String>();
        for (int size : new int[]{-1, 0, 128, 512, 1 << 26, Integer.MIN_VALUE})
        {
            for (String alg : new String[]{"Ed25519", "Ed448"})
            {
                try
                {
                    KeyPairGenerator.getInstance(alg, jsl).initialize(size);
                    failures.add(alg + " accepted key size " + size);
                }
                catch (InvalidParameterException expected)
                {
                    Assertions.assertNotNull(expected.getMessage());
                }
                catch (Throwable wrong)
                {
                    failures.add(alg + " size " + size + " raised " + wrong.getClass().getName());
                }
            }
        }
        Assertions.assertTrue(failures.isEmpty(), "Edwards key-size violations: " + failures);
    }

    /**
     * The other half of the boundary: the sizes the references DO name must
     * still work. A fix that refuses everything would pass the test above.
     */
    @Test
    public void edwardsGeneratorsStillAcceptTheReferenceSizes() throws Exception
    {
        // 255 is the JDK's spelling, 256 BouncyCastle's; both mean Ed25519.
        for (int size : new int[]{255, 256})
        {
            KeyPairGenerator g = KeyPairGenerator.getInstance("Ed25519", jsl);
            g.initialize(size);
            Assertions.assertNotNull(g.generateKeyPair().getPublic(),
                    "Ed25519 must still accept " + size);
        }
        KeyPairGenerator g448 = KeyPairGenerator.getInstance("Ed448", jsl);
        g448.initialize(448);
        Assertions.assertNotNull(g448.generateKeyPair().getPublic());
    }

    /** MT-52's other half: X25519 used to ACCEPT a null spec and refuse every real one. */
    @Test
    public void xdhGeneratorsRefuseANullParameterSpec() throws Exception
    {
        List<String> failures = new ArrayList<String>();
        for (String alg : new String[]{"X25519", "X448"})
        {
            try
            {
                KeyPairGenerator.getInstance(alg, jsl).initialize((AlgorithmParameterSpec) null);
                failures.add(alg + " accepted a null spec");
            }
            catch (InvalidAlgorithmParameterException expected)
            {
                Assertions.assertNotNull(expected.getMessage());
            }
            catch (Throwable wrong)
            {
                failures.add(alg + " raised " + wrong.getClass().getName());
            }
            // And a foreign spec is still refused, as it always was.
            try
            {
                KeyPairGenerator.getInstance(alg, jsl).initialize(new IvParameterSpec(new byte[16]));
                failures.add(alg + " accepted a foreign spec");
            }
            catch (InvalidAlgorithmParameterException expected)
            {
                // as before
            }
        }
        Assertions.assertTrue(failures.isEmpty(), "XDH spec violations: " + failures);
    }

    /**
     * MT-54a, with the sibling that was already right asserted beside it.
     */
    @Test
    public void aNullKeySpecIsTypedOnEveryKdfFactory() throws Exception
    {
        List<String> failures = new ArrayList<String>();
        for (String alg : new String[]{"PBKDF2WITHHMACSHA256", "HKDF-SHA256", "SCRYPT", "ARGON2"})
        {
            try
            {
                SecretKeyFactory.getInstance(alg, jsl).generateSecret(null);
                failures.add(alg + " accepted a null KeySpec");
            }
            catch (InvalidKeySpecException expected)
            {
                Assertions.assertNotNull(expected.getMessage(), alg);
            }
            catch (Throwable wrong)
            {
                failures.add(alg + " raised " + wrong.getClass().getName() + " for a null KeySpec");
            }
        }
        Assertions.assertTrue(failures.isEmpty(), "null-KeySpec violations: " + failures);
    }

    /** MT-54b: still unimplemented, but with the declared checked type. */
    @Test
    public void getKeySpecRaisesTheDeclaredCheckedException() throws Exception
    {
        List<String> failures = new ArrayList<String>();
        for (String alg : new String[]{"PBKDF2WITHHMACSHA256", "HKDF-SHA256", "SCRYPT", "ARGON2"})
        {
            try
            {
                SecretKeyFactory.getInstance(alg, jsl).getKeySpec(
                        new javax.crypto.spec.SecretKeySpec(new byte[16], "AES"),
                        javax.crypto.spec.DESKeySpec.class);
                failures.add(alg + " accepted an unservable spec class");
            }
            catch (InvalidKeySpecException expected)
            {
                Assertions.assertNotNull(expected.getMessage(), alg);
            }
            catch (Throwable wrong)
            {
                failures.add(alg + " raised " + wrong.getClass().getName() + " from getKeySpec");
            }
        }
        Assertions.assertTrue(failures.isEmpty(), "getKeySpec violations: " + failures);
    }
}
