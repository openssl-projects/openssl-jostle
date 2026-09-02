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
import org.openssl.jostle.util.Arrays;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.List;

/**
 * MT-48: every {@code KeyGenerator} init overload answers with the type JCA
 * names for it.
 *
 * <h2>Why the type matters more than it looks</h2>
 *
 * <p>{@code init(AlgorithmParameterSpec, SecureRandom)} DECLARES
 * {@code InvalidAlgorithmParameterException}. We raised
 * {@code UnsupportedOperationException}, which is unchecked - so a caller's
 * {@code catch (InvalidAlgorithmParameterException)} never fired and the error
 * escaped to whatever sat above. BouncyCastle and the JDK both raise the
 * declared type.
 *
 * <p>{@code init(int)} names {@code InvalidParameterException}. Ours raised
 * {@code IllegalArgumentException}, its SUPERTYPE - so a caller catching the
 * specific type missed ours. Retyping widens what callers catch rather than
 * narrowing it, which is why it is safe to apply to all three families rather
 * than only the one the survey attributed.
 */
public class KeyGeneratorInitContractTest
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

    /** 48a: the spec overload raises its DECLARED checked exception. */
    @Test
    public void initWithParametersRaisesTheDeclaredCheckedException() throws Exception
    {
        List<String> failures = new ArrayList<String>();
        for (String alg : new String[]{"AES", "ChaCha20", "DESede"})
        {
            for (AlgorithmParameterSpec spec : new AlgorithmParameterSpec[]{
                    null, new IvParameterSpec(new byte[16])})
            {
                try
                {
                    KeyGenerator.getInstance(alg, jsl).init(spec, new SecureRandom());
                    failures.add(alg + " accepted " + (spec == null ? "a null spec" : "a foreign spec"));
                }
                catch (InvalidAlgorithmParameterException expected)
                {
                    Assertions.assertNotNull(expected.getMessage(), alg + ": the refusal must say something");
                }
                catch (Throwable wrong)
                {
                    failures.add(alg + " (" + (spec == null ? "null" : "foreign") + ") raised "
                            + wrong.getClass().getName() + ", not InvalidAlgorithmParameterException");
                }
            }
        }
        Assertions.assertTrue(failures.isEmpty(), "init(spec) contract violations: " + failures);
    }

    /** 48c: the int overload raises the JCA-named type, not its supertype. */
    @Test
    public void initWithBadKeySizeRaisesInvalidParameterException() throws Exception
    {
        List<String> failures = new ArrayList<String>();
        int[] bad = {-1, 0, 1 << 26, Integer.MIN_VALUE, 7};
        for (String alg : new String[]{"AES", "ChaCha20", "DESede"})
        {
            for (int size : bad)
            {
                try
                {
                    KeyGenerator.getInstance(alg, jsl).init(size);
                    failures.add(alg + " accepted key size " + size);
                }
                catch (InvalidParameterException expected)
                {
                    // The declared type. Note it EXTENDS IllegalArgumentException,
                    // so a caller catching the old type still catches this.
                    Assertions.assertTrue(expected instanceof IllegalArgumentException,
                            "InvalidParameterException must remain catchable as IllegalArgumentException");
                }
                catch (Throwable wrong)
                {
                    failures.add(alg + " size " + size + " raised " + wrong.getClass().getName());
                }
            }
        }
        Assertions.assertTrue(failures.isEmpty(), "init(int) contract violations: " + failures);
    }

    /**
     * 48d - the ONLY loosening in this arc, so it is pinned on its own.
     *
     * <p>We used to refuse a null {@code SecureRandom}; BouncyCastle and the JDK
     * both accept it as "use the default", and the overload declares no
     * exception. Acceptance alone would be a weak pin - a generator that
     * accepted the null and then produced a CONSTANT key would pass it - so the
     * observable for "the default random is actually used" is that successive
     * keys differ.
     */
    @Test
    public void aNullSecureRandomMeansUseTheDefaultAndStillRandomises() throws Exception
    {
        KeyGenerator g = KeyGenerator.getInstance("DESede", jsl);
        g.init((SecureRandom) null);
        SecretKey a = g.generateKey();
        SecretKey b = g.generateKey();
        Assertions.assertNotNull(a.getEncoded());
        Assertions.assertFalse(Arrays.areEqual(a.getEncoded(), b.getEncoded()),
                "a null SecureRandom must fall back to a working default, not a constant");

        KeyGenerator sized = KeyGenerator.getInstance("DESede", jsl);
        sized.init(192, null);
        SecretKey c = sized.generateKey();
        SecretKey d = sized.generateKey();
        Assertions.assertFalse(Arrays.areEqual(c.getEncoded(), d.getEncoded()),
                "init(int, null) must randomise too - the other overload was refusing as well");
    }

    /**
     * 48b: our first raw NullPointerException, and the sibling that was already
     * right.
     *
     * <p>{@code MLXKEMKeyGenerator} already guarded this; ML-KEM was the
     * outlier. Both are asserted so the fix cannot regress into the asymmetry
     * it removed.
     */
    @Test
    public void aNullSpecOnTheKemGeneratorsIsTypedNotAnNpe() throws Exception
    {
        for (String alg : new String[]{"ML-KEM-512", "X25519MLKEM768"})
        {
            try
            {
                KeyGenerator.getInstance(alg, jsl).init((AlgorithmParameterSpec) null, new SecureRandom());
                Assertions.fail(alg + " accepted a null spec");
            }
            catch (InvalidAlgorithmParameterException expected)
            {
                Assertions.assertNotNull(expected.getMessage(), alg + ": the refusal must say something");
            }
            catch (Throwable wrong)
            {
                Assertions.fail(alg + " raised " + wrong.getClass().getName()
                        + " for a null spec, not InvalidAlgorithmParameterException");
            }
        }
    }
}
