/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.fips;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.jcajce.provider.ProviderCapabilityException;
import org.openssl.jostle.util.Arrays;

import javax.crypto.KeyAgreement;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;

/**
 * MT-71: JSLFIPS minted EC keys on curves it could not then agree on.
 *
 * <h2>Why this is diagnosed at the derive and not gated earlier</h2>
 *
 * <p>Three designs were killed by measurement before this one. Setting OpenSSL's
 * cofactor mode would change the secret — cofactor ECDH computes h·d·Q, plain
 * computes d·Q — and JSL agrees with BouncyCastle today, so it would break
 * interoperability. Gating at keygen would remove ECDSA and KeyFactory, both of
 * which work on these curves. Gating at KeyAgreement init would break the 3.1.2
 * module, which performs plain ECDH on them happily.
 *
 * <p>So the refusal is classified where it happens, and the branch never fires
 * on a provider that accepts the input. That is why the cells below are
 * module-branched by MEASURED behaviour rather than by a version string: a
 * module swap cannot pass silently.
 */
public class FIPSEcCofactorEcdhTest
{
    /** Every curve JSL serves with cofactor != 1 — eight, not the five first reported. */
    private static final String[] COFACTOR_CURVES = {
            "sect233k1", "sect233r1", "sect283k1", "sect283r1",
            "sect409k1", "sect409r1", "sect571k1", "sect571r1"};

    /** Below 112-bit security. Refused by both modules, at different POINTS. */
    private static final String[] WEAK_CURVES = {"secp192r1", "sect163k1", "sect163r2"};

    /** Cofactor 1 and strong: must keep working on every module. */
    private static final String[] HEALTHY_CURVES = {
            "secp224r1", "secp256r1", "secp384r1", "secp521r1", "P-256", "P-384"};

    private static Provider fips;
    private static Provider jsl;
    private static Provider bc;

    @BeforeAll
    public static void setUp()
    {
        fips = FIPSTestUtil.assumeFipsProvider();
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        jsl = Security.getProvider(JostleProvider.PROVIDER_NAME);
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        bc = Security.getProvider("BC");
    }

    /**
     * The property. On a module that refuses plain ECDH for cofactor != 1 the
     * caller gets a typed, explanatory refusal; on one that accepts it, the
     * derive works. Branched on what the module DOES, so neither module can
     * silently take the other's path.
     */
    @Test
    public void cofactorCurvesAreEitherRefusedTypedOrDeriveCleanly() throws Exception
    {
        for (String curve : COFACTOR_CURVES)
        {
            KeyPair a = generate(fips, curve);
            KeyPair b = generate(fips, curve);

            byte[] secret;
            try
            {
                secret = derive(fips, a.getPrivate(), b.getPublic());
            }
            catch (ProviderCapabilityException ex)
            {
                Assertions.assertEquals(
                        "ECDH on a curve with cofactor != 1 requires cofactor ECDH, which the loaded"
                                + " provider requires and this provider does not perform",
                        ex.getMessage(), curve + ": the refusal must name the constraint");
                continue;
            }

            // The module performed it, so it must be a real plain-ECDH secret:
            // BouncyCastle computes the same one from the same keys.
            byte[] viaBc = derive(bc, a.getPrivate(), b.getPublic());
            Assertions.assertTrue(Arrays.areEqual(secret, viaBc),
                    curve + ": a module that derives must produce the plain-ECDH secret BC computes");
        }
    }

    /**
     * The weak curves, pinned as they are: the SAME curves are refused at
     * DIFFERENT points by the two modules — keygen on 3.5.x, derive on 3.1.2.
     * Left untyped deliberately: the module's own message already names the
     * curve and the rule, so a typed code would add nothing.
     */
    @Test
    public void weakCurvesAreRefusedAtWhicheverPointTheModuleChooses() throws Exception
    {
        for (String curve : WEAK_CURVES)
        {
            KeyPair kp;
            try
            {
                kp = generate(fips, curve);
            }
            catch (Exception refusedAtKeygen)
            {
                Assertions.assertTrue(String.valueOf(refusedAtKeygen.getMessage()).contains("curve"),
                        curve + ": a keygen refusal must say it is about the curve; got: "
                                + refusedAtKeygen.getMessage());
                continue;
            }

            OpenSSLException ex = Assertions.assertThrows(OpenSSLException.class,
                    () -> derive(fips, kp.getPrivate(), generate(fips, curve).getPublic()),
                    curve + ": a module that mints a key on a sub-112-bit curve must refuse the derive");
            Assertions.assertTrue(String.valueOf(ex.getMessage()).contains(shortName(curve)),
                    curve + ": the refusal must name the curve; got: " + ex.getMessage());
        }
    }

    /** Nothing moved for cofactor-1 curves on the FIPS provider. */
    @Test
    public void healthyCurvesStillDeriveOnFips() throws Exception
    {
        for (String curve : HEALTHY_CURVES)
        {
            KeyPair a = generate(fips, curve);
            KeyPair b = generate(fips, curve);
            Assertions.assertTrue(derive(fips, a.getPrivate(), b.getPublic()).length > 0, curve);
        }
    }

    /**
     * The control that shows the base provider did not move: JSL derives on every
     * curve, cofactor or not, and agrees with BouncyCastle. If the classifier had
     * been a pre-check it would have fired here too.
     */
    @Test
    public void jslStillDerivesEverywhereAndAgreesWithBouncyCastle() throws Exception
    {
        for (String curve : concat(COFACTOR_CURVES, HEALTHY_CURVES))
        {
            KeyPair a = generate(jsl, curve);
            KeyPair b = generate(jsl, curve);
            byte[] mine = derive(jsl, a.getPrivate(), b.getPublic());
            byte[] theirs = derive(bc, a.getPrivate(), b.getPublic());
            Assertions.assertTrue(Arrays.areEqual(mine, theirs),
                    curve + ": JSL must still compute the plain-ECDH secret BC computes");
        }
    }

    /**
     * OpenSSL names the curve K-163 / P-192 where the JCE says sect163k1 /
     * secp192r1, so the assertion compares on the FIELD SIZE.
     *
     * <p>The first digit run only: stripping every non-digit turns
     * {@code secp192r1} into {@code 1921}, which appears in no message and made
     * this cell fail against a correct implementation.
     */
    private static String shortName(String curve)
    {
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("[0-9]+").matcher(curve);
        Assertions.assertTrue(m.find(), "curve name must carry a field size: " + curve);
        return m.group();
    }

    private static String[] concat(String[] a, String[] b)
    {
        String[] out = new String[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static KeyPair generate(Provider provider, String curve) throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", provider);
        kpg.initialize(new ECGenParameterSpec(curve));
        return kpg.generateKeyPair();
    }

    private static byte[] derive(Provider provider, PrivateKey priv, PublicKey pub) throws Exception
    {
        KeyAgreement ka = KeyAgreement.getInstance("ECDH", provider);
        ka.init(priv);
        ka.doPhase(pub, true);
        return ka.generateSecret();
    }
}
