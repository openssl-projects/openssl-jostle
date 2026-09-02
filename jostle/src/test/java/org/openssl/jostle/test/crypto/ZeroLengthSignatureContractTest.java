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

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

/**
 * MT-39: what a zero-length signature does, per family.
 *
 * <h2>The ruling, and why it does not give one answer</h2>
 *
 * <p>Megan, 2026-09-02: <i>"if BC or the JCE accept zero length signatures then
 * we should too"</i> — return false where EITHER reference returns false; throw
 * only where BOTH throw. Applied to measurement rather than to intuition, that
 * splits the surface in two:
 *
 * <ul>
 *   <li><b>ECDSA and DSA</b> — both references throw, so the OR clause never
 *       engages and we throw. This also removed an inconsistency of our own:
 *       the digest paths returned false while the {@code NONEwith*} paths
 *       already threw.</li>
 *   <li><b>RSA and Ed25519</b> — BouncyCastle returns false and the JDK throws.
 *       The OR clause selects acceptance, so we return false.</li>
 * </ul>
 *
 * <h2>The RSA/Ed rows are a DELIBERATE divergence from the JDK</h2>
 *
 * <p><b>A caller migrating from the JDK gets {@code false} here where the JDK
 * would have thrown.</b> That is the ruling's OR clause choosing the more
 * permissive of two disagreeing references, not an oversight. A parity sweep
 * that reads "the JDK throws and we do not" as a defect would be fixing this
 * the wrong way, which is exactly why the consequence is stated here rather
 * than only the fact.
 *
 * <p>Note also what does NOT justify the split: the review's original
 * recommendation reached the right answer for ECDSA/DSA by arguing that
 * ASN.1-encoded families should throw. RSA and Ed25519 carry structured
 * signatures too, so extending that argument gives the WRONG answer for them.
 * The rule is about what the references do, not about the encoding.
 *
 * <h2>Both halves are asserted live</h2>
 *
 * <p>Our behaviour AND each reference's, measured in-test rather than
 * transcribed, so a bcprov or JDK change that moves the ground under this
 * ruling fails loudly instead of leaving a pin that quietly no longer means
 * what it says.
 */
public class ZeroLengthSignatureContractTest
{
    private static Provider jsl;
    private static Provider bc;

    @BeforeAll
    public static void setUp()
    {
        jsl = Security.getProvider(JostleProvider.PROVIDER_NAME);
        if (jsl == null)
        {
            jsl = new JostleProvider();
            Security.addProvider(jsl);
        }
        bc = Security.getProvider("BC");
        if (bc == null)
        {
            bc = new BouncyCastleProvider();
            Security.addProvider(bc);
        }
    }

    /** null = the call threw; TRUE/FALSE = it returned that. */
    private static Boolean verifyEmpty(Provider p, String xform, String kpgAlg,
                                       KeyPair kp, byte[] input) throws Exception
    {
        KeyFactory kf = KeyFactory.getInstance(kpgAlg, p);
        PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));
        Signature v = Signature.getInstance(xform, p);
        v.initVerify(pub);
        v.update(input);
        try
        {
            return Boolean.valueOf(v.verify(new byte[0]));
        }
        catch (SignatureException threw)
        {
            return null;
        }
    }

    private static Provider jdkFor(String xform, String kfAlg)
    {
        for (Provider p : Security.getProviders())
        {
            // Exclude ours by CLASS, not by name. Naming the FIPS provider here
            // tripped FIPSTestNamingParityTest - correctly, since it cannot tell
            // an exclusion from a use - and the class check is the better
            // implementation anyway: it covers every Jostle provider however it
            // is registered, including instances registered under a
            // non-standard name.
            if (p.getClass().getName().startsWith("org.openssl.jostle")
                    || p instanceof BouncyCastleProvider)
            {
                continue;
            }
            if (p.getService("Signature", xform) != null && p.getService("KeyFactory", kfAlg) != null)
            {
                return p;
            }
        }
        return null;
    }

    private static KeyPair keys(String alg) throws Exception
    {
        KeyPairGenerator g = KeyPairGenerator.getInstance(alg, jsl);
        if ("EC".equals(alg))
        {
            g.initialize(new ECGenParameterSpec("P-256"));
        }
        else if ("DSA".equals(alg) || "RSA".equals(alg))
        {
            g.initialize(2048);
        }
        return g.generateKeyPair();
    }

    /** ECDSA and DSA: both references throw, so we throw — all four entry points. */
    @Test
    public void ecdsaAndDsaThrowBecauseBothReferencesDo() throws Exception
    {
        String[][] cells = {
                {"SHA256withECDSA", "EC", null},
                {"NONEwithECDSA", "EC", "SHA-256"},
                {"SHA256withDSA", "DSA", null},
                {"NONEwithDSA", "DSA", "SHA-1"}};
        byte[] msg = new byte[64];
        new SecureRandom().nextBytes(msg);
        List<String> failures = new ArrayList<String>();

        for (String[] c : cells)
        {
            KeyPair kp = keys(c[1]);
            byte[] in = c[2] == null ? msg : MessageDigest.getInstance(c[2]).digest(msg);

            if (verifyEmpty(jsl, c[0], c[1], kp, in) != null)
            {
                failures.add(c[0] + ": we did not throw");
            }
            // The references, live - the ruling rests on both of them throwing.
            if (verifyEmpty(bc, c[0], c[1], kp, in) != null)
            {
                failures.add(c[0] + ": BouncyCastle no longer throws - the ruling's basis has moved");
            }
            Provider jdk = jdkFor(c[0], c[1]);
            if (jdk != null && verifyEmpty(jdk, c[0], c[1], kp, in) != null)
            {
                failures.add(c[0] + ": the JDK no longer throws - the ruling's basis has moved");
            }
        }
        Assertions.assertTrue(failures.isEmpty(), String.valueOf(failures));
    }

    /**
     * RSA and Ed25519: we return false, and so does BouncyCastle — while the
     * JDK throws.
     *
     * <p>The three-way split is asserted deliberately, JDK arm included. If a
     * future JDK stops throwing, this fails and the divergence note above needs
     * revisiting; if it keeps throwing, the failure message reminds the reader
     * that our answer is chosen, not accidental.
     */
    @Test
    public void rsaAndEdReturnFalseBecauseBouncyCastleAcceptsEvenThoughTheJdkThrows() throws Exception
    {
        String[][] cells = {{"SHA256withRSA", "RSA"}, {"Ed25519", "Ed25519"}};
        byte[] msg = new byte[64];
        new SecureRandom().nextBytes(msg);
        List<String> failures = new ArrayList<String>();

        for (String[] c : cells)
        {
            KeyPair kp = keys(c[1]);

            Boolean ours = verifyEmpty(jsl, c[0], c[1], kp, msg);
            if (!Boolean.FALSE.equals(ours))
            {
                failures.add(c[0] + ": expected false, got " + (ours == null ? "a throw" : ours));
            }
            Boolean theirs = verifyEmpty(bc, c[0], c[1], kp, msg);
            if (!Boolean.FALSE.equals(theirs))
            {
                failures.add(c[0] + ": BouncyCastle no longer returns false ("
                        + (theirs == null ? "throws" : theirs)
                        + ") - it is the OR clause's basis, so the ruling needs revisiting");
            }
            Provider jdk = jdkFor(c[0], c[1]);
            if (jdk != null)
            {
                Boolean theJdk = verifyEmpty(jdk, c[0], c[1], kp, msg);
                if (theJdk != null)
                {
                    failures.add(c[0] + ": the JDK returned " + theJdk
                            + " where it threw when this was ruled; the three-way split has changed");
                }
            }
        }
        Assertions.assertTrue(failures.isEmpty(),
                "MT-39 RSA/Ed contract - we deliberately differ from the JDK here: " + failures);
    }

    /**
     * The null case, which rode the same guard.
     *
     * <p>Disclosed rather than assumed: DSA previously raised
     * {@code IllegalArgumentException} — undeclared and unchecked — where
     * {@code verify} declares {@code SignatureException} and BouncyCastle
     * raises it. The JDK raises a raw {@code NullPointerException} for DSA,
     * which is its own defect and not a target.
     */
    @Test
    public void aNullSignatureRaisesTheDeclaredCheckedException() throws Exception
    {
        byte[] msg = new byte[64];
        new SecureRandom().nextBytes(msg);
        for (String[] c : new String[][]{{"SHA256withECDSA", "EC"}, {"SHA256withDSA", "DSA"}})
        {
            KeyPair kp = keys(c[1]);
            KeyFactory kf = KeyFactory.getInstance(c[1], jsl);
            Signature v = Signature.getInstance(c[0], jsl);
            v.initVerify(kf.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded())));
            v.update(msg);
            Assertions.assertThrows(SignatureException.class, () -> v.verify(null),
                    c[0] + ": a null signature must raise the exception verify() declares");
        }
    }
}
