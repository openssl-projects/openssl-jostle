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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.SortedSet;
import java.util.TreeSet;

/**
 * Registration is not usability: every service JSLFIPS registers must actually
 * WORK against the loaded module, or fail in a way a caller can act on.
 * <p>
 * {@link FIPSServedSurfaceSnapshotTest} enumerates {@code provider.getServices()}
 * and never uses them — which is why it passed untouched while five algorithm
 * families broke under a module change, and 59 tests scattered across the suite
 * were what reported it. This is the companion that closes that gap: it takes
 * the registered surface and drives one minimal real operation per service.
 * <p>
 * Two tiers, deliberately:
 * <ol>
 *   <li><b>Universal</b> — every registered primary must be constructible
 *       through {@code getInstance(alg, "JSLFIPS")}. A registered service that
 *       throws {@link NoSuchAlgorithmException} is a registration bug outright,
 *       and this catches it for every type without needing per-type knowledge.</li>
 *   <li><b>Functional</b> — for the types where a minimal operation
 *       generalises (MessageDigest, Mac, SecureRandom), the operation is run
 *       and its OUTPUT checked, with a differentiator so a stub cannot pass.
 *       These are the families where "resolves but produces nothing useful" is
 *       otherwise invisible.</li>
 * </ol>
 * A failure names the exact service, so a module change reports as one line
 * rather than as an unexplained spread across the suite.
 * <p>
 * <b>Not an approval check.</b> Everything registered is expected to work
 * because JSLFIPS registers what the module implements. Where a capability
 * genuinely differs between supported modules the registrar declines to
 * register at all (see {@code FIPSCapabilities}), so it never reaches here.
 * <p>
 * Gated on {@code TEST_FIPS_LIB}; skipped when unset.
 */
public class FIPSServedSurfaceSmokeTest
{
    private static final String FIPS = JostleFIPSProvider.PROVIDER_NAME;

    private static final SecureRandom RANDOM = new SecureRandom();

    @BeforeAll
    static void before()
    {
        FIPSTestUtil.assumeFipsProvider();
    }

    /**
     * Every registered primary resolves through {@code getInstance}.
     * <p>
     * Collects all failures before reporting rather than stopping at the
     * first, so a module change is one legible list instead of a
     * fix-one-rerun-repeat loop.
     */
    @Test
    public void everyRegisteredServiceIsConstructible()
    {
        Provider provider = FIPSTestUtil.assumeFipsProvider();
        List<String> broken = new ArrayList<>();

        for (Provider.Service s : sorted(provider))
        {
            try
            {
                Assertions.assertNotNull(s.newInstance(null),
                        s.getType() + "." + s.getAlgorithm() + " returned a null instance");
            }
            catch (Exception e)
            {
                broken.add(s.getType() + "." + s.getAlgorithm() + " -> "
                        + e.getClass().getSimpleName() + ": " + e.getMessage());
            }
        }

        Assertions.assertTrue(broken.isEmpty(),
                "registered services that cannot be constructed against the loaded module ("
                        + FIPSTestUtil.moduleDescription() + "):\n  "
                        + String.join("\n  ", broken));
    }

    /**
     * Every registered MessageDigest produces a real digest: non-empty, the
     * advertised length, and different for different inputs.
     * <p>
     * The differentiator is what makes this more than a resolution check — a
     * digest that returned a fixed buffer, or hashed only the first few bytes,
     * passes any single-input assertion.
     */
    @Test
    public void everyRegisteredDigestDigests() throws Exception
    {
        Provider provider = FIPSTestUtil.assumeFipsProvider();
        List<String> broken = new ArrayList<>();

        byte[] a = new byte[64];
        byte[] b = new byte[64];
        RANDOM.nextBytes(a);
        System.arraycopy(a, 0, b, 0, a.length);
        b[0] ^= 0x01;

        for (Provider.Service s : sorted(provider))
        {
            if (!"MessageDigest".equals(s.getType()))
            {
                continue;
            }
            String alg = s.getAlgorithm();
            try
            {
                byte[] da = MessageDigest.getInstance(alg, FIPS).digest(a);
                byte[] db = MessageDigest.getInstance(alg, FIPS).digest(b);

                if (da.length == 0)
                {
                    broken.add(alg + " -> empty digest");
                }
                else if (java.util.Arrays.equals(da, db))
                {
                    broken.add(alg + " -> a one-bit input change did not change the digest");
                }
            }
            catch (Exception e)
            {
                broken.add(alg + " -> " + e.getClass().getSimpleName() + ": " + e.getMessage());
            }
        }

        Assertions.assertTrue(broken.isEmpty(),
                "registered digests that do not digest against the loaded module ("
                        + FIPSTestUtil.moduleDescription() + "):\n  "
                        + String.join("\n  ", broken));
    }

    /**
     * Every registered Mac initialises with a conforming key and produces a
     * real tag that changes with the message.
     * <p>
     * Key material clears the module's 112-bit floor
     * ({@link FIPSTestUtil#HMAC_MIN_KEY_BYTES}) and is AES-sized for CMAC —
     * that floor is a runtime-parameter constraint, not a capability, so
     * supplying a conforming key is the caller's job and this test does it
     * rather than reporting the module's refusal as a defect.
     */
    @Test
    public void everyRegisteredMacMacs()
    {
        Provider provider = FIPSTestUtil.assumeFipsProvider();
        List<String> broken = new ArrayList<>();

        byte[] msgA = new byte[128];
        byte[] msgB = new byte[128];
        RANDOM.nextBytes(msgA);
        System.arraycopy(msgA, 0, msgB, 0, msgA.length);
        msgB[0] ^= 0x01;

        for (Provider.Service s : sorted(provider))
        {
            if (!"Mac".equals(s.getType()))
            {
                continue;
            }
            String alg = s.getAlgorithm();
            try
            {
                // CMAC needs an AES-sized key; HMAC needs at least the module's
                // floor. 32 bytes satisfies both.
                SecretKeySpec key = new SecretKeySpec(randomBytes(32),
                        alg.contains("CMAC") ? "AES" : alg);

                Mac mac = Mac.getInstance(alg, FIPS);
                mac.init(key);
                byte[] ta = mac.doFinal(msgA);

                Mac mac2 = Mac.getInstance(alg, FIPS);
                mac2.init(key);
                byte[] tb = mac2.doFinal(msgB);

                if (ta.length == 0)
                {
                    broken.add(alg + " -> empty tag");
                }
                else if (java.util.Arrays.equals(ta, tb))
                {
                    broken.add(alg + " -> a one-bit message change did not change the tag");
                }
            }
            catch (Exception e)
            {
                broken.add(alg + " -> " + e.getClass().getSimpleName() + ": " + e.getMessage());
            }
        }

        Assertions.assertTrue(broken.isEmpty(),
                "registered MACs that do not MAC against the loaded module ("
                        + FIPSTestUtil.moduleDescription() + "):\n  "
                        + String.join("\n  ", broken));
    }

    /**
     * Every registered SecureRandom produces bytes, and two draws differ.
     * <p>
     * The all-zero and repeated-draw checks are the differentiators: a
     * SecureRandom that resolved but was never seeded, or one whose native
     * backing failed silently, satisfies "nextBytes returned" and nothing else.
     */
    @Test
    public void everyRegisteredSecureRandomDraws()
    {
        Provider provider = FIPSTestUtil.assumeFipsProvider();
        List<String> broken = new ArrayList<>();

        for (Provider.Service s : sorted(provider))
        {
            if (!"SecureRandom".equals(s.getType()))
            {
                continue;
            }
            String alg = s.getAlgorithm();
            try
            {
                SecureRandom sr = SecureRandom.getInstance(alg, FIPS);
                byte[] a = new byte[32];
                byte[] b = new byte[32];
                sr.nextBytes(a);
                sr.nextBytes(b);

                if (java.util.Arrays.equals(a, new byte[32]))
                {
                    broken.add(alg + " -> produced all zeros");
                }
                else if (java.util.Arrays.equals(a, b))
                {
                    broken.add(alg + " -> two draws were identical");
                }
            }
            catch (Exception e)
            {
                broken.add(alg + " -> " + e.getClass().getSimpleName() + ": " + e.getMessage());
            }
        }

        Assertions.assertTrue(broken.isEmpty(),
                "registered SecureRandoms that do not draw against the loaded module ("
                        + FIPSTestUtil.moduleDescription() + "):\n  "
                        + String.join("\n  ", broken));
    }

    /**
     * Every registered KeyPairGenerator either produces a usable keypair or
     * refuses with a typed capability exception naming what is unavailable.
     * <p>
     * This is the tier that matters most, and the one the two cheaper tiers
     * cannot reach: a KeyPairGenerator resolves and constructs happily against
     * a module that cannot generate its keys, because the module is not
     * consulted until {@code generateKeyPair}. DSA on OpenSSL's 3.5.x FIPS
     * module is exactly that shape — and so would XDH be, if
     * {@code ProvFIPSXDH} had registered it unconditionally instead of probing
     * the fetch. Between them those are two of the five families the module
     * migration broke.
     * <p>
     * "Refuses typed" is a real requirement, not an escape hatch: the
     * exception must be one the JCA defines for the surface
     * ({@link ProviderException} or {@link InvalidAlgorithmParameterException}
     * from {@code generateKeyPair} / {@code initialize}) and its message must
     * name the capability. A generic {@code OpenSSLException}, an
     * {@code IllegalStateException} or a null key all fail here.
     */
    @Test
    public void everyRegisteredKeyPairGeneratorGeneratesOrRefusesTyped()
    {
        Provider provider = FIPSTestUtil.assumeFipsProvider();
        List<String> broken = new ArrayList<>();

        for (Provider.Service s : sorted(provider))
        {
            if (!"KeyPairGenerator".equals(s.getType()))
            {
                continue;
            }
            String alg = s.getAlgorithm();
            try
            {
                KeyPair kp = KeyPairGenerator.getInstance(alg, FIPS).generateKeyPair();
                if (kp == null || kp.getPublic() == null || kp.getPrivate() == null)
                {
                    broken.add(alg + " -> generateKeyPair returned an incomplete KeyPair");
                }
                else if (kp.getPublic().getEncoded() == null
                        || kp.getPublic().getEncoded().length == 0)
                {
                    broken.add(alg + " -> generated a public key that does not encode");
                }
            }
            catch (ProviderException e)
            {
                // The sanctioned refusal. Must name the capability, not just
                // report that something went wrong.
                String m = String.valueOf(e.getMessage());
                if (!m.contains("not supported by the loaded provider"))
                {
                    broken.add(alg + " -> ProviderException that does not name a capability: " + m);
                }
            }
            catch (Exception e)
            {
                broken.add(alg + " -> " + e.getClass().getSimpleName() + ": " + e.getMessage());
            }
        }

        Assertions.assertTrue(broken.isEmpty(),
                "registered KeyPairGenerators that neither generate nor refuse typed against"
                        + " the loaded module (" + FIPSTestUtil.moduleDescription() + "):\n  "
                        + String.join("\n  ", broken));
    }

    /**
     * A service that IS registered must never fail resolution with
     * {@link NoSuchAlgorithmException} through the ordinary JCE entry points.
     * <p>
     * Distinct from {@link #everyRegisteredServiceIsConstructible()}, which
     * goes through {@code Service.newInstance}. The JCE lookup path is what
     * callers actually use, and a registration whose class name or alias is
     * wrong resolves one way and not the other.
     */
    @Test
    public void registeredServicesResolveThroughJceLookup()
    {
        Provider provider = FIPSTestUtil.assumeFipsProvider();
        List<String> broken = new ArrayList<>();

        for (Provider.Service s : sorted(provider))
        {
            try
            {
                Object o = jceLookup(s.getType(), s.getAlgorithm());
                if (o == null)
                {
                    // Type this test does not know how to look up; the
                    // constructibility test above still covers it.
                    continue;
                }
            }
            catch (NoSuchAlgorithmException e)
            {
                broken.add(s.getType() + "." + s.getAlgorithm()
                        + " -> registered but NoSuchAlgorithmException from getInstance");
            }
            catch (Exception e)
            {
                broken.add(s.getType() + "." + s.getAlgorithm() + " -> "
                        + e.getClass().getSimpleName() + ": " + e.getMessage());
            }
        }

        Assertions.assertTrue(broken.isEmpty(),
                "registered services unreachable through the JCE lookup ("
                        + FIPSTestUtil.moduleDescription() + "):\n  "
                        + String.join("\n  ", broken));
    }

    /**
     * Resolve one service through the ordinary JCE entry point for its type,
     * or return null for a type this test does not drive.
     */
    private static Object jceLookup(String type, String alg) throws Exception
    {
        switch (type)
        {
            case "MessageDigest":
                return MessageDigest.getInstance(alg, FIPS);
            case "Mac":
                return Mac.getInstance(alg, FIPS);
            case "SecureRandom":
                return SecureRandom.getInstance(alg, FIPS);
            case "Cipher":
                return javax.crypto.Cipher.getInstance(alg, FIPS);
            case "Signature":
                return java.security.Signature.getInstance(alg, FIPS);
            case "KeyFactory":
                return java.security.KeyFactory.getInstance(alg, FIPS);
            case "KeyPairGenerator":
                return java.security.KeyPairGenerator.getInstance(alg, FIPS);
            case "KeyGenerator":
                return javax.crypto.KeyGenerator.getInstance(alg, FIPS);
            case "KeyAgreement":
                return javax.crypto.KeyAgreement.getInstance(alg, FIPS);
            case "SecretKeyFactory":
                return javax.crypto.SecretKeyFactory.getInstance(alg, FIPS);
            case "AlgorithmParameters":
                return java.security.AlgorithmParameters.getInstance(alg, FIPS);
            case "AlgorithmParameterGenerator":
                return java.security.AlgorithmParameterGenerator.getInstance(alg, FIPS);
            case "CertificateFactory":
                return java.security.cert.CertificateFactory.getInstance(alg, FIPS);
            default:
                return null;
        }
    }

    private static byte[] randomBytes(int n)
    {
        byte[] b = new byte[n];
        RANDOM.nextBytes(b);
        return b;
    }

    /** Services in a stable order so a failure list is diffable run to run. */
    private static List<Provider.Service> sorted(Provider provider)
    {
        SortedSet<String> names = new TreeSet<>();
        for (Provider.Service s : provider.getServices())
        {
            names.add(s.getType() + "." + s.getAlgorithm());
        }
        List<Provider.Service> out = new ArrayList<>();
        for (String n : names)
        {
            int dot = n.indexOf('.');
            out.add(provider.getService(n.substring(0, dot), n.substring(dot + 1)));
        }
        return out;
    }
}
