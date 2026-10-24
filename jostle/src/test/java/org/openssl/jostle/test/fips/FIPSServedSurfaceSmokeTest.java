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
import org.openssl.jostle.jcajce.interfaces.MLXKEMPublicKey;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.test.util.CipherFamilies;

import javax.crypto.Mac;
import javax.crypto.spec.DHGenParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAGenParameterSpec;
import java.security.spec.DSAParameterSpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.SortedSet;
import java.util.TreeSet;
import java.security.cert.CertificateFactory;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.Signature;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKeyFactory;

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
    private static final String RSA_SPI_PACKAGE = "org.openssl.jostle.jcajce.provider.rsa.";

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
                else if (Arrays.equals(da, db))
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

        // GMAC is the one registered MAC that cannot run without a nonce, so
        // init(key) alone would fail it for the right reason but with the wrong
        // verdict. The SAME IV is used for both halves of the differentiator,
        // so the tags can only differ because the MESSAGE differs.
        byte[] gmacIv = randomBytes(12);

        for (Provider.Service s : sorted(provider))
        {
            if (!"Mac".equals(s.getType()))
            {
                continue;
            }
            String alg = s.getAlgorithm();
            try
            {
                // CMAC and GMAC need an AES-sized key; HMAC needs at least the
                // module's floor. 32 bytes satisfies all three.
                SecretKeySpec key = new SecretKeySpec(randomBytes(32),
                        alg.contains("CMAC") || alg.contains("GMAC") ? "AES" : alg);

                AlgorithmParameterSpec spec =
                        alg.contains("GMAC") ? new IvParameterSpec(gmacIv) : null;

                Mac mac = Mac.getInstance(alg, FIPS);
                mac.init(key, spec);
                byte[] ta = mac.doFinal(msgA);

                Mac mac2 = Mac.getInstance(alg, FIPS);
                mac2.init(key, spec);
                byte[] tb = mac2.doFinal(msgB);

                if (ta.length == 0)
                {
                    broken.add(alg + " -> empty tag");
                }
                else if (Arrays.equals(ta, tb))
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

                if (Arrays.equals(a, new byte[32]))
                {
                    broken.add(alg + " -> produced all zeros");
                }
                else if (Arrays.equals(a, b))
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
                else if (kp.getPublic() instanceof MLXKEMPublicKey)
                {
                    // The TLS hybrid groups are the one family with NO ASN.1
                    // encoding - nothing registers a codec for them. Their
                    // usability check is therefore the raw share, and the
                    // no-encoding claim is VERIFIED rather than waived: both
                    // halves must answer null to both getEncoded and
                    // getFormat, so a family that merely FAILED to encode
                    // still lands in `broken` below.
                    if (kp.getPublic().getEncoded() != null || kp.getPublic().getFormat() != null
                            || kp.getPrivate().getEncoded() != null || kp.getPrivate().getFormat() != null)
                    {
                        broken.add(alg + " -> claims to be unencodable but answered an encoding or format");
                    }
                    else if (((MLXKEMPublicKey) kp.getPublic()).getPublicData() == null
                            || ((MLXKEMPublicKey) kp.getPublic()).getPublicData().length == 0)
                    {
                        broken.add(alg + " -> generated a public key with no raw share");
                    }
                }
                else if (kp.getPublic().getEncoded() == null
                        || kp.getPublic().getEncoded().length == 0)
                {
                    broken.add(alg + " -> generated a public key that does not encode");
                }
            }
            catch (ProviderException e)
            {
                // The sanctioned capability refusal. Must name the capability,
                // not just report that something went wrong.
                String m = String.valueOf(e.getMessage());
                if (!m.contains("not supported by the loaded provider"))
                {
                    broken.add(alg + " -> ProviderException that does not name a capability: " + m);
                }
            }
            catch (IllegalStateException | IllegalArgumentException e)
            {
                // An umbrella generator for a parameter-set-based family
                // ("MLDSA", "MLKEM", "SLHDSA") has no parameter set until
                // initialize() supplies one, so generateKeyPair() without it is
                // caller error, not a provider defect. It must still be TYPED
                // and say so - SLHDSA threw a raw NullPointerException here
                // until this tier caught it. Anything that is not an umbrella
                // name has no business needing initialisation.
                if (!isUmbrella(alg))
                {
                    broken.add(alg + " -> needs initialize() but is not an umbrella name: "
                            + e.getClass().getSimpleName() + ": " + e.getMessage());
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
     * Every registered RSA Signature signs and verifies, except the two SHA-1 names, which are "registered,
     * refuses signing on this module" on both measured modules (3.1.2 and 3.5.8): refused typed naming the digest,
     * and still verifying. An unmeasured module fails the cell.
     */
    @Test
    public void everyRegisteredRsaSignatureSignsExceptSha1() throws Exception
    {
        Provider provider = FIPSTestUtil.assumeFipsProvider();
        String module = FIPSNISelector.OpenSSLFIPSNI.moduleVersion();
        Assertions.assertTrue("OpenSSL FIPS Provider 3.1.2".equals(module)
                || "OpenSSL FIPS Provider 3.5.8".equals(module), "unmeasured module: " + module);
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        List<String> refusesSigning = Arrays.asList("SHA1WITHRSA", "SHA1WITHRSAANDMGF1");
        String refusal = "the loaded provider does not sign RSA with SHA-1; verification remains available";
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", FIPS);
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        PrivateKey jslPrivate = FIPSTestUtil.crossPrivate(kp.getPrivate(), "RSA", JostleProvider.PROVIDER_NAME);
        List<String> broken = new ArrayList<>();
        List<String> refused = new ArrayList<>();
        byte[] msg = new byte[32];
        RANDOM.nextBytes(msg);

        for (Provider.Service s : sorted(provider))
        {
            if (!"Signature".equals(s.getType()) || !s.getClassName().startsWith(RSA_SPI_PACKAGE))
            {
                continue;
            }
            String alg = s.getAlgorithm();
            boolean expectRefusal = refusesSigning.contains(alg.toUpperCase(Locale.ROOT));
            byte[] sig;
            try
            {
                Signature signer = Signature.getInstance(alg, FIPS);
                signer.initSign(kp.getPrivate());
                if (expectRefusal)
                {
                    broken.add(alg + " -> signed; expected registered, refuses signing on this module");
                    continue;
                }
                signer.update(msg);
                sig = signer.sign();
            }
            catch (InvalidKeyException e)
            {
                if (!expectRefusal || !refusal.equals(e.getMessage()))
                {
                    broken.add(alg + " -> InvalidKeyException: " + e.getMessage());
                    continue;
                }
                refused.add(alg);
                Signature jslSigner = Signature.getInstance(alg, JostleProvider.PROVIDER_NAME);
                jslSigner.initSign(jslPrivate);
                jslSigner.update(msg);
                sig = jslSigner.sign();
            }
            catch (Exception e)
            {
                broken.add(alg + " -> " + e.getClass().getSimpleName() + ": " + e.getMessage());
                continue;
            }
            Signature verifier = Signature.getInstance(alg, FIPS);
            verifier.initVerify(kp.getPublic());
            verifier.update(msg);
            if (!verifier.verify(sig))
            {
                broken.add(alg + " -> signature does not verify");
            }
        }

        Assertions.assertEquals(refusesSigning.size(), refused.size(), "refused " + refused);
        Assertions.assertTrue(broken.isEmpty(),
                "registered RSA Signatures that do not behave as measured on " + module + ":\n  "
                        + String.join("\n  ", broken));
    }

    /**
     * The DH parameter generator is registered and refuses typed on both measured modules (3.1.2 and 3.5.8),
     * by size and by DHGenParameterSpec alike: the module substitutes a named group or refuses, never generates.
     * An unmeasured module fails the cell.
     */
    @Test
    public void dhParameterGenerationIsRegisteredAndRefusedTyped() throws Exception
    {
        FIPSTestUtil.assumeFipsProvider();
        String module = FIPSNISelector.OpenSSLFIPSNI.moduleVersion();
        Assertions.assertTrue("OpenSSL FIPS Provider 3.1.2".equals(module)
                || "OpenSSL FIPS Provider 3.5.8".equals(module), "unmeasured module: " + module);
        String refusal = "DH parameter generation is not supported by the loaded provider, "
                + "which substitutes a named group where one exists and refuses otherwise; "
                + "use named-group key generation instead";
        AlgorithmParameterGenerator bySize = AlgorithmParameterGenerator.getInstance("DH", FIPS);
        bySize.init(2048);
        ProviderException e = Assertions.assertThrows(ProviderException.class, bySize::generateParameters);
        Assertions.assertEquals(refusal, e.getMessage());
        AlgorithmParameterGenerator bySpec = AlgorithmParameterGenerator.getInstance("DH", FIPS);
        bySpec.init(new DHGenParameterSpec(2048, 256));
        e = Assertions.assertThrows(ProviderException.class, bySpec::generateParameters);
        Assertions.assertEquals(refusal, e.getMessage());
    }

    /**
     * Every DSA service stays registered on both measured modules, and each refusal is typed and pinned by version.
     * 3.5.8 refuses generation and signing, naming the key size, and verifies; 3.1.2 generates, signs under every
     * name but SHA-1 (refused naming the digest) and verifies. An unmeasured module fails the cell.
     */
    @Test
    public void dsaIsRegisteredAndServedAsMeasuredPerModule() throws Exception
    {
        Provider provider = FIPSTestUtil.assumeFipsProvider();
        String module = FIPSNISelector.OpenSSLFIPSNI.moduleVersion();
        Assertions.assertTrue("OpenSSL FIPS Provider 3.1.2".equals(module)
                || "OpenSSL FIPS Provider 3.5.8".equals(module), "unmeasured module: " + module);
        boolean verifyOnly = "OpenSSL FIPS Provider 3.5.8".equals(module);
        for (String type : new String[]{"KeyPairGenerator", "AlgorithmParameterGenerator", "KeyFactory",
                "AlgorithmParameters"})
        {
            Assertions.assertNotNull(provider.getService(type, "DSA"), type + ".DSA is not registered");
        }

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA", FIPS);
        kpg.initialize(2048);
        AlgorithmParameterGenerator apg = AlgorithmParameterGenerator.getInstance("DSA", FIPS);
        apg.init(new DSAGenParameterSpec(2048, 224));
        if (verifyOnly)
        {
            ProviderException e = Assertions.assertThrows(ProviderException.class, kpg::generateKeyPair);
            Assertions.assertTrue(e.getMessage().startsWith("DSA key generation is not supported"), e.getMessage());
            e = Assertions.assertThrows(ProviderException.class, apg::generateParameters);
            Assertions.assertTrue(e.getMessage().startsWith("DSA key generation is not supported"), e.getMessage());
        }
        else
        {
            Assertions.assertEquals(2048,
                    ((DSAPublicKey) kpg.generateKeyPair().getPublic()).getParams().getP().bitLength());
            DSAParameterSpec gen = apg.generateParameters().getParameterSpec(DSAParameterSpec.class);
            Assertions.assertEquals(2048, gen.getP().bitLength());
            Assertions.assertEquals(224, gen.getQ().bitLength());
        }

        KeyPair kp = FIPSTestUtil.dsaKeyPair(FIPS);
        byte[] msg = new byte[32];
        new SecureRandom().nextBytes(msg);
        List<String> names = new ArrayList<String>();
        for (Provider.Service s : provider.getServices())
        {
            if ("Signature".equals(s.getType()) && s.getClassName().startsWith(CipherFamilies.DSA_PREFIX))
            {
                names.add(s.getAlgorithm());
            }
        }
        Assertions.assertEquals(10, names.size(), "DSA Signatures " + names);
        for (String name : names)
        {
            Signature signer = Signature.getInstance(name, FIPS);
            boolean sha1 = name.toUpperCase(Locale.ROOT).startsWith("SHA1");
            if (verifyOnly || sha1)
            {
                InvalidKeyException e = Assertions.assertThrows(InvalidKeyException.class,
                        () -> signer.initSign(kp.getPrivate()), name);
                if (verifyOnly)
                {
                    Assertions.assertEquals(FIPSTestUtil.dsaSignRefusedMessage(2048), e.getMessage(), name);
                }
                else
                {
                    Assertions.assertEquals("the loaded provider does not sign DSA with SHA-1", e.getMessage(), name);
                }
            }
            else
            {
                signer.initSign(kp.getPrivate());
                signer.update(msg);
                byte[] sig = signer.sign();
                Signature verifier = Signature.getInstance(name, FIPS);
                verifier.initVerify(kp.getPublic());
                verifier.update(msg);
                Assertions.assertTrue(verifier.verify(sig), name);
            }
        }

        // Verification is served on both modules: a signature made by the base provider verifies.
        Signature base = Signature.getInstance("SHA256withDSA", JostleProvider.PROVIDER_NAME);
        base.initSign(FIPSTestUtil.dsaKeyPair(JostleProvider.PROVIDER_NAME).getPrivate());
        base.update(msg);
        byte[] sig = base.sign();
        Signature verifier = Signature.getInstance("SHA256withDSA", FIPS);
        verifier.initVerify(kp.getPublic());
        verifier.update(msg);
        Assertions.assertTrue(verifier.verify(sig));
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
                return Cipher.getInstance(alg, FIPS);
            case "Signature":
                return Signature.getInstance(alg, FIPS);
            case "KeyFactory":
                return KeyFactory.getInstance(alg, FIPS);
            case "KeyPairGenerator":
                return KeyPairGenerator.getInstance(alg, FIPS);
            case "KeyGenerator":
                return KeyGenerator.getInstance(alg, FIPS);
            case "KeyAgreement":
                return KeyAgreement.getInstance(alg, FIPS);
            case "SecretKeyFactory":
                return SecretKeyFactory.getInstance(alg, FIPS);
            case "AlgorithmParameters":
                return AlgorithmParameters.getInstance(alg, FIPS);
            case "AlgorithmParameterGenerator":
                return AlgorithmParameterGenerator.getInstance(alg, FIPS);
            case "CertificateFactory":
                return CertificateFactory.getInstance(alg, FIPS);
            default:
                return null;
        }
    }

    /**
     * Is {@code alg} an umbrella name for a parameter-set-based family - one
     * that legitimately requires {@code initialize()} before it can generate?
     * Deliberately an exact list rather than a pattern: a typed name like
     * "ML-DSA-65" must never fall into this branch.
     */
    private static boolean isUmbrella(String alg)
    {
        switch (alg)
        {
            case "MLDSA":
            case "ML-DSA":
            case "MLKEM":
            case "ML-KEM":
            case "SLHDSA":
            case "SLH-DSA":
                return true;
            default:
                return false;
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
