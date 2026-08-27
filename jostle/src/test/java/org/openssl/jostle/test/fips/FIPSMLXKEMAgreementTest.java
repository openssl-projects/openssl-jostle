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

package org.openssl.jostle.test.fips;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.SecretKeyWithEncapsulation;
import org.openssl.jostle.jcajce.interfaces.MLXKEMPublicKey;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.jcajce.spec.KEMExtractSpec;
import org.openssl.jostle.jcajce.spec.KEMGenerateSpec;
import org.openssl.jostle.jcajce.spec.MLXKEMParameterSpec;
import org.openssl.jostle.jcajce.spec.MLXKEMPublicKeySpec;
import org.openssl.jostle.test.mlxkem.HybridRef;
import org.openssl.jostle.test.util.ProviderSurfaceGuard;
import org.openssl.jostle.util.Arrays;

import javax.crypto.KeyGenerator;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

/**
 * Cross-implementation agreement for the hybrid KEM groups served by JSLFIPS:
 * against {@link HybridRef} (BouncyCastle's primitives composed per the draft)
 * and against JSL.
 *
 * <p>Not redundant with {@code MLXKEMAgreementTest}: this one drives
 * {@code libinterface_fips_*} through the FIPS {@code OSSL_LIB_CTX}, which is
 * a different library and a different provider chain. A base-side green run is
 * no evidence about either.
 *
 * <p>Every test iterates only the variants the loaded module actually serves.
 * The registered set differs across supported modules — 3.1.2 serves none,
 * 3.5.7 all four, 3.5.8 all but X448MLKEM1024 — so pinning any one module's
 * answer would be wrong against the others.
 * {@code FIPSServedSurfaceSnapshotTest} is what proves an absence is the
 * module's doing rather than ours.
 */
public class FIPSMLXKEMAgreementTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String JSLFIPS = JostleFIPSProvider.PROVIDER_NAME;

    private static final String[] GUARDED_TYPES = {"KeyPairGenerator", "KeyGenerator", "KeyFactory"};

    private static final String MLXKEM_PREFIX = "org.openssl.jostle.jcajce.provider.mlxkem.";

    private static final int TRIALS = 3;

    private static final SecureRandom RANDOM = new SecureRandom();

    private static SecureRandom seededRandom(String testName) throws Exception
    {
        long seed = RANDOM.nextLong();
        System.out.println(testName + " seed=" + seed);
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(seed);
        return sr;
    }

    @BeforeAll
    static void before()
    {
        // Class-level gate, deliberately here and not inside served(). A
        // per-method gate fails OPEN: remove it from one helper and the tests
        // run without a module rather than skipping. FIPSTestGateParityTest
        // enforces this shape across every FIPS test class, and it is what
        // caught this class missing it.
        FIPSTestUtil.assumeFipsProvider();

        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    /**
     * The groups JSLFIPS actually registers on the loaded module.
     *
     * <p>Requires all THREE service types to agree, rather than reading
     * KeyPairGenerator alone. A variant registered with two of its three
     * services is a real defect, and reading one type would silently drop the
     * other two from every sweep below — the vacuous-pass shape that
     * {@code ProviderSurfaceGuard}'s non-empty assertion exists to prevent,
     * one level up.
     */
    private static List<MLXKEMParameterSpec> served()
    {
        Provider provider = FIPSTestUtil.assumeFipsProvider();
        List<MLXKEMParameterSpec> out = new ArrayList<MLXKEMParameterSpec>();
        for (MLXKEMParameterSpec spec : MLXKEMParameterSpec.all())
        {
            int present = 0;
            for (String type : SERVICE_TYPES)
            {
                if (provider.getService(type, spec.getName()) != null)
                {
                    present++;
                }
            }
            Assertions.assertTrue(present == 0 || present == SERVICE_TYPES.length,
                    spec.getName() + " is partly registered (" + present + " of "
                            + SERVICE_TYPES.length + " services) — a capability gate is "
                            + "all-or-nothing within a variant");
            if (present == SERVICE_TYPES.length)
            {
                out.add(spec);
            }
        }
        return out;
    }

    private static final String[] SERVICE_TYPES = {"KeyPairGenerator", "KeyGenerator", "KeyFactory"};

    /**
     * JSLFIPS encapsulates to a key share the reference composed; the
     * reference must recover the same secret. Byte-equality is unavailable
     * (encapsulation is randomised), so recovery by the other implementation
     * is the check — a wrong-but-self-consistent FIPS path fails it.
     */
    @Test
    public void fipsEncapsulate_referenceDecapsulates() throws Exception
    {
        SecureRandom random = seededRandom("fipsEncapsulate_referenceDecapsulates");

        for (MLXKEMParameterSpec spec : served())
        {
            for (int t = 0; t < TRIALS; t++)
            {
                HybridRef.Party peer = HybridRef.Party.generate(spec, random);

                PublicKey view = KeyFactory.getInstance(spec.getName(), JSLFIPS)
                        .generatePublic(new MLXKEMPublicKeySpec(spec, peer.share));

                SecretKeyWithEncapsulation sent = encapsulate(JSLFIPS, spec, view);

                Assertions.assertEquals(spec.getSharedSecretBytes(), sent.getEncoded().length,
                        spec.getName() + ": shared secret length");
                Assertions.assertTrue(Arrays.areEqual(
                                sent.getEncoded(), peer.decapsulate(sent.getEncapsulation())),
                        spec.getName() + ": reference must recover JSLFIPS's secret");
            }
        }
    }

    /**
     * The reference encapsulates to a JSLFIPS-generated key share; JSLFIPS
     * must recover the same secret. Drives the FIPS library's decapsulation
     * against an encapsulation it did not produce.
     */
    @Test
    public void referenceEncapsulate_fipsDecapsulates() throws Exception
    {
        SecureRandom random = seededRandom("referenceEncapsulate_fipsDecapsulates");

        for (MLXKEMParameterSpec spec : served())
        {
            for (int t = 0; t < TRIALS; t++)
            {
                KeyPair kp = KeyPairGenerator.getInstance(spec.getName(), JSLFIPS).generateKeyPair();
                byte[] share = ((MLXKEMPublicKey) kp.getPublic()).getPublicData();

                byte[][] made = HybridRef.encapsulate(spec, share, random);

                Assertions.assertTrue(Arrays.areEqual(made[1],
                                decapsulate(JSLFIPS, spec, kp.getPrivate(), made[0]).getEncoded()),
                        spec.getName() + ": JSLFIPS must recover the reference's secret");
            }
        }
    }


    /**
     * Negative path, per half, through the FIPS library.
     *
     * <p>Not redundant with the base {@code MLXKEMAgreementTest} twin: the two
     * halves fail differently (ML-KEM implicitly rejects a damaged ciphertext
     * to a DIFFERENT secret, a damaged EC point is usually refused outright)
     * and both paths run inside {@code libinterface_fips_*} against the FIPS
     * lib ctx here. A single "flip any byte" check would pass against a
     * decapsulator that ignored one component entirely.
     */
    @Test
    public void tamperingEitherHalfChangesTheSecret() throws Exception
    {
        SecureRandom random = seededRandom("tamperingEitherHalfChangesTheSecret[FIPS]");

        for (MLXKEMParameterSpec spec : served())
        {
            KeyPair kp = KeyPairGenerator.getInstance(spec.getName(), JSLFIPS).generateKeyPair();
            byte[] share = ((MLXKEMPublicKey) kp.getPublic()).getPublicData();
            byte[][] made = HybridRef.encapsulate(spec, share, random);

            byte[] good = decapsulate(JSLFIPS, spec, kp.getPrivate(), made[0]).getEncoded();
            Assertions.assertTrue(Arrays.areEqual(made[1], good), spec.getName() + ": control");

            int ecdhLen = HybridRef.ecdhPublicLength(spec, random);
            int mlkemStart = HybridRef.mlkemFirst(spec) ? 0 : ecdhLen;
            int ecdhStart = HybridRef.mlkemFirst(spec) ? made[0].length - ecdhLen : 0;

            assertDiverges(spec, kp.getPrivate(), made[0], mlkemStart, good, "ML-KEM half");
            assertDiverges(spec, kp.getPrivate(), made[0], ecdhStart, good, "ECDH half");
        }
    }

    private void assertDiverges(MLXKEMParameterSpec spec, PrivateKey priv, byte[] encapsulation,
                                int offset, byte[] good, String what) throws Exception
    {
        byte[] bad = Arrays.clone(encapsulation);
        bad[offset] ^= (byte) 0x01;

        boolean diverged;
        try
        {
            diverged = !Arrays.areEqual(good,
                    decapsulate(JSLFIPS, spec, priv, bad).getEncoded());
        }
        catch (RuntimeException e)
        {
            diverged = true;
        }
        Assertions.assertTrue(diverged, spec.getName() + ": tampering the " + what
                + " must not yield the original secret");
    }

    /**
     * The two providers interoperate in both directions, over the raw share
     * that is the only crossing these keys have. Each side's library and lib
     * ctx does half the work, so a divergence between the two trees shows up
     * here and in no single-provider test.
     */
    @Test
    public void jslAndFipsInteroperateBothDirections() throws Exception
    {
        for (MLXKEMParameterSpec spec : served())
        {
            crossEncapsulate(spec, JSL, JSLFIPS);
            crossEncapsulate(spec, JSLFIPS, JSL);
        }
    }

    private void crossEncapsulate(MLXKEMParameterSpec spec, String encapsulator, String holder)
            throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance(spec.getName(), holder).generateKeyPair();
        byte[] share = ((MLXKEMPublicKey) kp.getPublic()).getPublicData();

        PublicKey view = KeyFactory.getInstance(spec.getName(), encapsulator)
                .generatePublic(new MLXKEMPublicKeySpec(spec, share));
        SecretKeyWithEncapsulation sent = encapsulate(encapsulator, spec, view);

        Assertions.assertTrue(Arrays.areEqual(sent.getEncoded(),
                        decapsulate(holder, spec, kp.getPrivate(), sent.getEncapsulation()).getEncoded()),
                spec.getName() + ": " + encapsulator + " -> " + holder);
    }

    /**
     * Provider isolation, in the shape that actually holds for this family.
     *
     * <p>Since MT-14 neither half crosses as an OBJECT; the test above does
     * not depend on it, because it already interoperates over the raw share
     * (re-imported through the encapsulator's own KeyFactory), which is the
     * only crossing this family has. The refusal message differs from every
     * other family's on purpose: the usual remedy ("encode it with
     * getEncoded()") does not exist here, because these keys have no
     * encoding, so the message names the only remedy that does.
     */
    @Test
    public void privateKeysAreIsolatedBothDirections() throws Exception
    {
        for (MLXKEMParameterSpec spec : served())
        {
            assertPrivateRejected(spec, JSL, JSLFIPS);
            assertPrivateRejected(spec, JSLFIPS, JSL);
        }
    }

    private void assertPrivateRejected(MLXKEMParameterSpec spec, String owner, String user)
            throws Exception
    {
        PrivateKey foreign = KeyPairGenerator.getInstance(spec.getName(), owner)
                .generateKeyPair().getPrivate();

        KeyGenerator kg = KeyGenerator.getInstance(spec.getName(), user);
        InvalidAlgorithmParameterException e = Assertions.assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> kg.init(KEMExtractSpec.builder()
                        .withPrivate(foreign)
                        .withAlgorithmName("AES")
                        .withKeySizeInBits(spec.getSharedSecretBytes() * 8)
                        .withEncapsulatedKey(new byte[1])
                        .build()),
                spec.getName() + ": " + user + " must refuse a " + owner + " private key");
        Assertions.assertEquals(
                "private key was created by a different Jostle provider instance; hybrid KEM keys have no encoding, "
                        + "so generate the keypair through this provider instead",
                e.getMessage(), spec.getName());
    }

    /**
     * Every hybrid service JSLFIPS registers is DRIVEN. Discovery is from
     * {@code JostleFIPSProvider.getServices()}, which is a different set from
     * JSL's — so this cannot be covered by the base guard, and a variant
     * registered here alone would otherwise go untested.
     */
    @Test
    public void everyRegisteredHybridServiceIsDriven() throws Exception
    {
        JostleFIPSProvider provider = FIPSTestUtil.assumeFipsProvider();
        if (served().isEmpty())
        {
            // 3.1.2 serves no hybrid group at all. The absence is verified
            // against the module by FIPSServedSurfaceSnapshotTest; there is
            // nothing to drive here, and a vacuous guard would fail below.
            return;
        }

        ProviderSurfaceGuard.assertEveryServiceDriven(provider,
                MLXKEM_PREFIX, "hybrid KEM (JSLFIPS)", GUARDED_TYPES,
                new ProviderSurfaceGuard.ServiceDriver()
                {
                    public void drive(String type, String alg) throws Exception
                    {
                        MLXKEMParameterSpec spec = MLXKEMParameterSpec.fromName(alg);
                        KeyPair kp = KeyPairGenerator.getInstance(alg, JSLFIPS).generateKeyPair();

                        if ("KeyFactory".equals(type))
                        {
                            byte[] raw = ((MLXKEMPublicKey) kp.getPublic()).getPublicData();
                            MLXKEMPublicKey back = (MLXKEMPublicKey) KeyFactory
                                    .getInstance(alg, JSLFIPS)
                                    .generatePublic(new MLXKEMPublicKeySpec(spec, raw));
                            Assertions.assertTrue(Arrays.areEqual(raw, back.getPublicData()), alg);
                        }
                        else
                        {
                            // KeyPairGenerator and KeyGenerator are both driven
                            // end to end: a keypair that generates but cannot
                            // carry a KEM is not a working registration.
                            SecretKeyWithEncapsulation sent =
                                    encapsulate(JSLFIPS, spec, kp.getPublic());
                            Assertions.assertTrue(Arrays.areEqual(sent.getEncoded(),
                                            decapsulate(JSLFIPS, spec, kp.getPrivate(),
                                                    sent.getEncapsulation()).getEncoded()),
                                    alg);
                        }
                    }
                });
    }

    // -----------------------------------------------------------------

    private static SecretKeyWithEncapsulation encapsulate(String provider,
                                                          MLXKEMParameterSpec spec,
                                                          PublicKey pub) throws Exception
    {
        KeyGenerator kg = KeyGenerator.getInstance(spec.getName(), provider);
        kg.init(KEMGenerateSpec.builder()
                .withPublicKey(pub)
                .withAlgorithmName("AES")
                .withKeySizeInBits(spec.getSharedSecretBytes() * 8)
                .build());
        return (SecretKeyWithEncapsulation) kg.generateKey();
    }

    private static SecretKeyWithEncapsulation decapsulate(String provider,
                                                          MLXKEMParameterSpec spec,
                                                          PrivateKey priv,
                                                          byte[] encapsulation) throws Exception
    {
        KeyGenerator kg = KeyGenerator.getInstance(spec.getName(), provider);
        kg.init(KEMExtractSpec.builder()
                .withPrivate(priv)
                .withAlgorithmName("AES")
                .withKeySizeInBits(spec.getSharedSecretBytes() * 8)
                .withEncapsulatedKey(encapsulation)
                .build());
        return (SecretKeyWithEncapsulation) kg.generateKey();
    }
}
