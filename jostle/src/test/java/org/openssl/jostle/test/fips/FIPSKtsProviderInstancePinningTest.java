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

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.interfaces.OSSLKey;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.test.TestUtil;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;

/**
 * MT-16, FIPS half: a JSLFIPS KTS cipher resolves its inner AES key wrap from
 * the provider INSTANCE it belongs to, and the key an asymmetric unwrap
 * returns is bound to that instance and resident in the module.
 *
 * <p>Not a duplicate of {@code KtsProviderInstancePinningTest}: that drives
 * {@code libinterface_{jni,ffi}} and the base lib ctx, this drives
 * {@code libinterface_fips_{jni,ffi}} and the module's, and only this half can
 * ask whether the module actually served the key. Before MT-16 a JSLFIPS KTS
 * unwrap reconstructed its key inside an AES key-wrap {@code Cipher} resolved
 * by NAME, so a second JSLFIPS instance installed under that name got the
 * work — and no functional test could tell, because both instances drive the
 * same module and compute the same bytes.
 *
 * <p><b>The capability arms have no FIPS twin.</b>
 * {@code StrippedJostleProvider} makes an instance selectively incapable so a
 * name pin can be caught borrowing; {@code JostleFIPSProvider} is
 * {@code final}, so no such instance exists here. Binding is the observable
 * this side has, and residency is the one it adds.
 */
public class FIPSKtsProviderInstancePinningTest
{
    private static final SecureRandom RANDOM = new SecureRandom();

    /** The instance the NAME resolves to. Never the one a Cipher is built from. */
    private JostleFIPSProvider named;

    private Provider original;

    @BeforeEach
    void installASecondInstanceUnderTheName()
    {
        FIPSTestUtil.assumeFipsProvider();
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }

        original = Security.getProvider(JostleFIPSProvider.PROVIDER_NAME);
        if (original != null)
        {
            Security.removeProvider(JostleFIPSProvider.PROVIDER_NAME);
        }
        // A second instance over the SAME resolved configuration is
        // deliberately allowed by the one-shot guard (JostleFIPSProviderTest
        // pins that); only a DIFFERENT configuration is rejected.
        named = newFipsInstance();
        Assertions.assertTrue(Security.addProvider(named) > 0,
                "the second instance must install under the JSLFIPS name, or nothing here "
                        + "distinguishes a name pin from an instance pin");
    }

    @AfterEach
    void restore()
    {
        Security.removeProvider(JostleFIPSProvider.PROVIDER_NAME);
        if (original != null)
        {
            Security.addProvider(original);
        }
    }

    private static JostleFIPSProvider newFipsInstance()
    {
        return new JostleFIPSProvider("fips_module='" + TestUtil.fipsLibPath() + "'");
    }

    /** The arrangement every other test depends on. */
    @Test
    public void theNameResolvesToTheOtherInstance()
    {
        Provider outer = newFipsInstance();
        Assertions.assertNotSame(outer, named, "two instances must be distinct objects");
        Assertions.assertSame(named, Security.getProvider(JostleFIPSProvider.PROVIDER_NAME),
                "the name must resolve to the second instance");
    }

    /**
     * Control for {@link #servedBy}: it must be able to answer something other
     * than {@code "fips"}, or a stub returning that constant would pass every
     * residency assertion below.
     */
    @Test
    public void theResidencyProbeCanAnswerSomethingOtherThanFips() throws Exception
    {
        Provider jsl = Security.getProvider(JostleProvider.PROVIDER_NAME);
        Provider outer = newFipsInstance();

        KeyPair mine = KeyPairGenerator.getInstance("EC", outer).generateKeyPair();
        KeyPair theirs = KeyPairGenerator.getInstance("EC", jsl).generateKeyPair();

        Assertions.assertEquals("fips", servedBy(mine.getPublic()));
        Assertions.assertEquals("default", servedBy(theirs.getPublic()));
    }

    @Test
    public void rsaKts_unwrappedPrivateKeyIsBoundToTheOuterInstanceAndResidentInTheModule()
            throws Exception
    {
        unwrapThroughAnInstanceTheNameDoesNotPointAt("RSA-KTS-KEM-KWS", "RSA");
    }

    /**
     * ML-KEM is capability-gated on JSLFIPS — the 3.1.2 module does not
     * implement it, the 3.5.x one does. Assert the contract against whichever
     * module is loaded rather than pinning either module's answer: run the arm
     * when the service is registered, skip it when it is not.
     */
    @Test
    public void mlkemKts_unwrappedPrivateKeyIsBoundToTheOuterInstanceAndResidentInTheModule()
            throws Exception
    {
        Assumptions.assumeTrue(named.getService("Cipher", "ML-KEM") != null,
                "this FIPS module does not implement ML-KEM, so JSLFIPS registers no ML-KEM "
                        + "KTS Cipher (" + FIPSTestUtil.moduleDescription() + ")");
        unwrapThroughAnInstanceTheNameDoesNotPointAt("ML-KEM", "ML-KEM-768");
    }

    /**
     * Wrap a private key through an instance the NAME does not point at, then
     * unwrap through the same instance, and require the key back to carry THAT
     * instance and to be served by the module. Under the name pin it carried
     * the other instance — the very provider that produced it then refused it.
     */
    private void unwrapThroughAnInstanceTheNameDoesNotPointAt(String transform, String kekAlgorithm)
            throws Exception
    {
        Provider outer = newFipsInstance();
        Assertions.assertNotSame(named, outer);

        KeyPair kek = keyPair(outer, kekAlgorithm);
        KeyPair payload = eightAlignedRsaKeyPair(outer);

        Cipher w = Cipher.getInstance(transform, outer);
        w.init(Cipher.WRAP_MODE, kek.getPublic(), ktsSpec(), RANDOM);
        byte[] wrapped = w.wrap(payload.getPrivate());

        Cipher u = Cipher.getInstance(transform, outer);
        u.init(Cipher.UNWRAP_MODE, kek.getPrivate(), ktsSpec(), RANDOM);
        Key back = u.unwrap(wrapped, "RSA", Cipher.PRIVATE_KEY);

        Assertions.assertTrue(back instanceof OSSLKey,
                transform + ": the unwrapped key must be a Jostle key; got "
                        + back.getClass().getName());
        Assertions.assertSame(outer, ((OSSLKey) back).getSpec().getProviderInstance(),
                transform + ": the unwrapped key must be bound to the instance that unwrapped "
                        + "it, not to whatever the JSLFIPS name resolves to");
        Assertions.assertEquals("fips", servedBy(back),
                transform + ": the unwrapped key must be served by the FIPS module — binding "
                        + "to the right instance is not the same claim as the module having "
                        + "done the work");

        // And it is usable in the instance that produced it: a key bound
        // elsewhere is refused, so this is the caller-visible half.
        byte[] message = new byte[64];
        RANDOM.nextBytes(message);
        java.security.Signature signer =
                java.security.Signature.getInstance("SHA256withRSA", outer);
        signer.initSign((java.security.PrivateKey) back);
        signer.update(message);
        byte[] sig = signer.sign();

        java.security.Signature verifier =
                java.security.Signature.getInstance("SHA256withRSA", outer);
        verifier.initVerify(payload.getPublic());
        verifier.update(message);
        Assertions.assertTrue(verifier.verify(sig),
                transform + ": the unwrapped private key must be the one that was wrapped");

        message[0] ^= (byte) 0x01;
        verifier.initVerify(payload.getPublic());
        verifier.update(message);
        Assertions.assertFalse(verifier.verify(sig),
                transform + ": a tampered message must not verify — otherwise the check above "
                        + "would pass against a verifier that always says yes");
    }

    // -----------------------------------------------------------------
    // helpers
    // -----------------------------------------------------------------

    /** Which OSSL_PROVIDER owns this key's keymgmt: "fips" or "default". */
    private static String servedBy(Key key)
    {
        PKEYKeySpec spec = ((OSSLKey) key).getSpec();
        return spec.getSpecNI().getKeyProvider(spec.getReference());
    }

    private static KeyPair keyPair(Provider p, String algorithm) throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm, p);
        if ("RSA".equals(algorithm))
        {
            kpg.initialize(2048, RANDOM);
        }
        return kpg.generateKeyPair();
    }

    /**
     * An RSA key pair whose PKCS#8 private encoding is a multiple of 8 bytes:
     * the KTS ciphers wrap with AES-KW (id-aes256-wrap), not KWP, and RFC 3394
     * requires 8-byte-aligned input. RSA is the family whose encoding length
     * actually varies; see the twin of this helper in
     * {@code KtsProviderInstancePinningTest} for the full reasoning.
     */
    private static KeyPair eightAlignedRsaKeyPair(Provider p) throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", p);
        kpg.initialize(2048, RANDOM);
        for (int i = 0; i != 64; i++)
        {
            KeyPair kp = kpg.generateKeyPair();
            if (kp.getPrivate().getEncoded().length % 8 == 0)
            {
                return kp;
            }
        }
        throw new IllegalStateException(
                "no 8-aligned RSA PKCS#8 encoding in 64 tries — AES-KW needs one and about a "
                        + "third of keys should qualify, so the encoding has changed shape");
    }

    private static KTSParameterSpec ktsSpec()
    {
        return new KTSParameterSpec.Builder("AES", 256)
                .withKdfAlgorithm(new AlgorithmIdentifier(
                        X9ObjectIdentifiers.id_kdf_kdf3,
                        new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256)))
                .build();
    }
}
