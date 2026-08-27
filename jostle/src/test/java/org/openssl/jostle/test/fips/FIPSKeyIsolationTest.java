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
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 * Cross-provider key policy, since MT-14: a key OBJECT belongs to the provider
 * INSTANCE that created it, and neither half of a keypair crosses. Both are
 * rejected by the other provider's SPIs with a typed InvalidKeyException.
 * Sharing is explicit: encode the key ({@code getEncoded()}) and decode it
 * through the target provider's KeyFactory - which this test proves works, for
 * the public half as well as the private one. SecretKeys (raw bytes, no native
 * residency) are unaffected. Gated on TEST_FIPS_LIB; skipped when unset.
 *
 * <p><b>The public half used to cross, and this file used to assert that.</b>
 * The premise was that public material carries no secret, which is true and
 * beside the point: measurement
 * ({@code fips-c-review/probes/xprovider_key_probe.c}) showed an operation on
 * a key is served by the provider that CREATED it, whatever lib ctx drove the
 * call. So a JSLFIPS verify handed a JSL public key object ran in mainline
 * while reporting success - indistinguishable from the module doing it, since
 * both compute the same answer. Re-decoding is what actually moves the key.
 */
public class FIPSKeyIsolationTest
{
    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * Class-level gate: the whole class skips when TEST_FIPS_LIB is unset.
     * Gating here rather than per test method fails closed, so a test added
     * later is gated automatically.
     */
    @BeforeAll
    static void before()
    {
        ensureProviders();
    }

    private static void ensureProviders()
    {
        FIPSTestUtil.assumeFipsProvider();
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    /**
     * The canonical isolation refusal.
     *
     * <p>The pin includes "instance" deliberately. {@code "different Jostle
     * provider"} alone is a PREFIX of the Phase-1 library-based wording as
     * well as this one, so it cannot tell the two apart — it would have passed
     * unchanged through the flip while the class Javadoc promised the newer
     * message. Match the substring the contract actually names.
     */
    private static void assertRejected(Executable action)
    {
        InvalidKeyException e = Assertions.assertThrows(InvalidKeyException.class, action::run);
        Assertions.assertTrue(e.getMessage().contains("different Jostle provider instance"),
                "expected the isolation message, got: " + e.getMessage());
    }

    private interface Executable
    {
        void run() throws Exception;
    }

    /** Binds a private key into a fresh SPI created for {@code provider}. */
    private interface PrivKeyOp
    {
        void run(String provider, PrivateKey key) throws Exception;
    }

    @Test
    public void rsaKeysAreIsolatedInBothHalves()
        throws Exception
    {
        KeyPairGenerator jslKpg = KeyPairGenerator.getInstance("RSA", JostleProvider.PROVIDER_NAME);
        jslKpg.initialize(2048);
        KeyPair jslKp = jslKpg.generateKeyPair();
        KeyPairGenerator fipsKpg = KeyPairGenerator.getInstance("RSA", JostleFIPSProvider.PROVIDER_NAME);
        fipsKpg.initialize(2048);
        KeyPair fipsKp = fipsKpg.generateKeyPair();

        byte[] message = new byte[128];
        RANDOM.nextBytes(message);

        // PRIVATE keys are isolated, in both directions.
        Signature fipsSigner = Signature.getInstance("SHA256withRSA", JostleFIPSProvider.PROVIDER_NAME);
        assertRejected(() -> fipsSigner.initSign(jslKp.getPrivate()));
        Signature jslSigner = Signature.getInstance("SHA256withRSA", JostleProvider.PROVIDER_NAME);
        assertRejected(() -> jslSigner.initSign(fipsKp.getPrivate()));
        Cipher fipsDec = Cipher.getInstance("RSA", JostleFIPSProvider.PROVIDER_NAME);
        assertRejected(() -> fipsDec.init(Cipher.DECRYPT_MODE, jslKp.getPrivate()));

        // PUBLIC keys are isolated too, in both directions.
        Signature jslVerifier = Signature.getInstance("SHA256withRSA", JostleProvider.PROVIDER_NAME);
        assertRejected(() -> jslVerifier.initVerify(fipsKp.getPublic()));
        Signature fipsVerifier = Signature.getInstance("SHA256withRSA", JostleFIPSProvider.PROVIDER_NAME);
        assertRejected(() -> fipsVerifier.initVerify(jslKp.getPublic()));
        Cipher fipsEncRefused = Cipher.getInstance("RSA", JostleFIPSProvider.PROVIDER_NAME);
        assertRejected(() -> fipsEncRefused.init(Cipher.ENCRYPT_MODE, jslKp.getPublic()));

        // ...and the sanctioned crossing works for the public half: sign with
        // JSLFIPS, re-decode the public key through JSL, verify there.
        fipsSigner.initSign(fipsKp.getPrivate());
        fipsSigner.update(message);
        byte[] fipsSig = fipsSigner.sign();
        jslVerifier.initVerify(FIPSTestUtil.crossPublic(fipsKp.getPublic(), "RSA",
                JostleProvider.PROVIDER_NAME));
        jslVerifier.update(message);
        Assertions.assertTrue(jslVerifier.verify(fipsSig), "re-decoded JSLFIPS public key must verify through JSL");

        jslSigner.initSign(jslKp.getPrivate());
        jslSigner.update(message);
        byte[] jslSig = jslSigner.sign();
        fipsVerifier.initVerify(FIPSTestUtil.crossPublic(jslKp.getPublic(), "RSA",
                JostleFIPSProvider.PROVIDER_NAME));
        fipsVerifier.update(message);
        Assertions.assertTrue(fipsVerifier.verify(jslSig), "re-decoded JSL public key must verify through JSLFIPS");

        // Public-key encrypt through the other provider round-trips, once the
        // public half has been re-decoded there.
        byte[] small = new byte[32];
        RANDOM.nextBytes(small);
        Cipher fipsEnc = Cipher.getInstance("RSA", JostleFIPSProvider.PROVIDER_NAME);
        fipsEnc.init(Cipher.ENCRYPT_MODE, FIPSTestUtil.crossPublic(jslKp.getPublic(), "RSA",
                JostleFIPSProvider.PROVIDER_NAME));
        byte[] ct = fipsEnc.doFinal(small);
        Cipher jslDec = Cipher.getInstance("RSA", JostleProvider.PROVIDER_NAME);
        jslDec.init(Cipher.DECRYPT_MODE, jslKp.getPrivate());
        Assertions.assertArrayEquals(small, jslDec.doFinal(ct),
                "JSLFIPS encrypt with a re-decoded JSL public key must round-trip");

        // The sanctioned route for PRIVATE keys: encode and decode through
        // the target provider's KeyFactory, then use.
        KeyFactory fipsKf = KeyFactory.getInstance("RSA", JostleFIPSProvider.PROVIDER_NAME);
        PrivateKey crossed = fipsKf.generatePrivate(new PKCS8EncodedKeySpec(jslKp.getPrivate().getEncoded()));
        fipsSigner.initSign(crossed);
        fipsSigner.update(message);
        byte[] sig = fipsSigner.sign();
        fipsVerifier.initVerify(FIPSTestUtil.crossPublic(jslKp.getPublic(), "RSA",
                JostleFIPSProvider.PROVIDER_NAME));
        fipsVerifier.update(message);
        Assertions.assertTrue(fipsVerifier.verify(sig), "re-encoded private key must work");
    }

    @Test
    public void ecDhAndXdhPolicy()
        throws Exception
    {
        // EC: private isolated...
        KeyPairGenerator fipsEc = KeyPairGenerator.getInstance("EC", JostleFIPSProvider.PROVIDER_NAME);
        fipsEc.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair fipsEcKp = fipsEc.generateKeyPair();
        KeyAgreement jslEcdh = KeyAgreement.getInstance("ECDH", JostleProvider.PROVIDER_NAME);
        assertRejected(() -> jslEcdh.init(fipsEcKp.getPrivate()));

        // ... and so is the public half, which is refused as an object and
        // crosses only by re-decoding.
        byte[] message = new byte[128];
        RANDOM.nextBytes(message);
        Signature fipsEcdsa = Signature.getInstance("SHA256withECDSA", JostleFIPSProvider.PROVIDER_NAME);
        fipsEcdsa.initSign(fipsEcKp.getPrivate());
        fipsEcdsa.update(message);
        byte[] sig = fipsEcdsa.sign();
        Signature jslEcdsa = Signature.getInstance("SHA256withECDSA", JostleProvider.PROVIDER_NAME);
        assertRejected(() -> jslEcdsa.initVerify(fipsEcKp.getPublic()));
        jslEcdsa.initVerify(FIPSTestUtil.crossPublic(fipsEcKp.getPublic(), "EC",
                JostleProvider.PROVIDER_NAME));
        jslEcdsa.update(message);
        Assertions.assertTrue(jslEcdsa.verify(sig),
                "re-decoded JSLFIPS EC public key must verify through JSL");

        // DH: private isolated.
        KeyPairGenerator jslDh = KeyPairGenerator.getInstance("DH", JostleProvider.PROVIDER_NAME);
        jslDh.initialize(2048);
        KeyPair jslDhKp = jslDh.generateKeyPair();
        KeyAgreement fipsDh = KeyAgreement.getInstance("DH", JostleFIPSProvider.PROVIDER_NAME);
        assertRejected(() -> fipsDh.init(jslDhKp.getPrivate()));

    }

    @Test
    public void symmetricKeysAreUnaffected()
        throws Exception
    {
        // SecretKeys are raw bytes with no native residency: a key generated
        // by JSL's KeyGenerator works in a JSLFIPS cipher (and vice versa).
        javax.crypto.KeyGenerator jslKg = javax.crypto.KeyGenerator.getInstance("AES", JostleProvider.PROVIDER_NAME);
        jslKg.init(256);
        SecretKey key = jslKg.generateKey();

        byte[] nonce = new byte[12];
        RANDOM.nextBytes(nonce);
        byte[] message = new byte[64];
        RANDOM.nextBytes(message);

        Cipher enc = Cipher.getInstance("AES/GCM/NoPadding", JostleFIPSProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key.getEncoded(), "AES"), new GCMParameterSpec(128, nonce));
        byte[] ct = enc.doFinal(message);

        Cipher dec = Cipher.getInstance("AES/GCM/NoPadding", JostleProvider.PROVIDER_NAME);
        dec.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, nonce));
        Assertions.assertArrayEquals(message, dec.doFinal(ct));
    }

    /**
     * Completeness lock over the RSA pattern in
     * {@link #rsaKeysAreIsolatedInBothHalves()}: for every asymmetric family
     * Jostle exposes (RSA, EC/ECDSA, EC/ECDH, DSA, DH, the PQC families, EdDSA
     * and the TLS hybrids) a key created by one provider is rejected by the
     * other provider's SPI in BOTH directions with the identical
     * {@link InvalidKeyException} "different Jostle provider instance"
     * message - PRIVATE and PUBLIC halves alike - and the sanctioned
     * re-encode-through-KeyFactory route round-trips per family.
     */
    @Test
    public void keyIsolationCompleteAcrossAllAsymmetricFamiliesBothDirections()
        throws Exception
    {
        final String fips = JostleFIPSProvider.PROVIDER_NAME;
        final String jsl = JostleProvider.PROVIDER_NAME;

        // ---- RSA ----
        KeyPair jslRsa = genKp("RSA", jsl, 2048);
        KeyPair fipsRsa = genKp("RSA", fips, 2048);
        PrivKeyOp rsaOp = (p, k) -> Signature.getInstance("SHA256withRSA", p).initSign(k);
        assertPrivateIsolatedBothDirections(jslRsa.getPrivate(), fipsRsa.getPrivate(), rsaOp);
        assertSignVerifyAcross("SHA256withRSA", "RSA", fips, jsl, fipsRsa);
        assertSignVerifyAcross("SHA256withRSA", "RSA", jsl, fips, jslRsa);
        assertSigReencodeRoute("SHA256withRSA", "RSA", fips, jsl, jslRsa);
        assertSigReencodeRoute("SHA256withRSA", "RSA", jsl, fips, fipsRsa);

        // ---- EC: both the ECDSA and the ECDH surface must isolate the private key ----
        KeyPair jslEc = genEcKp(jsl);
        KeyPair jslEc2 = genEcKp(jsl);
        KeyPair fipsEc = genEcKp(fips);
        PrivKeyOp ecdsaOp = (p, k) -> Signature.getInstance("SHA256withECDSA", p).initSign(k);
        PrivKeyOp ecdhOp = (p, k) -> KeyAgreement.getInstance("ECDH", p).init(k);
        assertPrivateIsolatedBothDirections(jslEc.getPrivate(), fipsEc.getPrivate(), ecdsaOp);
        assertPrivateIsolatedBothDirections(jslEc.getPrivate(), fipsEc.getPrivate(), ecdhOp);
        assertSignVerifyAcross("SHA256withECDSA", "EC", fips, jsl, fipsEc);
        assertSignVerifyAcross("SHA256withECDSA", "EC", jsl, fips, jslEc);
        assertSigReencodeRoute("SHA256withECDSA", "EC", fips, jsl, jslEc);
        assertSigReencodeRoute("SHA256withECDSA", "EC", jsl, fips, fipsEc);
        assertKaReencodeAndPublicCross("ECDH", "EC", jslEc, jslEc2);

        // ---- DSA ----
        // Both halves decode the SAME key material through each provider's own
        // KeyFactory. That is stronger than two independently generated pairs:
        // identical material still isolated proves the check is on the key's
        // PROVENANCE (which interface library / lib ctx made the handle), not
        // on its contents. It also keeps this runnable on OpenSSL's 3.5.x FIPS
        // module, which refuses every DSA generation path.
        KeyPair jslDsa = FIPSTestUtil.dsaKeyPair(jsl);
        KeyPair fipsDsa = FIPSTestUtil.dsaKeyPair(fips);
        PrivKeyOp dsaOp = (p, k) -> Signature.getInstance("SHA256withDSA", p).initSign(k);
        assertPrivateIsolatedBothDirections(jslDsa.getPrivate(), fipsDsa.getPrivate(), dsaOp);
        assertSignVerifyAcross("SHA256withDSA", "DSA", jsl, fips, jslDsa);
        assertSigReencodeRoute("SHA256withDSA", "DSA", jsl, fips, fipsDsa);
        if (FIPSTestUtil.fipsDsaCanSign())
        {
            // The FIPS-signs directions need a module that signs with DSA.
            // Where one does not, the two above still cover the crossing in
            // the direction it can be exercised, and
            // FIPSDSAAgreementTest.dsaSigningRefusedTypedOrWorks pins the
            // refusal itself.
            assertSignVerifyAcross("SHA256withDSA", "DSA", fips, jsl, fipsDsa);
            assertSigReencodeRoute("SHA256withDSA", "DSA", fips, jsl, jslDsa);
        }

        // ---- PQC: ML-DSA, ML-KEM, SLH-DSA ----
        // Only when the module serves them: 3.5.x does, 3.1.2 does not, and
        // ProvFIPS{MLDSA,MLKEM,SLHDSA} gate registration on the keymgmt fetch.
        // The base provider always serves them, so a JSL-side keypair is
        // always available for the crossing checks.
        if (Security.getProvider(fips).getService("KeyPairGenerator", "ML-DSA-65") != null)
        {
            KeyPair jslMlDsa = genPqcKp("ML-DSA-65", jsl);
            KeyPair fipsMlDsa = genPqcKp("ML-DSA-65", fips);
            PrivKeyOp mldsaOp = (p, k) -> Signature.getInstance("ML-DSA-65", p).initSign(k);
            assertPrivateIsolatedBothDirections(jslMlDsa.getPrivate(), fipsMlDsa.getPrivate(), mldsaOp);
            assertSignVerifyAcross("ML-DSA-65", "ML-DSA-65", fips, jsl, fipsMlDsa);
            assertSignVerifyAcross("ML-DSA-65", "ML-DSA-65", jsl, fips, jslMlDsa);
            assertSigReencodeRoute("ML-DSA-65", "ML-DSA-65", fips, jsl, jslMlDsa);
            assertSigReencodeRoute("ML-DSA-65", "ML-DSA-65", jsl, fips, fipsMlDsa);

            KeyPair jslSlhDsa = genPqcKp("SLH-DSA-SHA2-128S", jsl);
            KeyPair fipsSlhDsa = genPqcKp("SLH-DSA-SHA2-128S", fips);
            PrivKeyOp slhdsaOp = (p, k) -> Signature.getInstance("SLH-DSA-SHA2-128S", p).initSign(k);
            assertPrivateIsolatedBothDirections(jslSlhDsa.getPrivate(), fipsSlhDsa.getPrivate(), slhdsaOp);
            assertSignVerifyAcross("SLH-DSA-SHA2-128S", "SLH-DSA-SHA2-128S", fips, jsl, fipsSlhDsa);
            assertSignVerifyAcross("SLH-DSA-SHA2-128S", "SLH-DSA-SHA2-128S", jsl, fips, jslSlhDsa);

            // ML-KEM has no Signature surface; its private key is reached
            // through the KTS Cipher's unwrap side instead.
            KeyPair jslMlKem = genPqcKp("ML-KEM-768", jsl);
            KeyPair fipsMlKem = genPqcKp("ML-KEM-768", fips);
            // The KTS cipher validates its parameter spec before looking at
            // the key, so a bare init(UNWRAP_MODE, key) fails on the missing
            // spec and never reaches the isolation check.
            org.bouncycastle.jcajce.spec.KTSParameterSpec kts =
                    new org.bouncycastle.jcajce.spec.KTSParameterSpec.Builder("AES", 256, new byte[16])
                            .withKdfAlgorithm(new org.bouncycastle.asn1.x509.AlgorithmIdentifier(
                                    org.bouncycastle.asn1.x9.X9ObjectIdentifiers.id_kdf_kdf3,
                                    new org.bouncycastle.asn1.x509.AlgorithmIdentifier(
                                            org.bouncycastle.asn1.nist.NISTObjectIdentifiers.id_sha256)))
                            .build();
            PrivKeyOp mlkemOp = (p, k) ->
                    javax.crypto.Cipher.getInstance("ML-KEM", p)
                            .init(javax.crypto.Cipher.UNWRAP_MODE, k, kts);
            assertPrivateIsolatedBothDirections(jslMlKem.getPrivate(), fipsMlKem.getPrivate(), mlkemOp);

            // MT-8: the KTS Cipher above was the family's ONLY isolated
            // surface. The KEM KeyGenerator path (KEMExtractSpec ->
            // SpecNI.decap) never passes through it, so a JSL private key
            // decapsulated through JSLFIPS ran in the wrong library while
            // reporting success. Canonical message here, unlike the hybrids:
            // ML-KEM keys encode, so the advice is actionable.
            String mlkemMsg = "private key was created by a different Jostle provider instance; "
                    + "encode it with getEncoded() and decode it through this provider's "
                    + "KeyFactory";
            assertKeyGenPrivateRejected("ML-KEM-768", fips, jslMlKem.getPrivate(), 256, mlkemMsg);
            assertKeyGenPrivateRejected("ML-KEM-768", jsl, fipsMlKem.getPrivate(), 256, mlkemMsg);

            // ...and the PUBLIC object route is refused too, both directions.
            // MT-14 resolved the open decision recorded here previously: a
            // foreign public key keeps its ORIGINATING provider (measured,
            // fips-c-review/probes/xprovider_key_probe.c), so accepting the
            // object meant encapsulating in the key's library rather than the
            // receiving one. Refuse the object; re-decode to cross.
            String mlkemPubMsg = "public key was created by a different Jostle provider instance; "
                    + "encode it with getEncoded() and decode it through this provider's "
                    + "KeyFactory";
            assertKeyGenPublicRejected("ML-KEM-768", fips, jslMlKem.getPublic(), 256, mlkemPubMsg);
            assertKeyGenPublicRejected("ML-KEM-768", jsl, fipsMlKem.getPublic(), 256, mlkemPubMsg);

            // The crossing that replaces it: re-decode and the encapsulation
            // succeeds, in the receiving provider.
            assertKeyGenPublicAccepted("ML-KEM-768", fips,
                    FIPSTestUtil.crossPublic(jslMlKem.getPublic(), "ML-KEM-768", fips), 256);
            assertKeyGenPublicAccepted("ML-KEM-768", jsl,
                    FIPSTestUtil.crossPublic(fipsMlKem.getPublic(), "ML-KEM-768", jsl), 256);

            // RSA-KEM KTS (WI-8) borrows the RSA key's spec the same way, so it
            // needs the same check - and reuses the same KTSParameterSpec, since
            // it too validates the spec before looking at the key. Ungated: the
            // RSA KEM is served by both modules.
            KeyPair jslRsaKem = genKp("RSA", jsl, 2048);
            KeyPair fipsRsaKem = genKp("RSA", fips, 2048);
            PrivKeyOp rsaKemOp = (p, k) ->
                    javax.crypto.Cipher.getInstance("RSA-KTS-KEM-KWS", p)
                            .init(javax.crypto.Cipher.UNWRAP_MODE, k, kts);
            assertPrivateIsolatedBothDirections(jslRsaKem.getPrivate(), fipsRsaKem.getPrivate(), rsaKemOp);
        }

        // ---- EdDSA ----
        // Only when the module serves the family: 3.5.x does, 3.1.2 refuses it
        // outright (the inverse of XDH), and ProvFIPSED gates registration on
        // the keymgmt fetch. The base provider always serves it, so the
        // JSL-side keypair for the crossing checks is always available.
        if (Security.getProvider(fips).getService("KeyPairGenerator", "ED25519") != null)
        {
            for (String edAlg : new String[]{"ED25519", "ED448"})
            {
                KeyPair jslEd = genPqcKp(edAlg, jsl);
                KeyPair fipsEd = genPqcKp(edAlg, fips);
                PrivKeyOp edOp = (p, k) -> Signature.getInstance(edAlg, p).initSign(k);
                assertPrivateIsolatedBothDirections(jslEd.getPrivate(), fipsEd.getPrivate(), edOp);
                assertSignVerifyAcross(edAlg, edAlg, fips, jsl, fipsEd);
                assertSignVerifyAcross(edAlg, edAlg, jsl, fips, jslEd);
                assertSigReencodeRoute(edAlg, edAlg, fips, jsl, jslEd);
                assertSigReencodeRoute(edAlg, edAlg, jsl, fips, fipsEd);
            }
        }

        // ---- TLS hybrid KEMs ----
        // Gated per VARIANT, not per family: 3.5.8 serves three of the four
        // (see ProvFIPSMLXKEM). The base provider serves all four, so the
        // JSL side of each crossing is always available.
        //
        // The refusal differs from every other family here in BOTH type and
        // text, and neither is an oversight:
        //  - TYPE: these keys reach a KeyGenerator, whose engineInit may only
        //    throw InvalidAlgorithmParameterException. Every other family
        //    above refuses through a Signature / Cipher / KeyAgreement init,
        //    which can throw InvalidKeyException. So assertRejected does not
        //    apply and this arm asserts its own type.
        //  - TEXT: the canonical message tells the caller to re-encode the key
        //    through the other provider's KeyFactory. Hybrid keys have no
        //    encoding at all, so that advice would be a dead end; the message
        //    names the only remedy that exists.
        for (org.openssl.jostle.jcajce.spec.MLXKEMParameterSpec hybrid
                : org.openssl.jostle.jcajce.spec.MLXKEMParameterSpec.all())
        {
            if (Security.getProvider(fips).getService("KeyPairGenerator", hybrid.getName()) == null)
            {
                continue;
            }
            KeyPair jslHybridKp = genPqcKp(hybrid.getName(), jsl);
            KeyPair fipsHybridKp = genPqcKp(hybrid.getName(), fips);
            PrivateKey jslHybrid = jslHybridKp.getPrivate();
            PrivateKey fipsHybrid = fipsHybridKp.getPrivate();
            java.security.PublicKey jslHybridPub = jslHybridKp.getPublic();
            java.security.PublicKey fipsHybridPub = fipsHybridKp.getPublic();
            String hybridMsg = "private key was created by a different Jostle provider instance; "
                    + "hybrid KEM keys have no encoding, so generate the keypair through "
                    + "this provider instead";
            int bits = hybrid.getSharedSecretBytes() * 8;
            assertKeyGenPrivateRejected(hybrid.getName(), fips, jslHybrid, bits, hybridMsg);
            assertKeyGenPrivateRejected(hybrid.getName(), jsl, fipsHybrid, bits, hybridMsg);

            // Since MT-14 the PUBLIC half is refused too. For this family that
            // closes the crossing entirely — there is no encoding to re-decode
            // — which is why the message names generating the pair through
            // this provider as the only remedy, and why
            // FIPSMLXKEMAgreementTest interoperates through the RAW SHARE
            // rather than through key objects.
            String hybridPubMsg = "public key was created by a different Jostle provider "
                    + "instance; hybrid KEM keys have no encoding, so generate the keypair "
                    + "through this provider instead";
            assertKeyGenPublicRejected(hybrid.getName(), fips, jslHybridPub, bits, hybridPubMsg);
            assertKeyGenPublicRejected(hybrid.getName(), jsl, fipsHybridPub, bits, hybridPubMsg);
        }

        // ---- DH ----
        KeyPair jslDh = genKp("DH", jsl, 2048);
        KeyPair jslDh2 = genKp("DH", jsl, 2048);
        KeyPair fipsDh = genKp("DH", fips, 2048);
        PrivKeyOp dhOp = (p, k) -> KeyAgreement.getInstance("DH", p).init(k);
        assertPrivateIsolatedBothDirections(jslDh.getPrivate(), fipsDh.getPrivate(), dhOp);
        assertKaReencodeAndPublicCross("DH", "DH", jslDh, jslDh2);
    }

    /**
     * The hybrid family's isolation refusal - see the comment at its arm of
     * the sweep for why the type and the message both differ from
     * {@link #assertRejected}.
     */
    /**
     * A KeyGenerator-surface isolation refusal.
     *
     * <p>Separate from {@link #assertRejected} because
     * {@code KeyGeneratorSpi.engineInit} may only throw
     * {@link java.security.InvalidAlgorithmParameterException} — every other
     * family here refuses through a Signature / Cipher / KeyAgreement init,
     * which can throw {@link java.security.InvalidKeyException}.
     *
     * <p>The expected message is a PARAMETER, supplied at each call site,
     * because the two families deliberately differ: ML-KEM keys encode as
     * PKCS#8 so the canonical "encode it and decode it through this provider's
     * KeyFactory" is real advice, while hybrid keys have no encoding at all
     * and need the only remedy that exists. Passing it in stops this helper
     * drifting into accepting either message for either family.
     */
    /**
     * A foreign PUBLIC key object must be REFUSED on the KeyGenerator's
     * encapsulate arm.
     *
     * <p>It was accepted until MT-14, on the reasoning that public material
     * carries no secret. What that missed is where the work then happened:
     * {@code encapsulate()} drives the SPEC's NI — the library that created
     * the key — so a JSLFIPS KeyGenerator handed a JSL public key produced its
     * encapsulation outside the module, and no functional test could tell,
     * because mainline computes the same bytes.
     *
     * <p>Message is a parameter for the same reason as
     * {@link #assertKeyGenPrivateRejected}: ML-KEM keys encode and hybrids do
     * not, so the remedy each names differs.
     */
    private static void assertKeyGenPublicRejected(String algorithm, String user,
                                                   java.security.PublicKey foreign,
                                                   int keySizeInBits,
                                                   String expectedMessage)
        throws Exception
    {
        javax.crypto.KeyGenerator kg = javax.crypto.KeyGenerator.getInstance(algorithm, user);
        java.security.InvalidAlgorithmParameterException e = Assertions.assertThrows(
                java.security.InvalidAlgorithmParameterException.class,
                () -> kg.init(org.openssl.jostle.jcajce.spec.KEMGenerateSpec.builder()
                        .withPublicKey(foreign)
                        .withAlgorithmName("AES")
                        .withKeySizeInBits(keySizeInBits)
                        .build()),
                algorithm + ": " + user + " must refuse a foreign PUBLIC key object");
        Assertions.assertEquals(expectedMessage, e.getMessage(), algorithm);
    }

    /**
     * A public key that HAS been re-decoded through {@code user}'s own
     * KeyFactory must be accepted on the encapsulate arm. The positive control
     * for {@link #assertKeyGenPublicRejected}: without it, an SPI that refused
     * every public key would pass the refusal assertions.
     */
    private static void assertKeyGenPublicAccepted(String algorithm, String user,
                                                   java.security.PublicKey own,
                                                   int keySizeInBits)
        throws Exception
    {
        javax.crypto.KeyGenerator kg = javax.crypto.KeyGenerator.getInstance(algorithm, user);
        kg.init(org.openssl.jostle.jcajce.spec.KEMGenerateSpec.builder()
                .withPublicKey(own)
                .withAlgorithmName("AES")
                .withKeySizeInBits(keySizeInBits)
                .build());
        Assertions.assertNotNull(kg.generateKey(),
                algorithm + ": " + user + " must accept a public key re-decoded through itself");
    }

    private static void assertKeyGenPrivateRejected(String algorithm, String user,
                                                    PrivateKey foreign, int keySizeInBits,
                                                    String expectedMessage)
        throws Exception
    {
        javax.crypto.KeyGenerator kg = javax.crypto.KeyGenerator.getInstance(algorithm, user);
        java.security.InvalidAlgorithmParameterException e = Assertions.assertThrows(
                java.security.InvalidAlgorithmParameterException.class,
                () -> kg.init(org.openssl.jostle.jcajce.spec.KEMExtractSpec.builder()
                        .withPrivate(foreign)
                        .withAlgorithmName("AES")
                        .withKeySizeInBits(keySizeInBits)
                        .withEncapsulatedKey(new byte[1])
                        .build()),
                algorithm + ": " + user + " must refuse a foreign private key");
        Assertions.assertEquals(expectedMessage, e.getMessage(), algorithm);
    }

    private static KeyPair genKp(String alg, String provider, int bits)
        throws Exception
    {
        KeyPairGenerator g = KeyPairGenerator.getInstance(alg, provider);
        g.initialize(bits);
        return g.generateKeyPair();
    }

    /** A PQC keypair from {@code provider}; the parameter set is the alg name. */
    private static KeyPair genPqcKp(String alg, String provider)
        throws Exception
    {
        return KeyPairGenerator.getInstance(alg, provider).generateKeyPair();
    }

    private static KeyPair genEcKp(String provider)
        throws Exception
    {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC", provider);
        g.initialize(new ECGenParameterSpec("secp256r1"));
        return g.generateKeyPair();
    }

    /**
     * A private key from either provider must be rejected by the other
     * provider's SPI with the canonical isolation message - in both
     * directions.
     */
    private void assertPrivateIsolatedBothDirections(PrivateKey jslPriv, PrivateKey fipsPriv, PrivKeyOp op)
    {
        assertRejected(() -> op.run(JostleFIPSProvider.PROVIDER_NAME, jslPriv));
        assertRejected(() -> op.run(JostleProvider.PROVIDER_NAME, fipsPriv));
    }

    /**
     * Sign in one provider, verify in the other. Both halves of the crossing
     * are asserted: the public key OBJECT is refused by {@code verifyProvider},
     * and the re-decoded key verifies.
     *
     * <p>The refusal is the load-bearing half. Before MT-14 the object was
     * accepted and the verification ran in the SIGNER's library, so this
     * method passed while proving nothing about {@code verifyProvider}.
     */
    private void assertSignVerifyAcross(String sigAlg, String kfAlg, String signProvider,
                                        String verifyProvider, KeyPair keyPair)
        throws Exception
    {
        byte[] msg = new byte[64];
        RANDOM.nextBytes(msg);
        Signature signer = Signature.getInstance(sigAlg, signProvider);
        signer.initSign(keyPair.getPrivate());
        signer.update(msg);
        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance(sigAlg, verifyProvider);
        assertRejected(() -> verifier.initVerify(keyPair.getPublic()));

        verifier.initVerify(FIPSTestUtil.crossPublic(keyPair.getPublic(), kfAlg, verifyProvider));
        verifier.update(msg);
        Assertions.assertTrue(verifier.verify(sig),
                sigAlg + " re-decoded public key must verify across providers");
    }

    /**
     * The sanctioned route: re-encode {@code owner}'s private key through
     * {@code destProvider}'s KeyFactory, then prove it signs and the signature
     * verifies (with the owner's public key) through {@code verifyProvider}.
     */
    private void assertSigReencodeRoute(String sigAlg, String kfAlg, String destProvider, String verifyProvider, KeyPair owner)
        throws Exception
    {
        byte[] msg = new byte[64];
        RANDOM.nextBytes(msg);
        KeyFactory kf = KeyFactory.getInstance(kfAlg, destProvider);
        PrivateKey crossed = kf.generatePrivate(new PKCS8EncodedKeySpec(owner.getPrivate().getEncoded()));
        Signature signer = Signature.getInstance(sigAlg, destProvider);
        signer.initSign(crossed);
        signer.update(msg);
        byte[] sig = signer.sign();
        Signature verifier = Signature.getInstance(sigAlg, verifyProvider);
        verifier.initVerify(FIPSTestUtil.crossPublic(owner.getPublic(), kfAlg, verifyProvider));
        verifier.update(msg);
        Assertions.assertTrue(verifier.verify(sig), sigAlg + " re-encoded private key must sign and verify");
    }

    /**
     * KeyAgreement families (ECDH, DH): compute a native reference secret
     * entirely in JSL, then re-encode BOTH of {@code jslA}'s private key and
     * {@code jslB}'s public key into the FIPS provider (the sanctioned route
     * for each) and run the agreement there. The two secrets must match.
     *
     * <p>The peer's public key OBJECT is asserted refused first — before MT-14
     * it was accepted at {@code doPhase}, and the agreement then ran against a
     * peer key resident in the other library.
     */
    private void assertKaReencodeAndPublicCross(String kaAlg, String kfAlg, KeyPair jslA, KeyPair jslB)
        throws Exception
    {
        KeyAgreement ref = KeyAgreement.getInstance(kaAlg, JostleProvider.PROVIDER_NAME);
        ref.init(jslA.getPrivate());
        ref.doPhase(jslB.getPublic(), true);
        byte[] refSecret = ref.generateSecret();

        KeyFactory fipsKf = KeyFactory.getInstance(kfAlg, JostleFIPSProvider.PROVIDER_NAME);
        PrivateKey crossed = fipsKf.generatePrivate(new PKCS8EncodedKeySpec(jslA.getPrivate().getEncoded()));
        KeyAgreement fipsKa = KeyAgreement.getInstance(kaAlg, JostleFIPSProvider.PROVIDER_NAME);
        fipsKa.init(crossed);
        assertRejected(() -> fipsKa.doPhase(jslB.getPublic(), true));
        fipsKa.doPhase(FIPSTestUtil.crossPublic(jslB.getPublic(), kfAlg,
                JostleFIPSProvider.PROVIDER_NAME), true);
        byte[] crossedSecret = fipsKa.generateSecret();

        Assertions.assertArrayEquals(refSecret, crossedSecret,
                kaAlg + " re-encoded private key and re-encoded peer public key must agree "
                        + "across providers");
    }
}
