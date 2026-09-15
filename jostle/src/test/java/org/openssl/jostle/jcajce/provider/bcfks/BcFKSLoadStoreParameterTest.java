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

package org.openssl.jostle.jcajce.provider.bcfks;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.BCFKSLoadStoreParameter;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.interfaces.PBEKey;
import javax.crypto.spec.PBEKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * {@link BCFKSLoadStoreParameter}-driven write options (KWP, HMAC-SHA3-512,
 * PBKDF2-SHA3-512, scrypt), signature-based integrity (SignatureCheck), and
 * PBKDF_KEY (type 5, a stored {@link PBEKey}) -- each measured against
 * BouncyCastle 1.86 at test time, per {@link BcFKSKeyStoreSpiTest}'s own
 * convention. Ours only: BC's own {@code BCFKSLoadStoreParameter} is used
 * here ONLY as an interop witness, never accepted by our SPI.
 */
public class BcFKSLoadStoreParameterTest
{
    private static char[] storePw(String suffix)
    {
        return ("store password " + suffix).toCharArray();
    }

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }

    private static KeyStore ours() throws Exception
    {
        return KeyStore.getInstance("BCFKS", JostleProvider.PROVIDER_NAME);
    }

    private static KeyStore bc() throws Exception
    {
        return KeyStore.getInstance("BCFKS", "BC");
    }

    private static Certificate trustedCert() throws Exception
    {
        KeyStore src = ours();
        src.load(new ByteArrayInputStream(BcFKSFixtures.KWP_KEY_STORE), BcFKSKeyStoreSpiTest.testPassword);
        return src.getCertificate("trusted");
    }

    // ---- Write-option round trips, measured against BC -----------------

    @Test
    public void loadStoreParameterRoundTrip_regression() throws Exception
    {
        char[] pw = storePw("lsp round trip");
        Certificate cert = trustedCert();

        KeyStore fresh = ours();
        fresh.load(null, pw);
        fresh.setCertificateEntry("cert", cert);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        BCFKSLoadStoreParameter storeParam = new BCFKSLoadStoreParameter.Builder(out, pw)
                .withStoreEncryptionAlgorithm(BCFKSLoadStoreParameter.EncryptionAlgorithm.AES256_KWP)
                .withStoreMacAlgorithm(BCFKSLoadStoreParameter.MacAlgorithm.HmacSHA3_512)
                .withStorePBKDFConfig(new BCFKSLoadStoreParameter.PBKDF2Config.Builder()
                        .withIterationCount(2048)
                        .withSaltLength(32)
                        .withPRF(BCFKSLoadStoreParameter.PBKDF2Config.PRF.SHA3_512)
                        .build())
                .build();
        fresh.store(storeParam);

        KeyStore reloaded = ours();
        BCFKSLoadStoreParameter loadParam =
                new BCFKSLoadStoreParameter.Builder(new ByteArrayInputStream(out.toByteArray()), pw).build();
        reloaded.load(loadParam);

        Assertions.assertEquals(1, reloaded.size());
        Assertions.assertArrayEquals(cert.getEncoded(), reloaded.getCertificate("cert").getEncoded());
    }

    @Test
    public void writtenWithKwpInteropsWithBouncyCastle_regression() throws Exception
    {
        char[] pw = storePw("kwp interop");
        Certificate cert = trustedCert();

        KeyStore fresh = ours();
        fresh.load(null, pw);
        fresh.setCertificateEntry("cert", cert);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        fresh.store(new BCFKSLoadStoreParameter.Builder(out, pw)
                .withStoreEncryptionAlgorithm(BCFKSLoadStoreParameter.EncryptionAlgorithm.AES256_KWP)
                .build());

        KeyStore bc = bc();
        bc.load(new ByteArrayInputStream(out.toByteArray()), pw);
        Assertions.assertEquals(1, bc.size());
        Assertions.assertArrayEquals(cert.getEncoded(), bc.getCertificate("cert").getEncoded());
    }

    @Test
    public void writtenWithHmacSha3_512InteropsWithBouncyCastle_regression() throws Exception
    {
        char[] pw = storePw("sha3-512 mac interop");
        Certificate cert = trustedCert();

        KeyStore fresh = ours();
        fresh.load(null, pw);
        fresh.setCertificateEntry("cert", cert);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        fresh.store(new BCFKSLoadStoreParameter.Builder(out, pw)
                .withStoreMacAlgorithm(BCFKSLoadStoreParameter.MacAlgorithm.HmacSHA3_512)
                .build());

        KeyStore bc = bc();
        bc.load(new ByteArrayInputStream(out.toByteArray()), pw);
        Assertions.assertEquals(1, bc.size());
        Assertions.assertArrayEquals(cert.getEncoded(), bc.getCertificate("cert").getEncoded());
    }

    @Test
    public void writtenWithPbkdf2Sha3_512PrfInteropsWithBouncyCastle_regression() throws Exception
    {
        char[] pw = storePw("sha3-512 prf interop");
        Certificate cert = trustedCert();

        KeyStore fresh = ours();
        fresh.load(null, pw);
        fresh.setCertificateEntry("cert", cert);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        fresh.store(new BCFKSLoadStoreParameter.Builder(out, pw)
                .withStorePBKDFConfig(new BCFKSLoadStoreParameter.PBKDF2Config.Builder()
                        .withPRF(BCFKSLoadStoreParameter.PBKDF2Config.PRF.SHA3_512)
                        .build())
                .build());

        KeyStore bc = bc();
        bc.load(new ByteArrayInputStream(out.toByteArray()), pw);
        Assertions.assertEquals(1, bc.size());
        Assertions.assertArrayEquals(cert.getEncoded(), bc.getCertificate("cert").getEncoded());
    }

    /** scrypt store config is JSL only; this pins the JSL write -> BC read half. */
    @Test
    public void scryptStoreConfigWritesAndBcReads_regression() throws Exception
    {
        char[] pw = storePw("scrypt store config");
        Certificate cert = trustedCert();

        KeyStore fresh = ours();
        fresh.load(null, pw);
        fresh.setCertificateEntry("cert", cert);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        fresh.store(new BCFKSLoadStoreParameter.Builder(out, pw)
                .withStorePBKDFConfig(new BCFKSLoadStoreParameter.ScryptConfig.Builder(16, 8, 1)
                        .withSaltLength(16)
                        .build())
                .build());

        KeyStore bc = bc();
        bc.load(new ByteArrayInputStream(out.toByteArray()), pw);
        Assertions.assertEquals(1, bc.size());
        Assertions.assertArrayEquals(cert.getEncoded(), bc.getCertificate("cert").getEncoded());
    }

    // ---- Signature-based integrity (SignatureCheck) ---------------------

    private static KeyPair rsaKeyPair() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", JostleProvider.PROVIDER_NAME);
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    /**
     * BC as a test-time witness: a self-signed certificate wrapping
     * {@code pair}'s own public key, built with BC's certificate builder --
     * not part of the implementation, only of the test fixture.
     */
    private static X509Certificate selfSignedCertificate(KeyPair pair) throws Exception
    {
        X500Name name = new X500Name("CN=BCFKS LoadStoreParameter Test");
        Date notBefore = new Date(System.currentTimeMillis() - 3600_000L);
        Date notAfter = new Date(System.currentTimeMillis() + 3600_000L);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                name, BigInteger.ONE, notBefore, notAfter, name, pair.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC").build(pair.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }

    @Test
    public void signatureCheckRoundTripWithPublicKey_regression() throws Exception
    {
        char[] storePassword = storePw("signature round trip");
        KeyPair signingPair = rsaKeyPair();
        Certificate cert = trustedCert();

        KeyStore fresh = ours();
        fresh.load(null, storePassword);
        fresh.setCertificateEntry("cert", cert);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        fresh.store(new BCFKSLoadStoreParameter.Builder(out, (PrivateKey) signingPair.getPrivate())
                .withStoreSignatureAlgorithm(BCFKSLoadStoreParameter.SignatureAlgorithm.SHA512withRSA)
                .build());

        KeyStore reloaded = ours();
        reloaded.load(new BCFKSLoadStoreParameter.Builder(
                new ByteArrayInputStream(out.toByteArray()), signingPair.getPublic()).build());

        Assertions.assertEquals(1, reloaded.size());
        Assertions.assertArrayEquals(cert.getEncoded(), reloaded.getCertificate("cert").getEncoded());
    }

    @Test
    public void signatureCheckWithChainValidatorAcceptsAndRejects_regression() throws Exception
    {
        char[] storePassword = storePw("chain validator");
        KeyPair signingPair = rsaKeyPair();
        // Must actually wrap signingPair's public key -- verification
        // resolves the key from chain[0], so an unrelated certificate would
        // make even a correctly-ACCEPTING validator fail at the signature
        // check rather than at the validator.
        Certificate signerCert = selfSignedCertificate(signingPair);
        Certificate storedCert = trustedCert();

        KeyStore fresh = ours();
        fresh.load(null, storePassword);
        fresh.setCertificateEntry("cert", storedCert);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        fresh.store(new BCFKSLoadStoreParameter.Builder(out, (PrivateKey) signingPair.getPrivate())
                .withStoreSignatureAlgorithm(BCFKSLoadStoreParameter.SignatureAlgorithm.SHA512withRSA)
                .withCertificates(new Certificate[]{signerCert})
                .build());

        BCFKSLoadStoreParameter.ChainValidator accepting = chain -> true;
        KeyStore acceptedLoad = ours();
        acceptedLoad.load(new BCFKSLoadStoreParameter.Builder(
                new ByteArrayInputStream(out.toByteArray()), accepting).build());
        Assertions.assertEquals(1, acceptedLoad.size());

        BCFKSLoadStoreParameter.ChainValidator rejecting = chain -> false;
        KeyStore rejectedLoad = ours();
        IOException e = Assertions.assertThrows(IOException.class,
                () -> rejectedLoad.load(new BCFKSLoadStoreParameter.Builder(
                        new ByteArrayInputStream(out.toByteArray()), rejecting).build()));
        Assertions.assertTrue(e.getMessage().contains("not valid"), e.getMessage());
    }

    @Test
    public void signatureCheckInteropsWithBouncyCastle_regression() throws Exception
    {
        char[] storePassword = storePw("signature interop out");
        KeyPair signingPair = rsaKeyPair();
        Certificate cert = trustedCert();

        KeyStore fresh = ours();
        fresh.load(null, storePassword);
        fresh.setCertificateEntry("cert", cert);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        fresh.store(new BCFKSLoadStoreParameter.Builder(out, (PrivateKey) signingPair.getPrivate())
                .withStoreSignatureAlgorithm(BCFKSLoadStoreParameter.SignatureAlgorithm.SHA512withRSA)
                .build());

        KeyStore bcLoad = bc();
        // BC's own load-side Builder defaults storeSignatureAlgorithm to
        // SHA512withECDSA regardless of the wire content and throws before
        // ever reading the file if the verification key's type does not
        // match -- measured: BcFKSKeyStoreSpi.generateSignatureAlgId,
        // r1rv86 :1571-1610. Must be named explicitly for an RSA key.
        org.bouncycastle.jcajce.BCFKSLoadStoreParameter bcParam =
                new org.bouncycastle.jcajce.BCFKSLoadStoreParameter.Builder(
                        new ByteArrayInputStream(out.toByteArray()), signingPair.getPublic())
                        .withStoreSignatureAlgorithm(
                                org.bouncycastle.jcajce.BCFKSLoadStoreParameter.SignatureAlgorithm.SHA512withRSA)
                        .build();
        bcLoad.load(bcParam);
        Assertions.assertEquals(1, bcLoad.size());
        Assertions.assertArrayEquals(cert.getEncoded(), bcLoad.getCertificate("cert").getEncoded());
    }

    @Test
    public void bcSignedStoreLoadsThroughOurs_regression() throws Exception
    {
        char[] storePassword = storePw("signature interop in");
        KeyPair signingPair = rsaKeyPair();
        Certificate cert = trustedCert();

        KeyStore bcWriter = bc();
        bcWriter.load(null, storePassword);
        bcWriter.setCertificateEntry("cert", cert);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        org.bouncycastle.jcajce.BCFKSLoadStoreParameter bcStoreParam =
                new org.bouncycastle.jcajce.BCFKSLoadStoreParameter.Builder(
                        out, (PrivateKey) signingPair.getPrivate())
                        .withStoreSignatureAlgorithm(
                                org.bouncycastle.jcajce.BCFKSLoadStoreParameter.SignatureAlgorithm.SHA512withRSA)
                        .build();
        bcWriter.store(bcStoreParam);

        KeyStore reloaded = ours();
        reloaded.load(new BCFKSLoadStoreParameter.Builder(
                new ByteArrayInputStream(out.toByteArray()), signingPair.getPublic()).build());
        Assertions.assertEquals(1, reloaded.size());
        Assertions.assertArrayEquals(cert.getEncoded(), reloaded.getCertificate("cert").getEncoded());
    }

    /**
     * A signature-checked store loaded through the plain char[]-password
     * form has no PublicKey/ChainValidator configured on that instance, so
     * verification cannot proceed -- typed refusal, measured as an
     * IOException the same way BC's own null-verificationKey path wraps a
     * GeneralSecurityException.
     */
    @Test
    public void signatureCheckedStorePasswordOnlyLoadRefusesTyped_regression() throws Exception
    {
        char[] storePassword = storePw("signature password-only");
        KeyPair signingPair = rsaKeyPair();
        Certificate cert = trustedCert();

        KeyStore fresh = ours();
        fresh.load(null, storePassword);
        fresh.setCertificateEntry("cert", cert);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        fresh.store(new BCFKSLoadStoreParameter.Builder(out, (PrivateKey) signingPair.getPrivate())
                .withStoreSignatureAlgorithm(BCFKSLoadStoreParameter.SignatureAlgorithm.SHA512withRSA)
                .build());

        KeyStore freshInstance = ours();
        IOException e = Assertions.assertThrows(IOException.class,
                () -> freshInstance.load(new ByteArrayInputStream(out.toByteArray()), storePassword));
        Assertions.assertTrue(e.getMessage().contains("PublicKey") || e.getMessage().contains("chain validator"),
                e.getMessage());
    }

    // ---- PBKDF_KEY (type 5) round trips ---------------------------------

    private static PBEKey pbeKey(char[] pbePassword) throws Exception
    {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WITHHMACSHA512", JostleProvider.PROVIDER_NAME);
        PBEKeySpec spec = new PBEKeySpec(pbePassword, "some salt bytes!".getBytes(), 4096, 256);
        return (PBEKey) factory.generateSecret(spec);
    }

    @Test
    public void pbkdfKeyEntryRoundTrip_regression() throws Exception
    {
        char[] storePassword = storePw("pbkdf key round trip");
        char[] entryPassword = "entry password".toCharArray();
        PBEKey original = pbeKey("the pbe password".toCharArray());

        KeyStore fresh = ours();
        fresh.load(null, storePassword);
        fresh.setKeyEntry("pbe", original, entryPassword, null);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        fresh.store(out, storePassword);

        KeyStore reloaded = ours();
        reloaded.load(new ByteArrayInputStream(out.toByteArray()), storePassword);
        Key recovered = reloaded.getKey("pbe", entryPassword);
        Assertions.assertTrue(recovered instanceof PBEKey);
        PBEKey recoveredPbe = (PBEKey) recovered;
        Assertions.assertEquals(original.getAlgorithm(), recoveredPbe.getAlgorithm());
        Assertions.assertArrayEquals(original.getPassword(), recoveredPbe.getPassword());
        Assertions.assertArrayEquals(original.getSalt(), recoveredPbe.getSalt());
        Assertions.assertEquals(original.getIterationCount(), recoveredPbe.getIterationCount());
        Assertions.assertArrayEquals(original.getEncoded(), recoveredPbe.getEncoded());

        // Matching BC's own engineIsKeyEntry: a PBKDF_KEY entry is NOT
        // reported as a key entry, even though getKey serves it.
        Assertions.assertFalse(reloaded.isKeyEntry("pbe"));
    }

    @Test
    public void pbkdfKeyEntryInteropsWithBouncyCastleBothDirections_regression() throws Exception
    {
        char[] storePassword = storePw("pbkdf key interop");
        char[] entryPassword = "entry password".toCharArray();
        PBEKey original = pbeKey("the pbe password".toCharArray());

        // Ours writes, BC reads.
        KeyStore fresh = ours();
        fresh.load(null, storePassword);
        fresh.setKeyEntry("pbe", original, entryPassword, null);
        ByteArrayOutputStream oursOut = new ByteArrayOutputStream();
        fresh.store(oursOut, storePassword);

        KeyStore bcReader = bc();
        bcReader.load(new ByteArrayInputStream(oursOut.toByteArray()), storePassword);
        Key bcRecovered = bcReader.getKey("pbe", entryPassword);
        Assertions.assertTrue(bcRecovered instanceof PBEKey);
        Assertions.assertArrayEquals(original.getEncoded(), bcRecovered.getEncoded());

        // BC writes, ours reads.
        KeyStore bcWriter = bc();
        bcWriter.load(null, storePassword);
        bcWriter.setKeyEntry("pbe", original, entryPassword, null);
        ByteArrayOutputStream bcOut = new ByteArrayOutputStream();
        bcWriter.store(bcOut, storePassword);

        KeyStore oursReader = ours();
        oursReader.load(new ByteArrayInputStream(bcOut.toByteArray()), storePassword);
        Key oursRecovered = oursReader.getKey("pbe", entryPassword);
        Assertions.assertTrue(oursRecovered instanceof PBEKey);
        Assertions.assertArrayEquals(original.getEncoded(), oursRecovered.getEncoded());
    }

    // ---- BC's own parameter class is refused, typed --------------------

    @Test
    public void foreignLoadStoreParameterClassRefusedTyped_regression() throws Exception
    {
        char[] pw = storePw("foreign parameter class");
        org.bouncycastle.jcajce.BCFKSLoadStoreParameter bcParam =
                new org.bouncycastle.jcajce.BCFKSLoadStoreParameter.Builder(
                        new ByteArrayInputStream(BcFKSFixtures.KWP_KEY_STORE), pw).build();

        KeyStore ks = ours();
        Assertions.assertThrows(IllegalArgumentException.class, () -> ks.load(bcParam));

        KeyStore ks2 = ours();
        ks2.load(null, pw);
        Assertions.assertThrows(IllegalArgumentException.class, () -> ks2.store(bcParam));
    }

    @Test
    public void loadStoreParameterNullLoadsEmptyAndNullStoreIsRefused_regression() throws Exception
    {
        // Load-only convention: the JCA contract itself says the parameter
        // "may be null", and both BC's own engineLoad(LoadStoreParameter)
        // and KSServiceSPI honour that as an empty-store init.
        KeyStore ks = ours();
        ks.load((KeyStore.LoadStoreParameter) null);
        Assertions.assertEquals(0, ks.size());

        // Store has no output stream to fall back to, so null still refuses.
        KeyStore ks2 = ours();
        ks2.load(null, storePw("null store param"));
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> ks2.store((KeyStore.LoadStoreParameter) null));
    }

    // ---- Signature algorithm validated against the signing key ----------

    private static Class<? extends Throwable> captureStoreExceptionClass(KeyStore ks,
                                                                           KeyStore.LoadStoreParameter param)
    {
        try
        {
            ks.store(param);
        }
        catch (Exception e)
        {
            return e.getClass();
        }
        Assertions.fail("expected store() to refuse");
        return null;
    }

    /**
     * BC has no distinct "unset" case of its own -- its Builder always
     * defaults storeSignatureAlgorithm to SHA512withECDSA -- so the
     * measured BC comparison here is BC's OWN Builder, un-configured,
     * signing with our RSA key: BC's default mismatches RSA the same way
     * our "unset" case refuses.
     */
    @Test
    public void signingKeyWithoutSignatureAlgorithmRefusedTyped_regression() throws Exception
    {
        char[] pw = storePw("no signature algorithm");
        KeyPair signingPair = rsaKeyPair();

        KeyStore fresh = ours();
        fresh.load(null, pw);
        BCFKSLoadStoreParameter noAlg =
                new BCFKSLoadStoreParameter.Builder(new ByteArrayOutputStream(), (PrivateKey) signingPair.getPrivate())
                        .build();
        Class<? extends Throwable> oursType = captureStoreExceptionClass(fresh, noAlg);
        Assertions.assertEquals(IOException.class, oursType);

        KeyStore bcFresh = bc();
        bcFresh.load(null, pw);
        org.bouncycastle.jcajce.BCFKSLoadStoreParameter bcNoAlg =
                new org.bouncycastle.jcajce.BCFKSLoadStoreParameter.Builder(
                        new ByteArrayOutputStream(), (PrivateKey) signingPair.getPrivate()).build();
        Class<? extends Throwable> bcType = captureStoreExceptionClass(bcFresh, bcNoAlg);
        Assertions.assertEquals(bcType, oursType);
    }

    @Test
    public void signatureAlgorithmMismatchedWithKeyRefusedTyped_regression() throws Exception
    {
        char[] pw = storePw("mismatched signature algorithm");
        KeyPair signingPair = rsaKeyPair();

        KeyStore fresh = ours();
        fresh.load(null, pw);
        BCFKSLoadStoreParameter mismatched =
                new BCFKSLoadStoreParameter.Builder(new ByteArrayOutputStream(), (PrivateKey) signingPair.getPrivate())
                        .withStoreSignatureAlgorithm(BCFKSLoadStoreParameter.SignatureAlgorithm.SHA512withECDSA)
                        .build();
        Class<? extends Throwable> oursType = captureStoreExceptionClass(fresh, mismatched);
        Assertions.assertEquals(IOException.class, oursType);

        KeyStore bcFresh = bc();
        bcFresh.load(null, pw);
        org.bouncycastle.jcajce.BCFKSLoadStoreParameter bcMismatched =
                new org.bouncycastle.jcajce.BCFKSLoadStoreParameter.Builder(
                        new ByteArrayOutputStream(), (PrivateKey) signingPair.getPrivate())
                        .withStoreSignatureAlgorithm(
                                org.bouncycastle.jcajce.BCFKSLoadStoreParameter.SignatureAlgorithm.SHA512withECDSA)
                        .build();
        Class<? extends Throwable> bcType = captureStoreExceptionClass(bcFresh, bcMismatched);
        Assertions.assertEquals(bcType, oursType);
    }

    // ---- Load-time PBKDF config mismatch ---------------------------------

    @Test
    public void loadStoreParameterPbkdfMismatchRefusedTyped_regression() throws Exception
    {
        char[] pw = storePw("pbkdf mismatch");
        Certificate cert = trustedCert();

        KeyStore bcWriter = bc();
        bcWriter.load(null, pw);
        bcWriter.setCertificateEntry("cert", cert);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        bcWriter.store(new org.bouncycastle.jcajce.BCFKSLoadStoreParameter.Builder(out, pw)
                .withStorePBKDFConfig(new org.bouncycastle.crypto.util.PBKDF2Config.Builder()
                        .withIterationCount(4096)
                        .withSaltLength(32)
                        .withPRF(org.bouncycastle.crypto.util.PBKDF2Config.PRF_SHA512)
                        .build())
                .build());

        KeyStore mismatchLoad = ours();
        BCFKSLoadStoreParameter mismatchParam = new BCFKSLoadStoreParameter.Builder(
                new ByteArrayInputStream(out.toByteArray()), pw)
                .withStorePBKDFConfig(new BCFKSLoadStoreParameter.PBKDF2Config.Builder()
                        .withIterationCount(8192)
                        .withSaltLength(32)
                        .build())
                .build();
        IOException e = Assertions.assertThrows(IOException.class, () -> mismatchLoad.load(mismatchParam));
        Assertions.assertTrue(e.getMessage().contains("do not match"), e.getMessage());

        KeyStore matchLoad = ours();
        BCFKSLoadStoreParameter matchParam = new BCFKSLoadStoreParameter.Builder(
                new ByteArrayInputStream(out.toByteArray()), pw)
                .withStorePBKDFConfig(new BCFKSLoadStoreParameter.PBKDF2Config.Builder()
                        .withIterationCount(4096)
                        .withSaltLength(32)
                        .build())
                .build();
        matchLoad.load(matchParam);
        Assertions.assertEquals(1, matchLoad.size());
    }

    // ---- Write-side KDF config validated against the read-side caps -----

    @Test
    public void writeSideRefusesIterationCountAboveCap_regression() throws Exception
    {
        char[] pw = storePw("write side iteration cap");
        KeyStore fresh = ours();
        fresh.load(null, pw);
        fresh.setCertificateEntry("cert", trustedCert());

        BCFKSLoadStoreParameter param = new BCFKSLoadStoreParameter.Builder(new ByteArrayOutputStream(), pw)
                .withStorePBKDFConfig(new BCFKSLoadStoreParameter.PBKDF2Config.Builder()
                        .withIterationCount(5_000_001)
                        .build())
                .build();
        IOException e = Assertions.assertThrows(IOException.class, () -> fresh.store(param));
        Assertions.assertTrue(e.getMessage().contains("greater than"), e.getMessage());
    }

    @Test
    public void writeSideRefusesScryptBlockSizeAboveCap_regression() throws Exception
    {
        char[] pw = storePw("write side scrypt cap");
        KeyStore fresh = ours();
        fresh.load(null, pw);
        fresh.setCertificateEntry("cert", trustedCert());

        BCFKSLoadStoreParameter param = new BCFKSLoadStoreParameter.Builder(new ByteArrayOutputStream(), pw)
                .withStorePBKDFConfig(new BCFKSLoadStoreParameter.ScryptConfig.Builder(16, 1025, 1).build())
                .build();
        IOException e = Assertions.assertThrows(IOException.class, () -> fresh.store(param));
        Assertions.assertTrue(e.getMessage().contains("greater than"), e.getMessage());
    }
}
