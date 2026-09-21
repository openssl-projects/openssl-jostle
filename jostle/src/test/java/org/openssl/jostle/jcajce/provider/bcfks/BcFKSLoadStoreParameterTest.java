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
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.provider.kdf.BytePasswordKdf;
import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.asn1.Der;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.interfaces.PBEKey;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
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

    // ---- Written parallelization parameter follows the property ---------
    // BC-shape probe: BCFKSStoreTest.checkScryptParallelization, bc-java
    // 0bd9d2bae5.

    private static final byte[] SECKEY_BYTES = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

    /**
     * REGRESSION: default and "true" write p equal to r (8, both a
     * conformant reader and releases up to 1.86 derive with it); "false"
     * writes the configured p (1). In every case the store's MAC has to
     * derive under whichever parallelization parameter was actually
     * encoded -- the wire value is what a reader must use, not a fixed
     * choice.
     */
    @Test
    public void writtenParallelizationFollowsProperty_regression() throws Exception
    {
        String propertyName = BcFKSKeyStoreSpi.SCRYPT_P_EQ_R_PROPERTY;
        String old = System.getProperty(propertyName);
        try
        {
            System.clearProperty(propertyName);
            checkScryptParallelization("unset", 8);

            System.setProperty(propertyName, "true");
            checkScryptParallelization("true", 8);

            System.setProperty(propertyName, "false");
            checkScryptParallelization("false", 1);
        }
        finally
        {
            if (old == null)
            {
                System.clearProperty(propertyName);
            }
            else
            {
                System.setProperty(propertyName, old);
            }
        }
    }

    private void checkScryptParallelization(String label, int expectedP) throws Exception
    {
        BCFKSLoadStoreParameter.ScryptConfig config = new BCFKSLoadStoreParameter.ScryptConfig.Builder(1024, 8, 1)
                .withSaltLength(20)
                .build();
        char[] pw = storePw("scrypt parallelization " + label);

        KeyStore fresh = ours();
        fresh.load(null, pw);
        fresh.setKeyEntry("seckey", new SecretKeySpec(SECKEY_BYTES, "AES"), pw, null);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        fresh.store(new BCFKSLoadStoreParameter.Builder(out, pw).withStorePBKDFConfig(config).build());
        byte[] enc = out.toByteArray();

        BcFKSFormat.ObjectStore store = BcFKSFormat.parseObjectStore(enc);
        BcFKSFormat.PbkdMac pbkdMac = store.integrityCheck.pbkdMac;
        Der.ScryptParams params = new Der.Reader(pbkdMac.pbkdAlgorithm.parameters).readScryptParams("scrypt-params");

        Assertions.assertEquals(expectedP, params.parallelizationParameter, "wrong parallelization parameter written");

        byte[] content = store.storeDataRaw;
        byte[] macUnderEncodedP = recalculateMac(pw, pbkdMac.macAlgorithm, content, params, params.parallelizationParameter);
        Assertions.assertTrue(Arrays.areEqual(pbkdMac.mac, macUnderEncodedP),
                "store not derived with the encoded parallelization parameter");

        boolean legacyOpens = Arrays.areEqual(pbkdMac.mac,
                recalculateMac(pw, pbkdMac.macAlgorithm, content, params, params.blockSize));
        Assertions.assertEquals(expectedP == params.blockSize, legacyOpens,
                "the up-to-1.86 convention agreement disagrees with p == r");

        KeyStore reloaded = ours();
        reloaded.load(new ByteArrayInputStream(enc), pw);
        SecretKey seckey = (SecretKey) reloaded.getKey("seckey", pw);
        Assertions.assertArrayEquals(SECKEY_BYTES, seckey.getEncoded());
    }

    /** Mirrors BC's own recalculateMac (BCFKSStoreTest, bc-java 0bd9d2bae5): Jostle's own scrypt, not BC's. */
    private static byte[] recalculateMac(char[] password, Der.AlgorithmIdentifier macAlgorithm, byte[] content,
                                          Der.ScryptParams params, int p) throws Exception
    {
        byte[] pin = BytePasswordKdf.derivationPassword(password, BytePasswordKdf.PURPOSE_INTEGRITY_CHECK);
        byte[] key = new byte[params.keyLength.intValue()];
        try
        {
            BytePasswordKdf.scrypt(NISelector.MemoryHardKdfNI, pin, params.salt,
                    (int) params.costParameter, params.blockSize, p, key, 0, key.length);
            Mac mac = Mac.getInstance(macAlgorithm.oid, JostleProvider.PROVIDER_NAME);
            mac.init(new SecretKeySpec(key, macAlgorithm.oid));
            return mac.doFinal(content);
        }
        finally
        {
            Arrays.clear(key);
            Arrays.clear(pin);
        }
    }

    /**
     * REGRESSION, BOTH directions, probe-then-assert-both. BC 1.86 (the
     * Gradle cache jar) loads a store written under the default (encoded p
     * equal to r) and answers its entry; BC 1.86 FAILS a store written with
     * the configured p (property "false", encoded p != r) with an
     * IOException, because BC 1.86 always derives with the block size in
     * the parallelization parameter's place. Pins that the default keeps
     * interop with the installed base.
     */
    @Test
    public void bc186ReadsDefaultWrittenScryptStoreAndRefusesConfiguredP_regression() throws Exception
    {
        String propertyName = BcFKSKeyStoreSpi.SCRYPT_P_EQ_R_PROPERTY;
        String old = System.getProperty(propertyName);
        try
        {
            System.clearProperty(propertyName);
            byte[] defaultWritten = writeScryptStore();

            KeyStore bcOnDefault = bc();
            bcOnDefault.load(new ByteArrayInputStream(defaultWritten), BcFKSKeyStoreSpiTest.testPassword);
            SecretKey seckey = (SecretKey) bcOnDefault.getKey("seckey", BcFKSKeyStoreSpiTest.testPassword);
            Assertions.assertArrayEquals(
                    new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, seckey.getEncoded());

            System.setProperty(propertyName, "false");
            byte[] configuredPWritten = writeScryptStore();

            KeyStore bcOnConfiguredP = bc();
            Assertions.assertThrows(IOException.class, () -> bcOnConfiguredP.load(
                    new ByteArrayInputStream(configuredPWritten), BcFKSKeyStoreSpiTest.testPassword));
        }
        finally
        {
            if (old == null)
            {
                System.clearProperty(propertyName);
            }
            else
            {
                System.setProperty(propertyName, old);
            }
        }
    }

    private static byte[] writeScryptStore() throws Exception
    {
        BCFKSLoadStoreParameter.ScryptConfig config = new BCFKSLoadStoreParameter.ScryptConfig.Builder(1024, 8, 1)
                .withSaltLength(20)
                .build();
        KeyStore fresh = ours();
        fresh.load(null, BcFKSKeyStoreSpiTest.testPassword);
        fresh.setKeyEntry("seckey",
                new SecretKeySpec(new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, "AES"),
                BcFKSKeyStoreSpiTest.testPassword, null);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        fresh.store(new BCFKSLoadStoreParameter.Builder(out, BcFKSKeyStoreSpiTest.testPassword)
                .withStorePBKDFConfig(config)
                .build());
        return out.toByteArray();
    }

    /**
     * REGRESSION: a store written with ScryptConfig(1024, 8, 1) under the
     * default property (encoded p equal to r) loads with that SAME config
     * (parity with BC, not a divergence); a config that differs in N is
     * still refused, unchanged.
     */
    @Test
    public void loadWithSameScryptConfigSucceeds_regression() throws Exception
    {
        String propertyName = BcFKSKeyStoreSpi.SCRYPT_P_EQ_R_PROPERTY;
        String old = System.getProperty(propertyName);
        try
        {
            System.clearProperty(propertyName);
            byte[] enc = writeScryptStore();

            BCFKSLoadStoreParameter.ScryptConfig writingConfig =
                    new BCFKSLoadStoreParameter.ScryptConfig.Builder(1024, 8, 1).withSaltLength(20).build();
            KeyStore matchLoad = ours();
            matchLoad.load(new BCFKSLoadStoreParameter.Builder(new ByteArrayInputStream(enc),
                    BcFKSKeyStoreSpiTest.testPassword).withStorePBKDFConfig(writingConfig).build());
            Assertions.assertEquals(1, matchLoad.size());

            BCFKSLoadStoreParameter.ScryptConfig mismatchedN =
                    new BCFKSLoadStoreParameter.ScryptConfig.Builder(2048, 8, 1).withSaltLength(20).build();
            KeyStore mismatchLoad = ours();
            IOException e = Assertions.assertThrows(IOException.class,
                    () -> mismatchLoad.load(new BCFKSLoadStoreParameter.Builder(new ByteArrayInputStream(enc),
                            BcFKSKeyStoreSpiTest.testPassword).withStorePBKDFConfig(mismatchedN).build()));
            Assertions.assertTrue(e.getMessage().contains("do not match"), e.getMessage());
        }
        finally
        {
            if (old == null)
            {
                System.clearProperty(propertyName);
            }
            else
            {
                System.setProperty(propertyName, old);
            }
        }
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
