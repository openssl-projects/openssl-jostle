/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.ec;

import org.bouncycastle.its.jcajce.JcaETSIDataDecryptor;
import org.bouncycastle.its.jcajce.JceETSIKeyWrapper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.oer.its.ieee1609dot2.EncryptedDataEncryptionKey;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.EciesP256EncryptedKey;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.spec.IESKEMParameterSpec;
import org.openssl.jostle.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Cross-provider agreement for {@code Cipher.ETSIKEMwithSHA256} — the IEEE
 * 1609.2 (ITS) integrated-encryption KEM — between {@code JSL} and
 * BouncyCastle.
 *
 * <p><b>The claim under test is interop with BouncyCastle, not conformance
 * with IEEE 1609.2.</b> Clause 5.3.5.1 has not been read; BouncyCastle at tag
 * {@code r1rv86} is the reference. Every derivation detail is therefore
 * asserted by comparison against BC rather than against a from-spec value.
 *
 * <p>Agreement here IS byte-equality of the recovered key, not of the wrap: an
 * ephemeral key pair makes the wrap random, so the two directions are
 * cross-recovery. The FIXED-SIZE fields are asserted separately against the
 * ASN.1 shape, which is what a byte comparison would otherwise have covered.
 *
 * <p>FIPS counterpart: {@link
 * org.openssl.jostle.test.fips.FIPSETSIKEMAgreementTest}. Neither substitutes
 * for the other — that one drives the FIPS interface library and its own lib
 * ctx, and runs only with {@code TEST_FIPS_LIB} set.
 *
 * <p>Inputs come from a per-test SHA1PRNG whose seed is logged.
 */
public class ETSIKEMAgreementTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    private static final String KEM = "ETSIKEMwithSHA256";

    /** The two curves BouncyCastle's ITS wrapper will emit; both have cofactor 1. */
    private static final String[] CURVES = {"secp256r1", "brainpoolP256r1"};

    /** Cofactors above 1, where our plain ECDH would diverge from BC's cofactor form. */
    private static final String[] COFACTOR_CURVES = {"sect233r1", "sect233k1"};

    private static final int TRIALS = 4;

    private static final SecureRandom RANDOM = new SecureRandom();

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private static SecureRandom seededRandom(String testName) throws Exception
    {
        long seed = RANDOM.nextLong();
        System.out.println(testName + " seed=" + seed);
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(seed);
        return sr;
    }

    private static KeyPair generate(String curve, SecureRandom sr) throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", JSL);
        kpg.initialize(new ECGenParameterSpec(curve), sr);
        return kpg.generateKeyPair();
    }

    /** The sanctioned crossing: encode here, decode through the peer's KeyFactory. */
    private static PublicKey crossPublic(PublicKey key, String provider) throws Exception
    {
        return KeyFactory.getInstance("EC", provider)
                .generatePublic(new X509EncodedKeySpec(key.getEncoded()));
    }

    private static PrivateKey crossPrivate(PrivateKey key, String provider) throws Exception
    {
        return KeyFactory.getInstance("EC", provider)
                .generatePrivate(new PKCS8EncodedKeySpec(key.getEncoded()));
    }

    /**
     * Provider-appropriate IESKEMParameterSpec, built fresh for each provider
     * from the same content — BC and Jostle now each accept only their own
     * type directly, so one object can no longer drive both.
     */
    private static java.security.spec.AlgorithmParameterSpec iesKemSpec(String provider,
                                                                         byte[] recipientInfo, boolean compress)
    {
        if (BC.equals(provider))
        {
            return new org.bouncycastle.jcajce.spec.IESKEMParameterSpec(recipientInfo, compress);
        }
        return new IESKEMParameterSpec(recipientInfo, compress);
    }

    private static byte[] wrap(String provider, PublicKey recipient, byte[] recipientInfo,
                               boolean compress, Key cek, SecureRandom sr) throws Exception
    {
        Cipher c = Cipher.getInstance(KEM, provider);
        c.init(Cipher.WRAP_MODE, recipient, iesKemSpec(provider, recipientInfo, compress), sr);
        return c.wrap(cek);
    }

    private static Key unwrap(String provider, PrivateKey recipient, byte[] recipientInfo,
                              byte[] wrapped) throws Exception
    {
        Cipher c = Cipher.getInstance(KEM, provider);
        c.init(Cipher.UNWRAP_MODE, recipient, iesKemSpec(provider, recipientInfo, false));
        return c.unwrap(wrapped, "AES", Cipher.SECRET_KEY);
    }

    /**
     * Wrap with each provider, recover with the other, over both curves and
     * both point forms. The recovered key is the agreement; the wrap itself
     * cannot be byte-compared because the ephemeral pair is random.
     */
    @Test
    public void agreesWithBouncyCastleInBothDirections() throws Exception
    {
        SecureRandom sr = seededRandom("agreesWithBouncyCastleInBothDirections");
        for (String curve : CURVES)
        {
            for (boolean compress : new boolean[]{false, true})
            {
                for (int t = 0; t < TRIALS; t++)
                {
                    KeyPair recipient = generate(curve, sr);
                    PublicKey bcPub = crossPublic(recipient.getPublic(), BC);
                    PrivateKey bcPriv = crossPrivate(recipient.getPrivate(), BC);

                    byte[] recipientInfo = new byte[1 + sr.nextInt(48)];
                    sr.nextBytes(recipientInfo);
                    byte[] cek = new byte[16];
                    sr.nextBytes(cek);
                    SecretKeySpec key = new SecretKeySpec(cek, "AES");

                    byte[] ours = wrap(JSL, recipient.getPublic(), recipientInfo, compress, key, sr);
                    Assertions.assertArrayEquals(cek,
                            unwrap(BC, bcPriv, recipientInfo, ours).getEncoded(),
                            curve + " compress=" + compress + ": BouncyCastle could not recover our wrap");

                    byte[] theirs = wrap(BC, bcPub, recipientInfo, compress, key, sr);
                    Assertions.assertArrayEquals(cek,
                            unwrap(JSL, recipient.getPrivate(), recipientInfo, theirs).getEncoded(),
                            curve + " compress=" + compress + ": we could not recover BouncyCastle's wrap");
                }
            }
        }
    }

    /**
     * The ASN.1 fixes {@code c} and {@code t} at 16 bytes and {@code v} at the
     * point length the form implies, so the total is fully determined — the
     * check a byte comparison of a randomised wrap cannot make.
     */
    @Test
    public void theFieldSizesMatchTheAsn1() throws Exception
    {
        SecureRandom sr = seededRandom("theFieldSizesMatchTheAsn1");
        for (String curve : CURVES)
        {
            KeyPair recipient = generate(curve, sr);
            byte[] recipientInfo = new byte[8];
            sr.nextBytes(recipientInfo);
            byte[] cek = new byte[16];
            sr.nextBytes(cek);
            SecretKeySpec key = new SecretKeySpec(cek, "AES");

            byte[] uncompressed = wrap(JSL, recipient.getPublic(), recipientInfo, false, key, sr);
            byte[] compressed = wrap(JSL, recipient.getPublic(), recipientInfo, true, key, sr);

            // 32-byte field: 65-byte uncompressed point, 33-byte compressed one,
            // each followed by a 16-byte key and a 16-byte tag.
            Assertions.assertEquals(65 + 16 + 16, uncompressed.length, curve + " uncompressed length");
            Assertions.assertEquals(33 + 16 + 16, compressed.length, curve + " compressed length");
            Assertions.assertEquals(0x04, uncompressed[0] & 0xFF, curve + " uncompressed point prefix");
            Assertions.assertTrue((compressed[0] & 0xFF) == 0x02 || (compressed[0] & 0xFF) == 0x03,
                    curve + " compressed point prefix was " + (compressed[0] & 0xFF));
        }
    }

    /** The recipient info feeds the KDF, so changing it must change the recovered key. */
    @Test
    public void theRecipientInfoChangesTheDerivation() throws Exception
    {
        SecureRandom sr = seededRandom("theRecipientInfoChangesTheDerivation");
        KeyPair recipient = generate("secp256r1", sr);
        byte[] one = new byte[16];
        sr.nextBytes(one);
        byte[] other = Arrays.clone(one);
        other[0] ^= 0x01;

        byte[] cek = new byte[16];
        sr.nextBytes(cek);
        byte[] wrapped = wrap(JSL, recipient.getPublic(), one, false, new SecretKeySpec(cek, "AES"), sr);

        Assertions.assertArrayEquals(cek, unwrap(JSL, recipient.getPrivate(), one, wrapped).getEncoded(),
                "the matching recipient info must recover the key");
        Assertions.assertThrows(InvalidKeyException.class,
                () -> unwrap(JSL, recipient.getPrivate(), other, wrapped),
                "a different recipient info must not recover the key");
    }

    /**
     * The tag covers the ciphertext, so damaging either must be refused — and
     * refused as {@code InvalidKeyException}, which is what BouncyCastle's own
     * {@code BaseCipherSpi.engineUnwrap} converts its {@code BadPaddingException}
     * into at the {@code Cipher.unwrap} surface.
     */
    @Test
    public void aDamagedWrapIsRefused() throws Exception
    {
        SecureRandom sr = seededRandom("aDamagedWrapIsRefused");
        KeyPair recipient = generate("secp256r1", sr);
        byte[] recipientInfo = new byte[8];
        sr.nextBytes(recipientInfo);
        byte[] cek = new byte[16];
        sr.nextBytes(cek);
        byte[] wrapped = wrap(JSL, recipient.getPublic(), recipientInfo, false,
                new SecretKeySpec(cek, "AES"), sr);

        // Control first: the untouched wrap recovers, so a refusal below is the
        // damage and not the fixture.
        Assertions.assertArrayEquals(cek,
                unwrap(JSL, recipient.getPrivate(), recipientInfo, wrapped).getEncoded());

        int pointLen = 65;
        int[] positions = {pointLen, pointLen + 15, wrapped.length - 1};
        for (int pos : positions)
        {
            byte[] damaged = Arrays.clone(wrapped);
            damaged[pos] ^= 0x01;
            Assertions.assertThrows(InvalidKeyException.class,
                    () -> unwrap(JSL, recipient.getPrivate(), recipientInfo, damaged),
                    "a wrap damaged at " + pos + " must be refused");
        }
    }

    /**
     * A short or empty input must be refused as a typed unwrap failure, not as
     * whatever indexing byte 0 happens to raise. The point FORM is read from
     * that byte, so the length check has to precede it.
     */
    @Test
    public void aShortInputIsRefusedTyped() throws Exception
    {
        SecureRandom sr = seededRandom("aShortInputIsRefusedTyped");
        KeyPair recipient = generate("secp256r1", sr);
        byte[] recipientInfo = new byte[8];
        sr.nextBytes(recipientInfo);

        // 32-byte field: the smallest conceivable input is a 33-byte compressed
        // point plus a 16-byte tag, so everything below 49 is short.
        for (int len : new int[]{0, 1, 32, 48})
        {
            byte[] tooShort = new byte[len];
            sr.nextBytes(tooShort);
            Assertions.assertThrows(InvalidKeyException.class,
                    () -> unwrap(JSL, recipient.getPrivate(), recipientInfo, tooShort),
                    "an input of " + len + " bytes must be refused as InvalidKeyException");
        }

        // An uncompressed point needs 65 + 16, so a 49-byte input claiming 0x04
        // is short too — the arm the minimum above cannot reach.
        byte[] claimsUncompressed = new byte[49];
        sr.nextBytes(claimsUncompressed);
        claimsUncompressed[0] = 0x04;
        Assertions.assertThrows(InvalidKeyException.class,
                () -> unwrap(JSL, recipient.getPrivate(), recipientInfo, claimsUncompressed),
                "an uncompressed-claiming input below the point length must be refused");
    }

    /**
     * BouncyCastle's KEM agrees with {@code ECDHCRawAgreement} — COFACTOR ECDH
     * — and Jostle exposes plain ECDH only. The two coincide exactly at
     * cofactor 1, so any other curve is refused rather than served by an
     * agreement that would silently derive a different secret.
     */
    @Test
    public void aCurveWhoseCofactorIsNotOneIsRefused() throws Exception
    {
        SecureRandom sr = seededRandom("aCurveWhoseCofactorIsNotOneIsRefused");
        for (String curve : COFACTOR_CURVES)
        {
            KeyPair kp = generate(curve, sr);
            int cofactor = ((ECPublicKey) kp.getPublic()).getParams().getCofactor();
            Assertions.assertNotEquals(1, cofactor, curve + " was expected to have a cofactor above 1");

            for (int mode : new int[]{Cipher.WRAP_MODE, Cipher.UNWRAP_MODE})
            {
                Key key = mode == Cipher.WRAP_MODE ? kp.getPublic() : kp.getPrivate();
                InvalidKeyException e = Assertions.assertThrows(InvalidKeyException.class, () ->
                {
                    Cipher c = Cipher.getInstance(KEM, JSL);
                    c.init(mode, key, new IESKEMParameterSpec(new byte[8]));
                }, curve + " must be refused in mode " + mode);
                Assertions.assertTrue(e.getMessage().contains("cofactor " + cofactor),
                        "the refusal must name the cofactor, got: " + e.getMessage());
            }
        }

        // Control: cofactor 1 is accepted in both halves, so the check above is
        // a cofactor test and not a refuse-everything test.
        KeyPair ok = generate("secp256r1", sr);
        for (int mode : new int[]{Cipher.WRAP_MODE, Cipher.UNWRAP_MODE})
        {
            Cipher c = Cipher.getInstance(KEM, JSL);
            c.init(mode, mode == Cipher.WRAP_MODE ? (Key) ok.getPublic() : (Key) ok.getPrivate(),
                    new IESKEMParameterSpec(new byte[8]));
        }
    }

    /**
     * Jostle's own spec must derive what BouncyCastle's does — wrapped with
     * Jostle's spec through Jostle's cipher, and the full ITS content path
     * (CCM-encrypted content plus the KEM-wrapped key) recovered through
     * BouncyCastle's own high-level {@link JcaETSIDataDecryptor}, driven by
     * BouncyCastle's own provider. This is the JSL-wrap-side interop
     * evidence that {@code stockBouncyCastleItsHelpersOnJslAreRefusedTyped}
     * used to carry before that cell was inverted to a refusal.
     */
    @Test
    public void jostlesOwnSpecDerivesWhatBouncyCastlesDoes() throws Exception
    {
        SecureRandom sr = seededRandom("jostlesOwnSpecDerivesWhatBouncyCastlesDoes");
        Provider bc = Security.getProvider(BC);

        for (int t = 0; t < TRIALS; t++)
        {
            KeyPair recipient = generate("secp256r1", sr);
            byte[] recipientInfo = new byte[12];
            sr.nextBytes(recipientInfo);
            byte[] cek = new byte[16];
            sr.nextBytes(cek);
            byte[] nonce = new byte[12];
            sr.nextBytes(nonce);
            byte[] plaintext = new byte[1 + sr.nextInt(256)];
            sr.nextBytes(plaintext);

            Cipher ccm = Cipher.getInstance("CCM", JSL);
            ccm.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(cek, "AES"),
                    new GCMParameterSpec(128, nonce));
            byte[] content = ccm.doFinal(plaintext);

            Cipher c = Cipher.getInstance(KEM, JSL);
            c.init(Cipher.WRAP_MODE, recipient.getPublic(),
                    new IESKEMParameterSpec(recipientInfo, true), sr);
            byte[] wrapped = c.wrap(new SecretKeySpec(cek, "AES"));
            Assertions.assertEquals(33 + 16 + 16, wrapped.length,
                    "our spec's point-compression flag must reach the output");

            // v/c/t split, exactly as the ASN.1-derived check elsewhere in
            // this file: 33-byte compressed point, 16-byte wrapped key,
            // 16-byte tag. Our wrap output is already the flat v||c||t form
            // JcaETSIDataDecryptor expects — no ASN.1 round trip needed here.
            byte[] v = java.util.Arrays.copyOfRange(wrapped, 0, 33);
            byte[] wrappedKey = java.util.Arrays.copyOfRange(wrapped, 33, 33 + 16);
            byte[] tag = java.util.Arrays.copyOfRange(wrapped, 33 + 16, 33 + 16 + 16);
            Assertions.assertEquals(33, v.length, "v is the compressed point");
            Assertions.assertEquals(16, wrappedKey.length, "c is the wrapped key");
            Assertions.assertEquals(16, tag.length, "t is the truncated MAC");

            JcaETSIDataDecryptor decryptor =
                    JcaETSIDataDecryptor.builder(crossPrivate(recipient.getPrivate(), BC), recipientInfo)
                            .provider(bc).build();
            Assertions.assertArrayEquals(plaintext, decryptor.decrypt(wrapped, content, nonce),
                    "BouncyCastle's own ITS decryptor, on BC's own provider, "
                            + "must recover our wrap's content");
            Assertions.assertArrayEquals(cek, decryptor.getKey(),
                    "BouncyCastle's own ITS decryptor must recover our wrapped key");
        }
    }

    /**
     * The reverse direction: BouncyCastle's own {@link JceETSIKeyWrapper}, on
     * BC's own provider, wraps a key that Jostle's cipher — driven by
     * Jostle's own spec — must recover.
     */
    @Test
    public void bouncyCastlesOwnWrapperOnBcIsRecoveredByJostle() throws Exception
    {
        SecureRandom sr = seededRandom("bouncyCastlesOwnWrapperOnBcIsRecoveredByJostle");
        Provider bc = Security.getProvider(BC);

        for (int t = 0; t < TRIALS; t++)
        {
            KeyPair recipient = generate("secp256r1", sr);
            byte[] recipientHash = new byte[8];
            sr.nextBytes(recipientHash);
            byte[] cek = new byte[16];
            sr.nextBytes(cek);

            JceETSIKeyWrapper wrapper = new JceETSIKeyWrapper.Builder(
                    (ECPublicKey) recipient.getPublic(), recipientHash).setProvider(bc).build();
            EncryptedDataEncryptionKey edek = wrapper.wrap(cek);

            EciesP256EncryptedKey ek =
                    EciesP256EncryptedKey.getInstance(edek.getEncryptedDataEncryptionKey());
            byte[] flat = org.bouncycastle.util.Arrays.concatenate(
                    ek.getV().getEncodedPoint(), ek.getC().getOctets(), ek.getT().getOctets());

            Cipher u = Cipher.getInstance(KEM, JSL);
            u.init(Cipher.UNWRAP_MODE, recipient.getPrivate(),
                    new IESKEMParameterSpec(recipientHash, false));
            Key recovered = u.unwrap(flat, "AES", Cipher.SECRET_KEY);
            Assertions.assertArrayEquals(cek, recovered.getEncoded(),
                    "Jostle must recover BouncyCastle's own key wrapper's output");
        }
    }

    /**
     * BouncyCastle casts the spec unchecked, so a foreign type reaches its
     * caller as {@code ClassCastException} and a null one fails later still.
     * Both breach the {@code engineInit} contract, so JCE-canonical behaviour
     * wins here — see the divergence rule in java-spi.md.
     */
    @Test
    public void aForeignOrAbsentSpecIsRefusedTyped() throws Exception
    {
        SecureRandom sr = seededRandom("aForeignOrAbsentSpecIsRefusedTyped");
        KeyPair recipient = generate("secp256r1", sr);

        Assertions.assertThrows(InvalidAlgorithmParameterException.class, () ->
        {
            Cipher c = Cipher.getInstance(KEM, JSL);
            c.init(Cipher.WRAP_MODE, recipient.getPublic(), new IvParameterSpec(new byte[12]));
        }, "an unrelated spec must be refused as an invalid parameter, not cast");

        Assertions.assertThrows(InvalidKeyException.class, () ->
        {
            Cipher c = Cipher.getInstance(KEM, JSL);
            c.init(Cipher.WRAP_MODE, recipient.getPublic(), sr);
        }, "the no-spec overload must be refused; the recipient info is mandatory");

        // BouncyCastle's half, measured live rather than transcribed, so a
        // bcprov bump that moves the reference fails here instead of leaving
        // the divergence above unexplained. BC casts the spec unchecked, so an
        // unrelated type escapes engineInit as ClassCastException.
        PublicKey bcPub = crossPublic(recipient.getPublic(), BC);
        Assertions.assertThrows(ClassCastException.class, () ->
        {
            Cipher c = Cipher.getInstance(KEM, BC);
            c.init(Cipher.WRAP_MODE, bcPub, new IvParameterSpec(new byte[12]));
        }, "BouncyCastle is expected to cast the spec unchecked; if it no longer does, "
                + "re-read whether our divergence is still warranted");
    }

    /** Wrap and unwrap only, per the registration; the other modes are refused. */
    @Test
    public void onlyWrapAndUnwrapAreServed() throws Exception
    {
        SecureRandom sr = seededRandom("onlyWrapAndUnwrapAreServed");
        KeyPair recipient = generate("secp256r1", sr);
        for (int mode : new int[]{Cipher.ENCRYPT_MODE, Cipher.DECRYPT_MODE})
        {
            Assertions.assertThrows(InvalidAlgorithmParameterException.class, () ->
            {
                Cipher c = Cipher.getInstance(KEM, JSL);
                c.init(mode, recipient.getPublic(), new IESKEMParameterSpec(new byte[8]));
            }, "mode " + mode + " must be refused");
        }
    }

    /**
     * Stock bcpkix ({@code org.bouncycastle.its.jcajce.JceETSIKeyWrapper} /
     * {@code JcaETSIDataDecryptor}) builds BC's own
     * {@code org.bouncycastle.jcajce.spec.IESKEMParameterSpec} internally and
     * cannot be redirected to build ours — only our own spec classes are
     * accepted, so {@code ETSIKEMCipherSpi} refuses it typed. The
     * bcpkix-jsl build (extensions repo, deferred) is the supported consumer
     * for driving this provider through those helpers; stock bcpkix pointed
     * at JSL is not.
     */
    @Test
    public void stockBouncyCastleItsHelpersOnJslAreRefusedTyped() throws Exception
    {
        SecureRandom sr = seededRandom("stockBouncyCastleItsHelpersOnJslAreRefusedTyped");
        Provider jsl = Security.getProvider(JSL);
        Provider bc = Security.getProvider(BC);

        KeyPair recipient = generate("secp256r1", sr);
        byte[] recipientHash = new byte[8];
        sr.nextBytes(recipientHash);
        byte[] cek = new byte[16];
        sr.nextBytes(cek);
        byte[] nonce = new byte[12];
        sr.nextBytes(nonce);
        byte[] plaintext = new byte[1 + sr.nextInt(256)];
        sr.nextBytes(plaintext);

        // Wrap side: BC's own wrapper, pointed at JSL, builds BC's spec
        // internally and hands it to our cipher.
        JceETSIKeyWrapper wrapper = new JceETSIKeyWrapper.Builder(
                (ECPublicKey) recipient.getPublic(), recipientHash).setProvider(jsl).build();
        RuntimeException wrapFailure = Assertions.assertThrows(RuntimeException.class,
                () -> wrapper.wrap(cek),
                "stock bcpkix's key wrapper must fail when pointed at JSL after D50");
        assertCauseNamesJostleIesKemSpec(wrapFailure);

        // Unwrap side: build a genuinely valid flat blob with BC's own
        // wrapper on BC's own provider, then hand that blob to
        // JcaETSIDataDecryptor pointed at JSL.
        JceETSIKeyWrapper bcWrapper = new JceETSIKeyWrapper.Builder(
                (ECPublicKey) recipient.getPublic(), recipientHash).setProvider(bc).build();
        EncryptedDataEncryptionKey edek = bcWrapper.wrap(cek);
        EciesP256EncryptedKey ek =
                EciesP256EncryptedKey.getInstance(edek.getEncryptedDataEncryptionKey());
        byte[] flat = org.bouncycastle.util.Arrays.concatenate(
                ek.getV().getEncodedPoint(), ek.getC().getOctets(), ek.getT().getOctets());

        Cipher ccm = Cipher.getInstance("CCM", BC);
        ccm.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(cek, "AES"), new GCMParameterSpec(128, nonce));
        byte[] content = ccm.doFinal(plaintext);

        JcaETSIDataDecryptor decryptor =
                JcaETSIDataDecryptor.builder(recipient.getPrivate(), recipientHash)
                        .provider(jsl).build();
        RuntimeException unwrapFailure = Assertions.assertThrows(RuntimeException.class,
                () -> decryptor.decrypt(flat, content, nonce),
                "stock bcpkix's data decryptor must fail when pointed at JSL after D50");
        assertCauseNamesJostleIesKemSpec(unwrapFailure);
    }

    /** Unwraps BC's wrapper exceptions to find the typed refusal underneath. */
    private static void assertCauseNamesJostleIesKemSpec(Throwable t)
    {
        for (Throwable cur = t; cur != null; cur = cur.getCause())
        {
            if (cur instanceof InvalidAlgorithmParameterException
                    && cur.getMessage() != null
                    && cur.getMessage().contains("org.openssl.jostle.jcajce.spec.IESKEMParameterSpec"))
            {
                return;
            }
        }
        Assertions.fail("expected an InvalidAlgorithmParameterException naming "
                + "org.openssl.jostle.jcajce.spec.IESKEMParameterSpec in the cause chain of: " + t);
    }
}
