/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.crypto;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * MT-90: the KTS ciphers honour {@code KTSParameterSpec.getKeyAlgorithmName()},
 * which selects RFC 3394 (KW) or RFC 5649 (KWP).
 *
 * <p><b>Every discriminating cell uses a 20-byte CEK; do not "tidy" them to
 * 32.</b> At 32 bytes {@code AESWRAP}, {@code AES} and {@code AES-KWP} all
 * produce 40 wrapped bytes, so no assertion on that input can tell the two RFCs
 * apart. Only a non-multiple of 8 separates them: KW refuses, KWP pads to 32.
 *
 * <p>Accepted set: {@code AESWRAP}, {@code AES}, {@code AES-KWP}, matched
 * case-insensitively; a null name means KW.
 *
 * <p>Four divergences from BouncyCastle are pinned here, all measured against
 * bcprov 1.85.2:
 * <ol>
 * <li>BC serves ARIA, Camellia and SEED wraps from the same spec; we serve AES
 * only and refuse them typed.</li>
 * <li>On an unknown name BC throws unchecked {@code UnsupportedOperationException}
 * from {@code wrap()}; we throw checked {@code InvalidAlgorithmParameterException}
 * from {@code init}.</li>
 * <li>On a null name BC throws {@code NullPointerException}; we use KW.</li>
 * <li>On a CEK length KW cannot carry, BC throws unchecked
 * {@code DataLengthException}; we throw checked
 * {@code IllegalBlockSizeException}.</li>
 * </ol>
 */
public class KtsWrapNameTest
{
    private static final SecureRandom RANDOM = new SecureRandom();

    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
    private static final String JSL = JostleProvider.PROVIDER_NAME;

    /** The only CEK length that can tell RFC 3394 from RFC 5649. */
    private static final int DISCRIMINATING_CEK_BYTES = 20;

    /** A length every wrap accepts, kept only to prove back-compat is intact. */
    private static final int NON_DISCRIMINATING_CEK_BYTES = 32;

    private static final String RSA_KTS = "RSA-KTS-KEM-KWS";

    private static final String ACCEPTED = "(accepted: AESWRAP, AES, AES-KWP)";

    @BeforeAll
    public static void setUp()
    {
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    private static KTSParameterSpec spec(String keyAlgorithmName)
    {
        byte[] otherInfo = new byte[1 + RANDOM.nextInt(32)];
        RANDOM.nextBytes(otherInfo);
        return new KTSParameterSpec.Builder(keyAlgorithmName, 256, otherInfo).build();
    }

    private static SecretKeySpec cek(int len)
    {
        byte[] raw = new byte[len];
        RANDOM.nextBytes(raw);
        return new SecretKeySpec(raw, "HMACSHA1");
    }

    private static KeyPair rsaPair() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", JSL);
        kpg.initialize(2048, RANDOM);
        return kpg.generateKeyPair();
    }

    /** Wrap through one provider, recover through the other, on one shared spec. */
    private static void recoversAcross(String xform, PublicKey pub, PrivateKey priv,
                                       String wrapProv, String unwrapProv,
                                       KTSParameterSpec spec, SecretKeySpec key, String label)
        throws Exception
    {
        Cipher w = Cipher.getInstance(xform, wrapProv);
        w.init(Cipher.WRAP_MODE, pub, spec, RANDOM);
        byte[] blob = w.wrap(key);

        Cipher u = Cipher.getInstance(xform, unwrapProv);
        u.init(Cipher.UNWRAP_MODE, priv, spec, RANDOM);
        byte[] back = u.unwrap(blob, "HMACSHA1", Cipher.SECRET_KEY).getEncoded();

        Assertions.assertTrue(Arrays.areEqual(key.getEncoded(), back),
                label + ": " + wrapProv + " wrap must be recoverable by " + unwrapProv);
    }

    /**
     * AES-KWP on a CEK length RFC 3394 cannot carry, both directions against
     * BouncyCastle. This is the cell that fails against the pre-MT-90 code.
     */
    @Test
    public void aesKwpIsHonouredAndAgreesWithBouncyCastleBothDirections() throws Exception
    {
        KeyPair kp = rsaPair();
        for (String name : new String[]{"AES-KWP", "aes-kwp"})
        {
            SecretKeySpec key = cek(DISCRIMINATING_CEK_BYTES);
            KTSParameterSpec s = spec(name);
            recoversAcross(RSA_KTS, kp.getPublic(), kp.getPrivate(), BC, JSL, s, key, name);
            recoversAcross(RSA_KTS, kp.getPublic(), kp.getPrivate(), JSL, BC, s, key, name);
        }
    }

    /** The same, on ML-KEM-768, whose SPI carries the identical selection. */
    @Test
    public void aesKwpIsHonouredOnMlKemAndAgreesWithBouncyCastle() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM-768", JSL);
        KeyPair kp = kpg.generateKeyPair();
        KeyFactory bcKf = KeyFactory.getInstance("ML-KEM-768", BC);
        PublicKey bcPub = bcKf.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));
        PrivateKey bcPriv = bcKf.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

        SecretKeySpec key = cek(DISCRIMINATING_CEK_BYTES);
        KTSParameterSpec s = spec("AES-KWP");

        // BC serves the transformation under the parameter-set name, we serve
        // the family name; same OID underneath.
        Cipher w = Cipher.getInstance("ML-KEM-768", BC);
        w.init(Cipher.WRAP_MODE, bcPub, s, RANDOM);
        byte[] fromBc = w.wrap(key);

        Cipher u = Cipher.getInstance("ML-KEM", JSL);
        u.init(Cipher.UNWRAP_MODE, kp.getPrivate(), s, RANDOM);
        Assertions.assertTrue(
                Arrays.areEqual(key.getEncoded(), u.unwrap(fromBc, "HMACSHA1", Cipher.SECRET_KEY).getEncoded()),
                "ML-KEM AES-KWP: Jostle must unwrap BouncyCastle's wrap");

        Cipher w2 = Cipher.getInstance("ML-KEM", JSL);
        w2.init(Cipher.WRAP_MODE, kp.getPublic(), s, RANDOM);
        byte[] fromJo = w2.wrap(key);

        Cipher u2 = Cipher.getInstance("ML-KEM-768", BC);
        u2.init(Cipher.UNWRAP_MODE, bcPriv, s, RANDOM);
        Assertions.assertTrue(
                Arrays.areEqual(key.getEncoded(), u2.unwrap(fromJo, "HMACSHA1", Cipher.SECRET_KEY).getEncoded()),
                "ML-KEM AES-KWP: BouncyCastle must unwrap Jostle's wrap");
    }

    /**
     * Every KW spelling refuses the 20-byte CEK. BC's refusal is asserted too,
     * because it is what proves the input is genuinely illegal for RFC 3394
     * rather than us being broken. Mixed-case {@code AESWrap} is bcpkix's
     * {@code OperatorHelper} spelling.
     *
     * <p>The types differ and both are pinned: BC raises unchecked
     * {@code DataLengthException}, we raise the JCE-canonical checked
     * {@code IllegalBlockSizeException}.
     */
    @Test
    public void kwNamesRefuseANonMultipleOfEightAsBouncyCastleDoes() throws Exception
    {
        KeyPair kp = rsaPair();
        for (String name : new String[]{"AESWRAP", "AES", "AESWrap", "aeswrap"})
        {
            SecretKeySpec key = cek(DISCRIMINATING_CEK_BYTES);

            Cipher jo = Cipher.getInstance(RSA_KTS, JSL);
            jo.init(Cipher.WRAP_MODE, kp.getPublic(), spec(name), RANDOM);
            Assertions.assertThrows(IllegalBlockSizeException.class, () -> jo.wrap(key),
                    name + ": KW must refuse a CEK that is not a multiple of 8");

            Cipher bc = Cipher.getInstance(RSA_KTS, BC);
            bc.init(Cipher.WRAP_MODE, kp.getPublic(), spec(name), RANDOM);
            DataLengthException e = Assertions.assertThrows(DataLengthException.class, () -> bc.wrap(key),
                    name + ": BouncyCastle must refuse it too, or the input was not illegal");
            Assertions.assertEquals("wrap data must be a multiple of 8 bytes", e.getMessage());
        }
    }

    /**
     * Back-compat: a 32-byte CEK round-trips under every accepted name — and
     * simultaneously shows this length discriminates nothing, since AES-KWP
     * passes here as readily as AESWRAP.
     */
    @Test
    public void everyAcceptedNameStillRoundTripsOnAnAlignedCek() throws Exception
    {
        KeyPair kp = rsaPair();
        for (String name : new String[]{"AESWRAP", "AES", "AES-KWP", "AESWrap"})
        {
            SecretKeySpec key = cek(NON_DISCRIMINATING_CEK_BYTES);
            KTSParameterSpec s = spec(name);
            recoversAcross(RSA_KTS, kp.getPublic(), kp.getPrivate(), JSL, JSL, s, key, name);
            recoversAcross(RSA_KTS, kp.getPublic(), kp.getPrivate(), JSL, BC, s, key, name);
        }
    }

    /**
     * A null name means AES-KW for us; BouncyCastle raises
     * {@code NullPointerException} on the same spec, pinned so a bcprov bump
     * that fixes it is visible.
     */
    @Test
    public void aNullNameMeansAesKwForUsAndNpesInBouncyCastle() throws Exception
    {
        KeyPair kp = rsaPair();

        SecretKeySpec aligned = cek(NON_DISCRIMINATING_CEK_BYTES);
        recoversAcross(RSA_KTS, kp.getPublic(), kp.getPrivate(), JSL, JSL, spec(null), aligned, "null name");

        // ...and it is KW, not KWP: the 20-byte CEK is refused.
        SecretKeySpec odd = cek(DISCRIMINATING_CEK_BYTES);
        Cipher jo = Cipher.getInstance(RSA_KTS, JSL);
        jo.init(Cipher.WRAP_MODE, kp.getPublic(), spec(null), RANDOM);
        Assertions.assertThrows(IllegalBlockSizeException.class, () -> jo.wrap(odd),
                "a null name must select KW, which cannot carry 20 bytes");

        Cipher bc = Cipher.getInstance(RSA_KTS, BC);
        bc.init(Cipher.WRAP_MODE, kp.getPublic(), spec(null), RANDOM);
        Assertions.assertThrows(NullPointerException.class, () -> bc.wrap(aligned),
                "pinning BouncyCastle's NPE on a null key-algorithm name (bcprov 1.85.2)");
    }

    /**
     * An unsupported name is refused at init with the message naming what is
     * accepted. Our own Cipher spellings are refused too: they are not
     * KTSParameterSpec vocabulary and would fail against BouncyCastle.
     */
    @Test
    public void unsupportedNameIsRefusedTypedAtInitNamingTheAcceptedSet() throws Exception
    {
        KeyPair kp = rsaPair();
        for (String name : new String[]{"NOSUCHWRAP", "AESKWP", "AESWrapPad", "DESEDEWrap", ""})
        {
            Cipher jo = Cipher.getInstance(RSA_KTS, JSL);
            InvalidAlgorithmParameterException e = Assertions.assertThrows(
                    InvalidAlgorithmParameterException.class,
                    () -> jo.init(Cipher.WRAP_MODE, kp.getPublic(), spec(name), RANDOM),
                    name + ": an unsupported key-algorithm name must be refused at init");
            Assertions.assertEquals("unsupported key algorithm name: " + name + " " + ACCEPTED,
                    e.getMessage(), name + ": refusal message");
        }
    }

    /**
     * The same refusal on the ML-KEM SPI. Its own cell, because the AES-KWP
     * cell would not catch an ML-KEM copy that dropped the null check — that
     * path fails later in {@code oidFor} with a different type.
     */
    @Test
    public void unsupportedNameIsRefusedTypedAtInitOnMlKemToo() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM-768", JSL);
        KeyPair kp = kpg.generateKeyPair();
        for (String name : new String[]{"NOSUCHWRAP", "ARIA", "AESWrapPad"})
        {
            Cipher jo = Cipher.getInstance("ML-KEM", JSL);
            InvalidAlgorithmParameterException e = Assertions.assertThrows(
                    InvalidAlgorithmParameterException.class,
                    () -> jo.init(Cipher.WRAP_MODE, kp.getPublic(), spec(name), RANDOM),
                    name + ": ML-KEM must refuse an unsupported name at init");
            Assertions.assertEquals("unsupported key algorithm name: " + name + " " + ACCEPTED,
                    e.getMessage(), name + ": ML-KEM refusal message");
        }
    }

    /**
     * Divergence in both type and timing: BouncyCastle accepts an unknown name
     * at init and throws unchecked {@code UnsupportedOperationException} from
     * {@code wrap()}; we throw the checked, JCE-canonical
     * {@code InvalidAlgorithmParameterException} from {@code init}.
     */
    @Test
    public void unknownNameDivergesFromBouncyCastleInBothTypeAndTiming() throws Exception
    {
        KeyPair kp = rsaPair();
        SecretKeySpec key = cek(NON_DISCRIMINATING_CEK_BYTES);

        Cipher bc = Cipher.getInstance(RSA_KTS, BC);
        Assertions.assertDoesNotThrow(
                () -> bc.init(Cipher.WRAP_MODE, kp.getPublic(), spec("NOSUCHWRAP"), RANDOM),
                "BouncyCastle accepts an unknown name at init (pinned, bcprov 1.85.2)");
        UnsupportedOperationException bcEx = Assertions.assertThrows(
                UnsupportedOperationException.class, () -> bc.wrap(key),
                "BouncyCastle defers the refusal to wrap()");
        Assertions.assertEquals("unknown key algorithm: NOSUCHWRAP", bcEx.getMessage());

        Cipher jo = Cipher.getInstance(RSA_KTS, JSL);
        Assertions.assertThrows(InvalidAlgorithmParameterException.class,
                () -> jo.init(Cipher.WRAP_MODE, kp.getPublic(), spec("NOSUCHWRAP"), RANDOM),
                "we refuse at init, checked");
    }

    /**
     * Decision divergence: BouncyCastle serves ARIA, Camellia and SEED wraps
     * from the same spec; we serve AES only. Both halves asserted, so narrowing
     * either side has to delete a self-explaining test first.
     */
    @Test
    public void weServeAesOnlyWhereBouncyCastleAlsoServesAriaCamelliaAndSeed() throws Exception
    {
        KeyPair kp = rsaPair();
        for (String name : new String[]{"ARIA", "Camellia", "SEED", "ARIA-KWP", "Camellia-KWP"})
        {
            Cipher bc = Cipher.getInstance(RSA_KTS, BC);
            Assertions.assertDoesNotThrow(
                    () -> bc.init(Cipher.WRAP_MODE, kp.getPublic(), spec(name), RANDOM),
                    name + ": BouncyCastle accepts this name (pinned, bcprov 1.85.2)");

            Cipher jo = Cipher.getInstance(RSA_KTS, JSL);
            InvalidAlgorithmParameterException e = Assertions.assertThrows(
                    InvalidAlgorithmParameterException.class,
                    () -> jo.init(Cipher.WRAP_MODE, kp.getPublic(), spec(name), RANDOM),
                    name + ": we serve AES only");
            Assertions.assertEquals("unsupported key algorithm name: " + name + " " + ACCEPTED,
                    e.getMessage());
        }
    }

    /**
     * The selection is load-bearing: a KWP-wrapped blob read back as KW must
     * not yield the CEK. Without this the two arms could both be reached and
     * still be interchangeable, making every cell above vacuous.
     *
     * <p>Measured 10/10 as {@code InvalidKeyException}, never a value.
     */
    @Test
    public void theTwoRfcsAreNotInterchangeable() throws Exception
    {
        KeyPair kp = rsaPair();
        SecretKeySpec key = cek(24);

        // Both specs must share otherInfo, or the KEKs differ and the cell is vacuous.
        byte[] sharedOtherInfo = new byte[24];
        RANDOM.nextBytes(sharedOtherInfo);
        KTSParameterSpec kwp = new KTSParameterSpec.Builder("AES-KWP", 256, sharedOtherInfo).build();
        KTSParameterSpec kw = new KTSParameterSpec.Builder("AESWRAP", 256, sharedOtherInfo).build();

        Cipher w = Cipher.getInstance(RSA_KTS, JSL);
        w.init(Cipher.WRAP_MODE, kp.getPublic(), kwp, RANDOM);
        byte[] blob = w.wrap(key);

        Cipher u = Cipher.getInstance(RSA_KTS, JSL);
        u.init(Cipher.UNWRAP_MODE, kp.getPrivate(), kw, RANDOM);
        Assertions.assertThrows(InvalidKeyException.class,
                () -> u.unwrap(blob, "HMACSHA1", Cipher.SECRET_KEY),
                "a KWP wrap must not be readable as KW, or the name selects nothing");
    }
}
