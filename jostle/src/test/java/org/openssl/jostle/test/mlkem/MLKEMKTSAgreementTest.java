/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.mlkem;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.spec.KTSParameterSpec;
import org.openssl.jostle.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.AlgorithmParameterSpec;

/**
 * The KTS ciphers against BouncyCastle. They honour {@code KTSParameterSpec.getKeyAlgorithmName()},
 * which selects RFC 3394 (KW) or RFC 5649 (KWP).
 *
 * <p><b>Every discriminating cell uses a 20-byte CEK; do not "tidy" them to
 * 32.</b> At 32 bytes {@code AESWRAP}, {@code AES} and {@code AES-KWP} all
 * produce 40 wrapped bytes, so no assertion on that input can tell the two RFCs
 * apart. Only a non-multiple of 8 separates them: KW refuses, KWP pads to 32.
 *
 * <p>Accepted set: {@code AESWRAP}, {@code AES}, {@code AES-KWP}, matched
 * case-insensitively; a null name is refused by the Builder (see below).
 *
 * <p>Four divergences from BouncyCastle are pinned here:
 * <ol>
 * <li>BC serves ARIA, Camellia and SEED wraps from the same spec; we serve AES
 * only and refuse them typed.</li>
 * <li>On an unknown name BC throws unchecked {@code UnsupportedOperationException}
 * from {@code wrap()}; we throw checked {@code InvalidAlgorithmParameterException}
 * from {@code init}.</li>
 * <li>Our Builder refuses a null name typed ({@code IllegalArgumentException});
 * BC's accepts it and throws {@code NullPointerException} from {@code wrap()}.</li>
 * <li>On a CEK length KW cannot carry, BC throws unchecked
 * {@code DataLengthException}; we throw checked
 * {@code IllegalBlockSizeException}.</li>
 * </ol>
 *
 * <p>BC and Jostle each accept only their own spec type directly (no more
 * reflection), so a cross-provider cell builds each provider's own spec from
 * the same content via {@link KtsSpec#forProvider(String)}.
 */
public class MLKEMKTSAgreementTest
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

    /**
     * Provider-agnostic description of a KTSParameterSpec. BC and Jostle each
     * accept only their OWN spec type directly, so a single spec object cannot
     * drive both providers - this descriptor builds the right one, from the
     * same content, at {@link #forProvider(String)} time. No KDF override is
     * ever built here (every cell uses the default), so unlike the KDF-bearing
     * descriptors elsewhere this one need not declare {@code IOException}.
     */
    private static final class KtsSpec
    {
        private final String keyAlgorithmName;
        private final byte[] otherInfo;

        KtsSpec(String keyAlgorithmName, byte[] otherInfo)
        {
            this.keyAlgorithmName = keyAlgorithmName;
            this.otherInfo = otherInfo;
        }

        AlgorithmParameterSpec forProvider(String provider)
        {
            if (BC.equals(provider))
            {
                // KTSParameterSpec is qualified where BouncyCastle's is meant: jostle's of that name is imported
                return new org.bouncycastle.jcajce.spec.KTSParameterSpec.Builder(
                        keyAlgorithmName, 256, otherInfo).build();
            }
            return new KTSParameterSpec.Builder(keyAlgorithmName, 256, otherInfo).build();
        }
    }

    private static KtsSpec spec(String keyAlgorithmName)
    {
        byte[] otherInfo = new byte[1 + RANDOM.nextInt(32)];
        RANDOM.nextBytes(otherInfo);
        return new KtsSpec(keyAlgorithmName, otherInfo);
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

    /** Wrap through one provider, recover through the other, on one shared spec content. */
    private static void recoversAcross(String xform, PublicKey pub, PrivateKey priv,
                                       String wrapProv, String unwrapProv,
                                       KtsSpec spec, SecretKeySpec key, String label)
        throws Exception
    {
        Cipher w = Cipher.getInstance(xform, wrapProv);
        w.init(Cipher.WRAP_MODE, pub, spec.forProvider(wrapProv), RANDOM);
        byte[] blob = w.wrap(key);

        Cipher u = Cipher.getInstance(xform, unwrapProv);
        u.init(Cipher.UNWRAP_MODE, priv, spec.forProvider(unwrapProv), RANDOM);
        byte[] back = u.unwrap(blob, "HMACSHA1", Cipher.SECRET_KEY).getEncoded();

        Assertions.assertTrue(Arrays.areEqual(key.getEncoded(), back),
                label + ": " + wrapProv + " wrap must be recoverable by " + unwrapProv);
    }

    /**
     * AES-KWP on a CEK length RFC 3394 cannot carry, both directions against
     * BouncyCastle. This is the cell that fails against code that ignores the name.
     */
    @Test
    public void aesKwpIsHonouredAndAgreesWithBouncyCastleBothDirections() throws Exception
    {
        KeyPair kp = rsaPair();
        for (String name : new String[]{"AES-KWP", "aes-kwp"})
        {
            SecretKeySpec key = cek(DISCRIMINATING_CEK_BYTES);
            KtsSpec s = spec(name);
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
        KtsSpec s = spec("AES-KWP");

        // BC serves the transformation under the parameter-set name, we serve
        // the family name; same OID underneath.
        Cipher w = Cipher.getInstance("ML-KEM-768", BC);
        w.init(Cipher.WRAP_MODE, bcPub, s.forProvider(BC), RANDOM);
        byte[] fromBc = w.wrap(key);

        Cipher u = Cipher.getInstance("ML-KEM", JSL);
        u.init(Cipher.UNWRAP_MODE, kp.getPrivate(), s.forProvider(JSL), RANDOM);
        Assertions.assertTrue(
                Arrays.areEqual(key.getEncoded(), u.unwrap(fromBc, "HMACSHA1", Cipher.SECRET_KEY).getEncoded()),
                "ML-KEM AES-KWP: Jostle must unwrap BouncyCastle's wrap");

        Cipher w2 = Cipher.getInstance("ML-KEM", JSL);
        w2.init(Cipher.WRAP_MODE, kp.getPublic(), s.forProvider(JSL), RANDOM);
        byte[] fromJo = w2.wrap(key);

        Cipher u2 = Cipher.getInstance("ML-KEM-768", BC);
        u2.init(Cipher.UNWRAP_MODE, bcPriv, s.forProvider(BC), RANDOM);
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
            jo.init(Cipher.WRAP_MODE, kp.getPublic(), spec(name).forProvider(JSL), RANDOM);
            Assertions.assertThrows(IllegalBlockSizeException.class, () -> jo.wrap(key),
                    name + ": KW must refuse a CEK that is not a multiple of 8");

            Cipher bc = Cipher.getInstance(RSA_KTS, BC);
            bc.init(Cipher.WRAP_MODE, kp.getPublic(), spec(name).forProvider(BC), RANDOM);
            DataLengthException e = Assertions.assertThrows(DataLengthException.class, () -> bc.wrap(key),
                    name + ": BouncyCastle must refuse it too, or the input was not illegal");
            Assertions.assertEquals("wrap data must be a multiple of 8 bytes", e.getMessage());
        }
    }

    /**
     * Back-compat: a 32-byte CEK round-trips under every accepted name - and
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
            KtsSpec s = spec(name);
            recoversAcross(RSA_KTS, kp.getPublic(), kp.getPrivate(), JSL, JSL, s, key, name);
            recoversAcross(RSA_KTS, kp.getPublic(), kp.getPrivate(), JSL, BC, s, key, name);
        }
    }

    /**
     * Our Builder refuses a null name typed ({@code IllegalArgumentException});
     * BC's accepts it and throws {@code NullPointerException} from {@code wrap()}.
     */
    @Test
    public void aNullNameIsRefusedByOurBuilderAndNpesInBouncyCastle() throws Exception
    {
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> new KTSParameterSpec.Builder(null, 256),
                "our own Builder must refuse a null key-algorithm name immediately");

        KeyPair kp = rsaPair();
        SecretKeySpec aligned = cek(NON_DISCRIMINATING_CEK_BYTES);
        Cipher bc = Cipher.getInstance(RSA_KTS, BC);
        bc.init(Cipher.WRAP_MODE, kp.getPublic(), spec(null).forProvider(BC), RANDOM);
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
                    () -> jo.init(Cipher.WRAP_MODE, kp.getPublic(), spec(name).forProvider(JSL), RANDOM),
                    name + ": an unsupported key-algorithm name must be refused at init");
            Assertions.assertEquals("unsupported key algorithm name: " + name + " " + ACCEPTED,
                    e.getMessage(), name + ": refusal message");
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
                () -> bc.init(Cipher.WRAP_MODE, kp.getPublic(), spec("NOSUCHWRAP").forProvider(BC), RANDOM),
                "BouncyCastle accepts an unknown name at init (pinned, bcprov 1.85.2)");
        UnsupportedOperationException bcEx = Assertions.assertThrows(
                UnsupportedOperationException.class, () -> bc.wrap(key),
                "BouncyCastle defers the refusal to wrap()");
        Assertions.assertEquals("unknown key algorithm: NOSUCHWRAP", bcEx.getMessage());

        Cipher jo = Cipher.getInstance(RSA_KTS, JSL);
        Assertions.assertThrows(InvalidAlgorithmParameterException.class,
                () -> jo.init(Cipher.WRAP_MODE, kp.getPublic(), spec("NOSUCHWRAP").forProvider(JSL), RANDOM),
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
                    () -> bc.init(Cipher.WRAP_MODE, kp.getPublic(), spec(name).forProvider(BC), RANDOM),
                    name + ": BouncyCastle accepts this name (pinned, bcprov 1.85.2)");

            Cipher jo = Cipher.getInstance(RSA_KTS, JSL);
            InvalidAlgorithmParameterException e = Assertions.assertThrows(
                    InvalidAlgorithmParameterException.class,
                    () -> jo.init(Cipher.WRAP_MODE, kp.getPublic(), spec(name).forProvider(JSL), RANDOM),
                    name + ": we serve AES only");
            Assertions.assertEquals("unsupported key algorithm name: " + name + " " + ACCEPTED,
                    e.getMessage());
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

    /**
     * The X9.44 KDF3 AlgorithmIdentifier {@code SEQUENCE { kdf3-OID, SEQUENCE { digestOID } }}
     * a KTSParameterSpec carries.
     */
    private static AlgorithmIdentifier kdf3(ASN1ObjectIdentifier digestOid)
    {
        return new AlgorithmIdentifier(X9ObjectIdentifiers.id_kdf_kdf3, new AlgorithmIdentifier(digestOid));
    }

    /**
     * Provider-agnostic description of a KTSParameterSpec. BC and Jostle each
     * accept only their OWN spec type directly, so a single spec object cannot
     * drive both providers - this descriptor builds the right one, from the
     * same content, at {@link #forProvider(String)} time.
     */
    private static final class KdfKtsSpec
    {
        private final String keyAlgorithmName;
        private final int keySizeInBits;
        private final byte[] otherInfo;
        /** null means {@code withNoKdf()}. */
        private final AlgorithmIdentifier kdf;

        KdfKtsSpec(String keyAlgorithmName, int keySizeInBits, byte[] otherInfo, AlgorithmIdentifier kdf)
        {
            this.keyAlgorithmName = keyAlgorithmName;
            this.keySizeInBits = keySizeInBits;
            this.otherInfo = otherInfo;
            this.kdf = kdf;
        }

        AlgorithmParameterSpec forProvider(String provider) throws IOException
        {
            if (BouncyCastleProvider.PROVIDER_NAME.equals(provider))
            {
                // KTSParameterSpec is qualified where BouncyCastle's is meant: jostle's of that name is imported
                org.bouncycastle.jcajce.spec.KTSParameterSpec.Builder b =
                        new org.bouncycastle.jcajce.spec.KTSParameterSpec.Builder(
                                keyAlgorithmName, keySizeInBits, otherInfo);
                return kdf == null ? b.withNoKdf().build() : b.withKdfAlgorithm(kdf).build();
            }
            KTSParameterSpec.Builder b = new KTSParameterSpec.Builder(keyAlgorithmName, keySizeInBits, otherInfo);
            return kdf == null ? b.withNoKdf().build() : b.withKdfAlgorithm(kdf.getEncoded()).build();
        }
    }

    private static KdfKtsSpec ktsKdf3Spec(int keyBits, byte[] otherInfo, ASN1ObjectIdentifier digestOid)
    {
        return new KdfKtsSpec("AES", keyBits, otherInfo, kdf3(digestOid));
    }

    private static SecretKeySpec randomAesKey(SecureRandom rng, int lenBytes)
    {
        byte[] k = new byte[lenBytes];
        rng.nextBytes(k);
        return new SecretKeySpec(k, "AES");
    }

    private static byte[] randomBytes(SecureRandom rng, int len)
    {
        byte[] b = new byte[len];
        rng.nextBytes(b);
        return b;
    }

    private static KeyPair jostleKeyPair(String name) throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(name, JostleProvider.PROVIDER_NAME);
        return kpg.generateKeyPair();
    }

    // ----------------------------------------------------------------------
    // Cross-provider agreement against BouncyCastle (the real interop guarantee)
    // ----------------------------------------------------------------------

    @Test
    public void testCrossProvider_JostleWrap_BCUnwrap() throws Exception
    {
        SecureRandom rng = seededRandom("testCrossProvider_JostleWrap_BCUnwrap");

        for (int t = 0; t < 5; t++)
        {
            KeyPair kp = jostleKeyPair("ML-KEM-768");
            PrivateKey bcPriv = bcImportPrivate(kp);
            KdfKtsSpec spec = ktsKdf3Spec(256, randomBytes(rng, 1 + rng.nextInt(32)), NISTObjectIdentifiers.id_sha256);
            SecretKeySpec cek = randomAesKey(rng, 16 + 8 * rng.nextInt(3));

            Cipher jslWrap = Cipher.getInstance("ML-KEM", JostleProvider.PROVIDER_NAME);
            jslWrap.init(Cipher.WRAP_MODE, kp.getPublic(), spec.forProvider(JostleProvider.PROVIDER_NAME));
            byte[] wrapped = jslWrap.wrap(cek);

            Cipher bcUnwrap = Cipher.getInstance("ML-KEM", BouncyCastleProvider.PROVIDER_NAME);
            bcUnwrap.init(Cipher.UNWRAP_MODE, bcPriv, spec.forProvider(BouncyCastleProvider.PROVIDER_NAME));
            Key recovered = bcUnwrap.unwrap(wrapped, "AES", Cipher.SECRET_KEY);

            Assertions.assertArrayEquals(cek.getEncoded(), recovered.getEncoded(),
                    "trial " + t + ": BC could not recover Jostle-wrapped CEK");
        }
    }

    @Test
    public void testCrossProvider_BCWrap_JostleUnwrap() throws Exception
    {
        SecureRandom rng = seededRandom("testCrossProvider_BCWrap_JostleUnwrap");

        for (int t = 0; t < 5; t++)
        {
            KeyPair kp = jostleKeyPair("ML-KEM-768");
            PublicKey bcPub = bcImportPublic(kp);
            KdfKtsSpec spec = ktsKdf3Spec(256, randomBytes(rng, 1 + rng.nextInt(32)), NISTObjectIdentifiers.id_sha256);
            SecretKeySpec cek = randomAesKey(rng, 16 + 8 * rng.nextInt(3));

            Cipher bcWrap = Cipher.getInstance("ML-KEM", BouncyCastleProvider.PROVIDER_NAME);
            bcWrap.init(Cipher.WRAP_MODE, bcPub, spec.forProvider(BouncyCastleProvider.PROVIDER_NAME));
            byte[] wrapped = bcWrap.wrap(cek);

            Cipher jslUnwrap = Cipher.getInstance("ML-KEM", JostleProvider.PROVIDER_NAME);
            jslUnwrap.init(Cipher.UNWRAP_MODE, kp.getPrivate(), spec.forProvider(JostleProvider.PROVIDER_NAME));
            Key recovered = jslUnwrap.unwrap(wrapped, "AES", Cipher.SECRET_KEY);

            Assertions.assertArrayEquals(cek.getEncoded(), recovered.getEncoded(),
                    "trial " + t + ": Jostle could not recover BC-wrapped CEK");
        }
    }

    private static PublicKey bcImportPublic(KeyPair jostleKeyPair) throws Exception
    {
        KeyFactory kf = KeyFactory.getInstance("ML-KEM", BouncyCastleProvider.PROVIDER_NAME);
        return kf.generatePublic(new X509EncodedKeySpec(jostleKeyPair.getPublic().getEncoded()));
    }

    private static PrivateKey bcImportPrivate(KeyPair jostleKeyPair) throws Exception
    {
        KeyFactory kf = KeyFactory.getInstance("ML-KEM", BouncyCastleProvider.PROVIDER_NAME);
        return kf.generatePrivate(new PKCS8EncodedKeySpec(jostleKeyPair.getPrivate().getEncoded()));
    }

    /**
     * BouncyCastle accepts a KEK size AES key wrap cannot take at init and refuses it at wrap with
     * IllegalBlockSizeException; ours refuses at init with InvalidAlgorithmParameterException, the exception init
     * declares. Both halves measured here.
     */
    @Test
    public void anUnsupportedKekSizeDivergesFromBouncyCastleOnPurpose() throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance("ML-KEM-768", BC).generateKeyPair();
        Cipher w = Cipher.getInstance("ML-KEM", BC);
        w.init(Cipher.WRAP_MODE, kp.getPublic(),
                // KTSParameterSpec is qualified where BouncyCastle's is meant: jostle's of that name is imported
                new org.bouncycastle.jcajce.spec.KTSParameterSpec.Builder("AESWRAP", 136).build());
        IllegalBlockSizeException theirs = Assertions.assertThrows(IllegalBlockSizeException.class,
                () -> w.wrap(new SecretKeySpec(new byte[16], "AES")));
        Assertions.assertEquals("unable to generate KTS secret: Key length not 128/192/256 bits.",
                theirs.getMessage());

        KeyPair ours = KeyPairGenerator.getInstance("ML-KEM-768", JSL).generateKeyPair();
        Cipher c = Cipher.getInstance("ML-KEM", JSL);
        InvalidAlgorithmParameterException e = Assertions.assertThrows(InvalidAlgorithmParameterException.class,
                () -> c.init(Cipher.WRAP_MODE, ours.getPublic(),
                        new KTSParameterSpec.Builder("AESWRAP", 136).build()));
        Assertions.assertEquals("unsupported AES-KW KEK size: 136 bits; AES key wrap takes 128, 192 or 256",
                e.getMessage());
    }

    /**
     * ENCRYPT_MODE and DECRYPT_MODE are refused with InvalidParameterException, the type Cipher.init declares for an
     * opmode a cipher does not support, on ours and on BouncyCastle. Each message is its own.
     */
    @Test
    public void encryptAndDecryptModesAreRefusedAsBouncyCastleRefusesThem() throws Exception
    {
        KeyPair ours = KeyPairGenerator.getInstance("ML-KEM-768", JSL).generateKeyPair();
        KeyPair theirs = KeyPairGenerator.getInstance("ML-KEM-768", BC).generateKeyPair();
        for (int mode : new int[]{Cipher.ENCRYPT_MODE, Cipher.DECRYPT_MODE})
        {
            Cipher jo = Cipher.getInstance("ML-KEM", JSL);
            InvalidParameterException e = Assertions.assertThrows(InvalidParameterException.class,
                    () -> jo.init(mode, ours.getPublic(), spec("AES-KWP").forProvider(JSL)));
            Assertions.assertEquals("ML-KEM KTS cipher only supports WRAP_MODE/UNWRAP_MODE", e.getMessage());

            Cipher bc = Cipher.getInstance("ML-KEM", BC);
            e = Assertions.assertThrows(InvalidParameterException.class,
                    () -> bc.init(mode, theirs.getPublic(), spec("AES-KWP").forProvider(BC)));
            Assertions.assertEquals("Cipher only valid for wrapping/unwrapping", e.getMessage());
        }
    }
}
