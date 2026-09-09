package org.openssl.jostle.test.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;

/**
 * RFC 3211 password-based key wrap, the CMS PasswordRecipientInfo construction.
 * <p>
 * Byte equality against BouncyCastle is NOT asserted: 2.3.1 pads with random
 * bytes, so two conforming implementations differ by design. The instrument is
 * cross-unwrap in both directions plus equality of the wrapped LENGTH.
 */
public class RFC3211WrapTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
    private static final SecureRandom RANDOM = new SecureRandom();

    /** ours, BC's, KEK bytes, block size. */
    private static final String[][] FAMILIES = {
            {"AESRFC3211Wrap", "AESRFC3211WRAP", "16", "16"},
            {"DESedeRFC3211Wrap", "DESEDERFC3211WRAP", "24", "8"},
            {"CamelliaRFC3211Wrap", "CAMELLIARFC3211WRAP", "16", "16"},
    };

    /** 1 and 2 matter: below three bytes the check value covers PADDING. */
    private static final int[] CEK_LENGTHS = {1, 2, 3, 5, 8, 16, 24, 32, 40};

    @BeforeAll
    static void before()
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

    private static byte[] rand(int n)
    {
        byte[] b = new byte[n];
        RANDOM.nextBytes(b);
        return b;
    }

    private static byte[] wrap(String provider, String alg, byte[] kek, byte[] iv, byte[] cek)
            throws Exception
    {
        Cipher c = Cipher.getInstance(alg, provider);
        c.init(Cipher.WRAP_MODE, new SecretKeySpec(kek, alg), new IvParameterSpec(iv), RANDOM);
        return c.wrap(new SecretKeySpec(cek, "CEK"));
    }

    private static byte[] unwrap(String provider, String alg, byte[] kek, byte[] iv, byte[] blob)
            throws Exception
    {
        Cipher c = Cipher.getInstance(alg, provider);
        c.init(Cipher.UNWRAP_MODE, new SecretKeySpec(kek, alg), new IvParameterSpec(iv));
        return c.unwrap(blob, "1.2.840.113549.3.7", Cipher.SECRET_KEY).getEncoded();
    }

    @Test
    public void crossUnwrapsWithBouncyCastleBothDirectionsAtEveryCekLength() throws Exception
    {
        for (String[] f : FAMILIES)
        {
            for (int cekLen : CEK_LENGTHS)
            {
                byte[] kek = rand(Integer.parseInt(f[2]));
                byte[] iv = rand(Integer.parseInt(f[3]));
                byte[] cek = rand(cekLen);
                String tag = f[0] + " cek=" + cekLen;

                byte[] ours = wrap(JSL, f[0], kek, iv, cek);
                byte[] theirs = wrap(BC, f[1], kek, iv, cek);

                Assertions.assertEquals(theirs.length, ours.length, tag + ": wrapped length");
                Assertions.assertArrayEquals(cek, unwrap(BC, f[1], kek, iv, ours),
                        tag + ": BC could not unwrap ours");
                Assertions.assertArrayEquals(cek, unwrap(JSL, f[0], kek, iv, theirs),
                        tag + ": we could not unwrap BC's");
            }
        }
    }

    /**
     * 2.3.4: the IV is applied to the inner layer, so the same CEK under the
     * same KEK wraps differently each time. Fails for an implementation that
     * dropped the IV or the random padding; a round-trip test does not.
     */
    @Test
    public void sameCekAndKekWrapDifferentlyEachTime() throws Exception
    {
        for (String[] f : FAMILIES)
        {
            byte[] kek = rand(Integer.parseInt(f[2]));
            byte[] iv = rand(Integer.parseInt(f[3]));
            byte[] cek = rand(16);
            Assertions.assertFalse(Arrays.areEqual(wrap(JSL, f[0], kek, iv, cek),
                            wrap(JSL, f[0], kek, iv, cek)),
                    f[0] + ": two wraps of one CEK were identical");
        }
    }

    /**
     * bcpkix names the KEK after the wrap, so the SPI must accept it by length
     * and never by algorithm name. All three spellings must behave alike.
     */
    @Test
    public void kekIsAcceptedByLengthWhateverItsAlgorithmNameSays() throws Exception
    {
        for (String[] f : FAMILIES)
        {
            byte[] kek = rand(Integer.parseInt(f[2]));
            byte[] iv = rand(Integer.parseInt(f[3]));
            byte[] cek = rand(16);

            for (String keyName : new String[]{f[0], "AES", "1.2.840.113549.3.7"})
            {
                Cipher c = Cipher.getInstance(f[0], JSL);
                c.init(Cipher.WRAP_MODE, new SecretKeySpec(kek, keyName), new IvParameterSpec(iv), RANDOM);
                byte[] blob = c.wrap(new SecretKeySpec(cek, "CEK"));
                Assertions.assertArrayEquals(cek, unwrap(BC, f[1], kek, iv, blob),
                        f[0] + ": KEK named " + keyName + " produced a wrap BC rejected");
            }
        }
    }

    /**
     * A PBKDF2-derived 3DES KEK has arbitrary parity and is used as-is, so an
     * even-parity key must work. If it did not, every parity-clean test would
     * pass while real CMS messages failed.
     */
    @Test
    public void desedeAcceptsAKekWithEvenParity() throws Exception
    {
        byte[] kek = rand(24);
        for (int i = 0; i < kek.length; i++)
        {
            int b = kek[i] & 0xFE;
            kek[i] = (byte) (b | (Integer.bitCount(b) & 1));
        }
        for (byte b : kek)
        {
            Assertions.assertEquals(0, Integer.bitCount(b & 0xFF) & 1, "test set up a non-even byte");
        }

        byte[] iv = rand(8);
        byte[] cek = rand(16);
        Assertions.assertArrayEquals(cek,
                unwrap(BC, "DESEDERFC3211WRAP", kek, iv, wrap(JSL, "DESedeRFC3211Wrap", kek, iv, cek)));
    }

    /**
     * 2.3.2 1a and 1b are one answer — separating a bad count from a bad check
     * value tells an attacker which half of the KEK guess was wrong.
     */
    @Test
    public void everyKekValidityFailureGivesTheSameTypeAndMessage() throws Exception
    {
        byte[] kek = rand(16);
        byte[] iv = rand(16);
        byte[] cek = rand(16);
        byte[] good = wrap(JSL, "AESRFC3211Wrap", kek, iv, cek);

        byte[] wrongKek = rand(16);
        byte[] tampered = Arrays.clone(good);
        tampered[tampered.length - 1] ^= 0x01;
        byte[] tamperedHead = Arrays.clone(good);
        tamperedHead[0] ^= 0x01;

        String message = null;
        for (Object[] probe : new Object[][]{
                {"wrong KEK", wrongKek, good},
                {"tampered tail", kek, tampered},
                {"tampered head", kek, tamperedHead},
        })
        {
            InvalidKeyException e = Assertions.assertThrows(InvalidKeyException.class,
                    () -> unwrap(JSL, "AESRFC3211Wrap", (byte[]) probe[1], iv, (byte[]) probe[2]),
                    probe[0] + " must be refused");
            if (message == null)
            {
                message = e.getMessage();
            }
            Assertions.assertEquals(message, e.getMessage(),
                    probe[0] + ": message differs from the other KEK-validity failures");
        }
        Assertions.assertEquals("wrapped key corrupted", message);
    }

    /**
     * A structurally impossible length IS reported apart, and may be: the
     * caller supplied it and can already see it, so it leaks nothing.
     */
    @Test
    public void aStructurallyImpossibleLengthIsReportedSeparately() throws Exception
    {
        byte[] kek = rand(16);
        byte[] iv = rand(16);
        InvalidKeyException e = Assertions.assertThrows(InvalidKeyException.class,
                () -> unwrap(JSL, "AESRFC3211Wrap", kek, iv, new byte[16]));
        Assertions.assertEquals("input too short", e.getMessage());
    }

    /**
     * Divergence from BouncyCastle, pinned in both halves. BC accepts any IV
     * length at init and raises an unchecked IllegalArgumentException later at
     * wrap; Cipher.init declares InvalidAlgorithmParameterException for a
     * parameter the cipher cannot use, so we refuse at init.
     */
    @Test
    public void aWrongLengthIvIsRefusedAtInitWhereBouncyCastleDefersToWrap() throws Exception
    {
        byte[] kek = rand(16);
        byte[] cek = rand(16);

        Assertions.assertThrows(InvalidAlgorithmParameterException.class, () -> {
            Cipher c = Cipher.getInstance("AESRFC3211Wrap", JSL);
            c.init(Cipher.WRAP_MODE, new SecretKeySpec(kek, "AES"), new IvParameterSpec(new byte[8]), RANDOM);
        }, "an 8-byte IV must be refused at init for a 16-byte block");

        // BC's half of the divergence, measured live so a bcprov bump that
        // changes it fails here rather than going unnoticed.
        Cipher bcCipher = Cipher.getInstance("AESRFC3211WRAP", BC);
        bcCipher.init(Cipher.WRAP_MODE, new SecretKeySpec(kek, "AES"), new IvParameterSpec(new byte[8]), RANDOM);
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> bcCipher.wrap(new SecretKeySpec(cek, "CEK")),
                "BC is expected to accept the short IV at init and fail at wrap");

        // The companion: refusing more must not mean refusing everything.
        Assertions.assertNotNull(wrap(JSL, "AESRFC3211Wrap", kek, rand(16), cek),
                "a correct 16-byte IV must still work");
        Assertions.assertNotNull(wrap(JSL, "DESedeRFC3211Wrap", rand(24), rand(8), cek),
                "a correct 8-byte IV must still work for DESede");
    }

    @Test
    public void unwrapWithoutAnIvIsRefusedTyped()
    {
        Assertions.assertThrows(InvalidKeyException.class, () -> {
            Cipher c = Cipher.getInstance("AESRFC3211Wrap", JSL);
            c.init(Cipher.UNWRAP_MODE, new SecretKeySpec(rand(16), "AES"), RANDOM);
        }, "unwrap needs the sender's IV");
    }

    @Test
    public void aWrongLengthKekIsRefusedTyped()
    {
        for (int n : new int[]{0, 8, 15, 17, 23, 25, 33})
        {
            Assertions.assertThrows(InvalidKeyException.class, () -> {
                Cipher c = Cipher.getInstance("AESRFC3211Wrap", JSL);
                c.init(Cipher.WRAP_MODE, new SecretKeySpec(new byte[Math.max(n, 1)], "AES"),
                        new IvParameterSpec(new byte[16]), RANDOM);
            }, "AES KEK of " + n + " bytes must be refused");
        }
    }

    /** WRAP with no parameters generates an IV and reports it, as BC does. */
    @Test
    public void wrapWithNoParametersGeneratesAndReportsAnIv() throws Exception
    {
        byte[] kek = rand(16);
        Cipher c = Cipher.getInstance("AESRFC3211Wrap", JSL);
        c.init(Cipher.WRAP_MODE, new SecretKeySpec(kek, "AES"), RANDOM);
        byte[] iv = c.getIV();
        Assertions.assertNotNull(iv, "WRAP with no parameters must generate an IV");
        Assertions.assertEquals(16, iv.length);

        java.security.AlgorithmParameters ap = c.getParameters();
        Assertions.assertNotNull(ap, "the generated IV must be reportable");
        Assertions.assertArrayEquals(iv, ap.getParameterSpec(IvParameterSpec.class).getIV(),
                "getParameters() must carry the IV getIV() reports");

        // And that the reported IV is the one actually used: BC unwraps the
        // blob when given it explicitly. Asserting non-null alone would pass
        // for an SPI that reported one IV and wrapped under another.
        byte[] cek = rand(16);
        byte[] blob = c.wrap(new SecretKeySpec(cek, "CEK"));
        Assertions.assertArrayEquals(cek, unwrap(BC, "AESRFC3211WRAP", kek, iv, blob),
                "the reported IV is not the IV the wrap used");
    }

    /** Every registered RFC 3211 name is driven above. */
    @Test
    public void everyRegisteredRfc3211WrapIsCovered()
    {
        Provider provider = Security.getProvider(JSL);
        java.util.SortedSet<String> registered = new java.util.TreeSet<String>();
        for (Provider.Service s : provider.getServices())
        {
            if ("Cipher".equals(s.getType())
                    && s.getAlgorithm().toUpperCase(java.util.Locale.ROOT).contains("RFC3211"))
            {
                registered.add(s.getAlgorithm().toUpperCase(java.util.Locale.ROOT));
            }
        }
        java.util.SortedSet<String> covered = new java.util.TreeSet<String>();
        for (String[] f : FAMILIES)
        {
            covered.add(f[0].toUpperCase(java.util.Locale.ROOT));
        }
        Assertions.assertEquals(covered, registered,
                "registered RFC 3211 wraps and the set this class drives must match exactly");
    }
}
