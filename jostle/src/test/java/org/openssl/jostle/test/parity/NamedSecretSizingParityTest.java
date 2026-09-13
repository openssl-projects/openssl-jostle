/**
 *   Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *   Licensed under the Apache License 2.0 (the "License"). You may not use
 *   this file except in compliance with the License.  You can obtain a copy
 *   in the file LICENSE in the source distribution or at
 *   https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 */

package org.openssl.jostle.test.parity;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.agreement.NamedSharedSecret;
import org.openssl.jostle.util.Arrays;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

/**
 * {@code generateSecret(String)} must produce the key the caller named, and the
 * same one BouncyCastle produces.
 *
 * <h2>The entries are listed HERE, not read from the production table</h2>
 *
 * <p>A test that enumerated {@code NamedSharedSecret}'s own map would compare
 * the table against itself and pass however wrong it was. The names below are
 * an independent list; each is driven through both providers and the outputs
 * compared. An entry dropped from the production table therefore FAILS — ours
 * would return the whole secret where BouncyCastle returns a sized key.
 *
 * <p>The table is a transcription of BouncyCastle's, so this is its drift
 * check: when BouncyCastle moves, these cells fail rather than the two
 * silently disagreeing.
 */
public class NamedSecretSizingParityTest
{
    private static Provider jsl;
    private static Provider bc;

    /** Sized entries: both providers must agree on bytes AND algorithm name. */
    private static final String[] SIZED = {
        "AES", "DES", "DESEDE", "BLOWFISH", "SM4",
        "2.16.840.1.101.3.4.1.1", "2.16.840.1.101.3.4.1.2", "2.16.840.1.101.3.4.1.3",
        "2.16.840.1.101.3.4.1.4", "2.16.840.1.101.3.4.1.5", "2.16.840.1.101.3.4.1.6",
        "2.16.840.1.101.3.4.1.7",
        "2.16.840.1.101.3.4.1.21", "2.16.840.1.101.3.4.1.22", "2.16.840.1.101.3.4.1.23",
        "2.16.840.1.101.3.4.1.24", "2.16.840.1.101.3.4.1.25", "2.16.840.1.101.3.4.1.26",
        "2.16.840.1.101.3.4.1.27",
        "2.16.840.1.101.3.4.1.41", "2.16.840.1.101.3.4.1.42", "2.16.840.1.101.3.4.1.43",
        "2.16.840.1.101.3.4.1.44", "2.16.840.1.101.3.4.1.45", "2.16.840.1.101.3.4.1.46",
        "2.16.840.1.101.3.4.1.47",
        "1.2.392.200011.61.1.1.3.2", "1.2.392.200011.61.1.1.3.3", "1.2.392.200011.61.1.1.3.4",
        "1.2.410.200004.7.1.1.1",
        "1.2.156.10197.1.104.2", "1.2.156.10197.1.104.8", "1.2.156.10197.1.104.9",
        "1.2.156.10197.1.104.11", "1.2.156.10197.1.104.12",
        "1.2.643.2.2.21", "1.2.643.2.2.13.0", "1.2.643.2.2.13.1",
        "1.2.840.113549.1.9.16.3.6", "1.2.840.113549.3.7", "1.3.14.3.2.7",
        "1.2.840.113549.2.7", "1.2.840.113549.2.9", "1.2.840.113549.2.10",
        "1.2.840.113549.2.11",
        "AES[256]", "AES[192]", "AES[128]", "DES[128]",
        // Case: the size lookup ignores it, the answered name does not.
        "des", "DESede", "aes" };

    /**
     * Names with NO size, which must yield the WHOLE secret under the name as
     * given. Each sits beside a sized sibling, so a family rule that over-fires
     * is caught: wrap-pad next to wrap, GMAC next to GCM, hmacWithSHA224 next
     * to its four sized siblings, camellia CBC next to camellia wrap.
     */
    private static final String[] WHOLE = {
        "2.16.840.1.101.3.4.1.8", "2.16.840.1.101.3.4.1.9",
        "2.16.840.1.101.3.4.1.28", "2.16.840.1.101.3.4.1.48",
        "1.2.840.113549.2.8",
        "1.2.392.200011.61.1.1.1.2",
        "CAMELLIA", "SEED", "ARIA",
        "NoSuchAlgorithmAnywhere" };

    @BeforeAll
    public static void setUp()
    {
        jsl = Security.getProvider(JostleProvider.PROVIDER_NAME);
        if (jsl == null)
        {
            jsl = new JostleProvider();
            Security.addProvider(jsl);
        }
        bc = Security.getProvider("BC");
        if (bc == null)
        {
            bc = new BouncyCastleProvider();
            Security.addProvider(bc);
        }
    }

    @Test
    public void sizedNamesAgreeWithBouncyCastleOnEveryCurve() throws Exception
    {
        List<String> bad = new ArrayList<String>();
        int cells = 0;
        for (String agreement : new String[] {"X448", "DH", "ECDH"})
        {
            Keys k = keys(agreement);
            for (String name : SIZED)
            {
                cells += compare(bad, agreement, k, name);
            }
        }
        // A cell count of zero reads exactly like agreement.
        Assertions.assertEquals(SIZED.length * 3, cells,
                "expected one cell per sized name per agreement");
        Assertions.assertTrue(bad.isEmpty(), "named-key sizing diverges from BouncyCastle:\n"
                + String.join("\n", bad));
    }

    @Test
    public void unsizedNamesYieldTheWholeSecretOnBothSides() throws Exception
    {
        List<String> bad = new ArrayList<String>();
        int cells = 0;
        for (String agreement : new String[] {"X448", "DH", "ECDH"})
        {
            Keys k = keys(agreement);
            byte[] raw = raw(jsl, agreement, k);
            for (String name : WHOLE)
            {
                cells += compare(bad, agreement, k, name);
                SecretKey ours = generate(jsl, agreement, k, name);
                if (ours.getEncoded().length != raw.length)
                {
                    bad.add(agreement + " " + name + ": ours sized it to "
                            + ours.getEncoded().length + ", expected the whole "
                            + raw.length + "-byte secret");
                }
            }
            Arrays.clear(raw);
        }
        Assertions.assertEquals(WHOLE.length * 3, cells,
                "expected one cell per unsized name per agreement");
        Assertions.assertTrue(bad.isEmpty(), "unsized-name handling diverges:\n"
                + String.join("\n", bad));
    }

    @Test
    public void aSecretTooShortForTheNamedKeyIsRefusedOnBothSides() throws Exception
    {
        // X25519 gives 32 bytes; HmacSHA512 wants 64.
        Keys k = keys("X25519");
        Class<?> ourType = refusalType(jsl, "X25519", k, "1.2.840.113549.2.11");
        Class<?> bcType = refusalType(bc, "X25519", k, "1.2.840.113549.2.11");
        Assertions.assertEquals(NoSuchAlgorithmException.class, bcType,
                "control: BouncyCastle must refuse a too-short named key");
        Assertions.assertEquals(bcType, ourType,
                "a secret too short for the named key must be refused as BouncyCastle does");
    }

    @Test
    public void malformedKeySizeBracketsAreRefusedAsBouncyCastleDoes() throws Exception
    {
        Keys k = keys("X448");
        for (String name : new String[] {"AES[456]", "AES[256", "AES[abc]", "AES[7]", "AES[0]"})
        {
            Class<?> bcType = refusalType(bc, "X448", k, name);
            Class<?> ourType = refusalType(jsl, "X448", k, name);
            Assertions.assertEquals(NoSuchAlgorithmException.class, bcType,
                    "control: BouncyCastle must refuse " + name);
            Assertions.assertEquals(bcType, ourType, "refusal type differs for " + name);
        }
    }

    /**
     * DH's TlsPremasterSecret strips the padding to the prime length.
     *
     * <p>Two branches, and the common one is the dangerous one. A secret with
     * no leading zero needs no trim — 255 draws in 256 — and an implementation
     * that clears the untrimmed array hands JSSE an all-zero premaster on
     * exactly those draws. So every draw asserts byte-equality with
     * BouncyCastle AND that the key is not all zero.
     *
     * <p>The trimming branch cannot be forced, only waited for. Its count is
     * reported: at zero the branch is UNWITNESSED and says so, rather than a
     * green result implying it was covered.
     */
    @Test
    public void dhTlsPremasterSecretMatchesBouncyCastleOnBothBranches() throws Exception
    {
        KeyPairGenerator g = KeyPairGenerator.getInstance("DH", jsl);
        g.initialize(2048);
        KeyFactory kf = KeyFactory.getInstance("DH", bc);
        int draws = 0;
        int trimmed = 0;
        List<String> bad = new ArrayList<String>();

        for (int i = 0; i < 64; i++)
        {
            KeyPair a = g.generateKeyPair();
            KeyPair b = g.generateKeyPair();
            Keys k = new Keys();
            k.ourPriv = a.getPrivate();
            k.ourPub = b.getPublic();
            k.bcPriv = kf.generatePrivate(new PKCS8EncodedKeySpec(a.getPrivate().getEncoded()));
            k.bcPub = kf.generatePublic(new X509EncodedKeySpec(b.getPublic().getEncoded()));

            byte[] raw = raw(jsl, "DH", k);
            byte[] ours = generate(jsl, "DH", k, "TlsPremasterSecret").getEncoded();
            byte[] theirs = generate(bc, "DH", k, "TlsPremasterSecret").getEncoded();
            draws++;
            if (raw[0] == 0)
            {
                trimmed++;
            }
            if (!Arrays.areEqual(ours, theirs))
            {
                bad.add("draw " + i + ": ours=" + ours.length + " bc=" + theirs.length
                        + " rawLeadingZero=" + (raw[0] == 0));
            }
            if (allZero(ours))
            {
                bad.add("draw " + i + ": the premaster secret is ALL ZERO");
            }
            Arrays.clear(raw);
        }

        System.out.println("DH TlsPremasterSecret: draws=" + draws + " needingTrim=" + trimmed
                + (trimmed == 0 ? "  [trimming branch UNWITNESSED this run]" : ""));
        Assertions.assertEquals(64, draws, "the draw loop did not run");
        Assertions.assertTrue(bad.isEmpty(), "TlsPremasterSecret diverges:\n"
                + String.join("\n", bad));
    }

    private static boolean allZero(byte[] b)
    {
        for (byte v : b)
        {
            if (v != 0)
            {
                return false;
            }
        }
        return true;
    }

    /**
     * The trimming branch, driven directly.
     *
     * <p>It fires on about one DH secret in 256, so no draw count witnesses it
     * without making the test flaky. These cells reach it deterministically.
     *
     * <p>The identity assertion is the load-bearing one: an untrimmed secret
     * must come back as the SAME array, because that is what tells a caller it
     * holds the original and must not clear it.
     */
    @Test
    public void trimmingLeadingZeroesIsDeterministicOnEveryShape()
    {
        byte[] none = {0x04, 0x00, 0x07};
        Assertions.assertSame(none, NamedSharedSecret.trimLeadingZeroes(none),
                "an untrimmed secret must come back as the same array, or a caller"
                        + " clearing the original will wipe the key it was given");

        byte[] one = {0x00, 0x04, 0x07};
        Assertions.assertArrayEquals(new byte[] {0x04, 0x07},
                NamedSharedSecret.trimLeadingZeroes(one));
        Assertions.assertArrayEquals(new byte[] {0x00, 0x04, 0x07}, one,
                "the input must not be modified in place");

        byte[] many = {0x00, 0x00, 0x00, 0x01};
        Assertions.assertArrayEquals(new byte[] {0x01},
                NamedSharedSecret.trimLeadingZeroes(many));

        byte[] allZero = {0x00, 0x00, 0x00};
        Assertions.assertArrayEquals(new byte[] {0x00},
                NamedSharedSecret.trimLeadingZeroes(allZero),
                "one byte is kept where BouncyCastle empties it; deliberate, and"
                        + " unreachable for a valid agreement");

        byte[] single = {0x00};
        Assertions.assertArrayEquals(new byte[] {0x00},
                NamedSharedSecret.trimLeadingZeroes(single));
    }

    // ------------------------------------------------------------------

    /** Returns 1 so callers can count cells actually driven. */
    private static int compare(List<String> bad, String agreement, Keys k, String name)
            throws Exception
    {
        // A name whose key is longer than this curve's secret is refused by
        // both; that is agreement. Only a disagreement is recorded.
        Class<?> ourRefusal = null;
        Class<?> bcRefusal = null;
        SecretKey ours = null;
        SecretKey theirs = null;
        try
        {
            ours = generate(jsl, agreement, k, name);
        }
        catch (Exception e)
        {
            ourRefusal = e.getClass();
        }
        try
        {
            theirs = generate(bc, agreement, k, name);
        }
        catch (Exception e)
        {
            bcRefusal = e.getClass();
        }
        if (ourRefusal != null || bcRefusal != null)
        {
            if (ourRefusal != bcRefusal)
            {
                bad.add(agreement + " " + name + ": refusal differs, ours="
                        + ourRefusal + " bc=" + bcRefusal);
            }
            return 1;
        }
        if (!Arrays.areEqual(ours.getEncoded(), theirs.getEncoded()))
        {
            bad.add(agreement + " " + name + ": bytes differ, ours="
                    + ours.getEncoded().length + " bc=" + theirs.getEncoded().length);
        }
        if (!ours.getAlgorithm().equals(theirs.getAlgorithm()))
        {
            bad.add(agreement + " " + name + ": algorithm differs, ours='"
                    + ours.getAlgorithm() + "' bc='" + theirs.getAlgorithm() + "'");
        }
        return 1;
    }

    private static Class<?> refusalType(Provider p, String agreement, Keys k, String name)
    {
        try
        {
            generate(p, agreement, k, name);
            return null;
        }
        catch (Exception e)
        {
            return e.getClass();
        }
    }

    private static SecretKey generate(Provider p, String agreement, Keys k, String name)
            throws Exception
    {
        KeyAgreement a = KeyAgreement.getInstance(agreement, p);
        a.init(p == jsl ? k.ourPriv : k.bcPriv);
        a.doPhase(p == jsl ? k.ourPub : k.bcPub, true);
        return a.generateSecret(name);
    }

    private static byte[] raw(Provider p, String agreement, Keys k) throws Exception
    {
        KeyAgreement a = KeyAgreement.getInstance(agreement, p);
        a.init(p == jsl ? k.ourPriv : k.bcPriv);
        a.doPhase(p == jsl ? k.ourPub : k.bcPub, true);
        return a.generateSecret();
    }

    private static final class Keys
    {
        PrivateKey ourPriv;
        PublicKey ourPub;
        PrivateKey bcPriv;
        PublicKey bcPub;
    }

    /** One key pair, shared by both providers through its encodings. */
    private static Keys keys(String agreement) throws Exception
    {
        String kpg = "ECDH".equals(agreement) ? "EC" : agreement;
        KeyPairGenerator g = KeyPairGenerator.getInstance(kpg, jsl);
        if ("DH".equals(kpg))
        {
            g.initialize(2048);
        }
        else if ("EC".equals(kpg))
        {
            g.initialize(new ECGenParameterSpec("P-521"));
        }
        KeyPair a = g.generateKeyPair();
        KeyPair b = g.generateKeyPair();
        KeyFactory kf = KeyFactory.getInstance(kpg, bc);
        Keys k = new Keys();
        k.ourPriv = a.getPrivate();
        k.ourPub = b.getPublic();
        k.bcPriv = kf.generatePrivate(new PKCS8EncodedKeySpec(a.getPrivate().getEncoded()));
        k.bcPub = kf.generatePublic(new X509EncodedKeySpec(b.getPublic().getEncoded()));
        return k;
    }
}
