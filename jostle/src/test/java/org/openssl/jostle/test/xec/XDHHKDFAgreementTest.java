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

package org.openssl.jostle.test.xec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.spec.UserKeyingMaterialSpec;
import org.openssl.jostle.util.Arrays;

import javax.crypto.KeyAgreement;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * RFC 8418 HKDF key agreement for X25519 / X448 — JSL against BouncyCastle.
 *
 * <p>The contract this file pins is byte-equality with BouncyCastle in every
 * UKM and salt shape, because the SPI is a pass-through: the HKDF {@code info}
 * is the UKM verbatim and the salt is whatever the caller put in the spec.
 *
 * <p><b>Why the salt is a caller value and not the UKM.</b> RFC 8418 §2.2 says
 * {@code salt = ukm}. No implementation applies that internally — BouncyCastle
 * takes the salt as an independent spec field and its CMS layer never sets one,
 * so it derives with HashLen zeros even when a UKM is present, and its own
 * RFC-named test passes a UKM with no salt. Applying the rule inside the SPI
 * would make every UKM-bearing message differ from the only other
 * implementation. A caller wanting the RFC's derivation passes the same bytes
 * as both, which {@link #saltEqualToTheUkmIsTheOnePairBothReadingsShare} pins.
 *
 * <p>Falsification, measured 2026-09-13 over the 72-cell matrix. Ignoring the
 * caller's salt fails exactly the distinct-salt and salt-equals-UKM cells (36)
 * and leaves the no-salt and empty-salt cells green. Applying {@code salt =
 * ukm} inside the SPI fails the no-salt, empty-salt and distinct-salt cells
 * (54) and leaves salt-equals-UKM green. The two failure sets differ, so a
 * green run discriminates both mistakes rather than one.
 */
public class XDHHKDFAgreementTest
{
    private static final SecureRandom RANDOM = new SecureRandom();

    /** The three RFC 8418 names, BouncyCastle's spelling, and their digests. */
    private static final String[][] SCHEMES = {
            {"XDHwithSHA256HKDF", "1.2.840.113549.1.9.16.3.19"},
            {"XDHwithSHA384HKDF", "1.2.840.113549.1.9.16.3.20"},
            {"XDHwithSHA512HKDF", "1.2.840.113549.1.9.16.3.21"},
    };

    private static final String[] CURVES = {"X25519", "X448"};

    /** CMS wrap OIDs a KeyAgreeRecipientInfo names: aes128-wrap, aes256-wrap. */
    private static final String AES128_WRAP = "2.16.840.1.101.3.4.1.5";
    private static final String AES256_WRAP = "2.16.840.1.101.3.4.1.45";

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    // ----- agreement -----

    /**
     * Every scheme, both curves, both directions, and all four salt shapes,
     * against BouncyCastle. The UKM and salt are drawn ONCE per cell and handed
     * to both providers — two constructions of "the same" value would measure
     * the helper rather than the derivation.
     */
    @Test
    public void agreesWithBouncyCastleAcrossEveryUkmAndSaltShape() throws Exception
    {
        for (String curve : CURVES)
        {
            KeyPair a = generate(curve);
            KeyPair b = generate(curve);

            for (String[] scheme : SCHEMES)
            {
                byte[] ukm = randomBytes(1 + RANDOM.nextInt(64));
                byte[] distinctSalt = randomBytes(1 + RANDOM.nextInt(64));

                byte[][] salts = {null, distinctSalt, ukm, new byte[0]};
                String[] saltNames = {"no salt", "distinct salt", "salt = ukm", "empty salt"};

                for (int i = 0; i != salts.length; i++)
                {
                    for (String out : new String[]{AES128_WRAP, AES256_WRAP})
                    {
                        String what = curve + " " + scheme[0] + " " + saltNames[i] + " out=" + out;

                        // Our private half against their public, and the reverse.
                        byte[] ours = derive(jsl(), scheme[0], a.getPrivate(), b.getPublic(),
                                ukm, salts[i], out);
                        byte[] theirs = derive(bc(), scheme[0], a.getPrivate(), b.getPublic(),
                                ukm, salts[i], out);
                        Assertions.assertTrue(Arrays.areEqual(ours, theirs),
                                what + ": JSL and BC must derive the same KEK");

                        byte[] oursRev = derive(jsl(), scheme[0], b.getPrivate(), a.getPublic(),
                                ukm, salts[i], out);
                        byte[] theirsRev = derive(bc(), scheme[0], b.getPrivate(), a.getPublic(),
                                ukm, salts[i], out);
                        Assertions.assertTrue(Arrays.areEqual(oursRev, theirsRev),
                                what + " (reversed): JSL and BC must derive the same KEK");

                        // The agreement itself must still agree end to end.
                        Assertions.assertTrue(Arrays.areEqual(ours, oursRev),
                                what + ": both parties must reach the same KEK");
                    }
                }
            }
        }
    }

    /**
     * BouncyCastle's own RFC-named vector: the UKM {@code beeffeed} with NO
     * salt. Pinned as a literal because it is the shape BC's
     * {@code testRFC8418HKDFAgreements} exercises, so a change on either side
     * that moves it is worth a red test rather than a silent divergence.
     * Named form only — the raw form is sealed (see
     * {@link #rawSharedSecretIsRefused}).
     */
    @Test
    public void agreesWithBouncyCastleOnItsOwnRfcNamedVector() throws Exception
    {
        byte[] ukm = {(byte) 0xbe, (byte) 0xef, (byte) 0xfe, (byte) 0xed};

        for (String curve : CURVES)
        {
            KeyPair a = generate(curve);
            KeyPair b = generate(curve);
            for (String[] scheme : SCHEMES)
            {
                byte[] ours = derive(jsl(), scheme[0], a.getPrivate(), b.getPublic(), ukm, null, AES256_WRAP);
                byte[] theirs = derive(bc(), scheme[0], a.getPrivate(), b.getPublic(), ukm, null, AES256_WRAP);
                Assertions.assertTrue(Arrays.areEqual(ours, theirs),
                        curve + " " + scheme[0] + ": BC's own RFC 8418 vector must agree");
            }
        }
    }

    /**
     * No spec at all — {@code init(priv)} with neither UKM nor salt. The SPI
     * clears both on that path, so the derivation is empty info and HashLen
     * zeros, and BouncyCastle does the same. Covered because it is the shape a
     * caller reaches by omission rather than by choice, and the one where a
     * stale UKM left over from a previous init would show. Named form only —
     * the raw form is sealed (see {@link #rawSharedSecretIsRefused}).
     */
    @Test
    public void agreesWithBouncyCastleWithNoSpecAtAll() throws Exception
    {
        for (String curve : CURVES)
        {
            KeyPair a = generate(curve);
            KeyPair b = generate(curve);

            for (String[] scheme : SCHEMES)
            {
                byte[] ours = deriveNoSpec(jsl(), scheme[0], a.getPrivate(), b.getPublic(), AES256_WRAP);
                byte[] theirs = deriveNoSpec(bc(), scheme[0], a.getPrivate(), b.getPublic(), AES256_WRAP);
                Assertions.assertTrue(Arrays.areEqual(ours, theirs),
                        curve + " " + scheme[0] + " no spec: JSL and BC must derive the same KEK");
            }
        }
    }

    /**
     * The raw forms are sealed — a KDF agreement yields keys only through
     * {@code generateSecret(String)}.
     */
    @Test
    public void rawSharedSecretIsRefused() throws Exception
    {
        for (String[] scheme : SCHEMES)
        {
            Assertions.assertThrows(UnsupportedOperationException.class, () ->
            {
                KeyPair a = generate("X25519");
                KeyPair b = generate("X25519");
                KeyAgreement ka = KeyAgreement.getInstance(scheme[0], jsl());
                ka.init(a.getPrivate(), new UserKeyingMaterialSpec(randomBytes(16)));
                ka.doPhase(b.getPublic(), true);
                ka.generateSecret();
            }, scheme[0] + ": raw generateSecret() must be refused");

            Assertions.assertThrows(UnsupportedOperationException.class, () ->
            {
                KeyPair a = generate("X25519");
                KeyPair b = generate("X25519");
                KeyAgreement ka = KeyAgreement.getInstance(scheme[0], jsl());
                ka.init(a.getPrivate(), new UserKeyingMaterialSpec(randomBytes(16)));
                ka.doPhase(b.getPublic(), true);
                try
                {
                    ka.generateSecret(new byte[128], 0);
                }
                catch (javax.crypto.ShortBufferException e)
                {
                    throw new AssertionError(e);
                }
            }, scheme[0] + ": raw generateSecret(byte[],int) must be refused");
        }
    }

    /**
     * A spec-less init must not inherit the previous init's UKM — the SPI
     * clears both fields on that path, and without this the cell above would
     * pass on a stale value that happened to match.
     */
    @Test
    public void aSpecLessInitDiscardsTheEarlierUkm() throws Exception
    {
        KeyPair a = generate("X25519");
        KeyPair b = generate("X25519");

        KeyFactory kf = KeyFactory.getInstance("X25519", jsl());
        PrivateKey priv = kf.generatePrivate(new PKCS8EncodedKeySpec(a.getPrivate().getEncoded()));
        PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(b.getPublic().getEncoded()));

        KeyAgreement ka = KeyAgreement.getInstance("XDHwithSHA256HKDF", jsl());
        ka.init(priv, new UserKeyingMaterialSpec(randomBytes(16)));
        ka.doPhase(pub, true);
        byte[] withUkm = ka.generateSecret(AES256_WRAP).getEncoded();

        ka.init(priv);
        ka.doPhase(pub, true);
        byte[] afterReinit = ka.generateSecret(AES256_WRAP).getEncoded();

        byte[] noSpecFresh = deriveNoSpec(jsl(), "XDHwithSHA256HKDF",
                a.getPrivate(), b.getPublic(), AES256_WRAP);

        Assertions.assertFalse(Arrays.areEqual(withUkm, afterReinit),
                "a spec-less re-init must not keep the earlier ukm");
        Assertions.assertTrue(Arrays.areEqual(afterReinit, noSpecFresh),
                "a spec-less re-init must derive as a fresh spec-less instance");
    }

    // ----- differentiators -----

    /** The salt must reach the extract phase: two salts, two KEKs. */
    @Test
    public void theSaltChangesTheDerivedKey() throws Exception
    {
        KeyPair a = generate("X25519");
        KeyPair b = generate("X25519");
        byte[] ukm = randomBytes(16);
        byte[] salt1 = randomBytes(16);
        byte[] salt2 = randomBytes(16);

        byte[] none = derive(jsl(), "XDHwithSHA256HKDF", a.getPrivate(), b.getPublic(), ukm, null, AES256_WRAP);
        byte[] one = derive(jsl(), "XDHwithSHA256HKDF", a.getPrivate(), b.getPublic(), ukm, salt1, AES256_WRAP);
        byte[] two = derive(jsl(), "XDHwithSHA256HKDF", a.getPrivate(), b.getPublic(), ukm, salt2, AES256_WRAP);

        Assertions.assertFalse(Arrays.areEqual(none, one), "a salt must change the KEK");
        Assertions.assertFalse(Arrays.areEqual(one, two), "a different salt must change the KEK");
    }

    /** The UKM must reach the expand phase as the info: two UKMs, two KEKs. */
    @Test
    public void theUkmChangesTheDerivedKey() throws Exception
    {
        KeyPair a = generate("X25519");
        KeyPair b = generate("X25519");
        byte[] salt = randomBytes(16);

        byte[] one = derive(jsl(), "XDHwithSHA256HKDF", a.getPrivate(), b.getPublic(), randomBytes(16), salt, AES256_WRAP);
        byte[] two = derive(jsl(), "XDHwithSHA256HKDF", a.getPrivate(), b.getPublic(), randomBytes(16), salt, AES256_WRAP);

        Assertions.assertFalse(Arrays.areEqual(one, two), "a different ukm must change the KEK");
    }

    /** Each scheme's digest must actually be used. */
    @Test
    public void eachSchemeDigestGivesADifferentKey() throws Exception
    {
        KeyPair a = generate("X25519");
        KeyPair b = generate("X25519");
        byte[] ukm = randomBytes(16);

        byte[] sha256 = derive(jsl(), "XDHwithSHA256HKDF", a.getPrivate(), b.getPublic(), ukm, null, AES256_WRAP);
        byte[] sha384 = derive(jsl(), "XDHwithSHA384HKDF", a.getPrivate(), b.getPublic(), ukm, null, AES256_WRAP);
        byte[] sha512 = derive(jsl(), "XDHwithSHA512HKDF", a.getPrivate(), b.getPublic(), ukm, null, AES256_WRAP);

        Assertions.assertFalse(Arrays.areEqual(sha256, sha384), "SHA-256 and SHA-384 must differ");
        Assertions.assertFalse(Arrays.areEqual(sha384, sha512), "SHA-384 and SHA-512 must differ");
        Assertions.assertFalse(Arrays.areEqual(sha256, sha512), "SHA-256 and SHA-512 must differ");
    }

    // ----- the two readings of the RFC -----

    /**
     * {@code salt = ukm} is the single input on which the pass-through reading
     * and RFC 8418 §2.2's reading agree, so it is the one cell that stays
     * meaningful whichever way the SPI is built — and BouncyCastle agrees there
     * too. If the SPI is ever changed to apply the RFC rule internally, this
     * cell is what still holds while the other three shapes move.
     */
    @Test
    public void saltEqualToTheUkmIsTheOnePairBothReadingsShare() throws Exception
    {
        KeyPair a = generate("X25519");
        KeyPair b = generate("X25519");
        byte[] ukm = randomBytes(24);

        byte[] ours = derive(jsl(), "XDHwithSHA256HKDF", a.getPrivate(), b.getPublic(), ukm, ukm, AES256_WRAP);
        byte[] theirs = derive(bc(), "XDHwithSHA256HKDF", a.getPrivate(), b.getPublic(), ukm, ukm, AES256_WRAP);

        Assertions.assertTrue(Arrays.areEqual(ours, theirs),
                "salt = ukm must agree with BC — it is the RFC's own derivation");

        byte[] noSalt = derive(jsl(), "XDHwithSHA256HKDF", a.getPrivate(), b.getPublic(), ukm, null, AES256_WRAP);
        Assertions.assertFalse(Arrays.areEqual(ours, noSalt),
                "the RFC derivation must differ from the salt-less one, or this cell proves nothing");
    }

    /** RFC 5869's default: an empty salt is HashLen zeros, exactly as none. */
    @Test
    public void anEmptySaltIsTheSameAsNoSalt() throws Exception
    {
        KeyPair a = generate("X25519");
        KeyPair b = generate("X25519");
        byte[] ukm = randomBytes(16);

        byte[] none = derive(jsl(), "XDHwithSHA256HKDF", a.getPrivate(), b.getPublic(), ukm, null, AES256_WRAP);
        byte[] empty = derive(jsl(), "XDHwithSHA256HKDF", a.getPrivate(), b.getPublic(), ukm, new byte[0], AES256_WRAP);

        Assertions.assertTrue(Arrays.areEqual(none, empty),
                "an empty salt must derive as RFC 5869's HashLen zeros, i.e. as no salt");
    }

    // ----- registration -----

    /** Each scheme OID must resolve, bare and OID-prefixed, to a working SPI. */
    @Test
    public void everySchemeOidResolves() throws Exception
    {
        for (String[] scheme : SCHEMES)
        {
            Assertions.assertNotNull(KeyAgreement.getInstance(scheme[0], jsl()),
                    scheme[0] + " must be registered");
            Assertions.assertNotNull(KeyAgreement.getInstance(scheme[1], jsl()),
                    scheme[1] + " must resolve as an alias of " + scheme[0]);
            Assertions.assertNotNull(KeyAgreement.getInstance("OID." + scheme[1], jsl()),
                    "OID." + scheme[1] + " must resolve too");
        }
    }

    /** The OID and the name must be the same SPI, not two configurations. */
    @Test
    public void theOidAndTheNameDeriveTheSameKey() throws Exception
    {
        KeyPair a = generate("X25519");
        KeyPair b = generate("X25519");
        byte[] ukm = randomBytes(16);

        for (String[] scheme : SCHEMES)
        {
            byte[] byName = derive(jsl(), scheme[0], a.getPrivate(), b.getPublic(), ukm, null, AES256_WRAP);
            byte[] byOid = derive(jsl(), scheme[1], a.getPrivate(), b.getPublic(), ukm, null, AES256_WRAP);
            Assertions.assertTrue(Arrays.areEqual(byName, byOid),
                    scheme[1] + " must derive as " + scheme[0]);
        }
    }

    /** An unknown wrap algorithm is refused by name, per the JCE contract. */
    @Test
    public void anUnknownWrapAlgorithmIsRefused() throws Exception
    {
        KeyPair a = generate("X25519");
        KeyPair b = generate("X25519");

        KeyAgreement ka = KeyAgreement.getInstance("XDHwithSHA256HKDF", jsl());
        ka.init(a.getPrivate(), new UserKeyingMaterialSpec(randomBytes(8)));
        ka.doPhase(b.getPublic(), true);

        Assertions.assertThrows(NoSuchAlgorithmException.class,
                () -> ka.generateSecret("1.2.3.4.5.6.7.8"),
                "an unknown wrap OID must be refused with NoSuchAlgorithmException");
    }

    // ----- helpers -----

    private static Provider jsl()
    {
        return Security.getProvider(JostleProvider.PROVIDER_NAME);
    }

    private static Provider bc()
    {
        return Security.getProvider("BC");
    }

    private static byte[] randomBytes(int len)
    {
        byte[] b = new byte[len];
        RANDOM.nextBytes(b);
        return b;
    }

    private static KeyPair generate(String curve) throws Exception
    {
        return KeyPairGenerator.getInstance(curve, jsl()).generateKeyPair();
    }

    /**
     * Derive through {@code provider}, re-decoding both key halves through that
     * provider's own KeyFactory first — the sanctioned crossing, and what a real
     * CMS peer does anyway, since it holds an SPKI rather than a key object.
     */
    private static byte[] derive(Provider provider, String alg, PrivateKey priv, PublicKey pub,
            byte[] ukm, byte[] salt, String wrapOid) throws Exception
    {
        String curve = priv.getAlgorithm();
        KeyFactory kf = KeyFactory.getInstance(curve, provider);
        PrivateKey ourPriv = kf.generatePrivate(new PKCS8EncodedKeySpec(priv.getEncoded()));
        PublicKey theirPub = kf.generatePublic(new X509EncodedKeySpec(pub.getEncoded()));

        KeyAgreement ka = KeyAgreement.getInstance(alg, provider);
        ka.init(ourPriv, spec(provider, ukm, salt));
        ka.doPhase(theirPub, true);
        if (wrapOid == null)
        {
            return ka.generateSecret();
        }
        return ka.generateSecret(wrapOid).getEncoded();
    }

    /** As {@link #derive}, with no parameter spec supplied at all. */
    private static byte[] deriveNoSpec(Provider provider, String alg, PrivateKey priv,
            PublicKey pub, String wrapOid) throws Exception
    {
        String curve = priv.getAlgorithm();
        KeyFactory kf = KeyFactory.getInstance(curve, provider);
        PrivateKey ourPriv = kf.generatePrivate(new PKCS8EncodedKeySpec(priv.getEncoded()));
        PublicKey theirPub = kf.generatePublic(new X509EncodedKeySpec(pub.getEncoded()));

        KeyAgreement ka = KeyAgreement.getInstance(alg, provider);
        ka.init(ourPriv);
        ka.doPhase(theirPub, true);
        if (wrapOid == null)
        {
            return ka.generateSecret();
        }
        return ka.generateSecret(wrapOid).getEncoded();
    }

    /**
     * Build the provider's own spec type. BouncyCastle's is constructed
     * reflectively — the test tree compiles against bcprov, but keeping the two
     * spellings in one place is what makes "the same ukm and salt reached both
     * providers" checkable at a glance.
     */
    private static AlgorithmParameterSpec spec(Provider provider, byte[] ukm, byte[] salt)
            throws Exception
    {
        if (provider == bc())
        {
            Class<?> c = Class.forName("org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec");
            if (salt == null)
            {
                return (AlgorithmParameterSpec) c.getConstructor(byte[].class).newInstance(ukm);
            }
            return (AlgorithmParameterSpec) c.getConstructor(byte[].class, byte[].class)
                    .newInstance(ukm, salt);
        }
        if (salt == null)
        {
            return new UserKeyingMaterialSpec(ukm);
        }
        return new UserKeyingMaterialSpec(ukm, salt);
    }
}
