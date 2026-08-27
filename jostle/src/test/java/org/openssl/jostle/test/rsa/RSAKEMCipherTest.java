/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.rsa;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;

/**
 * RSA-KEM key transport (ISO 18033-2 / RFC 9690) through {@code RSA-KTS-KEM-KWS}.
 *
 * <h2>What makes this interoperate</h2>
 *
 * OpenSSL's RSASVE returns the encapsulated value zero-padded to the full
 * modulus length, which is exactly BouncyCastle's
 * {@code R = asUnsignedByteArray(modLen, r)} - measured on mainline and both
 * FIPS modules ({@code fips-c-review/probes/rsakem_probe.c}). Given the same
 * KDF and wrap parameters the two providers therefore produce the same bytes,
 * and that is what the agreement tests below pin.
 *
 * <p>The KEM operation name is hard-coded to {@code RSASVE} in
 * {@code RSAKEMCipherSpi} because the CMVP-validated 3.1.2 module REQUIRES it -
 * without it, encapsulation fails there and fails mutely, while mainline and
 * 3.5.7 default to it and work. No test here can see that difference (both
 * behave identically once the name is set); it is pinned by the probe and by
 * the FIPS subclass running the whole contract against the module.
 *
 * <p>Subclassed by {@code FIPSRSAKEMCipherTest}, which re-runs everything
 * against the FIPS interface library and lib ctx.
 */
public class RSAKEMCipherTest
{
    protected static final String XFORM = "RSA-KTS-KEM-KWS";

    /** ISO 18033-2 id-kem-rsa, as named in CMS KEMRecipientInfo.kem. */
    protected static final String ID_KEM_RSA = "1.0.18033.2.2.4";
    /** PKCS-arc id-rsa-KEM (RFC 9690 s3.3). */
    protected static final String ID_RSA_KEM = "1.2.840.113549.1.9.16.3.14";

    protected static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    private static final SecureRandom RANDOM = new SecureRandom();

    /** One 2048-bit keypair per JVM - RSA keygen is slow and none of these tests need a fresh one. */
    private static KeyPair sharedKeyPair;

    /**
     * The KDF3 digests BouncyCastle will accept. BC's
     * {@code KdfUtil.isSupportedKdf} allows SHA-256, SHA-512, SHAKE-128 and
     * SHAKE-256 - notably NOT SHA-384 - so an agreement test can only use
     * these. Measured, not assumed: asking BC for SHA-384 raises
     * {@code InvalidKeyException: unrecognized digest OID: 2.16.840.1.101.3.4.2.2}.
     */
    protected static final ASN1ObjectIdentifier[] BC_SUPPORTED_KDF3_DIGESTS = {
            NISTObjectIdentifiers.id_sha256,
            NISTObjectIdentifiers.id_sha512,
    };

    protected static SecureRandom seededRandom(String testName) throws Exception
    {
        long seed = RANDOM.nextLong();
        System.out.println(testName + " seed=" + seed);
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(seed);
        return sr;
    }

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    /** Overridden by the FIPS subclass. */
    protected String providerName()
    {
        return JostleProvider.PROVIDER_NAME;
    }

    /**
     * The keypair every test wraps to. Generated through THIS test's provider so
     * the private half belongs to the library under test - RSA private keys do
     * not cross the JSL/JSLFIPS boundary.
     */
    protected KeyPair keyPair() throws Exception
    {
        if (sharedKeyPair == null || !ownsKey(sharedKeyPair))
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", providerName());
            kpg.initialize(2048);
            sharedKeyPair = kpg.generateKeyPair();
        }
        return sharedKeyPair;
    }

    private boolean ownsKey(KeyPair kp) throws Exception
    {
        // Cheap probe: an UNWRAP init refuses a private key from the other
        // provider, so a successful init means the cached pair is ours.
        try
        {
            Cipher c = Cipher.getInstance(XFORM, providerName());
            c.init(Cipher.UNWRAP_MODE, kp.getPrivate(), kdf3Spec(256, null, NISTObjectIdentifiers.id_sha256));
            return true;
        }
        catch (InvalidKeyException e)
        {
            return false;
        }
    }

    protected static KTSParameterSpec kdf3Spec(int keyBits, byte[] otherInfo, ASN1ObjectIdentifier digestOid)
    {
        return new KTSParameterSpec.Builder("AESWRAP", keyBits, otherInfo)
                .withKdfAlgorithm(new AlgorithmIdentifier(
                        X9ObjectIdentifiers.id_kdf_kdf3, new AlgorithmIdentifier(digestOid)))
                .build();
    }


    // -----------------------------------------------------------------
    // Agreement with BouncyCastle, both directions.
    // -----------------------------------------------------------------

    /**
     * Jostle wraps, BC unwraps - across every KEK size and KDF digest, with a
     * random CEK each trial. A wrong KDF, a wrong secret encoding or a wrong
     * output layout all surface here as BC failing to recover the CEK.
     */
    @Test
    public void jostleWrapsBouncyCastleUnwraps() throws Exception
    {
        SecureRandom sr = seededRandom("jostleWrapsBouncyCastleUnwraps");
        KeyPair kp = keyPair();

        for (int kekBits : new int[]{128, 192, 256})
        {
            // SHA-384 is deliberately absent: BouncyCastle's KdfUtil accepts only
            // SHA-256, SHA-512, SHAKE-128 and SHAKE-256 as a KDF3 digest and
            // refuses SHA-384 with "unrecognized digest OID". Jostle accepts it
            // (see sha384KdfWorksButBouncyCastleCannotReadIt) - do not "fix"
            // this loop by adding it back, the failure would be BC's.
            for (ASN1ObjectIdentifier dig : BC_SUPPORTED_KDF3_DIGESTS)
            {
                byte[] otherInfo = randomBytes(sr, sr.nextInt(24));
                KTSParameterSpec spec = kdf3Spec(kekBits, otherInfo, dig);
                SecretKey cek = randomCek(sr);

                byte[] wrapped = wrap(providerName(), kp, spec, cek);
                Key back = unwrap(BC, kp, spec, wrapped);

                Assertions.assertArrayEquals(cek.getEncoded(), back.getEncoded(),
                        "kek=" + kekBits + " digest=" + dig + ": BC must recover the CEK");
            }
        }
    }

    /** The reverse direction - a different code path on both sides. */
    @Test
    public void bouncyCastleWrapsJostleUnwraps() throws Exception
    {
        SecureRandom sr = seededRandom("bouncyCastleWrapsJostleUnwraps");
        KeyPair kp = keyPair();

        for (int kekBits : new int[]{128, 192, 256})
        {
            // SHA-384 is deliberately absent: BouncyCastle's KdfUtil accepts only
            // SHA-256, SHA-512, SHAKE-128 and SHAKE-256 as a KDF3 digest and
            // refuses SHA-384 with "unrecognized digest OID". Jostle accepts it
            // (see sha384KdfWorksButBouncyCastleCannotReadIt) - do not "fix"
            // this loop by adding it back, the failure would be BC's.
            for (ASN1ObjectIdentifier dig : BC_SUPPORTED_KDF3_DIGESTS)
            {
                byte[] otherInfo = randomBytes(sr, sr.nextInt(24));
                KTSParameterSpec spec = kdf3Spec(kekBits, otherInfo, dig);
                SecretKey cek = randomCek(sr);

                byte[] wrapped = wrap(BC, kp, spec, cek);
                Key back = unwrap(providerName(), kp, spec, wrapped);

                Assertions.assertArrayEquals(cek.getEncoded(), back.getEncoded(),
                        "kek=" + kekBits + " digest=" + dig + ": Jostle must recover the CEK");
            }
        }
    }

    /**
     * {@code withNoKdf()} - the shared secret used directly as the KEK. A
     * separate branch in both providers, and one where BC's WrapUtil clamps to
     * the secret length while the KDF path does not.
     */
    @Test
    public void noKdfAgreesWithBouncyCastle() throws Exception
    {
        SecureRandom sr = seededRandom("noKdfAgreesWithBouncyCastle");
        KeyPair kp = keyPair();

        for (int kekBits : new int[]{128, 192, 256})
        {
            KTSParameterSpec spec = new KTSParameterSpec.Builder("AESWRAP", kekBits)
                    .withNoKdf().build();
            SecretKey cek = randomCek(sr);

            Assertions.assertArrayEquals(cek.getEncoded(),
                    unwrap(BC, kp, spec, wrap(providerName(), kp, spec, cek)).getEncoded(),
                    "kek=" + kekBits + ": Jostle wrap -> BC unwrap with no KDF");
            Assertions.assertArrayEquals(cek.getEncoded(),
                    unwrap(providerName(), kp, spec, wrap(BC, kp, spec, cek)).getEncoded(),
                    "kek=" + kekBits + ": BC wrap -> Jostle unwrap with no KDF");
        }
    }

    /**
     * otherInfo is fed to the KDF, so changing it must change the KEK - and
     * both providers must change it the same way. Without this, an
     * implementation that silently dropped otherInfo would still round-trip
     * against itself and still agree with BC on the empty case.
     */
    @Test
    public void otherInfoIsHonouredAndAgrees() throws Exception
    {
        SecureRandom sr = seededRandom("otherInfoIsHonouredAndAgrees");
        KeyPair kp = keyPair();
        SecretKey cek = randomCek(sr);

        byte[] infoA = randomBytes(sr, 20);
        byte[] infoB = randomBytes(sr, 20);

        KTSParameterSpec specA = kdf3Spec(256, infoA, NISTObjectIdentifiers.id_sha256);
        KTSParameterSpec specB = kdf3Spec(256, infoB, NISTObjectIdentifiers.id_sha256);

        // Cross-decoding with the wrong otherInfo must fail: a different KEK
        // means the AES-KW integrity check rejects.
        byte[] wrappedA = wrap(providerName(), kp, specA, cek);
        Assertions.assertArrayEquals(cek.getEncoded(),
                unwrap(BC, kp, specA, wrappedA).getEncoded(), "matching otherInfo must recover");
        Assertions.assertThrows(InvalidKeyException.class,
                () -> unwrap(providerName(), kp, specB, wrappedA),
                "a different otherInfo must not unwrap");
    }

    /**
     * SHA-384 works as a KDF3 digest through Jostle, and BouncyCastle cannot
     * read the result. Both halves are asserted deliberately: the first so the
     * capability is not merely registered-but-unusable, the second so the
     * interop limit is recorded as a measured fact rather than folklore. A
     * caller choosing SHA-384 is choosing a wrap no BC peer can open.
     */
    @Test
    public void sha384KdfWorksButBouncyCastleCannotReadIt() throws Exception
    {
        SecureRandom sr = seededRandom("sha384KdfWorksButBouncyCastleCannotReadIt");
        KeyPair kp = keyPair();
        KTSParameterSpec spec = kdf3Spec(256, null, NISTObjectIdentifiers.id_sha384);
        SecretKey cek = randomCek(sr);

        byte[] wrapped = wrap(providerName(), kp, spec, cek);
        Assertions.assertArrayEquals(cek.getEncoded(),
                unwrap(providerName(), kp, spec, wrapped).getEncoded(),
                "SHA-384 must round-trip through Jostle");

        InvalidKeyException e = Assertions.assertThrows(InvalidKeyException.class,
                () -> unwrap(BC, kp, spec, wrapped),
                "BouncyCastle does not support SHA-384 for KDF3");
        Assertions.assertTrue(e.getMessage().contains("unrecognized digest OID"), e.getMessage());
    }

    /** Both OIDs resolve to the same behaviour as the name. */
    @Test
    public void bothOidsBehaveAsTheName() throws Exception
    {
        SecureRandom sr = seededRandom("bothOidsBehaveAsTheName");
        KeyPair kp = keyPair();
        KTSParameterSpec spec = kdf3Spec(256, null, NISTObjectIdentifiers.id_sha256);
        SecretKey cek = randomCek(sr);

        for (String name : new String[]{ID_KEM_RSA, ID_RSA_KEM})
        {
            Cipher w = Cipher.getInstance(name, providerName());
            w.init(Cipher.WRAP_MODE, kp.getPublic(), spec);
            byte[] wrapped = w.wrap(cek);

            // Unwrap through the NAME, so the OID and the name must be the same SPI.
            Assertions.assertArrayEquals(cek.getEncoded(),
                    unwrap(providerName(), kp, spec, wrapped).getEncoded(),
                    name + " must behave as " + XFORM);
            // ...and BC must read it too.
            Assertions.assertArrayEquals(cek.getEncoded(),
                    unwrap(BC, kp, spec, wrapped).getEncoded(),
                    name + " must interoperate with BC");
        }
    }


    // -----------------------------------------------------------------
    // Negative path.
    // -----------------------------------------------------------------

    /**
     * Tamper each half of {@code encapsulation ‖ wrappedKey} independently.
     * RSA-KEM itself has no integrity - a corrupted encapsulation simply
     * decapsulates to a different secret - so it is the AES-KW check that must
     * reject, and it must do so as InvalidKeyException rather than
     * BadPaddingException (which would be a decryption oracle).
     */
    @Test
    public void tamperedInputIsRejectedTyped() throws Exception
    {
        SecureRandom sr = seededRandom("tamperedInputIsRejectedTyped");
        KeyPair kp = keyPair();
        KTSParameterSpec spec = kdf3Spec(256, null, NISTObjectIdentifiers.id_sha256);
        SecretKey cek = randomCek(sr);
        byte[] wrapped = wrap(providerName(), kp, spec, cek);

        int modLen = 256; // 2048-bit key

        // Encapsulation half: yields a different KEK, so AES-KW rejects.
        byte[] badEncap = Arrays.clone(wrapped);
        badEncap[sr.nextInt(modLen)] ^= (byte) 0x01;
        Assertions.assertThrows(InvalidKeyException.class,
                () -> unwrap(providerName(), kp, spec, badEncap),
                "a tampered encapsulation must be rejected");

        // Wrapped-key half: AES-KW integrity check rejects directly.
        byte[] badWrap = Arrays.clone(wrapped);
        badWrap[modLen + sr.nextInt(wrapped.length - modLen)] ^= (byte) 0x01;
        Assertions.assertThrows(InvalidKeyException.class,
                () -> unwrap(providerName(), kp, spec, badWrap),
                "a tampered wrapped key must be rejected");
    }

    @Test
    public void truncatedInputRejectedTyped() throws Exception
    {
        KeyPair kp = keyPair();
        KTSParameterSpec spec = kdf3Spec(256, null, NISTObjectIdentifiers.id_sha256);

        Cipher u = Cipher.getInstance(XFORM, providerName());
        u.init(Cipher.UNWRAP_MODE, kp.getPrivate(), spec);
        InvalidKeyException e = Assertions.assertThrows(InvalidKeyException.class,
                () -> u.unwrap(new byte[8], "AES", Cipher.SECRET_KEY));
        Assertions.assertEquals("input shorter than RSA-KEM encapsulation", e.getMessage());
    }

    @Test
    public void specIsRequired() throws Exception
    {
        KeyPair kp = keyPair();
        Cipher c = Cipher.getInstance(XFORM, providerName());
        InvalidKeyException e = Assertions.assertThrows(InvalidKeyException.class,
                () -> c.init(Cipher.WRAP_MODE, kp.getPublic()));
        Assertions.assertEquals("RSA-KTS-KEM-KWS requires a KTSParameterSpec", e.getMessage());
    }

    @Test
    public void wrongKeyDirectionRejectedTyped() throws Exception
    {
        KeyPair kp = keyPair();
        KTSParameterSpec spec = kdf3Spec(256, null, NISTObjectIdentifiers.id_sha256);

        Cipher w = Cipher.getInstance(XFORM, providerName());
        InvalidKeyException e1 = Assertions.assertThrows(InvalidKeyException.class,
                () -> w.init(Cipher.WRAP_MODE, kp.getPrivate(), spec));
        Assertions.assertEquals("WRAP_MODE requires an RSA public key", e1.getMessage());

        Cipher u = Cipher.getInstance(XFORM, providerName());
        InvalidKeyException e2 = Assertions.assertThrows(InvalidKeyException.class,
                () -> u.init(Cipher.UNWRAP_MODE, kp.getPublic(), spec));
        Assertions.assertEquals("UNWRAP_MODE requires an RSA private key", e2.getMessage());
    }

    @Test
    public void encryptAndDecryptModesRejected() throws Exception
    {
        KeyPair kp = keyPair();
        KTSParameterSpec spec = kdf3Spec(256, null, NISTObjectIdentifiers.id_sha256);

        for (int mode : new int[]{Cipher.ENCRYPT_MODE, Cipher.DECRYPT_MODE})
        {
            Cipher c = Cipher.getInstance(XFORM, providerName());
            InvalidAlgorithmParameterException e = Assertions.assertThrows(
                    InvalidAlgorithmParameterException.class,
                    () -> c.init(mode, kp.getPublic(), spec));
            Assertions.assertEquals("RSA-KTS-KEM-KWS only supports WRAP_MODE/UNWRAP_MODE", e.getMessage());
        }
    }

    /** An unsupported KDF must name what IS supported rather than derive a wrong KEK. */
    @Test
    public void unsupportedKdfRejectedTyped() throws Exception
    {
        KeyPair kp = keyPair();
        KTSParameterSpec kdf2 = new KTSParameterSpec.Builder("AESWRAP", 256)
                .withKdfAlgorithm(new AlgorithmIdentifier(X9ObjectIdentifiers.id_kdf_kdf2,
                        new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256))).build();

        Cipher c = Cipher.getInstance(XFORM, providerName());
        InvalidAlgorithmParameterException e = Assertions.assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> c.init(Cipher.WRAP_MODE, kp.getPublic(), kdf2));
        Assertions.assertTrue(e.getMessage().startsWith("unsupported KDF "), e.getMessage());
        Assertions.assertTrue(e.getMessage().contains("KDF3"), e.getMessage());
    }

    @Test
    public void unsupportedKdfDigestRejectedTyped() throws Exception
    {
        KeyPair kp = keyPair();
        KTSParameterSpec sha1 = kdf3Spec(256, null, new ASN1ObjectIdentifier("1.3.14.3.2.26"));

        Cipher c = Cipher.getInstance(XFORM, providerName());
        InvalidAlgorithmParameterException e = Assertions.assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> c.init(Cipher.WRAP_MODE, kp.getPublic(), sha1));
        Assertions.assertTrue(e.getMessage().startsWith("unsupported KDF digest "), e.getMessage());
    }

    @Test
    public void streamingSurfaceRejected() throws Exception
    {
        KeyPair kp = keyPair();
        KTSParameterSpec spec = kdf3Spec(256, null, NISTObjectIdentifiers.id_sha256);
        Cipher c = Cipher.getInstance(XFORM, providerName());
        c.init(Cipher.WRAP_MODE, kp.getPublic(), spec);

        Assertions.assertThrows(IllegalStateException.class, () -> c.update(new byte[16]));
        Assertions.assertThrows(IllegalStateException.class, () -> c.doFinal(new byte[16]));
    }


    // -----------------------------------------------------------------
    // Reset / reuse, and the randomised-output property.
    // -----------------------------------------------------------------

    /**
     * RSASVE draws a fresh ephemeral value per call, so wrapping the SAME CEK
     * twice on the SAME instance must give different bytes. Identical output
     * would mean the SPI froze its randomness - a real correctness bug that a
     * round-trip test cannot see.
     */
    @Test
    public void repeatedWrapsAreRandomisedAndBothValid() throws Exception
    {
        SecureRandom sr = seededRandom("repeatedWrapsAreRandomisedAndBothValid");
        KeyPair kp = keyPair();
        KTSParameterSpec spec = kdf3Spec(256, null, NISTObjectIdentifiers.id_sha256);
        SecretKey cek = randomCek(sr);

        Cipher w = Cipher.getInstance(XFORM, providerName());
        w.init(Cipher.WRAP_MODE, kp.getPublic(), spec);
        byte[] first = w.wrap(cek);
        byte[] second = w.wrap(cek);

        Assertions.assertFalse(Arrays.areEqual(first, second),
                "RSASVE is randomised: two wraps of the same CEK must differ");
        Assertions.assertArrayEquals(cek.getEncoded(),
                unwrap(providerName(), kp, spec, first).getEncoded(), "first wrap must unwrap");
        Assertions.assertArrayEquals(cek.getEncoded(),
                unwrap(providerName(), kp, spec, second).getEncoded(), "second wrap must unwrap");
    }

    /**
     * Drive the instance to a failure, then a success. A native path that
     * released state only on success, or left a partial buffer, surfaces here.
     */
    @Test
    public void failureThenSuccessOnOneInstance() throws Exception
    {
        SecureRandom sr = seededRandom("failureThenSuccessOnOneInstance");
        KeyPair kp = keyPair();
        KTSParameterSpec spec = kdf3Spec(256, null, NISTObjectIdentifiers.id_sha256);
        SecretKey cek = randomCek(sr);
        byte[] good = wrap(providerName(), kp, spec, cek);

        Cipher u = Cipher.getInstance(XFORM, providerName());
        u.init(Cipher.UNWRAP_MODE, kp.getPrivate(), spec);

        byte[] bad = Arrays.clone(good);
        bad[bad.length - 1] ^= (byte) 0x01;
        Assertions.assertThrows(InvalidKeyException.class,
                () -> u.unwrap(bad, "AES", Cipher.SECRET_KEY));

        Key back = u.unwrap(good, "AES", Cipher.SECRET_KEY);
        Assertions.assertArrayEquals(cek.getEncoded(), back.getEncoded(),
                "the instance must be usable after a refused unwrap");
    }

    /** A 3072-bit key exercises the modulus-length arithmetic at a second size. */
    @Test
    public void worksAtThreeThousandAndSeventyTwoBits() throws Exception
    {
        SecureRandom sr = seededRandom("worksAtThreeThousandAndSeventyTwoBits");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", providerName());
        kpg.initialize(3072);
        KeyPair kp = kpg.generateKeyPair();

        KTSParameterSpec spec = kdf3Spec(256, null, NISTObjectIdentifiers.id_sha256);
        SecretKey cek = randomCek(sr);

        byte[] wrapped = wrap(providerName(), kp, spec, cek);
        Assertions.assertEquals(384 + 40, wrapped.length,
                "output is modulus length + AES-KW of a 32-byte CEK");
        Assertions.assertArrayEquals(cek.getEncoded(),
                unwrap(BC, kp, spec, wrapped).getEncoded(), "BC must read a 3072-bit wrap");
    }


    // -----------------------------------------------------------------
    // Registration.
    // -----------------------------------------------------------------

    @Test
    public void nameAndBothOidsAreRegistered()
    {
        Provider p = Security.getProvider(providerName());
        Assertions.assertNotNull(p, providerName() + " must be registered");
        Assertions.assertNotNull(p.getService("Cipher", XFORM), XFORM + " must be a Service");
        for (String oid : new String[]{ID_KEM_RSA, ID_RSA_KEM})
        {
            Assertions.assertDoesNotThrow(() -> Cipher.getInstance(oid, providerName()),
                    oid + " must resolve");
        }
    }


    // -----------------------------------------------------------------
    // Helpers.
    // -----------------------------------------------------------------

    protected static byte[] randomBytes(SecureRandom sr, int n)
    {
        byte[] b = new byte[n];
        sr.nextBytes(b);
        return b;
    }

    private static SecretKey randomCek(SecureRandom sr) throws Exception
    {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256, sr);
        return kg.generateKey();
    }

    protected byte[] wrap(String provider, KeyPair kp, KTSParameterSpec spec, SecretKey cek)
        throws Exception
    {
        return wrap(provider, kp.getPublic(), spec, cek);
    }

    /**
     * Key-level overload. Needed by the FIPS subclass, where the two providers
     * do not share key objects and the public half has to be re-decoded before
     * use — so the wrapping key is not the one in the caller's KeyPair.
     */
    protected byte[] wrap(String provider, java.security.PublicKey pub, KTSParameterSpec spec, SecretKey cek)
        throws Exception
    {
        Cipher c = Cipher.getInstance(XFORM, provider);
        c.init(Cipher.WRAP_MODE, pub, spec);
        return c.wrap(cek);
    }

    protected Key unwrap(String provider, KeyPair kp, KTSParameterSpec spec, byte[] wrapped)
        throws Exception
    {
        return unwrap(provider, kp.getPrivate(), spec, wrapped);
    }

    /** Key-level overload; see {@link #wrap(String, java.security.PublicKey, KTSParameterSpec, SecretKey)}. */
    protected Key unwrap(String provider, java.security.PrivateKey priv, KTSParameterSpec spec, byte[] wrapped)
        throws Exception
    {
        Cipher c = Cipher.getInstance(XFORM, provider);
        c.init(Cipher.UNWRAP_MODE, priv, spec);
        return c.unwrap(wrapped, "AES", Cipher.SECRET_KEY);
    }
}
