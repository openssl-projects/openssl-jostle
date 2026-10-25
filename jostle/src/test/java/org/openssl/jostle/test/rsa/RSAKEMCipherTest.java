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
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.kts.KtsKdf;
import org.openssl.jostle.jcajce.spec.KTSParameterSpec;
import org.openssl.jostle.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
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
 * and that is what {@link RSAKEMAgreementTest} pins.
 *
 * <p>The KEM operation name is hard-coded to {@code RSASVE} in
 * {@code RSAKEMCipherSpi} because the CMVP-validated 3.1.2 module REQUIRES it -
 * without it, encapsulation fails there and fails mutely, while mainline and
 * 3.5.8 default to it and work. No test here can see that difference (both
 * behave identically once the name is set); it is pinned by the probe and by
 * the FIPS subclass running the whole contract against the module.
 *
 * <p>Subclassed by {@code FIPSRSAKEMCipherTest}, which re-runs everything
 * against the FIPS interface library and lib ctx.
 */
public class RSAKEMCipherTest
    extends RSAKEMFixtures
{
    /** Both OIDs resolve to the same behaviour as the name. */
    @Test
    public void bothOidsBehaveAsTheName() throws Exception
    {
        SecureRandom sr = seededRandom("bothOidsBehaveAsTheName");
        KeyPair kp = keyPair();
        KtsSpec spec = kdf3Spec(256, null, NISTObjectIdentifiers.id_sha256);
        SecretKey cek = randomCek(sr);

        for (String name : new String[]{ID_KEM_RSA, ID_RSA_KEM})
        {
            Cipher w = Cipher.getInstance(name, providerName());
            w.init(Cipher.WRAP_MODE, kp.getPublic(), spec.forProvider(providerName()));
            byte[] wrapped = w.wrap(cek);

            // Unwrap through the NAME, so the OID and the name must be the same SPI.
            Assertions.assertArrayEquals(cek.getEncoded(),
                    unwrap(providerName(), kp, spec, wrapped).getEncoded(),
                    name + " must behave as " + XFORM);
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
        KtsSpec spec = kdf3Spec(256, null, NISTObjectIdentifiers.id_sha256);
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
        KtsSpec spec = kdf3Spec(256, null, NISTObjectIdentifiers.id_sha256);

        Cipher u = Cipher.getInstance(XFORM, providerName());
        u.init(Cipher.UNWRAP_MODE, kp.getPrivate(), spec.forProvider(providerName()));
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
        KtsSpec spec = kdf3Spec(256, null, NISTObjectIdentifiers.id_sha256);

        Cipher w = Cipher.getInstance(XFORM, providerName());
        InvalidKeyException e1 = Assertions.assertThrows(InvalidKeyException.class,
                () -> w.init(Cipher.WRAP_MODE, kp.getPrivate(), spec.forProvider(providerName())));
        Assertions.assertEquals("WRAP_MODE requires an RSA public key", e1.getMessage());

        Cipher u = Cipher.getInstance(XFORM, providerName());
        InvalidKeyException e2 = Assertions.assertThrows(InvalidKeyException.class,
                () -> u.init(Cipher.UNWRAP_MODE, kp.getPublic(), spec.forProvider(providerName())));
        Assertions.assertEquals("UNWRAP_MODE requires an RSA private key", e2.getMessage());
    }

    @Test
    public void encryptAndDecryptModesRejected() throws Exception
    {
        KeyPair kp = keyPair();
        KtsSpec spec = kdf3Spec(256, null, NISTObjectIdentifiers.id_sha256);

        for (int mode : new int[]{Cipher.ENCRYPT_MODE, Cipher.DECRYPT_MODE})
        {
            Cipher c = Cipher.getInstance(XFORM, providerName());
            InvalidParameterException e = Assertions.assertThrows(
                    InvalidParameterException.class,
                    () -> c.init(mode, kp.getPublic(), spec.forProvider(providerName())));
            Assertions.assertEquals("RSA-KTS-KEM-KWS only supports WRAP_MODE/UNWRAP_MODE", e.getMessage());
        }
    }

    /** An unsupported KDF must name what IS supported rather than derive a wrong KEK. */
    @Test
    public void unsupportedKdfRejectedTyped() throws Exception
    {
        KeyPair kp = keyPair();
        // MT-73: this used KDF2 as its "unsupported" example, on the rationale
        // that "the SPI only supports X9.44 KDF3". KDF2 is now accepted, so the
        // probe moves to an OID nothing serves; the refusal itself still stands.
        KtsSpec unknown = new KtsSpec("AESWRAP", 256, null, new AlgorithmIdentifier(
                new ASN1ObjectIdentifier("1.2.3.4.5.6.7"),
                new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256)));

        Cipher c = Cipher.getInstance(XFORM, providerName());
        InvalidAlgorithmParameterException e = Assertions.assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> c.init(Cipher.WRAP_MODE, kp.getPublic(), unknown.forProvider(providerName())));
        Assertions.assertEquals(KtsKdf.unsupportedKdfMessage("1.2.3.4.5.6.7"), e.getMessage());
    }

    @Test
    public void unsupportedKdfDigestRejectedTyped() throws Exception
    {
        KeyPair kp = keyPair();
        KtsSpec sha1 = kdf3Spec(256, null, new ASN1ObjectIdentifier("1.3.14.3.2.26"));

        Cipher c = Cipher.getInstance(XFORM, providerName());
        InvalidAlgorithmParameterException e = Assertions.assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> c.init(Cipher.WRAP_MODE, kp.getPublic(), sha1.forProvider(providerName())));
        Assertions.assertTrue(e.getMessage().startsWith("unsupported KDF digest "), e.getMessage());
    }

    @Test
    public void streamingSurfaceRejected() throws Exception
    {
        KeyPair kp = keyPair();
        KtsSpec spec = kdf3Spec(256, null, NISTObjectIdentifiers.id_sha256);
        Cipher c = Cipher.getInstance(XFORM, providerName());
        c.init(Cipher.WRAP_MODE, kp.getPublic(), spec.forProvider(providerName()));

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
        KtsSpec spec = kdf3Spec(256, null, NISTObjectIdentifiers.id_sha256);
        SecretKey cek = randomCek(sr);

        Cipher w = Cipher.getInstance(XFORM, providerName());
        w.init(Cipher.WRAP_MODE, kp.getPublic(), spec.forProvider(providerName()));
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
        KtsSpec spec = kdf3Spec(256, null, NISTObjectIdentifiers.id_sha256);
        SecretKey cek = randomCek(sr);
        byte[] good = wrap(providerName(), kp, spec, cek);

        Cipher u = Cipher.getInstance(XFORM, providerName());
        u.init(Cipher.UNWRAP_MODE, kp.getPrivate(), spec.forProvider(providerName()));

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

        KtsSpec spec = kdf3Spec(256, null, NISTObjectIdentifiers.id_sha256);
        SecretKey cek = randomCek(sr);

        byte[] wrapped = wrap(providerName(), kp, spec, cek);
        Assertions.assertEquals(384 + 40, wrapped.length,
                "output is modulus length + AES-KW of a 32-byte CEK");
        Assertions.assertArrayEquals(cek.getEncoded(),
                unwrap(providerName(), kp, spec, wrapped).getEncoded(), "a 3072-bit wrap must unwrap");
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
}
