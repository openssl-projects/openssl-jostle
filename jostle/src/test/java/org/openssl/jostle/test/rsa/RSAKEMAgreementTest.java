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
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.kts.KtsKdf;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

/**
 * RSA-KTS-KEM-KWS beside BouncyCastle: byte-level interop in both directions across the KEK sizes and KDF digests
 * both accept, and one cell per measured divergence holding both halves. {@code FIPSRSAKEMAgreementTest} re-runs it
 * against JSLFIPS.
 */
public class RSAKEMAgreementTest
    extends RSAKEMFixtures
{
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
            // These four are the whole accepted set on both sides. SHA-384 is
            // refused by both - see sha384KdfIsRefusedByBothProviders.
            for (ASN1ObjectIdentifier dig : BC_SUPPORTED_KDF3_DIGESTS)
            {
                byte[] otherInfo = randomBytes(sr, sr.nextInt(24));
                KtsSpec spec = kdf3Spec(kekBits, otherInfo, dig);
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
            // These four are the whole accepted set on both sides. SHA-384 is
            // refused by both - see sha384KdfIsRefusedByBothProviders.
            for (ASN1ObjectIdentifier dig : BC_SUPPORTED_KDF3_DIGESTS)
            {
                byte[] otherInfo = randomBytes(sr, sr.nextInt(24));
                KtsSpec spec = kdf3Spec(kekBits, otherInfo, dig);
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
            KtsSpec spec = new KtsSpec("AESWRAP", kekBits, null, null);
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

        KtsSpec specA = kdf3Spec(256, infoA, NISTObjectIdentifiers.id_sha256);
        KtsSpec specB = kdf3Spec(256, infoB, NISTObjectIdentifiers.id_sha256);

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
     * SHA-384 is refused as an X9.44 KDF digest, and BouncyCastle refuses it
     * too - the narrowing brought the two into agreement rather than away from
     * it. Both halves asserted, so a drift on either side is visible.
     *
     * <p>The two refuse at different POINTS: we
     * reject the spec at {@code init}, BC accepts it there and throws
     * {@code InvalidKeyException} from {@code wrap}. Asserted where each
     * actually throws, so a move of either boundary fails here.
     */
    @Test
    public void sha384KdfIsRefusedByBothProviders() throws Exception
    {
        SecureRandom sr = seededRandom("sha384KdfIsRefusedByBothProviders");
        KeyPair kp = keyPair();
        KtsSpec spec = kdf3Spec(256, null, NISTObjectIdentifiers.id_sha384);
        SecretKey cek = randomCek(sr);

        Cipher ours = Cipher.getInstance(XFORM, providerName());
        InvalidAlgorithmParameterException e = Assertions.assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> ours.init(Cipher.WRAP_MODE, kp.getPublic(), spec.forProvider(providerName())),
                "we must refuse SHA-384 at init");
        Assertions.assertEquals(KtsKdf.unsupportedKtsDigestMessage(
                NISTObjectIdentifiers.id_sha384.getId()), e.getMessage());

        Cipher theirs = Cipher.getInstance(XFORM, BC);
        theirs.init(Cipher.WRAP_MODE, kp.getPublic(), spec.forProvider(BC));   // BC accepts it here
        InvalidKeyException bc = Assertions.assertThrows(InvalidKeyException.class,
                () -> theirs.wrap(cek),
                "BouncyCastle must still refuse SHA-384, at wrap");
        Assertions.assertEquals("unrecognized digest OID: "
                + NISTObjectIdentifiers.id_sha384.getId(), bc.getMessage());
    }

    /** Both OIDs wrap what BouncyCastle reads. */
    @Test
    public void bothOidsInteroperateWithBouncyCastle() throws Exception
    {
        SecureRandom sr = seededRandom("bothOidsInteroperateWithBouncyCastle");
        KeyPair kp = keyPair();
        KtsSpec spec = kdf3Spec(256, null, NISTObjectIdentifiers.id_sha256);
        SecretKey cek = randomCek(sr);

        for (String name : new String[]{ID_KEM_RSA, ID_RSA_KEM})
        {
            Cipher w = Cipher.getInstance(name, providerName());
            w.init(Cipher.WRAP_MODE, kp.getPublic(), spec.forProvider(providerName()));
            Assertions.assertArrayEquals(cek.getEncoded(), unwrap(BC, kp, spec, w.wrap(cek)).getEncoded(),
                    name + " must interoperate with BC");
        }
    }

    /** BouncyCastle reads a 3072-bit wrap, the modulus-length arithmetic at a second size. */
    @Test
    public void bouncyCastleReadsAThreeThousandAndSeventyTwoBitWrap() throws Exception
    {
        SecureRandom sr = seededRandom("bouncyCastleReadsAThreeThousandAndSeventyTwoBitWrap");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", providerName());
        kpg.initialize(3072);
        KeyPair kp = kpg.generateKeyPair();

        KtsSpec spec = kdf3Spec(256, null, NISTObjectIdentifiers.id_sha256);
        SecretKey cek = randomCek(sr);
        Assertions.assertArrayEquals(cek.getEncoded(),
                unwrap(BC, kp, spec, wrap(providerName(), kp, spec, cek)).getEncoded(), "BC must read a 3072-bit wrap");
    }

    /**
     * ENCRYPT_MODE and DECRYPT_MODE are refused with InvalidParameterException, the type Cipher.init declares for an
     * opmode a cipher does not support, on ours and on BouncyCastle. Each message is its own.
     */
    @Test
    public void encryptAndDecryptModesAreRefusedAsBouncyCastleRefusesThem() throws Exception
    {
        KeyPair kp = keyPair();
        KtsSpec spec = kdf3Spec(256, null, NISTObjectIdentifiers.id_sha256);
        for (int mode : new int[]{Cipher.ENCRYPT_MODE, Cipher.DECRYPT_MODE})
        {
            Cipher ours = Cipher.getInstance(XFORM, providerName());
            InvalidParameterException e = Assertions.assertThrows(InvalidParameterException.class,
                    () -> ours.init(mode, kp.getPublic(), spec.forProvider(providerName())));
            Assertions.assertEquals("RSA-KTS-KEM-KWS only supports WRAP_MODE/UNWRAP_MODE", e.getMessage());

            Cipher bc = Cipher.getInstance(XFORM, BC);
            e = Assertions.assertThrows(InvalidParameterException.class,
                    () -> bc.init(mode, kp.getPublic(), spec.forProvider(BC)));
            Assertions.assertEquals("Cipher only valid for wrapping/unwrapping", e.getMessage());
        }
    }
}
