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

package org.openssl.jostle.test.mlkem;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;

/**
 * Wrap / unwrap coverage for {@code MLKEMKTSCipherSpi} — the ML-KEM KTS
 * (key-transport) Cipher for the CMS KEMRecipientInfo path (RFC 9629). Wrap
 * performs ML-KEM encapsulate &rarr; KDF3 &rarr; AES key-wrap and returns
 * {@code encapsulation ‖ wrappedKey}; unwrap is the inverse.
 *
 * <p>This guards two things:
 * <ol>
 *   <li><b>Strength (GH issue #34):</b> ML-KEM encapsulation consumes entropy
 *       through the C-side RAND gate, so ML-KEM-768 / -1024 need 192 / 256-bit
 *       strength. The wrap tests pass <em>no</em> explicit {@link SecureRandom},
 *       so the SPI must resolve a strength-appropriate RNG for the parameter set
 *       on its own — without that, the 768 / 1024 wrap throws on the encap call.</li>
 *   <li><b>Round-trip:</b> the wrapped CEK must recover exactly, across all three
 *       parameter sets, with KDF3 and with no KDF, and a tampered encapsulation or
 *       wrapped portion must be rejected (negative path).</li>
 * </ol>
 *
 * <p>{@code MLKEMKTSCipherSpi} reads BouncyCastle's {@code KTSParameterSpec}
 * reflectively ({@code getKeySize}/{@code getOtherInfo}/{@code getKdfAlgorithm}),
 * so this test supplies a duck-typed spec of the same shape — exercising the
 * identical SPI code path without a compile-time BouncyCastle dependency.
 */
public class MLKEMKTSCipherTest
{
    private static final SecureRandom RANDOM = new SecureRandom();

    // X9.44 KDF3 OID and SHA-256 OID — the KDF AlgorithmIdentifier the SPI parses.
    private static final ASN1ObjectIdentifier KDF3 = new ASN1ObjectIdentifier("1.3.133.16.840.9.44.1.2");
    private static final ASN1ObjectIdentifier SHA256 = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1");

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    // -----------------------------------------------------------------
    // Round-trip across all parameter sets (the wrap path also pins GH #34:
    // 768/1024 must succeed with no explicit SecureRandom).
    // -----------------------------------------------------------------

    @Test
    public void mlkem512_kdf3_roundTrip() throws Exception
    {
        roundTrip("ML-KEM-512", 256, true);
    }

    @Test
    public void mlkem768_kdf3_roundTrip() throws Exception
    {
        // The strength reproducer (192-bit): fails on encap without the F1 fix.
        roundTrip("ML-KEM-768", 256, true);
    }

    @Test
    public void mlkem1024_kdf3_roundTrip() throws Exception
    {
        // The strength reproducer (256-bit): fails on encap without the F1 fix.
        roundTrip("ML-KEM-1024", 256, true);
    }

    @Test
    public void mlkem768_noKdf_roundTrip() throws Exception
    {
        // withNoKdf(): the 256-bit KEK is taken directly from the 32-byte shared secret.
        roundTrip("ML-KEM-768", 256, false);
    }

    @Test
    public void mlkem768_kdf3_aes128Kek_roundTrip() throws Exception
    {
        // 128-bit KEK exercises the AES-128 key-wrap branch of aesKeyWrap().
        roundTrip("ML-KEM-768", 128, true);
    }

    // -----------------------------------------------------------------
    // Negative path
    // -----------------------------------------------------------------

    @Test
    public void tamperedWrappedKey_rejected() throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance("ML-KEM-768", JostleProvider.PROVIDER_NAME).generateKeyPair();
        AlgorithmParameterSpec spec = ktsSpec(256, randomOtherInfo(), true);

        byte[] wrapped = wrapCek(kp, spec, randomCek());

        // Flip a byte in the trailing AES-KW portion — the wrap integrity check must reject it.
        byte[] tampered = Arrays.clone(wrapped);
        tampered[tampered.length - 1] ^= 0x01;

        Cipher unwrap = Cipher.getInstance("ML-KEM", JostleProvider.PROVIDER_NAME);
        unwrap.init(Cipher.UNWRAP_MODE, kp.getPrivate(), spec);
        Assertions.assertThrows(InvalidKeyException.class,
            () -> unwrap.unwrap(tampered, "AES", Cipher.SECRET_KEY),
            "tampered wrapped key unexpectedly unwrapped");
    }

    @Test
    public void tamperedEncapsulation_rejected() throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance("ML-KEM-768", JostleProvider.PROVIDER_NAME).generateKeyPair();
        AlgorithmParameterSpec spec = ktsSpec(256, randomOtherInfo(), true);

        byte[] wrapped = wrapCek(kp, spec, randomCek());

        // Flip a byte in the leading encapsulation portion — decap yields a
        // different shared secret, so the derived KEK is wrong and the AES-KW
        // integrity check rejects the unwrap.
        byte[] tampered = Arrays.clone(wrapped);
        tampered[0] ^= 0x01;

        Cipher unwrap = Cipher.getInstance("ML-KEM", JostleProvider.PROVIDER_NAME);
        unwrap.init(Cipher.UNWRAP_MODE, kp.getPrivate(), spec);
        Assertions.assertThrows(InvalidKeyException.class,
            () -> unwrap.unwrap(tampered, "AES", Cipher.SECRET_KEY),
            "tampered encapsulation unexpectedly unwrapped");
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    private void roundTrip(String mlkemAlg, int kekBits, boolean useKdf) throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance(mlkemAlg, JostleProvider.PROVIDER_NAME).generateKeyPair();
        byte[] cek = randomCek();
        AlgorithmParameterSpec spec = ktsSpec(kekBits, randomOtherInfo(), useKdf);

        byte[] wrapped = wrapCek(kp, spec, cek);

        Cipher unwrap = Cipher.getInstance("ML-KEM", JostleProvider.PROVIDER_NAME);
        unwrap.init(Cipher.UNWRAP_MODE, kp.getPrivate(), spec);
        Key recovered = unwrap.unwrap(wrapped, "AES", Cipher.SECRET_KEY);

        Assertions.assertArrayEquals(cek, recovered.getEncoded(),
            mlkemAlg + (useKdf ? " (KDF3)" : " (no KDF)") + " kek=" + kekBits + ": CEK did not round-trip");
    }

    private static byte[] wrapCek(KeyPair kp, AlgorithmParameterSpec spec, byte[] cek) throws Exception
    {
        // No explicit SecureRandom: the SPI must resolve a strength-appropriate
        // RNG for the key's parameter set (GH #34) for the encap to succeed.
        Cipher wrap = Cipher.getInstance("ML-KEM", JostleProvider.PROVIDER_NAME);
        wrap.init(Cipher.WRAP_MODE, kp.getPublic(), spec);
        return wrap.wrap(new SecretKeySpec(cek, "AES"));
    }

    private static byte[] randomCek()
    {
        byte[] cek = new byte[16];
        RANDOM.nextBytes(cek);
        return cek;
    }

    private static byte[] randomOtherInfo()
    {
        byte[] otherInfo = new byte[12];
        RANDOM.nextBytes(otherInfo);
        return otherInfo;
    }

    private static AlgorithmParameterSpec ktsSpec(int kekBits, byte[] otherInfo, boolean useKdf)
    {
        // KDF AlgorithmIdentifier shape the SPI parses: SEQUENCE { KDF3-OID, SEQUENCE { digest-OID } }.
        AlgorithmIdentifier kdf = useKdf
            ? new AlgorithmIdentifier(KDF3, new AlgorithmIdentifier(SHA256))
            : null;
        return new TestKTSParameterSpec(kekBits, otherInfo, kdf);
    }

    /**
     * Duck-typed stand-in for {@code org.bouncycastle.jcajce.spec.KTSParameterSpec}.
     * {@code MLKEMKTSCipherSpi} reads {@code getKeySize}/{@code getOtherInfo}/
     * {@code getKdfAlgorithm} reflectively, so a same-shaped public class drives the
     * identical code path. {@code getKdfAlgorithm()} returns {@code null} for the
     * no-KDF case, mirroring {@code KTSParameterSpec.Builder.withNoKdf()}.
     */
    public static final class TestKTSParameterSpec
        implements AlgorithmParameterSpec
    {
        private final int keySize;
        private final byte[] otherInfo;
        private final AlgorithmIdentifier kdf;

        TestKTSParameterSpec(int keySize, byte[] otherInfo, AlgorithmIdentifier kdf)
        {
            this.keySize = keySize;
            this.otherInfo = otherInfo;
            this.kdf = kdf;
        }

        public int getKeySize()
        {
            return keySize;
        }

        public byte[] getOtherInfo()
        {
            return otherInfo;
        }

        public AlgorithmIdentifier getKdfAlgorithm()
        {
            return kdf;
        }
    }
}
