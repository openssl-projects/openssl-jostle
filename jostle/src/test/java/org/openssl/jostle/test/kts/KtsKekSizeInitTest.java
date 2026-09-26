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

package org.openssl.jostle.test.kts;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.spec.KTSParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Security;
import java.security.spec.RSAPublicKeySpec;

/**
 * The KTS ciphers refuse a key-encryption key they cannot use at init, where the spec is fully known: a KEK size
 * AES key wrap does not take (128, 192 and 256 bits only), and, with no KDF, a KEK larger than the shared secret.
 * Both wrap and unwrap, both ciphers, both wrap kinds. BouncyCastle refuses the first case only when it wraps,
 * with IllegalBlockSizeException; that divergence is pinned against it live.
 */
public class KtsKekSizeInitTest
{
    private static Provider jsl;
    private static Provider bc;

    @BeforeAll
    public static void setUp()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        jsl = Security.getProvider(JostleProvider.PROVIDER_NAME);
        bc = Security.getProvider("BC") != null ? Security.getProvider("BC") : new BouncyCastleProvider();
    }

    private static KTSParameterSpec spec(String wrap, int bits, boolean kdf)
    {
        KTSParameterSpec.Builder b = new KTSParameterSpec.Builder(wrap, bits);
        return (kdf ? b : b.withNoKdf()).build();
    }

    private static void refusedAtInit(String cipher, int mode, Key key, KTSParameterSpec spec, String message)
        throws Exception
    {
        final Cipher c = Cipher.getInstance(cipher, jsl);
        InvalidAlgorithmParameterException e = Assertions.assertThrows(InvalidAlgorithmParameterException.class,
                () -> c.init(mode, key, spec), cipher + " mode " + mode + " " + spec.getKeySize() + " bits");
        Assertions.assertEquals(message, e.getMessage());
    }

    @Test
    public void aKekSizeAesKeyWrapCannotTakeIsRefusedAtInit() throws Exception
    {
        KeyPair mlkem = KeyPairGenerator.getInstance("ML-KEM-768", jsl).generateKeyPair();
        KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA", jsl);
        rsaGen.initialize(2048);
        KeyPair rsa = rsaGen.generateKeyPair();
        Object[][] ciphers = {{"ML-KEM", mlkem}, {"RSA-KTS-KEM-KWS", rsa}};
        for (Object[] c : ciphers)
        {
            KeyPair kp = (KeyPair) c[1];
            for (int bits : new int[]{1, 64, 127, 129, 136, 255, 257, 384, 512, 4096})
            {
                for (boolean kdf : new boolean[]{true, false})
                {
                    String[][] wraps = {{"AESWRAP", "AES-KW"}, {"AES-KWP", "AES-KWP"}};
                    for (String[] w : wraps)
                    {
                        String message = "unsupported " + w[1] + " KEK size: " + bits
                                + " bits; AES key wrap takes 128, 192 or 256";
                        refusedAtInit((String) c[0], Cipher.WRAP_MODE, kp.getPublic(), spec(w[0], bits, kdf), message);
                        refusedAtInit((String) c[0], Cipher.UNWRAP_MODE, kp.getPrivate(), spec(w[0], bits, kdf),
                                message);
                    }
                }
            }
        }
    }

    /** The three sizes AES key wrap takes still initialise, with and without a KDF. */
    @Test
    public void theThreeAesKeyWrapSizesStillInitialise() throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance("ML-KEM-768", jsl).generateKeyPair();
        for (int bits : new int[]{128, 192, 256})
        {
            for (boolean kdf : new boolean[]{true, false})
            {
                Cipher w = Cipher.getInstance("ML-KEM", jsl);
                w.init(Cipher.WRAP_MODE, kp.getPublic(), spec("AESWRAP", bits, kdf));
                Cipher u = Cipher.getInstance("ML-KEM", jsl);
                u.init(Cipher.UNWRAP_MODE, kp.getPrivate(), spec("AESWRAP", bits, kdf));
                SecretKeySpec cek = new SecretKeySpec(new byte[16], "AES");
                Assertions.assertArrayEquals(cek.getEncoded(),
                        u.unwrap(w.wrap(cek), "AES", Cipher.SECRET_KEY).getEncoded());
            }
        }
    }

    /**
     * With no KDF the KEK is cut from the shared secret, so a KEK larger than the secret is refused at init. Only
     * an RSA modulus under 256 bits makes that reachable with an AES key-wrap size; a 192-bit one is imported.
     */
    @Test
    public void noKdfAndAKekLargerThanTheSecretIsRefusedAtInit() throws Exception
    {
        BigInteger n = BigInteger.ONE.shiftLeft(191).add(BigInteger.valueOf(0x3b));
        Key pub = KeyFactory.getInstance("RSA", jsl).generatePublic(new RSAPublicKeySpec(n,
                BigInteger.valueOf(65537)));
        refusedAtInit("RSA-KTS-KEM-KWS", Cipher.WRAP_MODE, pub, spec("AESWRAP", 256, false),
                "KEK size 256 bits is larger than the 192-bit shared secret, and no KDF is set");
    }

    /**
     * BouncyCastle accepts a KEK size AES key wrap cannot take at init and refuses it at wrap with
     * IllegalBlockSizeException; ours refuses at init with InvalidAlgorithmParameterException, the exception init
     * declares. Both halves measured here.
     */
    @Test
    public void anUnsupportedKekSizeDivergesFromBouncyCastleOnPurpose() throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance("ML-KEM-768", bc).generateKeyPair();
        Cipher w = Cipher.getInstance("ML-KEM", bc);
        w.init(Cipher.WRAP_MODE, kp.getPublic(),
                new org.bouncycastle.jcajce.spec.KTSParameterSpec.Builder("AESWRAP", 136).build());
        IllegalBlockSizeException theirs = Assertions.assertThrows(IllegalBlockSizeException.class,
                () -> w.wrap(new SecretKeySpec(new byte[16], "AES")));
        Assertions.assertEquals("unable to generate KTS secret: Key length not 128/192/256 bits.",
                theirs.getMessage());

        KeyPair ours = KeyPairGenerator.getInstance("ML-KEM-768", jsl).generateKeyPair();
        refusedAtInit("ML-KEM", Cipher.WRAP_MODE, ours.getPublic(), spec("AESWRAP", 136, true),
                "unsupported AES-KW KEK size: 136 bits; AES key wrap takes 128, 192 or 256");
    }
}
