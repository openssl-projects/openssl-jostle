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

package jostle.examples.fips;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.SecretKeyWithEncapsulation;
import org.openssl.jostle.jcajce.spec.KEMExtractSpec;
import org.openssl.jostle.jcajce.spec.KEMGenerateSpec;

import javax.crypto.KeyGenerator;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;

/**
 * Key generators in the FIPS module: AES and Triple-DES keys, and key encapsulation with ML-KEM and the hybrid
 * TLS groups. The KEM key is derived from the shared secret through a KDF (X9.44 KDF3 with SHA-256 unless the
 * spec names another), computed inside the module.
 */
public class FipsKeyGeneratorExamplesTest
        extends FipsExamples
{
    /**
     * AES keys, with the size chosen by `init` or fixed by the name.
     */
    @Test
    public void aesKeys()
            throws Exception
    {
        String[] names = {"AES", "AES128", "AES192", "AES256"};
        int[] keyBytes = {32, 16, 24, 32};
        for (int i = 0; i < names.length; i++)
        {
            Assertions.assertEquals(keyBytes[i],
                    KeyGenerator.getInstance(names[i], "JSLFIPS").generateKey().getEncoded().length, names[i]);
        }
        KeyGenerator aes = KeyGenerator.getInstance("AES", "JSLFIPS");
        aes.init(128);
        Assertions.assertEquals(16, aes.generateKey().getEncoded().length);
    }

    /**
     * A Triple-DES key, for decrypting existing data.
     */
    @Test
    public void tripleDesKey()
            throws Exception
    {
        Assumptions.assumeTrue(Security.getProvider("JSLFIPS").getService("KeyGenerator", "DESEDE") != null);
        Assertions.assertEquals(24, KeyGenerator.getInstance("DESede", "JSLFIPS").generateKey().getEncoded().length);
    }

    /**
     * ML-KEM and the hybrid groups: the sender encapsulates to the recipient's public key and gets an AES key
     * plus the encapsulation; the recipient extracts the same key with its private key.
     */
    @Test
    public void everyKem()
            throws Exception
    {
        Assumptions.assumeTrue(Security.getProvider("JSLFIPS").getService("KeyGenerator", "ML-KEM-768") != null);
        String[] names = {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "MLKEM", "X25519MLKEM768",
                "SecP256r1MLKEM768", "SecP384r1MLKEM1024"};
        for (String name : names)
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(name.equals("MLKEM") ? "ML-KEM-768" : name,
                    "JSLFIPS");
            KeyPair kp = kpg.generateKeyPair();
            KeyGenerator sender = KeyGenerator.getInstance(name, "JSLFIPS");
            sender.init(KEMGenerateSpec.builder().withPublicKey(kp.getPublic())
                    .withAlgorithmName("AES").withKeySizeInBits(256).build());
            SecretKeyWithEncapsulation sent = (SecretKeyWithEncapsulation) sender.generateKey();
            KeyGenerator receiver = KeyGenerator.getInstance(name, "JSLFIPS");
            receiver.init(KEMExtractSpec.builder().withPrivate(kp.getPrivate()).withAlgorithmName("AES")
                    .withKeySizeInBits(256).withEncapsulatedKey(sent.getEncapsulation()).build());
            Assertions.assertArrayEquals(sent.getEncoded(), receiver.generateKey().getEncoded(), name);
        }
    }
}
