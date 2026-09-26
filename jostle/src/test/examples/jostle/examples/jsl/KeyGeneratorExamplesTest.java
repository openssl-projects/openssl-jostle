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
package jostle.examples.jsl;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.SecretKeyWithEncapsulation;
import org.openssl.jostle.jcajce.spec.KEMExtractSpec;
import org.openssl.jostle.jcajce.spec.KEMGenerateSpec;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

/**
 * Key generators: fresh symmetric keys, and the key-encapsulation mechanisms (ML-KEM and the hybrid TLS
 * groups), which JSL serves as a `KeyGenerator` initialised with a Jostle KEM spec. The KEM key is derived from
 * the shared secret through a KDF (X9.44 KDF3 with SHA-256 unless the spec names another), so any key size works
 * and both sides derive the same key.
 */
public class KeyGeneratorExamplesTest
        extends JslExamples
{
    /**
     * Generate symmetric keys. With no `init` the size is the cipher's largest (256 bits for AES, ARIA and
     * Camellia); `init(bits)` chooses another, and a name with a size in it (`AES128`) always gives that
     * size.
     */
    @Test
    public void symmetricKeys()
            throws Exception
    {
        String[] names = {"AES", "AES128", "AES192", "AES256", "ARIA", "CAMELLIA", "SM4", "DESEDE", "CHACHA20"};
        int[] keyBytes = {32, 16, 24, 32, 32, 32, 16, 24, 32};
        for (int i = 0; i < names.length; i++)
        {
            SecretKey key = KeyGenerator.getInstance(names[i], "JSL").generateKey();
            Assertions.assertEquals(keyBytes[i], key.getEncoded().length, names[i]);
        }
        KeyGenerator aes = KeyGenerator.getInstance("AES", "JSL");
        aes.init(128);
        Assertions.assertEquals(16, aes.generateKey().getEncoded().length);
    }

    /**
     * ML-KEM key encapsulation. The sender initialises the generator with the recipient's public key and gets
     * an AES key plus the encapsulation to send; the recipient extracts the same key from the encapsulation with
     * its private key. Pass no SecureRandom: JSL picks a DRBG strong enough for the parameter set.
     */
    @Test
    public void mlKemEncapsulateAndExtract()
            throws Exception
    {
        KeyPair recipient = KeyPairGenerator.getInstance("ML-KEM-768", "JSL").generateKeyPair();

        KeyGenerator sender = KeyGenerator.getInstance("ML-KEM-768", "JSL");
        sender.init(KEMGenerateSpec.builder().withPublicKey(recipient.getPublic())
                .withAlgorithmName("AES").withKeySizeInBits(256).build());
        SecretKeyWithEncapsulation sent = (SecretKeyWithEncapsulation) sender.generateKey();

        KeyGenerator receiver = KeyGenerator.getInstance("ML-KEM-768", "JSL");
        receiver.init(KEMExtractSpec.builder().withPrivate(recipient.getPrivate())
                .withAlgorithmName("AES").withKeySizeInBits(256)
                .withEncapsulatedKey(sent.getEncapsulation()).build());
        SecretKey received = receiver.generateKey();
        Assertions.assertArrayEquals(sent.getEncoded(), received.getEncoded());
        Assertions.assertEquals(32, received.getEncoded().length);
    }

    /**
     * The same encapsulation for every ML-KEM parameter set and the hybrid TLS groups. The generic `MLKEM`
     * generator takes a key of any parameter set. Hybrid keys have no encoding, so they never leave the JVM.
     */
    @Test
    public void everyKem()
            throws Exception
    {
        String[] names = {"ML-KEM-512", "ML-KEM-1024", "MLKEM", "X25519MLKEM768", "X448MLKEM1024",
                "SecP256r1MLKEM768", "SecP384r1MLKEM1024"};
        for (String name : names)
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(name.equals("MLKEM") ? "ML-KEM-768" : name, "JSL");
            KeyPair kp = kpg.generateKeyPair();
            KeyGenerator sender = KeyGenerator.getInstance(name, "JSL");
            sender.init(KEMGenerateSpec.builder().withPublicKey(kp.getPublic())
                    .withAlgorithmName("AES").withKeySizeInBits(256).build());
            SecretKeyWithEncapsulation sent = (SecretKeyWithEncapsulation) sender.generateKey();
            KeyGenerator receiver = KeyGenerator.getInstance(name, "JSL");
            receiver.init(KEMExtractSpec.builder().withPrivate(kp.getPrivate()).withAlgorithmName("AES")
                    .withKeySizeInBits(256).withEncapsulatedKey(sent.getEncapsulation()).build());
            Assertions.assertArrayEquals(sent.getEncoded(), receiver.generateKey().getEncoded(), name);
        }
    }

    /**
     * For a protocol that feeds the raw shared secret to its own key schedule, as TLS does with the hybrid
     * groups, set no KDF and ask for exactly the secret's size: 64 bytes for X25519MLKEM768.
     */
    @Test
    public void rawSharedSecretWithNoKdf()
            throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance("X25519MLKEM768", "JSL").generateKeyPair();
        KeyGenerator sender = KeyGenerator.getInstance("X25519MLKEM768", "JSL");
        sender.init(KEMGenerateSpec.builder().withPublicKey(kp.getPublic()).withAlgorithmName("TlsSecret")
                .withKeySizeInBits(512).withNoKdf().build());
        SecretKeyWithEncapsulation sent = (SecretKeyWithEncapsulation) sender.generateKey();
        KeyGenerator receiver = KeyGenerator.getInstance("X25519MLKEM768", "JSL");
        receiver.init(KEMExtractSpec.builder().withPrivate(kp.getPrivate()).withAlgorithmName("TlsSecret")
                .withKeySizeInBits(512).withNoKdf().withEncapsulatedKey(sent.getEncapsulation()).build());
        Assertions.assertArrayEquals(sent.getEncoded(), receiver.generateKey().getEncoded());
        Assertions.assertEquals(64, sent.getEncoded().length);
    }
}
