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
import org.openssl.jostle.jcajce.spec.HybridValueParameterSpec;
import org.openssl.jostle.jcajce.spec.UserKeyingMaterialSpec;

import javax.crypto.KeyAgreement;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;

/**
 * Key agreement. Two parties each combine their own private key with the other's public key and arrive at the
 * same secret. Each party initialises its own `KeyAgreement` with its private key, passes the peer's public key
 * to `doPhase`, and reads the shared secret with `generateSecret`.
 */
public class KeyAgreementExamplesTest
        extends JslExamples
{
    /**
     * ECDH on P-256. The raw secret is not a key: derive one with a KDF, or ask for a named key as below.
     */
    @Test
    public void ecdhRawSecret()
            throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "JSL");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair alice = kpg.generateKeyPair();
        KeyPair bob = kpg.generateKeyPair();

        KeyAgreement a = KeyAgreement.getInstance("ECDH", "JSL");
        a.init(alice.getPrivate());
        a.doPhase(bob.getPublic(), true);
        byte[] aliceSecret = a.generateSecret();

        KeyAgreement b = KeyAgreement.getInstance("ECDH", "JSL");
        b.init(bob.getPrivate());
        b.doPhase(alice.getPublic(), true);
        Assertions.assertArrayEquals(aliceSecret, b.generateSecret());
    }

    /**
     * Ask for a named key: `generateSecret("AES")` takes the leading bytes of the secret as a 256-bit AES key.
     * `XDH` takes keys of either Montgomery curve.
     */
    @Test
    public void namedKeyFromEveryPlainAgreement()
            throws Exception
    {
        String[] agreements = {"X25519", "X448", "XDH", "ECDH", "DH"};
        String[] generators = {"X25519", "X448", "X25519", "EC", "DH"};
        for (int i = 0; i < agreements.length; i++)
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(generators[i], "JSL");
            KeyPair alice = kpg.generateKeyPair();
            KeyPair bob = kpg.generateKeyPair();
            KeyAgreement a = KeyAgreement.getInstance(agreements[i], "JSL");
            a.init(alice.getPrivate());
            a.doPhase(bob.getPublic(), true);
            KeyAgreement b = KeyAgreement.getInstance(agreements[i], "JSL");
            b.init(bob.getPrivate());
            b.doPhase(alice.getPublic(), true);
            Assertions.assertArrayEquals(a.generateSecret("AES").getEncoded(),
                    b.generateSecret("AES").getEncoded(), agreements[i]);
        }
    }

    /**
     * The agreements with a KDF built in derive a key-encryption key for AES key wrap, named by the wrap's
     * object identifier (here AES-256 wrap), with optional user keying material. These are the X9.63 KDF over
     * ECDH, and the RFC 2631 KDF over DH.
     */
    @Test
    public void agreementsWithAKdf()
            throws Exception
    {
        String[] agreements = {"ECDHwithSHA1KDF", "ECDHwithSHA224KDF", "ECDHwithSHA256KDF", "ECDHwithSHA384KDF",
                "ECDHwithSHA512KDF", "DHwithRFC2631KDF"};
        String aes256Wrap = "2.16.840.1.101.3.4.1.45";
        UserKeyingMaterialSpec ukm = new UserKeyingMaterialSpec("key id 7".getBytes(StandardCharsets.US_ASCII));
        for (String name : agreements)
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(name.startsWith("DH") ? "DH" : "EC", "JSL");
            KeyPair alice = kpg.generateKeyPair();
            KeyPair bob = kpg.generateKeyPair();
            KeyAgreement a = KeyAgreement.getInstance(name, "JSL");
            a.init(alice.getPrivate(), ukm);
            a.doPhase(bob.getPublic(), true);
            KeyAgreement b = KeyAgreement.getInstance(name, "JSL");
            b.init(bob.getPrivate(), ukm);
            b.doPhase(alice.getPublic(), true);
            byte[] kek = a.generateSecret(aes256Wrap).getEncoded();
            Assertions.assertArrayEquals(kek, b.generateSecret(aes256Wrap).getEncoded(), name);
            Assertions.assertEquals(32, kek.length, name);
        }
    }

    /**
     * The OpenPGP ECDH agreements (RFC 6637): the KDF input includes the OpenPGP parameter block, which each
     * side passes as user keying material; it is required.
     */
    @Test
    public void openPgpEcdh()
            throws Exception
    {
        String[] agreements = {"ECCDHwithSHA256CKDF", "ECCDHwithSHA384CKDF", "ECCDHwithSHA512CKDF",
                "X25519withSHA256CKDF", "X25519withSHA384CKDF", "X25519withSHA512CKDF", "X448withSHA256CKDF",
                "X448withSHA384CKDF", "X448withSHA512CKDF"};
        UserKeyingMaterialSpec param = new UserKeyingMaterialSpec("openpgp param block".getBytes(
                StandardCharsets.US_ASCII));
        for (String name : agreements)
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(name.startsWith("ECC") ? "EC"
                    : name.startsWith("X448") ? "X448" : "X25519", "JSL");
            KeyPair alice = kpg.generateKeyPair();
            KeyPair bob = kpg.generateKeyPair();
            KeyAgreement a = KeyAgreement.getInstance(name, "JSL");
            a.init(alice.getPrivate(), param);
            a.doPhase(bob.getPublic(), true);
            KeyAgreement b = KeyAgreement.getInstance(name, "JSL");
            b.init(bob.getPrivate(), param);
            b.doPhase(alice.getPublic(), true);
            Assertions.assertArrayEquals(a.generateSecret("2.16.840.1.101.3.4.1.45").getEncoded(),
                    b.generateSecret("2.16.840.1.101.3.4.1.45").getEncoded(), name);
        }
    }

    /**
     * HKDF over X25519 and X448: the `XDHwithSHAnHKDF` names take plain HKDF info as user keying material;
     * the OpenPGP v6 names (RFC 9580) also bind the two public keys, passed as `T` in a
     * `HybridValueParameterSpec`.
     */
    @Test
    public void hkdfOverXdh()
            throws Exception
    {
        String[] agreements = {"XDHwithSHA256HKDF", "XDHwithSHA384HKDF", "XDHwithSHA512HKDF",
                "X25519withSHA256HKDF", "X448withSHA512HKDF"};
        UserKeyingMaterialSpec info = new UserKeyingMaterialSpec("hkdf info".getBytes(StandardCharsets.US_ASCII));
        for (String name : agreements)
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(name.startsWith("X448") ? "X448" : "X25519", "JSL");
            KeyPair eph = kpg.generateKeyPair();
            KeyPair rcpt = kpg.generateKeyPair();
            byte[] ep = eph.getPublic().getEncoded();
            byte[] rp = rcpt.getPublic().getEncoded();
            byte[] t = new byte[ep.length + rp.length];
            System.arraycopy(ep, 0, t, 0, ep.length);
            System.arraycopy(rp, 0, t, ep.length, rp.length);
            boolean v6 = !name.startsWith("XDH");
            KeyAgreement a = KeyAgreement.getInstance(name, "JSL");
            a.init(eph.getPrivate(), v6 ? new HybridValueParameterSpec(t, true, info) : info);
            a.doPhase(rcpt.getPublic(), true);
            KeyAgreement b = KeyAgreement.getInstance(name, "JSL");
            b.init(rcpt.getPrivate(), v6 ? new HybridValueParameterSpec(t, true, info) : info);
            b.doPhase(eph.getPublic(), true);
            Assertions.assertArrayEquals(a.generateSecret("2.16.840.1.101.3.4.1.45").getEncoded(),
                    b.generateSecret("2.16.840.1.101.3.4.1.45").getEncoded(), name);
        }
    }
}
