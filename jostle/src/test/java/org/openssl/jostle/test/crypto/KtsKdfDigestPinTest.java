/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.crypto;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.spec.KTSParameterSpec;
import org.openssl.jostle.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

/**
 * The digests both KTS ciphers accept as an X9.44 KDF2/KDF3 parameter, and the
 * one sentence each refuses with, pinned verbatim so nothing moves silently.
 *
 * <p>One set for both ciphers: SHA-256, SHA-512, SHAKE-128, SHAKE-256. The
 * cells sweep both, so a set that diverged again fails here.
 *
 * <p>Every admitted digest is driven end to end, not merely past init — an
 * accepted digest that cannot derive a working KEK is not support.
 *
 * <p>Driven through {@code Cipher}, never reflection, so each leg measures the
 * multi-release copy it loads.
 */
public class KtsKdfDigestPinTest
{
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String JSL = JostleProvider.PROVIDER_NAME;

    /** The accepted set, and the JCA name each OID resolves to. */
    private static final Object[][] ACCEPTED = {
            {NISTObjectIdentifiers.id_sha256, "SHA-256"},
            {NISTObjectIdentifiers.id_sha512, "SHA-512"},
            {NISTObjectIdentifiers.id_shake128, "SHAKE-128"},
            {NISTObjectIdentifiers.id_shake256, "SHAKE-256"},
    };

    /**
     * Refused. The first three left in this commit. The two {@code -len} forms
     * carry an explicit output length that nothing here reads, so accepting
     * them would silently ignore it — a reader will otherwise assume the
     * distinction went the other way.
     */
    private static final ASN1ObjectIdentifier[] REFUSED = {
            OIWObjectIdentifiers.idSHA1,
            NISTObjectIdentifiers.id_sha224,
            NISTObjectIdentifiers.id_sha384,
            NISTObjectIdentifiers.id_shake128_len,
            NISTObjectIdentifiers.id_shake256_len,
    };

    /** Both KTS transformations, so no cell can cover one and miss the other. */
    private static final String[] CIPHERS = {"RSA-KTS-KEM-KWS", "ML-KEM"};

    @BeforeAll
    public static void setUp()
    {
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    private static String refusal(String oid)
    {
        return "unsupported KDF digest " + oid
                + "; supported: SHA-256, SHA-512, SHAKE128, SHAKE256";
    }

    private static KTSParameterSpec spec(ASN1ObjectIdentifier digest, byte[] otherInfo) throws java.io.IOException
    {
        AlgorithmIdentifier kdf = new AlgorithmIdentifier(X9ObjectIdentifiers.id_kdf_kdf2,
                new AlgorithmIdentifier(digest, DERNull.INSTANCE));
        return new KTSParameterSpec.Builder("AESWRAP", 256, otherInfo).withKdfAlgorithm(kdf.getEncoded()).build();
    }

    /**
     * For cells that need SOME spec. Never for a comparison between two specs:
     * otherInfo feeds the KEK, so two draws would differ whatever the digest
     * did and the comparison would pass vacuously.
     */
    private static KTSParameterSpec spec(ASN1ObjectIdentifier digest) throws java.io.IOException
    {
        byte[] otherInfo = new byte[16];
        RANDOM.nextBytes(otherInfo);
        return spec(digest, otherInfo);
    }

    private static KeyPair pairFor(String transformation) throws Exception
    {
        if ("ML-KEM".equals(transformation))
        {
            return KeyPairGenerator.getInstance("ML-KEM-768", JSL).generateKeyPair();
        }
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", JSL);
        kpg.initialize(2048, RANDOM);
        return kpg.generateKeyPair();
    }

    private static SecretKey cek() throws Exception
    {
        KeyGenerator kg = KeyGenerator.getInstance("AES", JSL);
        kg.init(256, RANDOM);
        return kg.generateKey();
    }

    /**
     * @return null when the cipher accepted the digest, else the refusal message.
     */
    private static String refusalFrom(String transformation, KeyPair kp,
                                      ASN1ObjectIdentifier digest) throws Exception
    {
        Cipher c = Cipher.getInstance(transformation, JSL);
        try
        {
            c.init(Cipher.WRAP_MODE, kp.getPublic(), spec(digest), RANDOM);
            return null;
        }
        catch (InvalidAlgorithmParameterException e)
        {
            return e.getMessage();
        }
    }

    /** Both ciphers take the same four digests and nothing else. */
    @Test
    public void bothCiphersAcceptExactlyFourDigests() throws Exception
    {
        // An emptied table would make the loops iterate nothing and the cell
        // pass on no evidence.
        Assertions.assertEquals(4, ACCEPTED.length, "four digests are accepted");
        Assertions.assertEquals(5, REFUSED.length, "five are pinned as refused");

        List<String> wrong = new ArrayList<String>();
        for (String transformation : CIPHERS)
        {
            KeyPair kp = pairFor(transformation);
            for (Object[] row : ACCEPTED)
            {
                String got = refusalFrom(transformation, kp, (ASN1ObjectIdentifier) row[0]);
                if (got != null)
                {
                    wrong.add(transformation + "/" + row[0] + ": expected accepted, refused with ["
                            + got + "]");
                }
            }
            for (ASN1ObjectIdentifier oid : REFUSED)
            {
                String got = refusalFrom(transformation, kp, oid);
                if (!refusal(oid.getId()).equals(got))
                {
                    wrong.add(transformation + "/" + oid.getId() + ": expected ["
                            + refusal(oid.getId()) + "], got [" + got + "]");
                }
            }
        }
        Assertions.assertTrue(wrong.isEmpty(), "KTS digest set or refusal moved: " + wrong);
    }

    /**
     * Every accepted digest derives a KEK that wraps and unwraps a real CEK, on
     * both ciphers. Acceptance at init is not support.
     */
    @Test
    public void everyAcceptedDigestWrapsAndUnwrapsOnBothCiphers() throws Exception
    {
        for (String transformation : CIPHERS)
        {
            KeyPair kp = pairFor(transformation);
            for (Object[] row : ACCEPTED)
            {
                ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) row[0];
                String label = transformation + "/" + row[1];
                SecretKey key = cek();
                // ONE otherInfo, shared by both specs: it feeds the KEK, so two
                // draws would make the unwrap fail for the wrong reason.
                byte[] otherInfo = new byte[16];
                RANDOM.nextBytes(otherInfo);
                KTSParameterSpec s = spec(oid, otherInfo);

                Cipher wrap = Cipher.getInstance(transformation, JSL);
                wrap.init(Cipher.WRAP_MODE, kp.getPublic(), s, RANDOM);
                byte[] wrapped = wrap.wrap(key);

                Cipher unwrap = Cipher.getInstance(transformation, JSL);
                unwrap.init(Cipher.UNWRAP_MODE, kp.getPrivate(), s, RANDOM);
                Assertions.assertTrue(Arrays.areEqual(key.getEncoded(),
                                unwrap.unwrap(wrapped, "AES", Cipher.SECRET_KEY).getEncoded()),
                        label + ": must round-trip a real CEK");

                // A cipher ignoring the digest would satisfy the line above, so
                // require the digest to reach the KEK: the same otherInfo under
                // a DIFFERENT digest must not recover it.
                ASN1ObjectIdentifier other = oid.equals(NISTObjectIdentifiers.id_sha256)
                        ? NISTObjectIdentifiers.id_sha512 : NISTObjectIdentifiers.id_sha256;
                Cipher wrongDigest = Cipher.getInstance(transformation, JSL);
                wrongDigest.init(Cipher.UNWRAP_MODE, kp.getPrivate(), spec(other, otherInfo), RANDOM);
                boolean recovered;
                try
                {
                    recovered = Arrays.areEqual(key.getEncoded(),
                            wrongDigest.unwrap(wrapped, "AES", Cipher.SECRET_KEY).getEncoded());
                }
                catch (InvalidKeyException e)
                {
                    recovered = false;   // the key-wrap integrity check refused it
                }
                Assertions.assertFalse(recovered,
                        label + ": another digest must not unwrap it, or the digest is "
                                + "not reaching the derivation");
            }
        }
    }

    /**
     * The SHAKE block length is the KDF block length, and it must equal
     * BouncyCastle's — they agree at 32 and 64 today, which is why a derivation
     * matches BC beyond the first block. A bcprov bump that moved either number
     * would otherwise change every derived KEK with nothing failing.
     */
    @Test
    public void theShakeBlockLengthsMatchBouncyCastle() throws Exception
    {
        Assertions.assertEquals(32, new SHAKEDigest(128).getDigestSize(), "BC SHAKE-128 block");
        Assertions.assertEquals(64, new SHAKEDigest(256).getDigestSize(), "BC SHAKE-256 block");
        Assertions.assertEquals(new SHAKEDigest(128).getDigestSize(),
                MessageDigest.getInstance("SHAKE-128", JSL).getDigestLength(),
                "our SHAKE-128 squeeze must equal BouncyCastle's");
        Assertions.assertEquals(new SHAKEDigest(256).getDigestSize(),
                MessageDigest.getInstance("SHAKE-256", JSL).getDigestLength(),
                "our SHAKE-256 squeeze must equal BouncyCastle's");
    }
}
