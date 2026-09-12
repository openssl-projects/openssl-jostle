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
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
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
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

/**
 * What each KTS cipher accepts as a KDF digest, and how each refuses, pinned
 * verbatim so the narrowing that follows cannot move anything silently.
 *
 * <p>Two divergences are pinned as measured, not corrected: ML-KEM KTS accepts
 * SHA-224 and SHA-1 where RSA-KTS-KEM-KWS accepts neither, and the same
 * rejected OID draws two differently-worded refusals.
 *
 * <p>SHA-1 is reachable end to end, not merely accepted at init — see
 * {@link #theSha1KdfDerivesAWorkingKekOnMlKem}.
 *
 * <p>Driven through {@code Cipher}, never reflection, so each leg measures the
 * multi-release copy it loads.
 */
public class KtsKdfDigestPinTest
{
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String JSL = JostleProvider.PROVIDER_NAME;

    /** Accepted by RSA-KTS-KEM-KWS and by ML-KEM KTS alike. */
    private static final ASN1ObjectIdentifier[] SHARED = {
            NISTObjectIdentifiers.id_sha256,
            NISTObjectIdentifiers.id_sha384,
            NISTObjectIdentifiers.id_sha512,
    };

    /** Accepted by ML-KEM KTS only. The divergence, as measured. */
    private static final ASN1ObjectIdentifier[] MLKEM_ONLY = {
            NISTObjectIdentifiers.id_sha224,
            OIWObjectIdentifiers.idSHA1,
    };

    /** Refused by both, so it pins each refusal against the same input. */
    private static final ASN1ObjectIdentifier REFUSED_BY_BOTH = NISTObjectIdentifiers.id_sha3_256;

    @BeforeAll
    public static void setUp()
    {
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    private static String rsaRefusal(String oid)
    {
        return "unsupported KDF digest " + oid
                + "; RSA-KTS-KEM-KWS supports SHA-256, SHA-384 and SHA-512";
    }

    private static String mlKemRefusal(String oid)
    {
        return "unsupported KDF digest: " + oid;
    }

    /** KDF2 over the named digest; KDF3 shares the parameter shape exactly. */
    private static KTSParameterSpec spec(ASN1ObjectIdentifier digest, byte[] otherInfo)
    {
        AlgorithmIdentifier kdf = new AlgorithmIdentifier(X9ObjectIdentifiers.id_kdf_kdf2,
                new AlgorithmIdentifier(digest, DERNull.INSTANCE));
        return new KTSParameterSpec.Builder("AESWRAP", 256, otherInfo).withKdfAlgorithm(kdf).build();
    }

    /**
     * For the cells that only need SOME spec. Never for a comparison between
     * two specs: otherInfo feeds the KEK, so two draws would differ whatever
     * the digest did and the comparison would pass vacuously.
     */
    private static KTSParameterSpec spec(ASN1ObjectIdentifier digest)
    {
        byte[] otherInfo = new byte[16];
        RANDOM.nextBytes(otherInfo);
        return spec(digest, otherInfo);
    }

    private static KeyPair rsaPair() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", JSL);
        kpg.initialize(2048, RANDOM);
        return kpg.generateKeyPair();
    }

    private static KeyPair mlKemPair() throws Exception
    {
        return KeyPairGenerator.getInstance("ML-KEM-768", JSL).generateKeyPair();
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

    /**
     * RSA-KTS-KEM-KWS takes SHA-256, SHA-384 and SHA-512 and nothing else,
     * refusing SHA-224, SHA-1 and SHA3-256 with one sentence each.
     */
    @Test
    public void rsaKtsAcceptsExactlyThreeDigests() throws Exception
    {
        KeyPair kp = rsaPair();
        List<String> wrong = new ArrayList<String>();
        // An emptied SHARED would make the accept loop iterate nothing and the
        // cell pass on no evidence.
        Assertions.assertEquals(3, SHARED.length, "three digests are accepted");

        for (ASN1ObjectIdentifier oid : SHARED)
        {
            String refusal = refusalFrom("RSA-KTS-KEM-KWS", kp, oid);
            if (refusal != null)
            {
                wrong.add(oid.getId() + ": expected accepted, refused with [" + refusal + "]");
            }
        }

        List<ASN1ObjectIdentifier> refused = new ArrayList<ASN1ObjectIdentifier>();
        refused.add(MLKEM_ONLY[0]);
        refused.add(MLKEM_ONLY[1]);
        refused.add(REFUSED_BY_BOTH);
        for (ASN1ObjectIdentifier oid : refused)
        {
            String refusal = refusalFrom("RSA-KTS-KEM-KWS", kp, oid);
            if (!rsaRefusal(oid.getId()).equals(refusal))
            {
                wrong.add(oid.getId() + ": expected [" + rsaRefusal(oid.getId())
                        + "], got [" + refusal + "]");
            }
        }

        Assertions.assertTrue(wrong.isEmpty(), "RSA-KTS digest set moved: " + wrong);
    }

    /**
     * ML-KEM KTS takes those three AND SHA-224 AND SHA-1 — the divergence — and
     * refuses SHA3-256 with its own, differently-worded sentence.
     */
    @Test
    public void mlKemKtsAcceptsExactlyFiveDigests() throws Exception
    {
        KeyPair kp = mlKemPair();
        List<String> wrong = new ArrayList<String>();

        List<ASN1ObjectIdentifier> accepted = new ArrayList<ASN1ObjectIdentifier>();
        for (ASN1ObjectIdentifier oid : SHARED)
        {
            accepted.add(oid);
        }
        for (ASN1ObjectIdentifier oid : MLKEM_ONLY)
        {
            accepted.add(oid);
        }
        // Same vacuity floor as the RSA cell.
        Assertions.assertEquals(5, accepted.size(), "five digests are accepted");

        for (ASN1ObjectIdentifier oid : accepted)
        {
            String refusal = refusalFrom("ML-KEM", kp, oid);
            if (refusal != null)
            {
                wrong.add(oid.getId() + ": expected accepted, refused with [" + refusal + "]");
            }
        }

        String got = refusalFrom("ML-KEM", kp, REFUSED_BY_BOTH);
        if (!mlKemRefusal(REFUSED_BY_BOTH.getId()).equals(got))
        {
            wrong.add(REFUSED_BY_BOTH.getId() + ": expected ["
                    + mlKemRefusal(REFUSED_BY_BOTH.getId()) + "], got [" + got + "]");
        }

        Assertions.assertTrue(wrong.isEmpty(), "ML-KEM KTS digest set moved: " + wrong);
    }

    /**
     * SHA-1 is not merely accepted at init — it derives a key-encryption key
     * that wraps and unwraps a real CEK. So the finding is about a reachable
     * path, not a dead branch in a reader.
     */
    @Test
    public void theSha1KdfDerivesAWorkingKekOnMlKem() throws Exception
    {
        KeyPair kp = mlKemPair();
        SecretKey key = cek();
        // ONE otherInfo, shared by both specs below: it feeds the KEK, so two
        // draws would make the wrong-digest unwrap fail for the wrong reason.
        byte[] otherInfo = new byte[16];
        RANDOM.nextBytes(otherInfo);
        KTSParameterSpec sha1 = spec(OIWObjectIdentifiers.idSHA1, otherInfo);

        Cipher wrap = Cipher.getInstance("ML-KEM", JSL);
        wrap.init(Cipher.WRAP_MODE, kp.getPublic(), sha1, RANDOM);
        byte[] wrapped = wrap.wrap(key);

        Cipher unwrap = Cipher.getInstance("ML-KEM", JSL);
        unwrap.init(Cipher.UNWRAP_MODE, kp.getPrivate(), sha1, RANDOM);
        SecretKey back = (SecretKey) unwrap.unwrap(wrapped, "AES", Cipher.SECRET_KEY);

        Assertions.assertTrue(Arrays.areEqual(key.getEncoded(), back.getEncoded()),
                "the SHA-1 KDF must derive the same KEK on both sides, or this "
                        + "path is not reachable and the finding is theoretical");
        // A cipher that ignored the digest entirely would satisfy the line
        // above too, so require the digest to actually reach the KEK: the same
        // wrap must NOT come back through SHA-256.
        Cipher wrongDigest = Cipher.getInstance("ML-KEM", JSL);
        wrongDigest.init(Cipher.UNWRAP_MODE, kp.getPrivate(),
                spec(NISTObjectIdentifiers.id_sha256, otherInfo), RANDOM);
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
                "a SHA-1 wrap must not unwrap under SHA-256, or the digest is "
                        + "not reaching the derivation at all");
    }

    /**
     * The two divergences stated as one assertion each, so the commit that
     * reconciles them must delete this cell rather than quietly pass it.
     */
    @Test
    public void theTwoCiphersDisagreeOnTheSetAndOnTheWording() throws Exception
    {
        KeyPair rsa = rsaPair();
        KeyPair mlKem = mlKemPair();

        for (ASN1ObjectIdentifier oid : MLKEM_ONLY)
        {
            Assertions.assertNull(refusalFrom("ML-KEM", mlKem, oid),
                    oid.getId() + ": ML-KEM KTS accepts it today");
            Assertions.assertEquals(rsaRefusal(oid.getId()),
                    refusalFrom("RSA-KTS-KEM-KWS", rsa, oid),
                    oid.getId() + ": RSA-KTS refuses it today");
        }

        String fromRsa = refusalFrom("RSA-KTS-KEM-KWS", rsa, REFUSED_BY_BOTH);
        String fromMlKem = refusalFrom("ML-KEM", mlKem, REFUSED_BY_BOTH);
        Assertions.assertNotNull(fromRsa);
        Assertions.assertNotNull(fromMlKem);
        Assertions.assertNotEquals(fromRsa, fromMlKem,
                "the same rejected OID must still draw two different sentences");
    }
}
