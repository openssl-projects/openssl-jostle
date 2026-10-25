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
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.spec.KTSParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.io.IOException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Fixtures shared by the RSA-KEM test classes: the provider hook, the shared key pair, the provider-agnostic
 * KTSParameterSpec description and the wrap and unwrap helpers. {@link RSAKEMCipherTest} holds the single-provider
 * contract and {@link RSAKEMAgreementTest} the comparisons with BouncyCastle; each has a FIPS subclass.
 */
public abstract class RSAKEMFixtures
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
            NISTObjectIdentifiers.id_shake128,
            NISTObjectIdentifiers.id_shake256,
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
            c.init(Cipher.UNWRAP_MODE, kp.getPrivate(),
                    kdf3Spec(256, null, NISTObjectIdentifiers.id_sha256).forProvider(providerName()));
            return true;
        }
        catch (InvalidKeyException e)
        {
            return false;
        }
    }

    /**
     * Provider-agnostic description of a KTSParameterSpec. BC and Jostle each
     * accept only their OWN spec type directly (no more reflection), so a
     * single spec object cannot drive both providers any more - this
     * descriptor builds the right one, from the same content, at
     * {@link #forProvider(String)} time.
     */
    protected static final class KtsSpec
    {
        private final String keyAlgorithmName;
        private final int keySizeInBits;
        private final byte[] otherInfo;
        /** null means {@code withNoKdf()}. */
        private final AlgorithmIdentifier kdf;

        KtsSpec(String keyAlgorithmName, int keySizeInBits, byte[] otherInfo, AlgorithmIdentifier kdf)
        {
            this.keyAlgorithmName = keyAlgorithmName;
            this.keySizeInBits = keySizeInBits;
            this.otherInfo = otherInfo;
            this.kdf = kdf;
        }

        public AlgorithmParameterSpec forProvider(String provider) throws IOException
        {
            if (BC.equals(provider))
            {
                // KTSParameterSpec is qualified where BouncyCastle's is meant: jostle's of that name is imported
                org.bouncycastle.jcajce.spec.KTSParameterSpec.Builder b =
                        new org.bouncycastle.jcajce.spec.KTSParameterSpec.Builder(
                                keyAlgorithmName, keySizeInBits, otherInfo);
                return kdf == null ? b.withNoKdf().build() : b.withKdfAlgorithm(kdf).build();
            }
            KTSParameterSpec.Builder b = new KTSParameterSpec.Builder(keyAlgorithmName, keySizeInBits, otherInfo);
            return kdf == null ? b.withNoKdf().build() : b.withKdfAlgorithm(kdf.getEncoded()).build();
        }
    }

    protected static KtsSpec kdf3Spec(int keyBits, byte[] otherInfo, ASN1ObjectIdentifier digestOid)
    {
        return new KtsSpec("AESWRAP", keyBits, otherInfo,
                new AlgorithmIdentifier(X9ObjectIdentifiers.id_kdf_kdf3, new AlgorithmIdentifier(digestOid)));
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

    protected static SecretKey randomCek(SecureRandom sr) throws Exception
    {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256, sr);
        return kg.generateKey();
    }

    protected byte[] wrap(String provider, KeyPair kp, KtsSpec spec, SecretKey cek)
        throws Exception
    {
        return wrap(provider, kp.getPublic(), spec, cek);
    }

    /**
     * Key-level overload. Needed by the FIPS subclass, where the two providers
     * do not share key objects and the public half has to be re-decoded before
     * use - so the wrapping key is not the one in the caller's KeyPair.
     */
    protected byte[] wrap(String provider, PublicKey pub, KtsSpec spec, SecretKey cek)
        throws Exception
    {
        Cipher c = Cipher.getInstance(XFORM, provider);
        c.init(Cipher.WRAP_MODE, pub, spec.forProvider(provider));
        return c.wrap(cek);
    }

    protected Key unwrap(String provider, KeyPair kp, KtsSpec spec, byte[] wrapped)
        throws Exception
    {
        return unwrap(provider, kp.getPrivate(), spec, wrapped);
    }

    /** Key-level overload; see {@link #wrap(String, PublicKey, KtsSpec, SecretKey)}. */
    protected Key unwrap(String provider, PrivateKey priv, KtsSpec spec, byte[] wrapped)
        throws Exception
    {
        Cipher c = Cipher.getInstance(XFORM, provider);
        c.init(Cipher.UNWRAP_MODE, priv, spec.forProvider(provider));
        return c.unwrap(wrapped, "AES", Cipher.SECRET_KEY);
    }
}
