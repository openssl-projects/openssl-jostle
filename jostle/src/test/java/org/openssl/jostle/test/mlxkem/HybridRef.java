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

package org.openssl.jostle.test.mlxkem;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.agreement.X25519Agreement;
import org.bouncycastle.crypto.agreement.X448Agreement;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import org.bouncycastle.crypto.generators.X448KeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.crypto.params.X448KeyGenerationParameters;
import org.bouncycastle.crypto.params.X448PublicKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.util.BigIntegers;
import org.openssl.jostle.jcajce.spec.MLXKEMParameterSpec;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * An INDEPENDENT implementation of the four TLS hybrid KEM groups
 * (draft-ietf-tls-ecdhe-mlkem), built from BouncyCastle's separate ML-KEM and
 * ECDH primitives and this file's own reading of the draft.
 *
 * <p>It exists because BouncyCastle registers no JCE name for these groups.
 * Its {@code MLKEM768-X25519-SHA3-256} family is the <i>composite</i> ML-KEM
 * draft, which combines the two secrets through a SHA3-256 KDF — a different
 * construction that does not interoperate. Per the testing guide's rule that a
 * missing BC JCE name is not a reason to skip agreement testing, the fallback
 * is the specification's own composition against independent primitives.
 *
 * <p>The construction under test is deliberately simple, which is exactly why
 * the reference is worth having: the two shared secrets are CONCATENATED, not
 * combined, so the only things Jostle can get wrong are the component
 * algorithms, the split points, and the ORDER. This class states all three
 * independently of the production code.
 */
public final class HybridRef
{
    /**
     * Does the ML-KEM half come first in this group's key share, ciphertext
     * and shared secret?
     *
     * <p>Stated here as the test's OWN reading of the draft, deliberately not
     * read from {@link MLXKEMParameterSpec#isMlkemFirst()} — that flag is one
     * of the things under test, and a reference that consulted it would agree
     * with a flipped implementation. OpenSSL encodes the same fact as
     * {@code ml_kem_slot} in {@code mlx_kmgmt.c}.
     */
    public static final Map<String, Boolean> MLKEM_FIRST = new HashMap<String, Boolean>();

    static
    {
        MLKEM_FIRST.put("X25519MLKEM768", Boolean.TRUE);
        MLKEM_FIRST.put("X448MLKEM1024", Boolean.TRUE);
        MLKEM_FIRST.put("SecP256r1MLKEM768", Boolean.FALSE);
        MLKEM_FIRST.put("SecP384r1MLKEM1024", Boolean.FALSE);
    }

    private HybridRef()
    {
    }

    /** One side's key material for a hybrid group, held as BC primitives. */
    public static final class Party
    {
        final MLXKEMParameterSpec spec;
        final AsymmetricCipherKeyPair kem;
        final AsymmetricCipherKeyPair ecdh;
        /** The raw hybrid key share, in this group's order. */
        public final byte[] share;
        /** Length of the ECDH half, measured from the generated key. */
        public final int ecdhLen;

        private Party(MLXKEMParameterSpec spec, AsymmetricCipherKeyPair kem,
                      AsymmetricCipherKeyPair ecdh, byte[] kemPub, byte[] ecdhPub)
        {
            this.spec = spec;
            this.kem = kem;
            this.ecdh = ecdh;
            this.ecdhLen = ecdhPub.length;
            this.share = mlkemFirst(spec) ? cat(kemPub, ecdhPub) : cat(ecdhPub, kemPub);
        }

        public static Party generate(MLXKEMParameterSpec spec, SecureRandom random)
        {
            MLKEMKeyPairGenerator kg = new MLKEMKeyPairGenerator();
            kg.init(new MLKEMKeyGenerationParameters(random, mlkemParameters(spec)));
            AsymmetricCipherKeyPair kem = kg.generateKeyPair();

            AsymmetricCipherKeyPair ecdh = generateEcdh(spec, random);

            return new Party(spec, kem, ecdh,
                    ((MLKEMPublicKeyParameters) kem.getPublic()).getEncoded(),
                    encodeEcdhPublic(spec, ecdh.getPublic()));
        }

        /**
         * Decapsulate an encapsulation produced against {@link #share},
         * entirely with BC primitives.
         */
        public byte[] decapsulate(byte[] encapsulation)
        {
            byte[][] halves = split(spec, encapsulation, ecdhLen);
            byte[] kemSecret = new MLKEMExtractor((MLKEMPrivateKeyParameters) kem.getPrivate())
                    .extractSecret(halves[0]);
            byte[] ecdhSecret = agree(spec, ecdh.getPrivate(), halves[1]);
            return mlkemFirst(spec) ? cat(kemSecret, ecdhSecret) : cat(ecdhSecret, kemSecret);
        }
    }

    /**
     * Encapsulate against a hybrid key share using BC primitives only: ML-KEM
     * encapsulation against the ML-KEM half, and an ephemeral ECDH against the
     * ECDH half.
     *
     * @return {@code {encapsulation, sharedSecret}}
     */
    public static byte[][] encapsulate(MLXKEMParameterSpec spec, byte[] share, SecureRandom random)
    {
        // The ECDH half's length is MEASURED from a freshly generated key of
        // the same group rather than transcribed, so the split point cannot
        // drift from what the curve actually produces.
        AsymmetricCipherKeyPair ephemeral = generateEcdh(spec, random);
        byte[] ephemeralPub = encodeEcdhPublic(spec, ephemeral.getPublic());

        byte[][] halves = split(spec, share, ephemeralPub.length);

        SecretWithEncapsulation kemPart = new MLKEMGenerator(random).generateEncapsulated(
                new MLKEMPublicKeyParameters(mlkemParameters(spec), halves[0]));
        byte[] ecdhSecret = agree(spec, ephemeral.getPrivate(), halves[1]);

        byte[] encapsulation = mlkemFirst(spec)
                ? cat(kemPart.getEncapsulation(), ephemeralPub)
                : cat(ephemeralPub, kemPart.getEncapsulation());
        byte[] secret = mlkemFirst(spec)
                ? cat(kemPart.getSecret(), ecdhSecret)
                : cat(ecdhSecret, kemPart.getSecret());

        return new byte[][]{encapsulation, secret};
    }

    /**
     * Split a concatenated share or ciphertext into {@code {mlkemHalf,
     * ecdhHalf}}, using the measured ECDH length and this class's own view of
     * the ordering.
     */
    public static byte[][] split(MLXKEMParameterSpec spec, byte[] blob, int ecdhLen)
    {
        if (mlkemFirst(spec))
        {
            return new byte[][]{
                    Arrays.copyOfRange(blob, 0, blob.length - ecdhLen),
                    Arrays.copyOfRange(blob, blob.length - ecdhLen, blob.length)};
        }
        return new byte[][]{
                Arrays.copyOfRange(blob, ecdhLen, blob.length),
                Arrays.copyOfRange(blob, 0, ecdhLen)};
    }

    /**
     * The length of this group's ECDH half, MEASURED by generating a key of
     * the right curve rather than transcribed. Also the length of the ECDH
     * half of an encapsulation, which carries an ephemeral public point in the
     * same encoding.
     */
    public static int ecdhPublicLength(MLXKEMParameterSpec spec, SecureRandom random)
    {
        return encodeEcdhPublic(spec, generateEcdh(spec, random).getPublic()).length;
    }

    public static boolean mlkemFirst(MLXKEMParameterSpec spec)
    {
        Boolean b = MLKEM_FIRST.get(spec.getName());
        if (b == null)
        {
            throw new IllegalStateException("HybridRef has no ordering for " + spec.getName()
                    + " — a new group was registered without a reference entry");
        }
        return b.booleanValue();
    }

    public static MLKEMParameters mlkemParameters(MLXKEMParameterSpec spec)
    {
        if (spec.getName().endsWith("768"))
        {
            return MLKEMParameters.ml_kem_768;
        }
        if (spec.getName().endsWith("1024"))
        {
            return MLKEMParameters.ml_kem_1024;
        }
        throw new IllegalStateException("no ML-KEM parameter set for " + spec.getName());
    }

    private static AsymmetricCipherKeyPair generateEcdh(MLXKEMParameterSpec spec, SecureRandom random)
    {
        String name = spec.getName();
        if (name.startsWith("X25519"))
        {
            X25519KeyPairGenerator g = new X25519KeyPairGenerator();
            g.init(new X25519KeyGenerationParameters(random));
            return g.generateKeyPair();
        }
        if (name.startsWith("X448"))
        {
            X448KeyPairGenerator g = new X448KeyPairGenerator();
            g.init(new X448KeyGenerationParameters(random));
            return g.generateKeyPair();
        }
        ECKeyPairGenerator g = new ECKeyPairGenerator();
        g.init(new ECKeyGenerationParameters(domain(spec), random));
        return g.generateKeyPair();
    }

    private static byte[] encodeEcdhPublic(MLXKEMParameterSpec spec, AsymmetricKeyParameter pub)
    {
        if (pub instanceof X25519PublicKeyParameters)
        {
            return ((X25519PublicKeyParameters) pub).getEncoded();
        }
        if (pub instanceof X448PublicKeyParameters)
        {
            return ((X448PublicKeyParameters) pub).getEncoded();
        }
        // Uncompressed point, which is what the TLS ECDHE share carries.
        return ((ECPublicKeyParameters) pub).getQ().getEncoded(false);
    }

    private static byte[] agree(MLXKEMParameterSpec spec, AsymmetricKeyParameter priv, byte[] peerPublic)
    {
        String name = spec.getName();
        if (name.startsWith("X25519"))
        {
            X25519Agreement a = new X25519Agreement();
            a.init(priv);
            byte[] out = new byte[a.getAgreementSize()];
            a.calculateAgreement(new X25519PublicKeyParameters(peerPublic, 0), out, 0);
            return out;
        }
        if (name.startsWith("X448"))
        {
            X448Agreement a = new X448Agreement();
            a.init(priv);
            byte[] out = new byte[a.getAgreementSize()];
            a.calculateAgreement(new X448PublicKeyParameters(peerPublic, 0), out, 0);
            return out;
        }
        ECDomainParameters dom = domain(spec);
        ECDHBasicAgreement a = new ECDHBasicAgreement();
        a.init(priv);
        // Fixed-length big-endian to the field size: the raw BigInteger would
        // lose a leading zero byte roughly once in 256 agreements.
        return BigIntegers.asUnsignedByteArray(a.getFieldSize(),
                a.calculateAgreement(new ECPublicKeyParameters(dom.getCurve().decodePoint(peerPublic), dom)));
    }

    private static ECDomainParameters domain(MLXKEMParameterSpec spec)
    {
        String curve = spec.getName().startsWith("SecP256r1") ? "P-256" : "P-384";
        X9ECParameters x9 = CustomNamedCurves.getByName(curve);
        return new ECDomainParameters(x9.getCurve(), x9.getG(), x9.getN(), x9.getH());
    }

    public static byte[] cat(byte[] a, byte[] b)
    {
        byte[] r = new byte[a.length + b.length];
        System.arraycopy(a, 0, r, 0, a.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }
}
