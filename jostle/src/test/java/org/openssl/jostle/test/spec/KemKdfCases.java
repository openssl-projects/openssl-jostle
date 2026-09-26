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

package org.openssl.jostle.test.spec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.junit.jupiter.api.Assertions;
import org.openssl.jostle.jcajce.SecretKeyWithEncapsulation;
import org.openssl.jostle.jcajce.spec.KEMExtractSpec;
import org.openssl.jostle.jcajce.spec.KEMGenerateSpec;

import javax.crypto.KeyGenerator;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

/**
 * The KEM {@code KeyGenerator} key-derivation cells, shared by the base and FIPS test classes so both providers
 * run the same rows. A null {@code kdf} below means no KDF.
 */
public final class KemKdfCases
{
    public static final String[] ML_KEM = {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"};
    public static final String[] HYBRIDS = {"X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024",
            "X448MLKEM1024"};

    /** BouncyCastle's default: X9.44 KDF3 with SHA-256. */
    public static final AlgorithmIdentifier KDF3_SHA256 = kdf(X9ObjectIdentifiers.id_kdf_kdf3,
            NISTObjectIdentifiers.id_sha256);

    /** One of each accepted KDF family and digest. */
    public static final AlgorithmIdentifier[] KDFS = {
            kdf(X9ObjectIdentifiers.id_kdf_kdf2, NISTObjectIdentifiers.id_sha256),
            kdf(X9ObjectIdentifiers.id_kdf_kdf3, NISTObjectIdentifiers.id_sha512),
            kdf(X9ObjectIdentifiers.id_kdf_kdf3, NISTObjectIdentifiers.id_shake128),
            kdf(X9ObjectIdentifiers.id_kdf_kdf2, NISTObjectIdentifiers.id_shake256),
            new AlgorithmIdentifier(PKCSObjectIdentifiers.id_alg_hkdf_with_sha256),
            new AlgorithmIdentifier(PKCSObjectIdentifiers.id_alg_hkdf_with_sha384),
            new AlgorithmIdentifier(PKCSObjectIdentifiers.id_alg_hkdf_with_sha512),
            new AlgorithmIdentifier(NISTObjectIdentifiers.id_shake256),
    };

    private KemKdfCases()
    {
    }

    public static AlgorithmIdentifier kdf(ASN1ObjectIdentifier kdf, ASN1ObjectIdentifier digest)
    {
        return new AlgorithmIdentifier(kdf, new AlgorithmIdentifier(digest));
    }

    public static KEMGenerateSpec ourGenerate(PublicKey pub, int bits, AlgorithmIdentifier kdf, byte[] otherInfo)
        throws Exception
    {
        KEMGenerateSpec.Builder b = KEMGenerateSpec.builder().withPublicKey(pub).withAlgorithmName("AES")
                .withKeySizeInBits(bits).withOtherInfo(otherInfo);
        return (kdf == null ? b.withNoKdf() : b.withKdfAlgorithm(kdf.getEncoded())).build();
    }

    public static KEMExtractSpec ourExtract(PrivateKey priv, byte[] enc, int bits, AlgorithmIdentifier kdf,
                                            byte[] otherInfo)
        throws Exception
    {
        KEMExtractSpec.Builder b = KEMExtractSpec.builder().withPrivate(priv).withEncapsulatedKey(enc)
                .withAlgorithmName("AES").withKeySizeInBits(bits).withOtherInfo(otherInfo);
        return (kdf == null ? b.withNoKdf() : b.withKdfAlgorithm(kdf.getEncoded())).build();
    }

    private static org.bouncycastle.jcajce.spec.KEMGenerateSpec bcGenerate(PublicKey pub, int bits,
                                                                           AlgorithmIdentifier kdf, byte[] other)
    {
        org.bouncycastle.jcajce.spec.KEMGenerateSpec.Builder b =
                new org.bouncycastle.jcajce.spec.KEMGenerateSpec.Builder(pub, "AES", bits).withOtherInfo(other);
        return (kdf == null ? b.withNoKdf() : b.withKdfAlgorithm(kdf)).build();
    }

    private static org.bouncycastle.jcajce.spec.KEMExtractSpec bcExtract(PrivateKey priv, byte[] enc, int bits,
                                                                         AlgorithmIdentifier kdf, byte[] other)
    {
        org.bouncycastle.jcajce.spec.KEMExtractSpec.Builder b =
                new org.bouncycastle.jcajce.spec.KEMExtractSpec.Builder(priv, enc, "AES", bits).withOtherInfo(other);
        return (kdf == null ? b.withNoKdf() : b.withKdfAlgorithm(kdf)).build();
    }

    /**
     * One ML-KEM cell against BouncyCastle, both directions: ours encapsulates and BouncyCastle extracts, then
     * the reverse, on keys carried across as encodings.
     *
     * @return a line for the log.
     */
    public static String agreeWithBc(Provider ours, Provider bc, String name, int bits, AlgorithmIdentifier kdf,
                                     byte[] otherInfo)
        throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance(name, ours).generateKeyPair();
        KeyFactory bcKf = KeyFactory.getInstance(name, bc);
        PublicKey bcPub = bcKf.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));
        PrivateKey bcPriv = bcKf.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));
        String what = name + " " + bits + " bits, kdf " + (kdf == null ? "none" : kdf.getAlgorithm().getId());

        KeyGenerator g = KeyGenerator.getInstance(name, ours);
        g.init(ourGenerate(kp.getPublic(), bits, kdf, otherInfo));
        SecretKeyWithEncapsulation sent = (SecretKeyWithEncapsulation) g.generateKey();
        KeyGenerator x = KeyGenerator.getInstance(name, bc);
        x.init(bcExtract(bcPriv, sent.getEncapsulation(), bits, kdf, otherInfo));
        Assertions.assertArrayEquals(sent.getEncoded(), x.generateKey().getEncoded(), what + ": ours to BC");
        Assertions.assertEquals((bits + 7) / 8, sent.getEncoded().length, what + ": key length");

        KeyGenerator bg = KeyGenerator.getInstance(name, bc);
        bg.init(bcGenerate(bcPub, bits, kdf, otherInfo));
        org.bouncycastle.jcajce.SecretKeyWithEncapsulation bcSent =
                (org.bouncycastle.jcajce.SecretKeyWithEncapsulation) bg.generateKey();
        KeyGenerator ox = KeyGenerator.getInstance(name, ours);
        ox.init(ourExtract(kp.getPrivate(), bcSent.getEncapsulation(), bits, kdf, otherInfo));
        Assertions.assertArrayEquals(bcSent.getEncoded(), ox.generateKey().getEncoded(), what + ": BC to ours");
        return what;
    }

    /**
     * Generates and then extracts on one key pair and one encapsulation, and asserts both halves produce the same
     * key.
     *
     * @return the key.
     */
    public static byte[] bothHalves(Provider ours, KeyPair kp, String name, int bits, AlgorithmIdentifier kdf,
                                    byte[] otherInfo)
        throws Exception
    {
        KeyGenerator g = KeyGenerator.getInstance(name, ours);
        g.init(ourGenerate(kp.getPublic(), bits, kdf, otherInfo));
        SecretKeyWithEncapsulation sent = (SecretKeyWithEncapsulation) g.generateKey();
        KeyGenerator x = KeyGenerator.getInstance(name, ours);
        x.init(ourExtract(kp.getPrivate(), sent.getEncapsulation(), bits, kdf, otherInfo));
        byte[] got = x.generateKey().getEncoded();
        Assertions.assertArrayEquals(sent.getEncoded(), got, name + " " + bits + " bits: the two halves differ");
        return got;
    }

    /**
     * A hybrid cell: the default-KDF key equals KDF3 with SHA-256, computed here from the raw shared secret of
     * the same encapsulation, and both halves agree. BouncyCastle serves no hybrid, so the reference is the
     * specification's own recurrence over a JDK digest.
     */
    public static String hybridDefaultIsKdf3(Provider ours, String name, int bits, byte[] otherInfo)
        throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance(name, ours).generateKeyPair();
        KeyGenerator g = KeyGenerator.getInstance(name, ours);
        g.init(ourGenerate(kp.getPublic(), bits, KDF3_SHA256, otherInfo));
        SecretKeyWithEncapsulation sent = (SecretKeyWithEncapsulation) g.generateKey();

        int secretLen = ((org.openssl.jostle.jcajce.interfaces.OSSLKey) kp.getPublic()).getSpec().getSpecNI()
                .encapSecretLength(((org.openssl.jostle.jcajce.interfaces.OSSLKey) kp.getPublic()).getSpec()
                        .getReference(), null, org.openssl.jostle.test.TestUtil.RNDSrc);
        KeyGenerator raw = KeyGenerator.getInstance(name, ours);
        raw.init(ourExtract(kp.getPrivate(), sent.getEncapsulation(), secretLen * 8, null, null));
        byte[] z = raw.generateKey().getEncoded();

        KeyGenerator x = KeyGenerator.getInstance(name, ours);
        x.init(ourExtract(kp.getPrivate(), sent.getEncapsulation(), bits, KDF3_SHA256, otherInfo));
        byte[] extracted = x.generateKey().getEncoded();

        byte[] expected = kdf3Sha256(z, otherInfo, (bits + 7) / 8);
        Assertions.assertArrayEquals(expected, sent.getEncoded(), name + " " + bits + " bits: sender is not KDF3");
        Assertions.assertArrayEquals(expected, extracted, name + " " + bits + " bits: receiver is not KDF3");
        return name + " " + bits + " bits over a " + secretLen + "-byte secret";
    }

    /** X9.44 KDF3: Hash(counter || Z || otherInfo), counter from 1, over the JDK's own SHA-256. */
    static byte[] kdf3Sha256(byte[] z, byte[] otherInfo, int len) throws Exception
    {
        MessageDigest md = MessageDigest.getInstance("SHA-256", "SUN");
        byte[] out = new byte[len];
        int off = 0;
        for (int counter = 1; off < len; counter++)
        {
            md.update(new byte[]{(byte) (counter >>> 24), (byte) (counter >>> 16), (byte) (counter >>> 8),
                    (byte) counter});
            md.update(z);
            if (otherInfo != null)
            {
                md.update(otherInfo);
            }
            byte[] h = md.digest();
            int n = Math.min(h.length, len - off);
            System.arraycopy(h, 0, out, off, n);
            off += n;
        }
        return out;
    }

    /**
     * The sizing rows of the secret-producer rule for one KEM, on both spec types. {@code secretBits} is the held
     * size; the caller learns it from the provider.
     *
     * @return one line per row, for the log.
     */
    public static List<String> sizingRows(Provider ours, String name, int secretBits) throws Exception
    {
        List<String> rows = new ArrayList<String>();
        KeyPair kp = KeyPairGenerator.getInstance(name, ours).generateKeyPair();

        // The held size, no KDF: the raw secret on both halves.
        rows.add("held " + secretBits + ": " + bothHalves(ours, kp, name, secretBits, null, null).length + " bytes");

        // MORE than held, no KDF: refused at init on both spec types, naming both sizes.
        for (int bits : new int[]{secretBits + 1, secretBits + 8, secretBits * 2, 32768})
        {
            String message = "KEM key size " + bits + " bits is larger than the " + secretBits
                    + "-bit shared secret, and no KDF is set";
            refusedAtInit(ours, name, kp, bits, null, message);
            rows.add("no KDF, " + bits + ": refused at init on both halves");
        }
        // MORE than held, with the default KDF: derived, both halves equal.
        for (int bits : new int[]{secretBits + 1, secretBits + 8, secretBits * 2, 32768})
        {
            rows.add("KDF3, " + bits + ": " + bothHalves(ours, kp, name, bits, KDF3_SHA256, null).length + " bytes");
        }
        // LESS than held, no KDF: a prefix of the raw secret on both halves.
        byte[] held = bothHalves(ours, kp, name, secretBits, null, null);
        for (int bits : new int[]{secretBits - 1, secretBits - 8, 8})
        {
            KeyGenerator g = KeyGenerator.getInstance(name, ours);
            g.init(ourGenerate(kp.getPublic(), secretBits, null, null));
            SecretKeyWithEncapsulation sent = (SecretKeyWithEncapsulation) g.generateKey();
            KeyGenerator whole = KeyGenerator.getInstance(name, ours);
            whole.init(ourExtract(kp.getPrivate(), sent.getEncapsulation(), secretBits, null, null));
            byte[] z = whole.generateKey().getEncoded();
            KeyGenerator part = KeyGenerator.getInstance(name, ours);
            part.init(ourExtract(kp.getPrivate(), sent.getEncapsulation(), bits, null, null));
            byte[] cut = part.generateKey().getEncoded();
            Assertions.assertArrayEquals(java.util.Arrays.copyOf(z, (bits + 7) / 8), cut,
                    name + " " + bits + " bits: not a prefix of the secret");
            rows.add("no KDF, " + bits + ": prefix, " + bothHalves(ours, kp, name, bits, null, null).length
                    + " bytes on both halves");
        }
        Assertions.assertEquals(secretBits / 8, held.length);
        // Zero and negative: refused at init on both spec types, with or without a KDF.
        for (int bits : new int[]{0, -1, -8})
        {
            for (AlgorithmIdentifier kdf : new AlgorithmIdentifier[]{null, KDF3_SHA256})
            {
                refusedAtInit(ours, name, kp, bits, kdf, "KEM key size in bits out of range [1, 32768]: " + bits);
            }
            rows.add(bits + ": refused at init on both halves");
        }
        // Not a whole number of bytes: rounded up, as BouncyCastle does.
        for (int bits : new int[]{7, 12})
        {
            rows.add("KDF3, " + bits + " bits: " + bothHalves(ours, kp, name, bits, KDF3_SHA256, null).length
                    + " bytes");
        }
        return rows;
    }

    /** Both spec types refuse {@code bits} at init with exactly {@code message}. */
    public static void refusedAtInit(Provider ours, String name, KeyPair kp, int bits, AlgorithmIdentifier kdf,
                                     String message)
        throws Exception
    {
        final KeyGenerator g = KeyGenerator.getInstance(name, ours);
        final KEMGenerateSpec gs = ourGenerate(kp.getPublic(), bits, kdf, null);
        InvalidAlgorithmParameterException e = Assertions.assertThrows(InvalidAlgorithmParameterException.class,
                () -> g.init(gs), name + " " + bits + ": generate side");
        Assertions.assertEquals(message, e.getMessage());

        final KeyGenerator x = KeyGenerator.getInstance(name, ours);
        final KEMExtractSpec xs = ourExtract(kp.getPrivate(), new byte[1], bits, kdf, null);
        e = Assertions.assertThrows(InvalidAlgorithmParameterException.class,
                () -> x.init(xs), name + " " + bits + ": extract side");
        Assertions.assertEquals(message, e.getMessage());
    }

    /** @return the held shared-secret size in bits, asked of the provider's library through a fresh key. */
    public static int secretBits(Provider ours, String name) throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance(name, ours).generateKeyPair();
        org.openssl.jostle.jcajce.spec.PKEYKeySpec spec =
                ((org.openssl.jostle.jcajce.interfaces.OSSLKey) kp.getPublic()).getSpec();
        return spec.getSpecNI().encapSecretLength(spec.getReference(), null, org.openssl.jostle.test.TestUtil.RNDSrc)
                * 8;
    }
}
