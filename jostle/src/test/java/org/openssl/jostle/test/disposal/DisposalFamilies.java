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

package org.openssl.jostle.test.disposal;

import org.openssl.jostle.disposal.NativeReference;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.ProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Drives one instance of every {@code NativeReference} family through the
 * PUBLIC JCA surface, so the reconciliation test measures the handles a caller
 * actually produces rather than handles a test allocated by hand.
 *
 * <p>A family is the class that declares the {@code NativeReference} wrapper.
 * The provider registers SUBCLASSES for most families (every symmetric cipher
 * is a {@code BlockCipherSpi} subclass, every RSA signature an
 * {@code RSASignatureSpiBase} subclass), so the family of a service is found by
 * walking its LOADED class hierarchy, never by its own simple name.
 *
 * <p>One driver per family. The wrapper and its disposer are declared by the
 * family class and by nothing below it, so a subclass adds no handle of its own;
 * the source census in the reconciliation test holds that true.
 *
 * <p>Only MessageDigest, Mac, SecureRandom and KeyStore use a DISCOVERED
 * algorithm name (the alphabetically first the family serves). Every other
 * driver names its algorithm, because it needs a key, a pair or a parameter set.
 *
 * <p>A family the provider does not register yields no driver, which is how
 * JSLFIPS legitimately has fewer than JSL.
 */
public final class DisposalFamilies
{
    private DisposalFamilies()
    {
    }

    /** Where a key is borrowed from when the target provider refuses to make one. */
    private static final String BASE_PROVIDER = "JSL";

    /**
     * The typed refusal a module raises for DSA key generation; the
     * KeyPairGenerator appends advice, so the match is on this prefix.
     */
    static final String DSA_KEYGEN_REFUSED =
            "DSA key generation is not supported by the loaded provider;"
                    + " DSA key import and signature verification remain available";

    /** The typed refusal a verify-only module raises at {@code initSign}. */
    static final String DSA_SIGN_REFUSED =
            "DSA signature generation is not supported by the loaded provider;"
                    + " signature verification remains available";

    /** One family, and the smallest real use of it. */
    public abstract static class Driver
    {
        private final String family;
        private final String algorithm;
        private volatile String detail = "";

        protected Driver(String family, String algorithm)
        {
            this.family = family;
            this.algorithm = algorithm;
        }

        /** The simple name of the class declaring the family's NativeReference. */
        public final String family()
        {
            return family;
        }

        public final String algorithm()
        {
            return algorithm;
        }

        /** How the last drive went where a module can change it, e.g. the key source and direction. */
        public final String detail()
        {
            return detail;
        }

        protected final void detail(String value)
        {
            detail = value;
        }

        /** Creates one instance, uses it once, and returns it for the caller to drop. */
        public abstract Object driveOnce() throws Exception;

        @Override
        public String toString()
        {
            return family + "(" + algorithm + (detail.isEmpty() ? "" : "; " + detail) + ")";
        }
    }

    /**
     * Family -> the alphabetically first algorithm any service of that family serves.
     *
     * <p>Alphabetically first, NOT first enumerated: {@code getServices()} order
     * differs by JDK, so enumeration order drove different algorithms per leg.
     */
    public static Map<String, String> familiesOf(Provider provider)
    {
        ClassLoader loader = provider.getClass().getClassLoader();
        Map<String, String> byFamily = new LinkedHashMap<String, String>();
        for (Provider.Service s : provider.getServices())
        {
            String family = familyOf(s, loader);
            if (family == null)
            {
                continue;
            }
            String current = byFamily.get(family);
            if (current == null || s.getAlgorithm().compareTo(current) < 0)
            {
                byFamily.put(family, s.getAlgorithm());
            }
        }
        return byFamily;
    }

    /** The family of a registered service, or null when nothing in its hierarchy holds a handle. */
    static String familyOf(Provider.Service s, ClassLoader loader)
    {
        Class<?> spi;
        try
        {
            spi = Class.forName(s.getClassName(), false, loader);
        }
        catch (ClassNotFoundException e)
        {
            throw new IllegalStateException(s.getType() + "." + s.getAlgorithm()
                    + " is registered with a class that does not load: " + s.getClassName(), e);
        }
        for (Class<?> k = spi; k != null && k != Object.class; k = k.getSuperclass())
        {
            if (NativeReference.class.isAssignableFrom(k) || declaresNativeReference(k))
            {
                return k.getSimpleName();
            }
        }
        return null;
    }

    private static boolean declaresNativeReference(Class<?> k)
    {
        for (Class<?> inner : k.getDeclaredClasses())
        {
            if (NativeReference.class.isAssignableFrom(inner) || declaresNativeReference(inner))
            {
                return true;
            }
        }
        return false;
    }

    private static final class Keys
    {
        private final Map<String, KeyPair> cache = new LinkedHashMap<String, KeyPair>();
        private final Map<String, String> source = new LinkedHashMap<String, String>();
        private final Provider provider;

        private Keys(Provider provider)
        {
            this.provider = provider;
        }

        private KeyPair of(String algorithm) throws Exception
        {
            KeyPair kp = cache.get(algorithm);
            if (kp == null)
            {
                kp = generate(algorithm);
                cache.put(algorithm, kp);
            }
            return kp;
        }

        /** "generated" or "imported", once {@link #of} has been asked. */
        private String source(String algorithm)
        {
            return source.get(algorithm);
        }

        /**
         * Generates under this provider; on the pinned DSA keygen refusal only,
         * generates under the base provider and imports through this one.
         */
        private KeyPair generate(String algorithm) throws Exception
        {
            try
            {
                KeyPair kp = KeyPairGenerator.getInstance(algorithm, provider).generateKeyPair();
                source.put(algorithm, "generated");
                return kp;
            }
            catch (ProviderException refused)
            {
                String msg = refused.getMessage();
                Provider base = Security.getProvider(BASE_PROVIDER);
                if (msg == null || !msg.startsWith(DSA_KEYGEN_REFUSED) || base == null || base == provider)
                {
                    throw refused;
                }
                KeyPair borrowed = KeyPairGenerator.getInstance(algorithm, base).generateKeyPair();
                KeyFactory kf = KeyFactory.getInstance(algorithm, provider);
                source.put(algorithm, "imported");
                return new KeyPair(
                        kf.generatePublic(new X509EncodedKeySpec(borrowed.getPublic().getEncoded())),
                        kf.generatePrivate(new PKCS8EncodedKeySpec(borrowed.getPrivate().getEncoded())));
            }
        }
    }

    /**
     * Builds a driver per family the provider registers. Families absent from
     * the provider are absent from the list, by construction.
     */
    public static List<Driver> drivers(final Provider provider) throws Exception
    {
        final Keys keys = new Keys(provider);
        final Map<String, String> byFamily = familiesOf(provider);
        List<Driver> out = new ArrayList<Driver>();

        add(out, byFamily, "MDServiceSPI", new Maker()
        {
            public Driver make(final String alg)
            {
                return new Driver("MDServiceSPI", alg)
                {
                    public Object driveOnce() throws Exception
                    {
                        MessageDigest md = MessageDigest.getInstance(alg, provider);
                        md.update(new byte[32]);
                        md.digest();
                        return md;
                    }
                };
            }
        });

        add(out, byFamily, "MacServiceSPI", new Maker()
        {
            public Driver make(final String alg)
            {
                return new Driver("MacServiceSPI", alg)
                {
                    public Object driveOnce() throws Exception
                    {
                        Mac mac = Mac.getInstance(alg, provider);
                        mac.init(new SecretKeySpec(new byte[32], alg));
                        mac.update(new byte[16]);
                        mac.doFinal();
                        return mac;
                    }
                };
            }
        });

        add(out, byFamily, "RandServiceSPI", new Maker()
        {
            public Driver make(final String alg)
            {
                return new Driver("RandServiceSPI", alg)
                {
                    public Object driveOnce() throws Exception
                    {
                        SecureRandom r = SecureRandom.getInstance(alg, provider);
                        r.nextBytes(new byte[16]);
                        return r;
                    }
                };
            }
        });

        addCipher(out, byFamily, provider, "BlockCipherSpi", "AES/CBC/PKCS5Padding", 16);
        addCipher(out, byFamily, provider, "CCMCipherSpi", "AES/CCM/NoPadding", 12);

        addSignature(out, byFamily, provider, keys, "RSASignatureSpiBase", "SHA256withRSA", "RSA");
        addSignature(out, byFamily, provider, keys, "ECDSASignatureSpi", "SHA256withECDSA", "EC");
        addSignature(out, byFamily, provider, keys, "DSASignatureSpi", "SHA256withDSA", "DSA");
        addSignature(out, byFamily, provider, keys, "EdSignatureSpi", "ED25519", "ED25519");
        addSignature(out, byFamily, provider, keys, "MLDSASignatureSpi", "ML-DSA-65", "ML-DSA-65");
        // The bare mechanism needs a parameter spec; 128F is the cheapest to key.
        addSignature(out, byFamily, provider, keys, "SLHDSASignatureSpi",
                "SLH-DSA-SHA2-128F", "SLH-DSA-SHA2-128F");

        addAgreement(out, byFamily, provider, keys, "ECDHKeyAgreementSpi", "ECDH", "EC");
        addAgreement(out, byFamily, provider, keys, "DHKeyAgreementSpi", "DH", "DH");
        addAgreement(out, byFamily, provider, keys, "XDHKeyAgreementSpi", "X25519", "X25519");

        addRsaCipher(out, byFamily, provider, keys, "RSAOAEPCipherSpi",
                "RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        addRsaCipher(out, byFamily, provider, keys, "RSAPKCS1CipherSpi", "RSA/ECB/PKCS1Padding");

        add(out, byFamily, "KSServiceSPI", new Maker()
        {
            public Driver make(final String alg)
            {
                return new Driver("KSServiceSPI", alg)
                {
                    public Object driveOnce() throws Exception
                    {
                        KeyStore ks = KeyStore.getInstance(alg, provider);
                        ks.load(null, "password".toCharArray());
                        return ks;
                    }
                };
            }
        });

        // PKEYKeySpec is not a registered service: every asymmetric key holds one,
        // so generating a pair produces two.
        if (provider.getService("KeyPairGenerator", "EC") != null)
        {
            out.add(new Driver("PKEYKeySpec", "EC")
            {
                public Object driveOnce() throws Exception
                {
                    return KeyPairGenerator.getInstance("EC", provider).generateKeyPair();
                }
            });
        }

        return out;
    }

    private interface Maker
    {
        Driver make(String algorithm);
    }

    private static void add(List<Driver> out, Map<String, String> byFamily, String family, Maker maker)
    {
        String alg = byFamily.get(family);
        if (alg != null)
        {
            out.add(maker.make(alg));
        }
    }

    private static void addCipher(List<Driver> out, Map<String, String> byFamily,
                                  final Provider provider, String family,
                                  final String transformation, final int ivLen)
    {
        if (!byFamily.containsKey(family))
        {
            return;
        }
        out.add(new Driver(family, transformation)
        {
            public Object driveOnce() throws Exception
            {
                Cipher c = Cipher.getInstance(transformation, provider);
                c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[16], "AES"),
                        new IvParameterSpec(new byte[ivLen]));
                c.doFinal(new byte[16]);
                return c;
            }
        });
    }

    private static void addRsaCipher(List<Driver> out, Map<String, String> byFamily,
                                     final Provider provider, final Keys keys,
                                     String family, final String transformation)
    {
        if (!byFamily.containsKey(family))
        {
            return;
        }
        out.add(new Driver(family, transformation)
        {
            public Object driveOnce() throws Exception
            {
                Cipher c = Cipher.getInstance(transformation, provider);
                c.init(Cipher.ENCRYPT_MODE, keys.of("RSA").getPublic());
                c.doFinal(new byte[16]);
                detail(keys.source("RSA"));
                return c;
            }
        });
    }

    private static void addSignature(List<Driver> out, Map<String, String> byFamily,
                                     final Provider provider, final Keys keys, String family,
                                     final String alg, final String keyAlg)
    {
        if (!byFamily.containsKey(family))
        {
            return;
        }
        out.add(new Driver(family, alg)
        {
            public Object driveOnce() throws Exception
            {
                Signature s = Signature.getInstance(alg, provider);
                KeyPair kp = keys.of(keyAlg);
                String direction;
                try
                {
                    s.initSign(kp.getPrivate());
                    direction = "sign";
                }
                catch (InvalidKeyException refused)
                {
                    // Only the pinned verify-only refusal falls back; anything else is a defect.
                    if (!DSA_SIGN_REFUSED.equals(refused.getMessage()))
                    {
                        throw refused;
                    }
                    s.initVerify(kp.getPublic());
                    direction = "verify only";
                }
                s.update(new byte[32]);
                if (direction.equals("sign"))
                {
                    s.sign();
                }
                else
                {
                    try
                    {
                        s.verify(new byte[64]);
                    }
                    catch (SignatureException unparseable)
                    {
                        // A DER signature these bytes are not; the handle was used either way.
                    }
                }
                detail(keys.source(keyAlg) + ", " + direction);
                return s;
            }
        });
    }

    private static void addAgreement(List<Driver> out, Map<String, String> byFamily,
                                     final Provider provider, final Keys keys, String family,
                                     final String alg, final String keyAlg)
    {
        if (!byFamily.containsKey(family))
        {
            return;
        }
        out.add(new Driver(family, alg)
        {
            public Object driveOnce() throws Exception
            {
                KeyAgreement ka = KeyAgreement.getInstance(alg, provider);
                KeyPair a = keys.of(keyAlg);
                KeyPair b = KeyPairGenerator.getInstance(keyAlg, provider).generateKeyPair();
                ka.init(a.getPrivate());
                ka.doPhase(b.getPublic(), true);
                ka.generateSecret();
                detail(keys.source(keyAlg));
                return ka;
            }
        });
    }
}
