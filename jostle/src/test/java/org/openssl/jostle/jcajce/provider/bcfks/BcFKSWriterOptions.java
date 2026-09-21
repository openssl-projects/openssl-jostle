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

package org.openssl.jostle.jcajce.provider.bcfks;

import org.junit.jupiter.api.Assertions;
import org.openssl.jostle.jcajce.BCFKSLoadStoreParameter;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The one table the BCFKS agreement classes drive: every writer option, and
 * every entry type, with the per-row facts a cell needs.
 *
 * <p>One source, so the base and FIPS classes cannot drift apart on what the
 * surface is. A row that the FIPS provider cannot serve says so in the row
 * rather than being dropped, and the FIPS class asserts the refusal -- an
 * absent row and a refused row look identical from a green run otherwise.
 */
public final class BcFKSWriterOptions
{
    private BcFKSWriterOptions()
    {
    }

    /** How a row configures OUR writer. */
    public interface Configure
    {
        BCFKSLoadStoreParameter.Builder apply(BCFKSLoadStoreParameter.Builder builder);
    }

    /**
     * How the same row configures BOUNCYCASTLE's writer. Without this column a
     * BC-writes-we-read cell drives BC's defaults every time, so the option is
     * never exercised in that direction and nine rows write one store.
     */
    public interface ConfigureBc
    {
        org.bouncycastle.jcajce.BCFKSLoadStoreParameter.Builder apply(
                org.bouncycastle.jcajce.BCFKSLoadStoreParameter.Builder builder);
    }

    /** One writer configuration. */
    public static final class Option
    {
        public final String name;
        public final Configure configure;
        /** The same option on BouncyCastle's builder; every row has one. */
        public final ConfigureBc configureBc;
        /** False when the FIPS provider cannot serve this option at all. */
        public final boolean servedOnFips;
        /** The message the FIPS write must carry when {@code servedOnFips} is false. */
        public final String fipsRefusal;

        Option(String name, boolean servedOnFips, String fipsRefusal, Configure configure,
               ConfigureBc configureBc)
        {
            this.name = name;
            this.servedOnFips = servedOnFips;
            this.fipsRefusal = fipsRefusal;
            this.configure = configure;
            this.configureBc = configureBc;
        }
    }

    private static final Map<String, Option> OPTIONS = buildOptions();

    private static Map<String, Option> buildOptions()
    {
        Map<String, Option> t = new LinkedHashMap<String, Option>();
        put(t, new Option("default", true, null, new Configure()
        {
            public BCFKSLoadStoreParameter.Builder apply(BCFKSLoadStoreParameter.Builder b)
            {
                return b;
            }
        }, new ConfigureBc()
        {
            public org.bouncycastle.jcajce.BCFKSLoadStoreParameter.Builder apply(
                    org.bouncycastle.jcajce.BCFKSLoadStoreParameter.Builder b)
            {
                return b;
            }
        }));
        for (final BCFKSLoadStoreParameter.EncryptionAlgorithm algorithm
                : BCFKSLoadStoreParameter.EncryptionAlgorithm.values())
        {
            put(t, new Option("encryption " + algorithm, true, null, new Configure()
            {
                public BCFKSLoadStoreParameter.Builder apply(BCFKSLoadStoreParameter.Builder b)
                {
                    return b.withStoreEncryptionAlgorithm(algorithm);
                }
            }, new ConfigureBc()
            {
                public org.bouncycastle.jcajce.BCFKSLoadStoreParameter.Builder apply(
                        org.bouncycastle.jcajce.BCFKSLoadStoreParameter.Builder b)
                {
                    return b.withStoreEncryptionAlgorithm(
                            org.bouncycastle.jcajce.BCFKSLoadStoreParameter.EncryptionAlgorithm
                                    .valueOf(algorithm.name()));
                }
            }));
        }
        for (final BCFKSLoadStoreParameter.MacAlgorithm algorithm
                : BCFKSLoadStoreParameter.MacAlgorithm.values())
        {
            put(t, new Option("mac " + algorithm, true, null, new Configure()
            {
                public BCFKSLoadStoreParameter.Builder apply(BCFKSLoadStoreParameter.Builder b)
                {
                    return b.withStoreMacAlgorithm(algorithm);
                }
            }, new ConfigureBc()
            {
                public org.bouncycastle.jcajce.BCFKSLoadStoreParameter.Builder apply(
                        org.bouncycastle.jcajce.BCFKSLoadStoreParameter.Builder b)
                {
                    return b.withStoreMacAlgorithm(
                            org.bouncycastle.jcajce.BCFKSLoadStoreParameter.MacAlgorithm
                                    .valueOf(algorithm.name()));
                }
            }));
        }
        for (final BCFKSLoadStoreParameter.PBKDF2Config.PRF prf
                : BCFKSLoadStoreParameter.PBKDF2Config.PRF.values())
        {
            put(t, new Option("pbkdf2 prf " + prf, true, null, new Configure()
            {
                public BCFKSLoadStoreParameter.Builder apply(BCFKSLoadStoreParameter.Builder b)
                {
                    return b.withStorePBKDFConfig(new BCFKSLoadStoreParameter.PBKDF2Config.Builder()
                            .withIterationCount(2048).withPRF(prf).build());
                }
            }, new ConfigureBc()
            {
                public org.bouncycastle.jcajce.BCFKSLoadStoreParameter.Builder apply(
                        org.bouncycastle.jcajce.BCFKSLoadStoreParameter.Builder b)
                {
                    return b.withStorePBKDFConfig(
                            new org.bouncycastle.crypto.util.PBKDF2Config.Builder()
                                    .withIterationCount(2048).withPRF(bcPrf(prf)).build());
                }
            }));
        }
        // The module has no scrypt, so this row is IMPOSSIBLE under FIPS rather
        // than absent, and the FIPS class asserts the refusal by this message.
        put(t, new Option("scrypt N=1024 r=8 p=1", false,
                "BCFKS store cannot write scrypt, which this provider does not serve", new Configure()
        {
            public BCFKSLoadStoreParameter.Builder apply(BCFKSLoadStoreParameter.Builder b)
            {
                return b.withStorePBKDFConfig(
                        new BCFKSLoadStoreParameter.ScryptConfig.Builder(1024, 8, 1).build());
            }
        }, new ConfigureBc()
        {
            public org.bouncycastle.jcajce.BCFKSLoadStoreParameter.Builder apply(
                    org.bouncycastle.jcajce.BCFKSLoadStoreParameter.Builder b)
            {
                return b.withStorePBKDFConfig(
                        new org.bouncycastle.crypto.util.ScryptConfig.Builder(1024, 8, 1).build());
            }
        }));
        return t;
    }

    /** Our PRF name to BouncyCastle's AlgorithmIdentifier constant for the same PRF. */
    static org.bouncycastle.asn1.x509.AlgorithmIdentifier bcPrf(
            BCFKSLoadStoreParameter.PBKDF2Config.PRF prf)
    {
        switch (prf)
        {
        case SHA512:
            return org.bouncycastle.crypto.util.PBKDF2Config.PRF_SHA512;
        case SHA3_512:
            return org.bouncycastle.crypto.util.PBKDF2Config.PRF_SHA3_512;
        default:
            return Assertions.fail("no BouncyCastle PRF constant for " + prf);
        }
    }

    private static void put(Map<String, Option> t, Option o)
    {
        Assertions.assertNull(t.put(o.name, o), "duplicate writer option: " + o.name);
    }

    public static Map<String, Option> options()
    {
        return OPTIONS;
    }

    // ---- Entry types -------------------------------------------------------

    /** Puts one entry of a given type into a store. */
    public interface EntrySetter
    {
        void set(KeyStore store, Certificate certificate, char[] password) throws Exception;
    }

    /** One {@code ObjectData} type, and how to write one. */
    public static final class EntryType
    {
        public final int type;
        public final String name;
        public final String alias;
        public final EntrySetter setter;

        EntryType(int type, String name, String alias, EntrySetter setter)
        {
            this.type = type;
            this.name = name;
            this.alias = alias;
            this.setter = setter;
        }
    }

    private static Map<Integer, EntryType> buildEntryTypes(final String provider)
    {
        Map<Integer, EntryType> t = new LinkedHashMap<Integer, EntryType>();
        t.put(Integer.valueOf(BcFKSFormat.ObjectData.TYPE_CERTIFICATE),
                new EntryType(BcFKSFormat.ObjectData.TYPE_CERTIFICATE, "CERTIFICATE", "cert",
                        new EntrySetter()
                        {
                            public void set(KeyStore store, Certificate certificate, char[] password)
                                throws Exception
                            {
                                store.setCertificateEntry("cert", certificate);
                            }
                        }));
        t.put(Integer.valueOf(BcFKSFormat.ObjectData.TYPE_PRIVATE_KEY),
                new EntryType(BcFKSFormat.ObjectData.TYPE_PRIVATE_KEY, "PRIVATE_KEY", "priv",
                        new EntrySetter()
                        {
                            public void set(KeyStore store, Certificate certificate, char[] password)
                                throws Exception
                            {
                                KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", provider);
                                generator.initialize(new ECGenParameterSpec("secp256r1"));
                                KeyPair pair = generator.generateKeyPair();
                                store.setKeyEntry("priv", pair.getPrivate(), password,
                                        new Certificate[]{certificate});
                            }
                        }));
        t.put(Integer.valueOf(BcFKSFormat.ObjectData.TYPE_SECRET_KEY),
                new EntryType(BcFKSFormat.ObjectData.TYPE_SECRET_KEY, "SECRET_KEY", "secret",
                        new EntrySetter()
                        {
                            public void set(KeyStore store, Certificate certificate, char[] password)
                                throws Exception
                            {
                                javax.crypto.KeyGenerator generator =
                                        javax.crypto.KeyGenerator.getInstance("AES", provider);
                                generator.init(256);
                                store.setKeyEntry("secret", generator.generateKey(), password, null);
                            }
                        }));
        t.put(Integer.valueOf(BcFKSFormat.ObjectData.TYPE_PROTECTED_PRIVATE_KEY),
                new EntryType(BcFKSFormat.ObjectData.TYPE_PROTECTED_PRIVATE_KEY,
                        "PROTECTED_PRIVATE_KEY", "protectedPriv", new EntrySetter()
                        {
                            public void set(KeyStore store, Certificate certificate, char[] password)
                                throws Exception
                            {
                                // The caller's own bytes, stored verbatim; only
                                // the EncryptedPrivateKeyInfo shape is checked.
                                store.setKeyEntry("protectedPriv", protectedPrivateKeyBytes(),
                                        new Certificate[]{certificate});
                            }
                        }));
        t.put(Integer.valueOf(BcFKSFormat.ObjectData.TYPE_PROTECTED_SECRET_KEY),
                new EntryType(BcFKSFormat.ObjectData.TYPE_PROTECTED_SECRET_KEY,
                        "PROTECTED_SECRET_KEY", "protectedSecret", new EntrySetter()
                        {
                            public void set(KeyStore store, Certificate certificate, char[] password)
                                throws Exception
                            {
                                store.setKeyEntry("protectedSecret", new byte[]{1, 2, 3, 4}, null);
                            }
                        }));
        t.put(Integer.valueOf(BcFKSFormat.ObjectData.TYPE_PBKDF_KEY),
                new EntryType(BcFKSFormat.ObjectData.TYPE_PBKDF_KEY, "PBKDF_KEY", "pbkdf",
                        new EntrySetter()
                        {
                            public void set(KeyStore store, Certificate certificate, char[] password)
                                throws Exception
                            {
                                javax.crypto.SecretKeyFactory factory = javax.crypto.SecretKeyFactory
                                        .getInstance("PBKDF2WITHHMACSHA512", provider);
                                Key key = factory.generateSecret(new javax.crypto.spec.PBEKeySpec(
                                        "entry password".toCharArray(),
                                        "sixteen byte salt".getBytes("UTF-8"), 4096, 256));
                                store.setKeyEntry("pbkdf", key, password, null);
                            }
                        }));
        return t;
    }

    /** A well-formed {@code EncryptedPrivateKeyInfo}; the shape is all that is checked. */
    static byte[] protectedPrivateKeyBytes()
    {
        return org.openssl.jostle.util.asn1.Der.encryptedPrivateKeyInfo(
                org.openssl.jostle.util.asn1.Der.algorithmIdentifier("1.2.840.113549.1.5.13",
                        org.openssl.jostle.util.asn1.Der.nullValue()),
                new byte[32]);
    }

    /**
     * Every {@code ObjectData} type, built through {@code provider}. Asserted
     * complete against the format's own constants, so a type added there
     * without a row here fails rather than going undriven.
     */
    public static Map<Integer, EntryType> entryTypes(String provider)
    {
        Map<Integer, EntryType> t = buildEntryTypes(provider);
        int[] declared = {BcFKSFormat.ObjectData.TYPE_CERTIFICATE,
                BcFKSFormat.ObjectData.TYPE_PRIVATE_KEY,
                BcFKSFormat.ObjectData.TYPE_SECRET_KEY,
                BcFKSFormat.ObjectData.TYPE_PROTECTED_PRIVATE_KEY,
                BcFKSFormat.ObjectData.TYPE_PROTECTED_SECRET_KEY,
                BcFKSFormat.ObjectData.TYPE_PBKDF_KEY};
        for (int type : declared)
        {
            Assertions.assertTrue(t.containsKey(Integer.valueOf(type)),
                    "the format declares entry type " + type + " and this table has no row for it");
        }
        Assertions.assertEquals(declared.length, t.size(),
                "this table carries a row the format does not declare");
        return t;
    }

    // ---- Signature-check algorithms ----------------------------------------

    /** The key algorithm a SignatureCheck algorithm needs. */
    public static String keyAlgorithmFor(BCFKSLoadStoreParameter.SignatureAlgorithm algorithm)
    {
        String name = algorithm.name();
        if (name.contains("ECDSA"))
        {
            return "EC";
        }
        return name.contains("DSA") ? "DSA" : "RSA";
    }
}
