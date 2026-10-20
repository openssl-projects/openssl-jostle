/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.ks;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.ContentInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS12PfxPdu;
import org.bouncycastle.pkcs.PKCS12PfxPduBuilder;
import org.bouncycastle.pkcs.PKCS12SafeBag;
import org.bouncycastle.pkcs.PKCS12SafeBagBuilder;
import org.bouncycastle.pkcs.PKCS12SafeBagFactory;
import org.bouncycastle.pkcs.jcajce.JcaPKCS12SafeBagBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCS12MacCalculatorBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEOutputEncryptorBuilder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import javax.crypto.spec.SecretKeySpec;

/**
 * The PKCS#12 keystore against the JDK's SUN and BouncyCastle on the contract
 * points where they were measured: an alias holding a NUL, a certificate entry
 * over a secret entry, the trusted-certificate attribute, chains written as
 * loose certificate bags, a load with a null password, and a store this build
 * cannot read. Each cell pins the references' half beside ours.
 */
public class PKCS12ContractAgreementTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    /** The JDK's own PKCS12 key store: provider SUN from JDK 9, SunJSSE on JDK 8. */
    private static final String SUN = jdkPkcs12Provider();
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final char[] P1 = "password-one".toCharArray();
    private static final char[] P2 = "password-two".toCharArray();

    /** Oracle's trusted-key-usage attribute, which the JDK requires on a trusted certificate bag. */
    private static final ASN1ObjectIdentifier TRUSTED_KEY_USAGE =
            new ASN1ObjectIdentifier("2.16.840.1.113894.746875.1.1");

    @BeforeAll
    public static void before()
    {
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    // ------------------------------------------------------------- fixtures

    /** A root, an intermediate and an end entity, EC P-256, with CA extensions on the two CAs. */
    private static final class Chain
    {
        final KeyPair rootKeys;
        final KeyPair intKeys;
        final KeyPair eeKeys;
        final X509Certificate root;
        final X509Certificate intermediate;
        final X509Certificate ee;

        Chain() throws Exception
        {
            rootKeys = ecKeys();
            intKeys = ecKeys();
            eeKeys = ecKeys();
            root = certificate("CN=Contract Root", rootKeys.getPublic(), "CN=Contract Root",
                    rootKeys.getPrivate(), true);
            intermediate = certificate("CN=Contract Intermediate", intKeys.getPublic(), "CN=Contract Root",
                    rootKeys.getPrivate(), true);
            ee = certificate("CN=Contract End Entity", eeKeys.getPublic(), "CN=Contract Intermediate",
                    intKeys.getPrivate(), false);
        }

        Certificate[] all()
        {
            return new Certificate[]{ee, intermediate, root};
        }
    }

    private static KeyPair ecKeys() throws Exception
    {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC", "SunEC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        return g.generateKeyPair();
    }

    private static X509Certificate certificate(String subject, PublicKey key, String issuer, PrivateKey signer,
                                               boolean ca)
        throws Exception
    {
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(new X500Name(issuer),
                new BigInteger(64, RANDOM).add(BigInteger.ONE), new Date(System.currentTimeMillis() - 3600_000L),
                new Date(System.currentTimeMillis() + 3600_000L), new X500Name(subject), key);
        if (ca)
        {
            b.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        }
        return new JcaX509CertificateConverter().getCertificate(
                b.build(new JcaContentSignerBuilder("SHA256withECDSA").setProvider(BC).build(signer)));
    }

    private static String jdkPkcs12Provider()
    {
        for (String name : new String[]{"SUN", "SunJSSE"})
        {
            Provider p = Security.getProvider(name);
            if (p != null && p.getService("KeyStore", "PKCS12") != null)
            {
                return name;
            }
        }
        throw new IllegalStateException("no JDK PKCS12 key store");
    }

    private static KeyStore empty(String provider) throws Exception
    {
        KeyStore ks = KeyStore.getInstance("PKCS12", provider);
        ks.load(null, null);
        return ks;
    }

    private static KeyStore load(String provider, byte[] file, char[] password) throws Exception
    {
        KeyStore ks = KeyStore.getInstance("PKCS12", provider);
        ks.load(new ByteArrayInputStream(file), password);
        return ks;
    }

    private static byte[] store(KeyStore ks, char[] password) throws Exception
    {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ks.store(out, password);
        return out.toByteArray();
    }

    /**
     * A SUN store under the JDK's PBES2 defaults. JDK 8 still writes a 40-bit
     * RC2 certificate safe, which this build cannot read; the properties make
     * it write what later JDKs write by default, and change nothing there.
     */
    private static byte[] storePbes2(KeyStore ks, char[] password) throws Exception
    {
        String[][] props = {
                {"keystore.pkcs12.certProtectionAlgorithm", "PBEWithHmacSHA256AndAES_256"},
                {"keystore.pkcs12.keyProtectionAlgorithm", "PBEWithHmacSHA256AndAES_256"},
                {"keystore.pkcs12.macAlgorithm", "HmacPBESHA256"}};
        String[] before = new String[props.length];
        for (int i = 0; i < props.length; i++)
        {
            before[i] = System.setProperty(props[i][0], props[i][1]);
        }
        try
        {
            return store(ks, password);
        }
        finally
        {
            for (int i = 0; i < props.length; i++)
            {
                if (before[i] == null)
                {
                    System.clearProperty(props[i][0]);
                }
                else
                {
                    System.setProperty(props[i][0], before[i]);
                }
            }
        }
    }

    private static Set<String> aliases(KeyStore ks) throws Exception
    {
        return new TreeSet<String>(Collections.list(ks.aliases()));
    }

    private static List<String> chainEncodings(KeyStore ks, String alias) throws Exception
    {
        List<String> out = new ArrayList<String>();
        Certificate[] chain = ks.getCertificateChain(alias);
        if (chain != null)
        {
            for (Certificate c : chain)
            {
                out.add(new BigInteger(1, c.getEncoded()).toString(16));
            }
        }
        return out;
    }

    // ------------------------------------------------------------ NUL alias

    /** SUN and BouncyCastle store an alias holding a NUL and read it back whole. */
    @Test
    public void theReferencesAcceptANulAliasAndRoundTripIt() throws Exception
    {
        Chain c = new Chain();
        for (String p : new String[]{SUN, BC})
        {
            KeyStore ks = empty(p);
            ks.setCertificateEntry("a\u0000b", c.root);
            Assertions.assertTrue(ks.containsAlias("a\u0000b"), p);
            Assertions.assertFalse(ks.containsAlias("a"), p);
            Assertions.assertEquals(Collections.singleton("a\u0000b"), aliases(load(p, store(ks, P1), P1)), p);
        }
    }

    /**
     * We refuse an alias holding a NUL on every writer: a C string would end at
     * the NUL, so "a\0b" would otherwise write "a". Every query answers as for
     * an absent alias, which is exact, since no stored alias can hold one, and a
     * refused write leaves nothing behind.
     */
    @Test
    public void weRefuseANulAliasOnEveryWriterAndAnswerAbsentOnEveryQuery() throws Exception
    {
        Chain c = new Chain();
        String nul = "a\u0000b";
        String message = "key store alias or OID contains a NUL character";
        KeyStore ks = empty(JSL);

        KeyStoreException cert = Assertions.assertThrows(KeyStoreException.class,
                () -> ks.setCertificateEntry(nul, c.root));
        Assertions.assertEquals(message, cert.getMessage());
        KeyStoreException key = Assertions.assertThrows(KeyStoreException.class,
                () -> ks.setKeyEntry(nul, c.eeKeys.getPrivate(), P1, c.all()));
        Assertions.assertEquals(message, key.getMessage());
        KeyStoreException secret = Assertions.assertThrows(KeyStoreException.class,
                () -> ks.setEntry(nul, new KeyStore.SecretKeyEntry(new SecretKeySpec(new byte[16], "AES")),
                        new KeyStore.PasswordProtection(P1)));
        Assertions.assertEquals(message, secret.getMessage());

        Assertions.assertFalse(ks.containsAlias(nul));
        Assertions.assertFalse(ks.isKeyEntry(nul));
        Assertions.assertFalse(ks.isCertificateEntry(nul));
        Assertions.assertNull(ks.getKey(nul, P1));
        Assertions.assertNull(ks.getCertificate(nul));
        Assertions.assertNull(ks.getCertificateChain(nul));
        Assertions.assertNull(ks.getCreationDate(nul));
        ks.deleteEntry(nul);

        Assertions.assertFalse(ks.containsAlias("a"), "no truncated write");
        Assertions.assertEquals(0, ks.size());
    }

    // ------------------------------------------------ certificate over secret

    /** A certificate entry over a secret entry is a KeyStoreException on all three. */
    @Test
    public void aCertificateEntryOverASecretEntryIsAKeyStoreException() throws Exception
    {
        Chain c = new Chain();
        for (String p : new String[]{JSL, SUN, BC})
        {
            KeyStore ks = empty(p);
            ks.setEntry("s", new KeyStore.SecretKeyEntry(new SecretKeySpec(new byte[16], "AES")),
                    new KeyStore.PasswordProtection(P1));
            KeyStoreException e = Assertions.assertThrows(KeyStoreException.class,
                    () -> ks.setCertificateEntry("s", c.root), p);
            if (JSL.equals(p))
            {
                Assertions.assertEquals("alias identifies a key entry", e.getMessage());
            }
        }
    }

    // ---------------------------------------------------- trusted attribute

    /**
     * A truststore we write shows its trusted entries to the JDK, which reads a
     * certificate bag as trusted only with Oracle's attribute; the attribute is
     * on the two certificate-entry bags and not on the key entry's chain.
     */
    @Test
    public void ourTruststoreShowsItsEntriesToTheJdk() throws Exception
    {
        Chain c = new Chain();
        KeyStore ks = empty(JSL);
        ks.setKeyEntry("key", c.eeKeys.getPrivate(), P1, c.all());
        ks.setCertificateEntry("root", c.root);
        ks.setCertificateEntry("intermediate", c.intermediate);
        byte[] file = store(ks, P1);

        KeyStore sun = load(SUN, file, P1);
        Assertions.assertEquals(new TreeSet<String>(Arrays.asList("intermediate", "key", "root")),
                aliases(sun));
        Assertions.assertTrue(sun.isCertificateEntry("root"));
        Assertions.assertTrue(sun.isCertificateEntry("intermediate"));
        Assertions.assertArrayEquals(c.root.getEncoded(), sun.getCertificate("root").getEncoded());
        Assertions.assertEquals(3, sun.getCertificateChain("key").length);

        int trusted = 0;
        int certificateBags = 0;
        for (PKCS12SafeBag bag : bags(file, P1))
        {
            if (bag.getBagValue() instanceof X509CertificateHolder)
            {
                certificateBags++;
                if (bag.getAttributes() != null)
                {
                    for (Attribute a : bag.getAttributes())
                    {
                        if (TRUSTED_KEY_USAGE.equals(a.getAttrType()))
                        {
                            trusted++;
                        }
                    }
                }
            }
        }
        Assertions.assertEquals(5, certificateBags, "three chain bags and two certificate entries");
        Assertions.assertEquals(2, trusted, "the attribute is on the certificate entries only");
    }

    private static List<PKCS12SafeBag> bags(byte[] file, char[] password) throws Exception
    {
        List<PKCS12SafeBag> out = new ArrayList<PKCS12SafeBag>();
        PKCS12PfxPdu pfx = new PKCS12PfxPdu(file);
        for (ContentInfo info : pfx.getContentInfos())
        {
            PKCS12SafeBagFactory f = info.getContentType().equals(PKCSObjectIdentifiers.encryptedData)
                    ? new PKCS12SafeBagFactory(info,
                    new JcePKCSPBEInputDecryptorProviderBuilder().setProvider(BC).build(password))
                    : new PKCS12SafeBagFactory(info);
            Collections.addAll(out, f.getSafeBags());
        }
        return out;
    }

    // ------------------------------------------------- chains as loose bags

    /** The file openssl pkcs12 -export wrote: one key entry with its whole chain, on all three. */
    @Test
    public void anOpensslExportedChainIsOneEntryWithItsChain() throws Exception
    {
        byte[] file = resource("ks/openssl-export-chain.p12");
        char[] pw = "changeit".toCharArray();
        List<String> sunChain = chainEncodings(load(SUN, file, pw), "fixture");
        Assertions.assertEquals(3, sunChain.size());
        for (String p : new String[]{JSL, BC})
        {
            KeyStore ks = load(p, file, pw);
            Assertions.assertEquals(Collections.singleton("fixture"), aliases(ks), p);
            Assertions.assertEquals(sunChain, chainEncodings(ks, "fixture"), p);
        }
    }

    /**
     * openssl's bag shape without a MAC, built here: the key and end entity
     * carry a friendlyName and a localKeyId, the CAs are bare bags.
     */
    @Test
    public void anOpensslShapedFileWithoutAMacIsOneEntryWithItsChain() throws Exception
    {
        Chain c = new Chain();
        byte[] file = opensslShaped(c, P1, false);
        assertSameEntriesAndChains(file, P1, SUN, JSL, BC);
    }

    /** The same shape with a MAC, so the two cells differ only in the MAC. */
    @Test
    public void anOpensslShapedFileWithAMacIsOneEntryWithItsChain() throws Exception
    {
        Chain c = new Chain();
        byte[] file = opensslShaped(c, P1, true);
        assertSameEntriesAndChains(file, P1, SUN, JSL, BC);
    }

    /** BouncyCastle's chain bags carry the localKeyId, so nothing moves. */
    @Test
    public void aBouncyCastleFileIsReadAsBouncyCastleReadsIt() throws Exception
    {
        Chain c = new Chain();
        KeyStore bc = KeyStore.getInstance("PKCS12-AES256-AES128", BC);
        bc.load(null, null);
        bc.setKeyEntry("key", c.eeKeys.getPrivate(), P1, c.all());
        bc.setCertificateEntry("root", c.root);
        assertSameEntriesAndChains(store(bc, P1), P1, BC, JSL);
    }

    /**
     * keytool writes through SUN, naming each chain certificate's bag with its
     * subject DN and giving it no localKeyId and no trusted attribute. A named
     * bag is an entry of its own and also completes the key's chain, so we list
     * the two DN-named certificates as BouncyCastle does; SUN lists only the key
     * and the trusted root.
     */
    @Test
    public void aKeytoolFileListsItsNamedChainBagsAsBouncyCastleDoes() throws Exception
    {
        Chain c = new Chain();
        KeyStore sun = empty(SUN);
        sun.setKeyEntry("key", c.eeKeys.getPrivate(), P1, c.all());
        sun.setCertificateEntry("root", c.root);
        byte[] file = storePbes2(sun, P1);
        Set<String> named = new TreeSet<String>(Arrays.asList(
                c.intermediate.getSubjectX500Principal().getName(), c.root.getSubjectX500Principal().getName(),
                "key", "root"));

        Assertions.assertEquals(new TreeSet<String>(Arrays.asList("key", "root")), aliases(load(SUN, file, P1)));
        for (String p : new String[]{JSL, BC})
        {
            KeyStore ks = load(p, file, P1);
            Assertions.assertEquals(named, aliases(ks), p);
            Assertions.assertEquals(3, ks.getCertificateChain("key").length, p);
        }
        Assertions.assertEquals(3, load(SUN, file, P1).getCertificateChain("key").length);
    }

    /**
     * The shape this provider's first release wrote: the key's chain set
     * without its root, every chain bag named after the key, and the root a
     * named entry with no trusted attribute. We keep the root entry and also
     * complete the chain with it, a superset of both references, so a file of
     * that release loses nothing: SUN completes the chain and drops the entry,
     * BouncyCastle keeps the entry and leaves the chain short.
     */
    @Test
    public void aFirstReleaseFileKeepsItsRootEntryAndCompletesTheChain() throws Exception
    {
        Chain c = new Chain();
        byte[] file = firstReleaseShaped(c, P1);

        KeyStore ours = load(JSL, file, P1);
        Assertions.assertEquals(new TreeSet<String>(Arrays.asList("key", "root")), aliases(ours));
        Assertions.assertEquals(3, ours.getCertificateChain("key").length);
        Assertions.assertTrue(ours.isCertificateEntry("root"));

        KeyStore sun = load(SUN, file, P1);
        Assertions.assertEquals(Collections.singleton("key"), aliases(sun));
        Assertions.assertEquals(3, sun.getCertificateChain("key").length);

        KeyStore bc = load(BC, file, P1);
        Assertions.assertEquals(new TreeSet<String>(Arrays.asList("key", "root")), aliases(bc));
        Assertions.assertEquals(2, bc.getCertificateChain("key").length);
    }

    private static byte[] firstReleaseShaped(Chain c, char[] pw) throws Exception
    {
        byte[] id = "key".getBytes("UTF-8");
        PKCS12SafeBagBuilder key = new JcaPKCS12SafeBagBuilder(c.eeKeys.getPrivate(),
                new JcePKCSPBEOutputEncryptorBuilder(NISTObjectIdentifiers.id_aes256_CBC).setProvider(BC).build(pw));
        key.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString("key"));
        key.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId, new DEROctetString(id));
        PKCS12SafeBagBuilder leaf = new JcaPKCS12SafeBagBuilder(c.ee);
        leaf.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString("key"));
        leaf.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId, new DEROctetString(id));
        PKCS12SafeBagBuilder mid = new JcaPKCS12SafeBagBuilder(c.intermediate);
        mid.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString("key"));
        PKCS12SafeBagBuilder top = new JcaPKCS12SafeBagBuilder(c.root);
        top.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString("root"));
        PKCS12PfxPduBuilder pfx = new PKCS12PfxPduBuilder();
        pfx.addData(key.build());
        pfx.addEncryptedData(new JcePKCSPBEOutputEncryptorBuilder(NISTObjectIdentifiers.id_aes128_CBC)
                .setProvider(BC).build(pw), new PKCS12SafeBag[]{leaf.build(), mid.build(), top.build()});
        return pfx.build(new JcePKCS12MacCalculatorBuilder(), pw).getEncoded();
    }

    private static void assertSameEntriesAndChains(byte[] file, char[] pw, String reference, String... others)
        throws Exception
    {
        KeyStore ref = load(reference, file, pw);
        Set<String> names = aliases(ref);
        for (String p : others)
        {
            KeyStore ks = load(p, file, pw);
            Assertions.assertEquals(names, aliases(ks), p + " against " + reference);
            for (String a : names)
            {
                Assertions.assertEquals(ref.isCertificateEntry(a), ks.isCertificateEntry(a), p + " " + a);
                Assertions.assertArrayEquals(ref.getCertificate(a).getEncoded(), ks.getCertificate(a).getEncoded(),
                        p + " certificate of " + a);
                if (ref.isKeyEntry(a))
                {
                    Assertions.assertEquals(chainEncodings(ref, a), chainEncodings(ks, a), p + " chain of " + a);
                }
            }
        }
    }

    private static byte[] opensslShaped(Chain c, char[] pw, boolean mac) throws Exception
    {
        byte[] id = new byte[20];
        RANDOM.nextBytes(id);
        PKCS12SafeBagBuilder key = new JcaPKCS12SafeBagBuilder(c.eeKeys.getPrivate(),
                new JcePKCSPBEOutputEncryptorBuilder(NISTObjectIdentifiers.id_aes256_CBC).setProvider(BC).build(pw));
        key.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString("fixture"));
        key.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId, new DEROctetString(id));
        PKCS12SafeBagBuilder ee = new JcaPKCS12SafeBagBuilder(c.ee);
        ee.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString("fixture"));
        ee.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId, new DEROctetString(id));
        PKCS12PfxPduBuilder pfx = new PKCS12PfxPduBuilder();
        pfx.addEncryptedData(new JcePKCSPBEOutputEncryptorBuilder(NISTObjectIdentifiers.id_aes256_CBC)
                        .setProvider(BC).build(pw),
                new PKCS12SafeBag[]{ee.build(), new JcaPKCS12SafeBagBuilder(c.intermediate).build(),
                        new JcaPKCS12SafeBagBuilder(c.root).build()});
        pfx.addData(key.build());
        PKCS12PfxPdu built = mac
                ? pfx.build(new JcePKCS12MacCalculatorBuilder(), pw)
                : pfx.build(null, pw);
        return built.getEncoded();
    }

    // ------------------------------------------------------- null password

    /**
     * load(stream, null) checks no MAC, skips every encrypted safe and keeps
     * keys and secrets encrypted until asked with their password; a store then
     * writes them back as read. The trusted entry lives in the encrypted
     * certificate safe, which the null load skipped, so neither store ever held
     * it and it is gone after the round trip, as on the JDK.
     */
    @Test
    public void aNullPasswordLoadKeepsKeysEncryptedAndStoresThemAsRead() throws Exception
    {
        for (String writer : new String[]{SUN, JSL})
        {
            Chain c = new Chain();
            KeyStore w = empty(writer);
            w.setKeyEntry("key", c.eeKeys.getPrivate(), P1, c.all());
            w.setCertificateEntry("trusted", c.root);
            if (SUN.equals(writer))
            {
                w.setEntry("secret", new KeyStore.SecretKeyEntry(new SecretKeySpec(new byte[16], "AES")),
                        new KeyStore.PasswordProtection(P1));
            }
            byte[] file = store(w, P1);
            Set<String> held = new TreeSet<String>(aliases(w));
            held.remove("trusted");

            for (String reader : new String[]{SUN, JSL})
            {
                String at = writer + " file, " + reader + ": ";
                KeyStore r = load(reader, file, null);
                Assertions.assertEquals(held, aliases(r), at + "aliases after the null load");
                Assertions.assertTrue(r.isKeyEntry("key"), at);
                Assertions.assertThrows(UnrecoverableKeyException.class, () -> r.getKey("key", P2), at);
                Assertions.assertNotNull(r.getKey("key", P1), at);

                KeyStore back = load(reader, store(r, P2), P2);
                Assertions.assertEquals(held, aliases(back), at + "aliases after store(P2)");
                Assertions.assertNotNull(back.getKey("key", P1), at + "the key keeps its own password");
                Assertions.assertThrows(UnrecoverableKeyException.class, () -> back.getKey("key", P2), at);
                if (held.contains("secret"))
                {
                    Key k = back.getKey("secret", P1);
                    Assertions.assertEquals("AES", k.getAlgorithm(), at);
                }
                Assertions.assertFalse(back.isCertificateEntry("trusted"), at + "the trusted entry is gone");
                Assertions.assertNull(back.getCertificate("trusted"), at);
                Assertions.assertThrows(IOException.class, () -> load(reader, store(r, P2), P1),
                        at + "the MAC is under P2");
            }
            // BouncyCastle's half: a null password is a NullPointerException.
            Assertions.assertThrows(NullPointerException.class, () -> load(BC, file, null), writer);
        }
    }

    /**
     * A key and a secret under their own password, not the store's: listed,
     * kept encrypted, and opened only under that password, on ours as on the
     * JDK.
     */
    @Test
    public void anEntryUnderItsOwnPasswordOpensOnlyUnderIt() throws Exception
    {
        Chain c = new Chain();
        KeyStore w = empty(SUN);
        w.setKeyEntry("key", c.eeKeys.getPrivate(), P1, c.all());
        w.setEntry("secret", new KeyStore.SecretKeyEntry(new SecretKeySpec(new byte[16], "AES")),
                new KeyStore.PasswordProtection(P1));
        byte[] file = storePbes2(w, P2);
        for (String p : new String[]{SUN, JSL})
        {
            KeyStore r = load(p, file, P2);
            Assertions.assertTrue(r.isKeyEntry("key"), p);
            Assertions.assertNotNull(r.getKey("key", P1), p);
            Assertions.assertEquals("AES", r.getKey("secret", P1).getAlgorithm(), p);
            Assertions.assertThrows(UnrecoverableKeyException.class, () -> r.getKey("key", P2), p);
            Assertions.assertThrows(UnrecoverableKeyException.class, () -> r.getKey("secret", P2), p);
        }
    }

    // ------------------------------------------------- unsupported schemes

    /**
     * BouncyCastle's default PKCS12 protects its certificates with 40-bit RC2,
     * which this build cannot run: an IOException whose cause is a
     * NoSuchAlgorithmException naming the algorithm. SUN and BouncyCastle read
     * the same file.
     */
    @Test
    public void bouncyCastlesDefaultFileIsAnUnsupportedAlgorithmNamedByItsOid() throws Exception
    {
        Chain c = new Chain();
        KeyStore bc = empty(BC);
        bc.setKeyEntry("key", c.eeKeys.getPrivate(), P1, c.all());
        byte[] file = store(bc, P1);
        assertUnsupported(file, "1.2.840.113549.1.12.1.6");
        Assertions.assertTrue(load(SUN, file, P1).isKeyEntry("key"));
        Assertions.assertTrue(load(BC, file, P1).isKeyEntry("key"));
    }

    /** BouncyCastle's GCM store: PBES2 over an AEAD cipher, which OpenSSL's PBES2 does not run. */
    @Test
    public void bouncyCastlesGcmFileIsAnUnsupportedAlgorithmNamedByItsOid() throws Exception
    {
        Chain c = new Chain();
        KeyStore bc = KeyStore.getInstance("PKCS12-AES256-AES128-GCM", BC);
        bc.load(null, null);
        bc.setKeyEntry("key", c.eeKeys.getPrivate(), P1, c.all());
        byte[] file = store(bc, P1);
        assertUnsupported(file, "2.16.840.1.101.3.4.1.6");
        Assertions.assertTrue(load(BC, file, P1).isKeyEntry("key"));
    }

    /** A malformed file stays a malformed file: no NoSuchAlgorithmException cause. */
    @Test
    public void aMalformedFileIsNotAnUnsupportedAlgorithm() throws Exception
    {
        Chain c = new Chain();
        KeyStore ks = empty(JSL);
        ks.setKeyEntry("key", c.eeKeys.getPrivate(), P1, c.all());
        byte[] file = store(ks, P1);
        file[file.length / 2] ^= 0x55;
        IOException e = Assertions.assertThrows(IOException.class, () -> load(JSL, file, P1));
        Assertions.assertFalse(e.getCause() instanceof NoSuchAlgorithmException, String.valueOf(e.getCause()));
    }

    private static void assertUnsupported(byte[] file, String oid)
    {
        IOException e = Assertions.assertThrows(IOException.class, () -> load(JSL, file, P1));
        Assertions.assertTrue(e.getCause() instanceof NoSuchAlgorithmException, String.valueOf(e.getCause()));
        Assertions.assertTrue(e.getMessage().startsWith("key store algorithm is not supported: "), e.getMessage());
        Assertions.assertTrue(e.getMessage().contains(oid), e.getMessage());
    }

    private static byte[] resource(String name) throws IOException
    {
        InputStream in = PKCS12ContractAgreementTest.class.getResourceAsStream("/" + name);
        Assertions.assertNotNull(in, name + " is not on the classpath");
        try
        {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] b = new byte[4096];
            int n;
            while ((n = in.read(b)) > 0)
            {
                out.write(b, 0, n);
            }
            return out.toByteArray();
        }
        finally
        {
            in.close();
        }
    }
}
