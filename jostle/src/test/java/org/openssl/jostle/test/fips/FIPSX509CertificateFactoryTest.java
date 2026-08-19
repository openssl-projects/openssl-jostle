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

package org.openssl.jostle.test.fips;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.V1TBSCertificateGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.util.Arrays;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import java.util.List;

/**
 * JCE-level tests for the JSLFIPS {@code CertificateFactory.X.509} registration
 * ({@code ProvFIPSX509}: {@code X509CertificateFactorySpi} in provider-bound mode).
 *
 * <p>Structure parsing is delegated to SUN exactly as in the JSL factory (ASN.1
 * decoding is not a cryptographic service); what these tests pin is the
 * provider-bound policy on everything cryptographic flowing from a parsed
 * certificate:</p>
 * <ol>
 *   <li>{@code getPublicKey()} resolves exclusively through JSLFIPS KeyFactories
 *       and the key verifies the certificate signature through a JSLFIPS
 *       {@link Signature} (with the tampered-TBS negative),</li>
 *   <li>one-argument {@code verify()} is pinned to JSLFIPS rather than left to
 *       JCA provider search,</li>
 *   <li>a certificate keyed with an algorithm the FIPS module does not serve
 *       (Ed25519) fails loud with {@link ProviderException} instead of silently
 *       returning a non-FIPS key — while the lenient JSL factory still resolves
 *       the same certificate (the regression pair proving the two policies
 *       differ),</li>
 *   <li>a certificate wrapped by the lenient JSL factory is re-wrapped under the
 *       bound policy when it flows into this factory via
 *       {@code generateCertPath(List)}.</li>
 * </ol>
 *
 * <p>Test certificates are built at runtime: keys from JSLFIPS
 * KeyPairGenerators (fresh random keys per run, per the test-discipline rule),
 * the certificate structure via bcprov's ASN.1 layer (test scaffolding only),
 * signatures through JSLFIPS. RSA and EC cover the two signature families the
 * module serves for certificates; DSA adds nothing cert-specific and its
 * parameter generation is slow, so it is deliberately omitted here (the
 * FIPSDSA* tests own that surface). The Ed25519 certificate is BC-generated
 * end to end, since JSLFIPS must not be able to produce it.</p>
 *
 * <p>Gated on {@code TEST_FIPS_LIB}; skipped when unset.</p>
 */
public class FIPSX509CertificateFactoryTest
{
    private static final String FIPS = JostleFIPSProvider.PROVIDER_NAME;
    private static final String JSL = JostleProvider.PROVIDER_NAME;

    private static final String SHA256_RSA_OID = "1.2.840.113549.1.1.11";
    private static final String SHA256_ECDSA_OID = "1.2.840.10045.4.3.2";
    private static final String ED25519_OID = "1.3.101.112";
    private static final String EC_PUBKEY_OID = "1.2.840.10045.2.1";

    /**
     * Gate the whole class on TEST_FIPS_LIB, rather than per test method. Every
     * test here needs the module, and a class-level gate fails closed: a test
     * added later is skipped without the module automatically. The per-method
     * form failed open, and one omission was enough to break every non-FIPS CI
     * job with NoSuchProviderException instead of a skip.
     */
    @BeforeAll
    static void before()
    {
        FIPSTestUtil.assumeFipsProvider();

        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    // -----------------------------------------------------------------
    // Provider plumbing
    // -----------------------------------------------------------------

    @Test
    public void factory_resolvesByNameAndAlias() throws Exception
    {
        CertificateFactory byName = CertificateFactory.getInstance("X.509", FIPS);
        CertificateFactory byAlias = CertificateFactory.getInstance("X509", FIPS);
        Assertions.assertEquals(FIPS, byName.getProvider().getName());
        Assertions.assertEquals(FIPS, byAlias.getProvider().getName());
    }

    // -----------------------------------------------------------------
    // Approved families: key re-derivation + in-boundary verification
    // -----------------------------------------------------------------

    @Test
    public void rsaCert_publicKeyIsFipsAndVerifiesInBoundary() throws Exception
    {
        KeyPair kp = generate("RSA", 2048);
        X509Certificate cert = parseFips(selfSigned(kp, "SHA256withRSA", SHA256_RSA_OID));
        assertBoundKeyVerifies(cert, "SHA256withRSA");
    }

    @Test
    public void ecCert_publicKeyIsFipsAndVerifiesInBoundary() throws Exception
    {
        KeyPair kp = generate("EC", 256);
        X509Certificate cert = parseFips(selfSigned(kp, "SHA256withECDSA", SHA256_ECDSA_OID));
        assertBoundKeyVerifies(cert, "SHA256withECDSA");
    }

    /**
     * The pinned one-argument verify: succeeds against the certificate's own
     * key, and fails typed against a wrong key of the same family (negative
     * path — a verify that rubber-stamps would pass both).
     */
    @Test
    public void verify_oneArg_pinnedToFips_rejectsWrongKey() throws Exception
    {
        KeyPair kp = generate("EC", 256);
        X509Certificate cert = parseFips(selfSigned(kp, "SHA256withECDSA", SHA256_ECDSA_OID));

        // Positive: the pinned path resolves the Signature from JSLFIPS.
        cert.verify(cert.getPublicKey());

        // Negative: a fresh key of the same family must not verify.
        PublicKey wrong = generate("EC", 256).getPublic();
        try
        {
            cert.verify(wrong);
            Assertions.fail("verification against an unrelated key should have failed");
        }
        catch (SignatureException e)
        {
            // expected: signature does not verify — the typed JCE failure.
        }
    }

    // -----------------------------------------------------------------
    // Fail-loud on a key algorithm the module does not serve
    // -----------------------------------------------------------------

    /**
     * The load-bearing strict-mode test: an Ed25519-keyed certificate parses
     * (structure is not crypto) but {@code getPublicKey()} must fail loud —
     * JSLFIPS registers no EdDSA KeyFactory, and silently returning the JDK/BC
     * key would route subsequent operations outside the FIPS boundary. The
     * same certificate through the lenient JSL factory still resolves a key,
     * proving the two factories' policies actually differ rather than both
     * accidentally sharing whichever behaviour this test pins.
     */
    @Test
    public void ed25519Cert_getPublicKey_failsLoudOnFips_lenientOnJsl() throws Exception
    {
        byte[] der = bcEd25519SelfSigned();

        X509Certificate fipsCert = parseFips(der);
        try
        {
            fipsCert.getPublicKey();
            Assertions.fail("expected ProviderException for an Ed25519 key on JSLFIPS");
        }
        catch (ProviderException e)
        {
            Assertions.assertEquals(
                    "provider " + FIPS
                            + " cannot re-derive the certificate public key (algorithm "
                            + ED25519_OID + "): no KeyFactory for the algorithm, or the key was refused",
                    e.getMessage());
        }

        // Regression pair: the lenient JSL factory resolves a key for the same
        // certificate (JSL serves EdDSA, and even without it would fall back).
        CertificateFactory jsl = CertificateFactory.getInstance("X.509", JSL);
        X509Certificate jslCert = (X509Certificate) jsl.generateCertificate(new ByteArrayInputStream(der));
        Assertions.assertNotNull(jslCert.getPublicKey(),
                "the lenient JSL factory must still resolve the Ed25519 key");
    }

    // -----------------------------------------------------------------
    // Policy re-wrap across factories
    // -----------------------------------------------------------------

    /**
     * A certificate wrapped by the lenient JSL factory carries JSL's fallback
     * policy. Feeding it into the FIPS factory's {@code generateCertPath(List)}
     * must re-wrap it under the bound policy — pinned by the Ed25519 cert whose
     * key resolves under JSL but must fail loud once the path element is
     * FIPS-bound. Without the re-wrap, the JSL wrapper would pass through the
     * double-wrap fast-path and quietly keep its lenient policy.
     */
    @Test
    public void certPath_reWrapsForeignPolicyWrappers() throws Exception
    {
        byte[] der = bcEd25519SelfSigned();
        CertificateFactory jsl = CertificateFactory.getInstance("X.509", JSL);
        Certificate jslWrapped = jsl.generateCertificate(new ByteArrayInputStream(der));
        Assertions.assertNotNull(((X509Certificate) jslWrapped).getPublicKey(),
                "precondition: the JSL wrapper resolves the key");

        CertificateFactory fips = CertificateFactory.getInstance("X.509", FIPS);
        CertPath path = fips.generateCertPath(java.util.Collections.singletonList(jslWrapped));
        X509Certificate element = (X509Certificate) path.getCertificates().get(0);
        try
        {
            element.getPublicKey();
            Assertions.fail("path element kept the lenient JSL policy through the FIPS factory");
        }
        catch (ProviderException e)
        {
            Assertions.assertEquals(
                    "provider " + FIPS
                            + " cannot re-derive the certificate public key (algorithm "
                            + ED25519_OID + "): no KeyFactory for the algorithm, or the key was refused",
                    e.getMessage());
        }
    }

    @Test
    public void certPath_boundElementsResolveFipsKeys() throws Exception
    {
        CertificateFactory fips = CertificateFactory.getInstance("X.509", FIPS);
        Certificate rsa = fips.generateCertificate(new ByteArrayInputStream(
                selfSigned(generate("RSA", 2048), "SHA256withRSA", SHA256_RSA_OID)));
        Certificate ec = fips.generateCertificate(new ByteArrayInputStream(
                selfSigned(generate("EC", 256), "SHA256withECDSA", SHA256_ECDSA_OID)));

        CertPath path = fips.generateCertPath(java.util.Arrays.asList(rsa, ec));
        List<? extends Certificate> certs = path.getCertificates();
        Assertions.assertEquals(2, certs.size());
        for (Certificate c : certs)
        {
            PublicKey pub = c.getPublicKey();
            Assertions.assertTrue(pub.getClass().getName().startsWith("org.openssl.jostle"),
                    "path element key is not a Jostle key: " + pub.getClass().getName());
        }
    }

    /**
     * Real-trigger for the OTHER arm of the fail-loud branch. The Ed25519 test
     * above exercises "no KeyFactory registered for the algorithm at all"; this
     * exercises "a KeyFactory exists but the module refuses the key" — an EC
     * certificate on secp256k1, a curve the 3.1.2 module does not serve
     * (FIPSECTest pins the generation-side rejection; JSL still serves it, which
     * is what lets this test build the certificate). JSLFIPS has an EC
     * KeyFactory, so the OID lookup succeeds and the failure happens inside
     * {@code generatePublic} — it must surface as the same pinned
     * ProviderException, not a fallback key and not a raw InvalidKeySpecException.
     */
    @Test
    public void nonApprovedCurveCert_getPublicKey_failsLoud() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", JSL);
        kpg.initialize(new ECGenParameterSpec("secp256k1"));
        KeyPair kp = kpg.generateKeyPair();
        byte[] der = buildCert(kp.getPublic().getEncoded(),
                "SHA256withECDSA", SHA256_ECDSA_OID, kp.getPrivate(), JSL);

        X509Certificate cert = parseFips(der);
        try
        {
            cert.getPublicKey();
            Assertions.fail("expected ProviderException for a secp256k1 key on JSLFIPS");
        }
        catch (ProviderException e)
        {
            Assertions.assertEquals(
                    "provider " + FIPS
                            + " cannot re-derive the certificate public key (algorithm "
                            + EC_PUBKEY_OID + "): no KeyFactory for the algorithm, or the key was refused",
                    e.getMessage());
        }
    }

    /**
     * The third arm of the fail-loud branch: a key with NO encoding at all.
     * {@code Key.getEncoded()} is specified as nullable ("...or null if this
     * key does not support encoding") and HSM/PKCS#11-backed keys exercise
     * that permission in the wild. A SUN-parsed certificate always yields an
     * encodable key, but {@code generateCertPath(List)} accepts CALLER-supplied
     * certificate objects and the factory wraps any {@link X509Certificate} —
     * so an HSM-flavoured implementation whose key refuses to encode is a
     * reachable input. Provider-bound, that must fail loud (nothing can be
     * re-derived from a key that will not encode); the lenient JSL factory
     * returns the caller's key unchanged.
     */
    @Test
    public void nullEncodedKeyCert_failsLoudOnFips_passesThroughOnJsl() throws Exception
    {
        // A real parsed certificate to delegate structure to, dressed with a
        // key that refuses to encode - the HSM shape.
        X509Certificate real = parseFips(selfSigned(generate("EC", 256), "SHA256withECDSA", SHA256_ECDSA_OID));
        X509Certificate hsmStyle = new NullEncodedKeyCertificate(real);

        CertificateFactory fips = CertificateFactory.getInstance("X.509", FIPS);
        X509Certificate bound = (X509Certificate) fips
                .generateCertPath(java.util.Collections.singletonList(hsmStyle))
                .getCertificates().get(0);
        try
        {
            bound.getPublicKey();
            Assertions.fail("expected ProviderException for a key with no encoding");
        }
        catch (ProviderException e)
        {
            Assertions.assertEquals(
                    "certificate public key (EC) has no encoding to re-derive through provider " + FIPS,
                    e.getMessage());
        }

        // Lenient regression pair: JSL hands the caller's key back unchanged.
        CertificateFactory jsl = CertificateFactory.getInstance("X.509", JSL);
        X509Certificate lenient = (X509Certificate) jsl
                .generateCertPath(java.util.Collections.singletonList(hsmStyle))
                .getCertificates().get(0);
        Assertions.assertNull(lenient.getPublicKey().getEncoded(),
                "the lenient factory must return the un-encodable key as-is");
    }

    /**
     * An {@link X509Certificate} whose public key refuses to encode - the
     * shape an HSM/PKCS#11-backed certificate object presents. Everything
     * structural delegates to a real parsed certificate.
     */
    private static final class NullEncodedKeyCertificate extends X509Certificate
    {
        private final X509Certificate delegate;

        NullEncodedKeyCertificate(X509Certificate delegate)
        {
            this.delegate = delegate;
        }

        public PublicKey getPublicKey()
        {
            return new PublicKey()
            {
                public String getAlgorithm()
                {
                    return "EC";
                }

                public String getFormat()
                {
                    return null;
                }

                public byte[] getEncoded()
                {
                    // The HSM stunt: the material cannot leave the token.
                    return null;
                }
            };
        }

        public void checkValidity() throws java.security.cert.CertificateExpiredException, java.security.cert.CertificateNotYetValidException
        {
            delegate.checkValidity();
        }

        public void checkValidity(Date date) throws java.security.cert.CertificateExpiredException, java.security.cert.CertificateNotYetValidException
        {
            delegate.checkValidity(date);
        }

        public int getVersion()
        {
            return delegate.getVersion();
        }

        public BigInteger getSerialNumber()
        {
            return delegate.getSerialNumber();
        }

        public java.security.Principal getIssuerDN()
        {
            return delegate.getIssuerDN();
        }

        public java.security.Principal getSubjectDN()
        {
            return delegate.getSubjectDN();
        }

        public Date getNotBefore()
        {
            return delegate.getNotBefore();
        }

        public Date getNotAfter()
        {
            return delegate.getNotAfter();
        }

        public byte[] getTBSCertificate() throws java.security.cert.CertificateEncodingException
        {
            return delegate.getTBSCertificate();
        }

        public byte[] getSignature()
        {
            return delegate.getSignature();
        }

        public String getSigAlgName()
        {
            return delegate.getSigAlgName();
        }

        public String getSigAlgOID()
        {
            return delegate.getSigAlgOID();
        }

        public byte[] getSigAlgParams()
        {
            return delegate.getSigAlgParams();
        }

        public boolean[] getIssuerUniqueID()
        {
            return delegate.getIssuerUniqueID();
        }

        public boolean[] getSubjectUniqueID()
        {
            return delegate.getSubjectUniqueID();
        }

        public boolean[] getKeyUsage()
        {
            return delegate.getKeyUsage();
        }

        public int getBasicConstraints()
        {
            return delegate.getBasicConstraints();
        }

        public byte[] getEncoded() throws java.security.cert.CertificateEncodingException
        {
            return delegate.getEncoded();
        }

        public void verify(PublicKey key) throws java.security.cert.CertificateException,
                java.security.NoSuchAlgorithmException, java.security.InvalidKeyException,
                java.security.NoSuchProviderException, SignatureException
        {
            delegate.verify(key);
        }

        public void verify(PublicKey key, String sigProvider) throws java.security.cert.CertificateException,
                java.security.NoSuchAlgorithmException, java.security.InvalidKeyException,
                java.security.NoSuchProviderException, SignatureException
        {
            delegate.verify(key, sigProvider);
        }

        public String toString()
        {
            return delegate.toString();
        }

        public boolean hasUnsupportedCriticalExtension()
        {
            return delegate.hasUnsupportedCriticalExtension();
        }

        public java.util.Set<String> getCriticalExtensionOIDs()
        {
            return delegate.getCriticalExtensionOIDs();
        }

        public java.util.Set<String> getNonCriticalExtensionOIDs()
        {
            return delegate.getNonCriticalExtensionOIDs();
        }

        public byte[] getExtensionValue(String oid)
        {
            return delegate.getExtensionValue(oid);
        }
    }

    // -----------------------------------------------------------------
    // JSL-generated keypairs and the provider boundary
    // -----------------------------------------------------------------

    /**
     * A certificate made from a keypair the non-FIPS JSL provider generated
     * DOES function through the FIPS factory — deliberately. Two distinct
     * mechanisms, each pinned here:
     * <ol>
     * <li>{@code getPublicKey()} re-derives from the certificate's ENCODING
     * through a JSLFIPS KeyFactory — encodings are provider-neutral, so the
     * key that comes back is a fresh FIPS-backed key regardless of which
     * provider generated the original, and it verifies in-boundary.</li>
     * <li>A JSL public key OBJECT passed to the pinned {@code verify()} is
     * accepted: per the key-isolation policy, public keys carry no secret
     * material and cross between the Jostle providers freely — only PRIVATE
     * keys are isolated ({@code InvalidKeyException}, "created by a different
     * Jostle provider"). That contract is owned across all asymmetric
     * families by {@code FIPSKeyIsolationTest}; the CertificateFactory has no
     * private-key surface at all, so the isolated half cannot reach it.</li>
     * </ol>
     * If the shared-public policy is ever tightened, this test names the
     * factory-level behaviour that changes with it.
     */
    @Test
    public void jslGeneratedKeypair_functionsThroughFipsFactory() throws Exception
    {
        // Keypair generated by the non-FIPS provider; certificate signed
        // through a JSL Signature.
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", JSL);
        kpg.initialize(256);
        KeyPair jslKp = kpg.generateKeyPair();
        byte[] der = buildCert(jslKp.getPublic().getEncoded(),
                "SHA256withECDSA", SHA256_ECDSA_OID, jslKp.getPrivate(), JSL);

        // Mechanism 1: the FIPS factory re-derives the key from the encoding —
        // it is FIPS-backed and verifies the certificate inside the boundary.
        X509Certificate cert = parseFips(der);
        assertBoundKeyVerifies(cert, "SHA256withECDSA");

        // Mechanism 2: the original JSL public key OBJECT is accepted by the
        // pinned verify (public keys are shared across the providers).
        cert.verify(jslKp.getPublic());
    }

    // -----------------------------------------------------------------
    // Reset / reuse: one factory instance across parses
    // -----------------------------------------------------------------

    @Test
    public void factoryInstance_reusableAcrossParses() throws Exception
    {
        CertificateFactory fips = CertificateFactory.getInstance("X.509", FIPS);
        byte[] rsaDer = selfSigned(generate("RSA", 2048), "SHA256withRSA", SHA256_RSA_OID);
        byte[] ecDer = selfSigned(generate("EC", 256), "SHA256withECDSA", SHA256_ECDSA_OID);
        for (byte[] der : new byte[][]{rsaDer, ecDer, rsaDer})
        {
            X509Certificate cert = (X509Certificate) fips.generateCertificate(new ByteArrayInputStream(der));
            Assertions.assertTrue(cert.getPublicKey().getClass().getName().startsWith("org.openssl.jostle"));
        }
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    private static KeyPair generate(String algorithm, int size) throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm, FIPS);
        kpg.initialize(size);
        return kpg.generateKeyPair();
    }

    /**
     * A PSS-PSS certificate — SPKI algorithm id-RSASSA-PSS
     * (1.2.840.113549.1.1.10) rather than rsaEncryption — must yield its public
     * key through the provider-bound factory, re-encoded under the identifier the
     * certificate carried.
     *
     * <p>Two defects met here. The OID and the name "RSASSA-PSS" had no
     * KeyFactory alias, so the bound factory could not re-derive the key at all;
     * and the RSA import normalised the identifier to rsaEncryption, so once it
     * could, the key it produced was unusable to callers that read the
     * re-encoded form (BouncyCastle's TLS layer identifies an rsa_pss_pss
     * certificate exactly that way, and briefly reported bad_certificate(46) on
     * the non-FIPS provider because of it). Both are fixed; this pins both.
     */
    @Test
    public void pssPssCertificateKeyReDerivesPreservingAlgorithmId() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", FIPS);
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        SubjectPublicKeyInfo rsaSpki =
                SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(kp.getPublic().getEncoded()));
        byte[] pssSpki = new SubjectPublicKeyInfo(
                new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.113549.1.1.10")),
                rsaSpki.getPublicKeyData().getBytes()).getEncoded(ASN1Encoding.DER);

        byte[] der = buildCert(pssSpki, "SHA256withRSA", "1.2.840.113549.1.1.11", kp.getPrivate(), FIPS);
        X509Certificate cert = parseFips(der);

        PublicKey pk = cert.getPublicKey();
        Assertions.assertNotNull(pk, "PSS-PSS certificate key must re-derive");
        // Bound-factory contract: the key must come from THIS provider.
        Assertions.assertTrue(pk.getClass().getName().startsWith("org.openssl.jostle"),
                "expected a Jostle key, got " + pk.getClass().getName());
        // The assertion that actually protects BC's callers: the identifier the
        // certificate carried must survive the re-encode.
        Assertions.assertEquals("1.2.840.113549.1.1.10",
                SubjectPublicKeyInfo.getInstance(pk.getEncoded()).getAlgorithm().getAlgorithm().getId(),
                "re-encoded key lost the id-RSASSA-PSS identifier");
        Assertions.assertTrue(Arrays.areEqual(pssSpki, pk.getEncoded()),
                "re-encoded key is not byte-identical to the certificate's SPKI");

        // Both aliases resolve independently and preserve the identifier too.
        for (String name : new String[]{"RSASSA-PSS", "1.2.840.113549.1.1.10"})
        {
            PublicKey decoded = java.security.KeyFactory.getInstance(name, FIPS)
                    .generatePublic(new java.security.spec.X509EncodedKeySpec(pssSpki));
            Assertions.assertTrue(Arrays.areEqual(pssSpki, decoded.getEncoded()),
                    name + ": did not round-trip the id-RSASSA-PSS SPKI");
        }

        // Differentiator: the preservation is driven by the INPUT, not applied to
        // every RSA key. A plain rsaEncryption certificate must still re-encode
        // as rsaEncryption — otherwise the mechanism would be "always emit PSS",
        // which would round-trip the test above while corrupting ordinary keys.
        byte[] plainDer = buildCert(kp.getPublic().getEncoded(),
                "SHA256withRSA", "1.2.840.113549.1.1.11", kp.getPrivate(), FIPS);
        PublicKey plainKey = parseFips(plainDer).getPublicKey();
        Assertions.assertEquals("1.2.840.113549.1.1.1",
                SubjectPublicKeyInfo.getInstance(plainKey.getEncoded())
                        .getAlgorithm().getAlgorithm().getId(),
                "a plain rsaEncryption certificate key must not acquire a PSS identifier");
        Assertions.assertFalse(Arrays.areEqual(pssSpki, plainKey.getEncoded()),
                "PSS and plain certificate keys must not encode identically");
    }

    private static X509Certificate parseFips(byte[] der) throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", FIPS);
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
    }

    /**
     * Minimal self-signed X.509 v1 certificate: subject key from {@code kp},
     * signed through the JSLFIPS {@link Signature} {@code sigAlgName}. bcprov
     * supplies only the ASN.1 structure.
     */
    private static byte[] selfSigned(KeyPair kp, String sigAlgName, String sigOid) throws Exception
    {
        return buildCert(kp.getPublic().getEncoded(), sigAlgName, sigOid, kp.getPrivate(), FIPS);
    }

    private static byte[] buildCert(byte[] subjectSpki, String sigAlgName, String sigOid,
                                    PrivateKey signerKey, String signerProvider) throws Exception
    {
        AlgorithmIdentifier sigAlgId = new AlgorithmIdentifier(new ASN1ObjectIdentifier(sigOid));

        V1TBSCertificateGenerator tbsGen = new V1TBSCertificateGenerator();
        tbsGen.setSerialNumber(new ASN1Integer(BigInteger.valueOf(1)));
        tbsGen.setSignature(sigAlgId);
        tbsGen.setIssuer(new X500Name("CN=Jostle FIPS CF Test"));
        tbsGen.setStartDate(new Time(new Date(1700000000000L)));
        tbsGen.setEndDate(new Time(new Date(1900000000000L)));
        tbsGen.setSubject(new X500Name("CN=Jostle FIPS CF Test"));
        tbsGen.setSubjectPublicKeyInfo(SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(subjectSpki)));
        TBSCertificate tbs = tbsGen.generateTBSCertificate();

        Signature signer = Signature.getInstance(sigAlgName, signerProvider);
        signer.initSign(signerKey);
        signer.update(tbs.getEncoded(ASN1Encoding.DER));
        byte[] sig = signer.sign();

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(tbs);
        v.add(sigAlgId);
        v.add(new DERBitString(sig));
        return new DERSequence(v).getEncoded(ASN1Encoding.DER);
    }

    /**
     * Ed25519 self-signed certificate produced entirely with BC — key,
     * signature, and structure — since JSLFIPS must not be able to make one.
     */
    private static byte[] bcEd25519SelfSigned() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519", BouncyCastleProvider.PROVIDER_NAME);
        KeyPair kp = kpg.generateKeyPair();

        AlgorithmIdentifier sigAlgId = new AlgorithmIdentifier(new ASN1ObjectIdentifier(ED25519_OID));
        V1TBSCertificateGenerator tbsGen = new V1TBSCertificateGenerator();
        tbsGen.setSerialNumber(new ASN1Integer(BigInteger.valueOf(1)));
        tbsGen.setSignature(sigAlgId);
        tbsGen.setIssuer(new X500Name("CN=Jostle FIPS CF Ed25519"));
        tbsGen.setStartDate(new Time(new Date(1700000000000L)));
        tbsGen.setEndDate(new Time(new Date(1900000000000L)));
        tbsGen.setSubject(new X500Name("CN=Jostle FIPS CF Ed25519"));
        tbsGen.setSubjectPublicKeyInfo(SubjectPublicKeyInfo.getInstance(
                ASN1Primitive.fromByteArray(kp.getPublic().getEncoded())));
        TBSCertificate tbs = tbsGen.generateTBSCertificate();

        Signature signer = Signature.getInstance("Ed25519", BouncyCastleProvider.PROVIDER_NAME);
        signer.initSign(kp.getPrivate());
        signer.update(tbs.getEncoded(ASN1Encoding.DER));
        byte[] sig = signer.sign();

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(tbs);
        v.add(sigAlgId);
        v.add(new DERBitString(sig));
        return new DERSequence(v).getEncoded(ASN1Encoding.DER);
    }

    /**
     * Shared positive+negative verification: the wrapped key is a Jostle key,
     * verifies the certificate's own signature through a JSLFIPS Signature, and
     * a tampered TBS does NOT verify.
     */
    private static void assertBoundKeyVerifies(X509Certificate cert, String sigAlg) throws Exception
    {
        PublicKey pub = cert.getPublicKey();
        Assertions.assertTrue(pub.getClass().getName().startsWith("org.openssl.jostle"),
                "getPublicKey() did not return a Jostle key, was: " + pub.getClass().getName());

        byte[] tbs = cert.getTBSCertificate();
        byte[] sig = cert.getSignature();

        Signature verifier = Signature.getInstance(sigAlg, FIPS);
        verifier.initVerify(pub);
        verifier.update(tbs);
        Assertions.assertTrue(verifier.verify(sig),
                sigAlg + ": FIPS key failed to verify the cert's self-signature");

        byte[] tampered = Arrays.clone(tbs);
        tampered[tampered.length / 2] ^= 0x01;
        Signature verifier2 = Signature.getInstance(sigAlg, FIPS);
        verifier2.initVerify(pub);
        verifier2.update(tampered);
        Assertions.assertFalse(verifier2.verify(sig),
                sigAlg + ": tampered TBS unexpectedly verified");
    }
}
