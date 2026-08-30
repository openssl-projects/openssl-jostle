/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.eddsa;

import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.signers.Ed25519ctxSigner;
import org.bouncycastle.crypto.signers.Ed25519phSigner;
import org.bouncycastle.crypto.signers.Ed448phSigner;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.spec.ContextParameterSpec;
import org.openssl.jostle.jcajce.spec.EdDSAParameterSpec;
import org.openssl.jostle.test.util.CipherFamilies;
import org.openssl.jostle.test.util.ProviderSurfaceGuard;
import org.openssl.jostle.util.Arrays;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.SortedSet;
import java.util.TreeSet;

/**
 * Cross-provider agreement for the WHOLE base-provider ({@code JSL}) Edwards
 * surface, against BouncyCastle.
 * <p>
 * Non-FIPS counterpart of {@link
 * org.openssl.jostle.test.fips.FIPSEdAgreementTest}, which cannot substitute:
 * JSLFIPS gates Ed PER NAME on what the loaded module can fetch, so on a module
 * without Ed that class self-skips entirely and this is the only Ed agreement
 * coverage that runs.
 * <p>
 * <b>What "agrees" means: BYTES, and cross-verification as well.</b> Ed25519 and
 * Ed448 are DETERMINISTIC (RFC 8032 derives the nonce from the key and message,
 * and the context where there is one), so key + message + context fixes the
 * signature completely and byte-equality is available. It is asserted, because
 * cross-verification alone cannot see the failure that matters most here: a
 * deviation in NONCE DERIVATION still produces signatures that verify — that is
 * the classic catastrophic EdDSA bug, and it leaks the private key — so a
 * verifier-only check is blind to it by construction. Cross-verification is
 * kept alongside, since it is what exercises the VERIFIER on each side. Key
 * encodings are compared byte-for-byte too, where byte-equality holds.
 * <p>
 * <b>Interop reference order</b> (CLAUDE.md). BouncyCastle's JCE serves three
 * of the six registered signature names; the pre-hash and context variants have
 * no BC JCE name, so the reference is BC's LIGHTWEIGHT signer for each
 * ({@link #BC_LIGHTWEIGHT_ONLY}). A missing BC JCE name is not a reason to skip
 * agreement testing, and all six are covered.
 * <p>
 * <b>Breadth, not depth.</b> {@link EdDSATest} keeps the parameter-spec
 * contracts, state-machine sequences and context handling;
 * {@link EdwardsOidResolutionTest} keeps the OID resolution.
 * <p>
 * Inputs come from a per-test SHA1PRNG whose seed is logged.
 */
public class EdAgreementTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    /** The three JCA types {@code ProvED} registers under. */
    private static final String[] GUARDED_TYPES = {"KeyFactory", "KeyPairGenerator", "Signature"};

    /**
     * Registered signature names BouncyCastle also serves through the JCE,
     * mapped to BC's spelling.
     */
    private static final Map<String, String> BC_JCE_SIGNATURE = new LinkedHashMap<String, String>();

    static
    {
        BC_JCE_SIGNATURE.put("EDDSA", "EDDSA");
        BC_JCE_SIGNATURE.put("ED25519", "Ed25519");
        BC_JCE_SIGNATURE.put("ED448", "Ed448");
    }

    /**
     * The registered signature names BouncyCastle does NOT expose through the
     * JCE — the RFC 8032 pre-hash and context variants. Compared against BC's
     * lightweight {@code Ed25519phSigner} / {@code Ed25519ctxSigner} /
     * {@code Ed448phSigner} instead of being skipped, and named so the
     * completeness guard reads them as a decision rather than a gap.
     */
    private static final SortedSet<String> BC_LIGHTWEIGHT_ONLY =
            Collections.unmodifiableSortedSet(new TreeSet<String>(
                    java.util.Arrays.asList("ED25519PH", "ED25519CTX", "ED448PH")));

    /** The two curves, by the name {@code ProvED} registers a KeyPairGenerator under. */
    private static final String[] CURVES = {"ED25519", "ED448"};

    private static final int TRIALS = 3;

    private static final SecureRandom RANDOM = new SecureRandom();

    @BeforeAll
    static void before()
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

    private static SecureRandom seededRandom(String testName) throws Exception
    {
        long seed = RANDOM.nextLong();
        System.out.println(testName + " seed=" + seed);
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(seed);
        return sr;
    }

    /** Every Ed primary of one type that {@code ProvED} registers, sorted. */
    private static List<String> registered(String type)
    {
        Provider provider = Security.getProvider(JSL);
        Assertions.assertNotNull(provider, "JSL provider is not registered");

        List<String> names = new ArrayList<String>();
        for (Provider.Service s : provider.getServices())
        {
            String cn = s.getClassName();
            if (type.equals(s.getType()) && cn != null && cn.startsWith(CipherFamilies.ED_PREFIX))
            {
                names.add(s.getAlgorithm());
            }
        }
        Assertions.assertFalse(names.isEmpty(), "JSL registered no Ed " + type + " services");
        Collections.sort(names);
        return names;
    }

    private static KeyPair generate(String curve) throws Exception
    {
        return KeyPairGenerator.getInstance(curve, JSL).generateKeyPair();
    }

    /** BC's JCE KeyFactory name for a curve. */
    private static String bcKeyFactory(String curve)
    {
        return "ED25519".equals(curve) ? "Ed25519" : "Ed448";
    }

    private static boolean isEd25519(String alg)
    {
        return alg.toUpperCase(Locale.ROOT).startsWith("ED25519");
    }

    /**
     * A signature under one registered name. {@code ED25519CTX} requires a
     * context — RFC 8032's Ed25519ctx is undefined without one, and OpenSSL
     * refuses to sign until it is set — so one is supplied when present.
     */
    private static byte[] sign(String alg, PrivateKey key, byte[] msg, byte[] ctx) throws Exception
    {
        Signature s = Signature.getInstance(alg, JSL);
        if (ctx != null)
        {
            s.setParameter(new ContextParameterSpec(ctx));
        }
        s.initSign(key);
        s.update(msg);
        return s.sign();
    }

    private static boolean verify(String alg, PublicKey key, byte[] msg, byte[] sig, byte[] ctx)
            throws Exception
    {
        Signature v = Signature.getInstance(alg, JSL);
        if (ctx != null)
        {
            v.setParameter(new ContextParameterSpec(ctx));
        }
        v.initVerify(key);
        v.update(msg);
        return v.verify(sig);
    }

    /** BC's lightweight signer for one of the three JCE-absent names. */
    private static Signer lightweightSigner(String alg, byte[] ctx)
    {
        if ("ED25519PH".equals(alg))
        {
            return new Ed25519phSigner(new byte[0]);
        }
        if ("ED25519CTX".equals(alg))
        {
            return new Ed25519ctxSigner(ctx);
        }
        return new Ed448phSigner(new byte[0]);
    }

    // -----------------------------------------------------------------
    // Completeness guards
    // -----------------------------------------------------------------

    /**
     * Every Ed service JSL registers is DRIVEN, discovered by SPI class-name
     * prefix, aliases included — which is what covers the OID spellings and the
     * mixed-case {@code Ed25519} / {@code EdDSA} forms.
     */
    @Test
    public void everyRegisteredEdServiceIsDriven() throws Exception
    {
        final SecureRandom sr = seededRandom("everyRegisteredEdServiceIsDriven");

        ProviderSurfaceGuard.assertEveryServiceDriven(Security.getProvider(JSL),
                CipherFamilies.ED_PREFIX, "Ed (JSL)", GUARDED_TYPES,
                new ProviderSurfaceGuard.ServiceDriver()
                {
                    public void drive(String type, String alg) throws Exception
                    {
                        // Curve inferred from the PRIMARY, not the spelling:
                        // Ed448's OID alias is 1.3.101.113, which contains no
                        // "448". A spelling test drove all four of its alias
                        // entries as Ed25519 and the guard caught it.
                        String curve = curveOf(type, alg);
                        KeyPair kp = generate(curve);

                        if ("Signature".equals(type))
                        {
                            byte[] msg = new byte[32];
                            sr.nextBytes(msg);
                            byte[] ctx = null;
                            if (alg.toUpperCase(Locale.ROOT).endsWith("CTX"))
                            {
                                ctx = new byte[8];
                                sr.nextBytes(ctx);
                            }
                            byte[] sig = sign(alg, kp.getPrivate(), msg, ctx);
                            Assertions.assertTrue(verify(alg, kp.getPublic(), msg, sig, ctx),
                                    alg + ": did not verify its own signature");
                        }
                        else if ("KeyFactory".equals(type))
                        {
                            PublicKey pub = KeyFactory.getInstance(alg, JSL)
                                    .generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));
                            Assertions.assertTrue(
                                    Arrays.areEqual(kp.getPublic().getEncoded(), pub.getEncoded()), alg);
                        }
                        else if ("KeyPairGenerator".equals(type))
                        {
                            KeyPairGenerator kpg = KeyPairGenerator.getInstance(alg, JSL);
                            // The bare EdDSA names take either curve; pin one so
                            // the driver does not depend on the SPI's default.
                            if (!alg.toUpperCase(Locale.ROOT).contains("25519")
                                    && !alg.toUpperCase(Locale.ROOT).contains("448"))
                            {
                                kpg.initialize(new EdDSAParameterSpec(curve));
                            }
                            KeyPair generated = kpg.generateKeyPair();
                            byte[] msg = new byte[32];
                            sr.nextBytes(msg);
                            byte[] sig = sign("EDDSA", generated.getPrivate(), msg, null);
                            Assertions.assertTrue(verify("EDDSA", generated.getPublic(), msg, sig, null),
                                    alg + ": generated a keypair that cannot sign");
                        }
                        else
                        {
                            throw new IllegalStateException("no drive defined for " + type + "." + alg
                                    + " — teach this driver rather than letting it go unexercised");
                        }
                    }
                });
    }

    /** The removal direction, at type granularity. */
    @Test
    public void everyGuardedTypeIsStillRegistered()
    {
        SortedSet<String> surface = ProviderSurfaceGuard.registeredSurface(
                Security.getProvider(JSL), CipherFamilies.ED_PREFIX, GUARDED_TYPES);

        SortedSet<String> missing = new TreeSet<String>();
        for (String type : GUARDED_TYPES)
        {
            boolean found = false;
            for (String entry : surface)
            {
                if (entry.startsWith(type + "."))
                {
                    found = true;
                    break;
                }
            }
            if (!found)
            {
                missing.add(type);
            }
        }
        Assertions.assertTrue(missing.isEmpty(),
                "JSL no longer registers any Ed service of these types: " + missing);
    }

    /**
     * Every registered signature name has a named reference — BC's JCE where it
     * has one, BC's lightweight signer where it does not — and every name this
     * class claims to cover is still registered.
     * <p>
     * This is the check that would fail if a seventh Ed signature variant were
     * registered and compared against nothing.
     */
    @Test
    public void everyRegisteredSignatureHasAReference()
    {
        SortedSet<String> covered = new TreeSet<String>(BC_JCE_SIGNATURE.keySet());
        covered.addAll(BC_LIGHTWEIGHT_ONLY);

        SortedSet<String> registeredSigs = new TreeSet<String>();
        for (String alg : registered("Signature"))
        {
            registeredSigs.add(alg.toUpperCase(Locale.ROOT));
        }

        SortedSet<String> uncovered = new TreeSet<String>(registeredSigs);
        uncovered.removeAll(covered);
        Assertions.assertTrue(uncovered.isEmpty(),
                "JSL registers Ed Signature services with no reference in this class: " + uncovered
                        + "\nGive each a BC JCE name, or a lightweight signer if BC has no JCE name.");

        SortedSet<String> stale = new TreeSet<String>(covered);
        stale.removeAll(registeredSigs);
        Assertions.assertTrue(stale.isEmpty(),
                "this class names Ed Signature services JSL does not register: " + stale);
    }

    // -----------------------------------------------------------------
    // Signature agreement
    // -----------------------------------------------------------------

    /**
     * The three names BouncyCastle serves through the JCE: byte-identical
     * signatures, cross-verified in both directions on both curves, with a
     * tampered-message differentiator.
     */
    @Test
    public void pureEdSignaturesAgreeWithBouncyCastleJce() throws Exception
    {
        SecureRandom sr = seededRandom("pureEdSignaturesAgreeWithBouncyCastleJce");

        for (Map.Entry<String, String> entry : BC_JCE_SIGNATURE.entrySet())
        {
            String alg = entry.getKey();
            String bcAlg = entry.getValue();

            for (String curve : CURVES)
            {
                // ED25519 and ED448 pin their curve; EDDSA takes either.
                if (!"EDDSA".equals(alg) && isEd25519(alg) != "ED25519".equals(curve))
                {
                    continue;
                }

                for (int t = 0; t < TRIALS; t++)
                {
                    KeyPair kp = generate(curve);
                    KeyFactory bcKf = KeyFactory.getInstance(bcKeyFactory(curve), BC);
                    PublicKey bcPub = bcKf.generatePublic(
                            new X509EncodedKeySpec(kp.getPublic().getEncoded()));
                    PrivateKey bcPriv = bcKf.generatePrivate(
                            new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

                    byte[] msg = new byte[1 + sr.nextInt(1024)];
                    sr.nextBytes(msg);
                    String tag = alg + " / " + curve;

                    byte[] jslSig = sign(alg, kp.getPrivate(), msg, null);
                    Signature bcVerify = Signature.getInstance(bcAlg, BC);
                    bcVerify.initVerify(bcPub);
                    bcVerify.update(msg);
                    Assertions.assertTrue(bcVerify.verify(jslSig), tag + ": BC rejected a JSL signature");

                    Signature bcSign = Signature.getInstance(bcAlg, BC);
                    bcSign.initSign(bcPriv);
                    bcSign.update(msg);
                    byte[] bcSig = bcSign.sign();

                    // The scheme is deterministic, so the two signatures must be
                    // the SAME BYTES. This is the check a nonce-derivation
                    // deviation fails — such a signature still verifies, so no
                    // amount of cross-verification would notice.
                    Assertions.assertArrayEquals(bcSig, jslSig,
                            tag + ": deterministic signatures differ — suspect nonce derivation");
                    Assertions.assertTrue(verify(alg, kp.getPublic(), msg, bcSig, null),
                            tag + ": JSL rejected a BC signature");

                    byte[] tampered = msg.clone();
                    tampered[sr.nextInt(tampered.length)] ^= (byte) (1 + sr.nextInt(255));
                    Assertions.assertFalse(verify(alg, kp.getPublic(), tampered, bcSig, null),
                            tag + ": JSL accepted a BC signature over a tampered message");

                    Signature bcTampered = Signature.getInstance(bcAlg, BC);
                    bcTampered.initVerify(bcPub);
                    bcTampered.update(tampered);
                    Assertions.assertFalse(bcTampered.verify(jslSig),
                            tag + ": BC accepted a JSL signature over a tampered message");
                }
            }
        }
    }

    /**
     * The three names BouncyCastle has no JCE service for — the RFC 8032
     * pre-hash and context variants — compared against BC's LIGHTWEIGHT
     * signers: byte-identical signatures, cross-verified both directions, with
     * a tampered-message differentiator.
     * <p>
     * {@code ED25519CTX} is driven with a random non-empty context, which the
     * scheme requires; the two pre-hash names are driven with the empty context
     * their BC signers default to.
     */
    @Test
    public void prehashAndContextSignaturesAgreeWithBouncyCastleLightweight() throws Exception
    {
        SecureRandom sr = seededRandom("prehashAndContextSignaturesAgreeWithBouncyCastleLightweight");

        for (String alg : BC_LIGHTWEIGHT_ONLY)
        {
            String curve = isEd25519(alg) ? "ED25519" : "ED448";

            for (int t = 0; t < TRIALS; t++)
            {
                KeyPair kp = generate(curve);
                AsymmetricKeyParameter bcPub =
                        PublicKeyFactory.createKey(kp.getPublic().getEncoded());
                AsymmetricKeyParameter bcPriv =
                        PrivateKeyFactory.createKey(kp.getPrivate().getEncoded());

                byte[] ctx = null;
                if (alg.endsWith("CTX"))
                {
                    ctx = new byte[1 + sr.nextInt(32)];
                    sr.nextBytes(ctx);
                }
                byte[] msg = new byte[1 + sr.nextInt(1024)];
                sr.nextBytes(msg);

                // JSL signs, BC's lightweight signer verifies.
                byte[] jslSig = sign(alg, kp.getPrivate(), msg, ctx);
                Signer bcVerifier = lightweightSigner(alg, ctx);
                bcVerifier.init(false, bcPub);
                bcVerifier.update(msg, 0, msg.length);
                Assertions.assertTrue(bcVerifier.verifySignature(jslSig),
                        alg + ": BC's lightweight signer rejected a JSL signature");

                // BC's lightweight signer signs, JSL verifies.
                Signer bcSigner = lightweightSigner(alg, ctx);
                bcSigner.init(true, bcPriv);
                bcSigner.update(msg, 0, msg.length);
                byte[] bcSig = bcSigner.generateSignature();
                Assertions.assertTrue(verify(alg, kp.getPublic(), msg, bcSig, ctx),
                        alg + ": JSL rejected a BC lightweight signature");

                // Deterministic, so the bytes must match — see the class javadoc
                // on why cross-verification alone is not enough here.
                Assertions.assertArrayEquals(bcSig, jslSig,
                        alg + ": deterministic signatures differ — suspect nonce derivation");

                byte[] tampered = msg.clone();
                tampered[sr.nextInt(tampered.length)] ^= (byte) (1 + sr.nextInt(255));
                Assertions.assertFalse(verify(alg, kp.getPublic(), tampered, bcSig, ctx),
                        alg + ": JSL accepted a signature over a tampered message");

                Signer bcTampered = lightweightSigner(alg, ctx);
                bcTampered.init(false, bcPub);
                bcTampered.update(tampered, 0, tampered.length);
                Assertions.assertFalse(bcTampered.verifySignature(jslSig),
                        alg + ": BC's lightweight signer accepted a tampered message");
            }
        }
    }

    /**
     * A context is load-bearing for {@code ED25519CTX}: a signature made under
     * one context must NOT verify under another. Without this the context could
     * be ignored on both sides and every agreement check above would still pass.
     */
    @Test
    public void ed25519CtxSignatureDoesNotVerifyUnderADifferentContext() throws Exception
    {
        SecureRandom sr = seededRandom("ed25519CtxSignatureDoesNotVerifyUnderADifferentContext");

        KeyPair kp = generate("ED25519");
        byte[] msg = new byte[64];
        sr.nextBytes(msg);
        byte[] ctxA = new byte[8];
        byte[] ctxB = new byte[8];
        sr.nextBytes(ctxA);
        do
        {
            sr.nextBytes(ctxB);
        }
        while (Arrays.areEqual(ctxA, ctxB));

        byte[] sig = sign("ED25519CTX", kp.getPrivate(), msg, ctxA);
        Assertions.assertTrue(verify("ED25519CTX", kp.getPublic(), msg, sig, ctxA),
                "the signature must verify under its own context");
        Assertions.assertFalse(verify("ED25519CTX", kp.getPublic(), msg, sig, ctxB),
                "a signature verified under a DIFFERENT context — the context is being ignored");

        // And BC's lightweight verifier agrees about which context is wrong.
        AsymmetricKeyParameter bcPub = PublicKeyFactory.createKey(kp.getPublic().getEncoded());
        Signer wrong = new Ed25519ctxSigner(ctxB);
        wrong.init(false, bcPub);
        wrong.update(msg, 0, msg.length);
        Assertions.assertFalse(wrong.verifySignature(sig),
                "BC accepted the signature under the wrong context");
    }

    // -----------------------------------------------------------------
    // Key encodings
    // -----------------------------------------------------------------

    /**
     * Ed keys survive a round trip through BouncyCastle on both halves and both
     * directions. What is asserted differs by direction, deliberately: bytes
     * where byte-equality holds, behaviour where it legitimately does not.
     * <ul>
     * <li>PUBLIC, both directions — byte-equal.</li>
     * <li>PRIVATE, JSL to BC — byte-equal.</li>
     * <li>PRIVATE, BC to JSL — NOT byte-equal, because BC's blob carries the
     * optional public half and JSL's does not (see
     * {@link #edPrivateKeyEncodingsDifferOnlyByTheOptionalPublicKey}). The
     * assertion is that the material survived, proven by signing with the
     * re-encoded key and verifying against BC's ORIGINAL public key.</li>
     * </ul>
     */
    @Test
    public void keysRoundTripThroughBothKeyFactories() throws Exception
    {
        SecureRandom sr = seededRandom("keysRoundTripThroughBothKeyFactories");

        for (String curve : CURVES)
        {
            KeyFactory jslKf = KeyFactory.getInstance(curve, JSL);
            KeyFactory bcKf = KeyFactory.getInstance(bcKeyFactory(curve), BC);

            KeyPair jslPair = generate(curve);
            Assertions.assertTrue(Arrays.areEqual(jslPair.getPublic().getEncoded(),
                            bcKf.generatePublic(new X509EncodedKeySpec(
                                    jslPair.getPublic().getEncoded())).getEncoded()),
                    curve + ": BC re-encoded a JSL public key differently");
            Assertions.assertTrue(Arrays.areEqual(jslPair.getPrivate().getEncoded(),
                            bcKf.generatePrivate(new PKCS8EncodedKeySpec(
                                    jslPair.getPrivate().getEncoded())).getEncoded()),
                    curve + ": BC re-encoded a JSL private key differently");

            KeyPair bcPair = KeyPairGenerator.getInstance(bcKeyFactory(curve), BC).generateKeyPair();
            PublicKey viaJslPub = jslKf.generatePublic(
                    new X509EncodedKeySpec(bcPair.getPublic().getEncoded()));
            PrivateKey viaJslPriv = jslKf.generatePrivate(
                    new PKCS8EncodedKeySpec(bcPair.getPrivate().getEncoded()));
            Assertions.assertTrue(Arrays.areEqual(bcPair.getPublic().getEncoded(),
                            viaJslPub.getEncoded()),
                    curve + ": JSL re-encoded a BC public key differently");

            // The BC -> JSL PRIVATE direction is NOT byte-equal, and legitimately
            // so; see edPrivateKeyEncodingsDifferOnlyByTheOptionalPublicKey.
            // The property here is that the key material survived, which the
            // signature below proves against BC's ORIGINAL public key.
            byte[] msg = new byte[64];
            sr.nextBytes(msg);
            byte[] sig = sign(curve, viaJslPriv, msg, null);
            Assertions.assertTrue(verify(curve, viaJslPub, msg, sig, null),
                    curve + ": a round-tripped BC keypair no longer operates under JSL");

            Signature bcCheck = Signature.getInstance(bcKeyFactory(curve), BC);
            bcCheck.initVerify(bcPair.getPublic());
            bcCheck.update(msg);
            Assertions.assertTrue(bcCheck.verify(sig),
                    curve + ": the re-encoded private key no longer matches BC's original public key");
        }
    }

    /**
     * The curve a registered name operates on, resolved through the provider's
     * alias table rather than guessed from the spelling.
     * <p>
     * Ed448's OID is {@code 1.3.101.113} and Ed25519's is {@code 1.3.101.112};
     * neither contains "448" or "25519", so a substring test on the ALIAS gets
     * Ed448's four alias entries wrong. Resolving to the primary first is what
     * makes the answer come from the registrar.
     */
    private static String curveOf(String type, String alg)
    {
        Provider provider = Security.getProvider(JSL);
        String primary = provider.getProperty("Alg.Alias." + type + "." + alg);
        String name = (primary == null ? alg : primary).toUpperCase(Locale.ROOT);
        return name.contains("448") ? "ED448" : "ED25519";
    }

    /** The {@code privateKey} OCTET STRING of a PKCS#8 / OneAsymmetricKey blob. */
    private static byte[] innerPrivateKey(byte[] pkcs8)
    {
        org.bouncycastle.asn1.ASN1Sequence seq =
                org.bouncycastle.asn1.ASN1Sequence.getInstance(pkcs8);
        return org.bouncycastle.asn1.ASN1OctetString.getInstance(seq.getObjectAt(2)).getOctets();
    }

    /** The version INTEGER of a PKCS#8 / OneAsymmetricKey blob. */
    private static int pkcs8Version(byte[] pkcs8)
    {
        org.bouncycastle.asn1.ASN1Sequence seq =
                org.bouncycastle.asn1.ASN1Sequence.getInstance(pkcs8);
        return org.bouncycastle.asn1.ASN1Integer.getInstance(seq.getObjectAt(0))
                .getValue().intValue();
    }

    /** Whether the blob carries the OPTIONAL {@code [1] publicKey} attribute. */
    private static boolean hasPublicKeyAttribute(byte[] pkcs8)
    {
        org.bouncycastle.asn1.ASN1Sequence seq =
                org.bouncycastle.asn1.ASN1Sequence.getInstance(pkcs8);
        for (int i = 0; i < seq.size(); i++)
        {
            org.bouncycastle.asn1.ASN1Encodable o = seq.getObjectAt(i);
            if (o instanceof org.bouncycastle.asn1.ASN1TaggedObject
                    && ((org.bouncycastle.asn1.ASN1TaggedObject) o).getTagNo() == 1)
            {
                return true;
            }
        }
        return false;
    }

    /**
     * JSL and BouncyCastle encode an Ed PRIVATE key differently, and the
     * difference is exactly RFC 5958's OPTIONAL {@code [1] publicKey} plus the
     * version integer that accompanies it. Pinned rather than tolerated, so a
     * change on either side is reported here and not as an interop failure
     * somewhere else.
     * <p>
     * RFC 5958's {@code OneAsymmetricKey} may carry the public half alongside
     * the private one, and REQUIRES version 1 when it does. BouncyCastle emits
     * that form; OpenSSL — and therefore JSL — emits version 0 with the private
     * key alone. Both are well-formed and each decodes the other, so private-key
     * agreement for Ed is the key material, not the bytes. Measured on Ed25519:
     * BC 83 bytes, JSL 48; on Ed448: BC 134, JSL 73.
     * <p>
     * Note the asymmetry — a JSL-generated key round-trips through BC
     * byte-for-byte, because there is no public half for BC to preserve. Only
     * the BC-to-JSL direction differs, which is why
     * {@link #keysRoundTripThroughBothKeyFactories} asserts bytes
     * one way and behaviour the other.
     */
    @Test
    public void edPrivateKeyEncodingsDifferOnlyByTheOptionalPublicKey() throws Exception
    {
        for (String curve : CURVES)
        {
            KeyPair bcPair = KeyPairGenerator.getInstance(bcKeyFactory(curve), BC).generateKeyPair();
            byte[] bcEnc = bcPair.getPrivate().getEncoded();
            byte[] jslEnc = KeyFactory.getInstance(curve, JSL)
                    .generatePrivate(new PKCS8EncodedKeySpec(bcEnc)).getEncoded();

            Assertions.assertFalse(Arrays.areEqual(bcEnc, jslEnc),
                    curve + ": the encoders now agree — if BC or OpenSSL changed, this pin is stale "
                            + "and keysRoundTripThroughBothKeyFactories should assert "
                            + "bytes in both directions again");

            // The difference is that attribute and the version that goes with
            // it, and nothing else: the private key OCTET STRING is identical.
            Assertions.assertTrue(hasPublicKeyAttribute(bcEnc),
                    curve + ": BC no longer emits the [1] publicKey this pin describes");
            Assertions.assertFalse(hasPublicKeyAttribute(jslEnc),
                    curve + ": JSL now emits the optional [1] publicKey");
            Assertions.assertEquals(1, pkcs8Version(bcEnc),
                    curve + ": RFC 5958 requires version 1 when publicKey is present");
            Assertions.assertEquals(0, pkcs8Version(jslEnc),
                    curve + ": JSL should emit version 0 with no publicKey");
            Assertions.assertArrayEquals(innerPrivateKey(bcEnc), innerPrivateKey(jslEnc),
                    curve + ": the two encodings carry different private key material");
        }
    }
}
