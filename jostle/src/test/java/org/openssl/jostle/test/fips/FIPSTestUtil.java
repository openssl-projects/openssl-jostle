/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.fips;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.test.TestUtil;

import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.jcajce.provider.ProviderCapabilityException;
import org.openssl.jostle.jcajce.provider.rsa.RSAPKCS1CipherNI;
import org.openssl.jostle.jcajce.provider.dsa.DSAServiceNI;
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;
import org.openssl.jostle.rand.RandSource;

import java.io.File;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.DSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Shared bootstrap for the env-gated FIPS tests. The single switch is the
 * {@code TEST_FIPS_LIB} environment variable (a full path to the FIPS module
 * library); everything here derives from it via {@link TestUtil}. All tests
 * construct the provider from the SAME resolved configuration, so the
 * one-shot native initialisation dedups across test classes sharing a JVM.
 */
final class FIPSTestUtil
{
    private FIPSTestUtil()
    {
    }

    /**
     * Smallest HMAC / HKDF key the FIPS module accepts, in bytes.
     * <p>
     * SP 800-131A retires MAC keys below 112 bits, and the 3.5.x module
     * enforces it: {@code hmac_setkey: invalid key length} for anything
     * shorter. Measured against 3.5.7 — 8 and 13 bytes are refused, 14 bytes
     * (112 bits) and above pass. The 3.1.2 module accepted any length, which
     * is why several tests were written with 1-byte-and-up key material.
     * <p>
     * This is a <b>runtime-parameter</b> constraint the caller chooses, not a
     * capability: the registration is correct on both modules and only the
     * key length is at issue, so tests supply conforming keys rather than the
     * provider filtering the service (see the migration plan, task 4).
     */
    static final int HMAC_MIN_KEY_BYTES = 14;

    /**
     * A genuine, non-named 2048-bit PKCS#3 safe prime (generator g = 2),
     * produced once with {@code openssl dhparam 2048} and pinned here.
     * Tests that prove the FIPS q-less DH rejection MUST use a prime that
     * is NOT an RFC 7919 / RFC 3526 named group: OpenSSL recognises a
     * named-group (p, g) pair on import and silently back-fills the
     * subgroup order q, which would disarm the very SP 800-56A q-check
     * those tests exist to exercise (the first review probe was
     * contaminated exactly this way by harvesting ffdhe2048 components).
     */
    static final String NON_NAMED_SAFE_PRIME_2048_HEX =
            "FCFEF6884ADDB08BF50CF530266529EEA5C111C1CDF35436AD82FB2198EAE6C5"
                    + "3409790433D42D3EC4CD6AAA2CD1F0191801A0C0FD8B6B6BE275A5BB3301B2EF"
                    + "1C894E68BB7A930C681D8B38C2ABB34FAF01A41E5E50EFC7813789A9C14DF9B1"
                    + "3132BE4EB73C2A5824C0944F2826E3392C756D88D29BC4547FB9684C65FA4536"
                    + "537489C5BB80DCF3DA5616557B14CBDE366CD9D709631F37AAE45C60045CF157"
                    + "F571B498D979235CE136C6A6A281B4A8688F056EEE918C0178DAB8CAF9431355"
                    + "B796F17C96DADCE788C2EAA3373D86B4F016CE8CF26B369EAC5D6B990277029F"
                    + "8697B35F83C972FDDE048EB404AF37A2FE308BA91218B84EAF2DF42C3D5E12FF";

    /**
     * Skip the calling test unless a FIPS module is configured
     * ({@code TEST_FIPS_LIB}); otherwise ensure the JSLFIPS provider is
     * registered and return it.
     */
    static JostleFIPSProvider assumeFipsProvider()
    {
        Assumptions.assumeFalse(TestUtil.skipFipsTests(),
                "TEST_FIPS_LIB not set (full path to the FIPS module library)");
        return TestUtil.addFipsProvider();
    }

    /**
     * The message a verify-only FIPS module's {@code initSign} must carry.
     * Pinned once so every DSA test asserts the same text — see
     * {@code DefaultServiceNI.baseErrorHandler}'s
     * {@code JO_DSA_SIGN_UNAVAILABLE} arm and
     * {@code DSASignatureSpi.engineInitSign}, which translates it to
     * {@link java.security.InvalidKeyException}.
     */
    static final String DSA_SIGN_REFUSED_MESSAGE =
            "DSA signature generation is not supported by the loaded provider;"
                    + " signature verification remains available";

    /** Cached {@link #dsaPublicEncoding()} / {@link #dsaPrivateEncoding()}. */
    private static byte[] dsaPubEnc;
    private static byte[] dsaPrivEnc;

    /** Memoized {@link #fipsDsaCanSign()}; null until first asked. */
    private static Boolean fipsDsaSigns;

    /**
     * Shared 2048/256 (FIPS 186-4) DSA keypair, generated once per JVM through
     * <b>JSL</b> and cached as X.509 / PKCS#8 encodings.
     * <p>
     * Generated through the non-FIPS provider because the two supported FIPS
     * modules disagree: 3.1.2 generates DSA keys, and OpenSSL's 3.5.x module
     * refuses every generation path — paramgen, and keygen even from supplied
     * (p, q, g). Sourcing the keypair from mainline libcrypto keeps the DSA
     * tests running against both, and it is exactly what a caller on a
     * verify-only module has to do. Encodings are provider-neutral, so each
     * provider decodes the same bytes through its own {@code KeyFactory}.
     * <p>
     * Freshly generated per JVM rather than a pinned fixture, per the
     * random-inputs rule; the domain-parameter search is why it is generated
     * only once.
     */
    private static synchronized void ensureDsaKeyPair() throws Exception
    {
        if (dsaPubEnc != null)
        {
            return;
        }
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                "DSA", JostleProvider.PROVIDER_NAME);
        kpg.initialize(2048); // FIPS 186-4: L=2048 forces a 256-bit q (N=256).
        KeyPair kp = kpg.generateKeyPair();
        dsaPubEnc = kp.getPublic().getEncoded();
        dsaPrivEnc = kp.getPrivate().getEncoded();
    }

    /** X.509 encoding of the shared DSA public key. */
    static byte[] dsaPublicEncoding() throws Exception
    {
        ensureDsaKeyPair();
        return dsaPubEnc.clone();
    }

    /** PKCS#8 encoding of the shared DSA private key. */
    static byte[] dsaPrivateEncoding() throws Exception
    {
        ensureDsaKeyPair();
        return dsaPrivEnc.clone();
    }

    /** The shared DSA keypair decoded through {@code provider}'s KeyFactory. */
    static KeyPair dsaKeyPair(String provider) throws Exception
    {
        // Before resolving the KeyFactory: ensureDsaKeyPair registers JSL if it
        // is not already there, and callers reach here with only JSLFIPS
        // registered (the NI-level limit / ops tests never touch the JCE).
        byte[] pub = dsaPublicEncoding();
        byte[] priv = dsaPrivateEncoding();

        KeyFactory kf = KeyFactory.getInstance("DSA", provider);
        return new KeyPair(
                kf.generatePublic(new X509EncodedKeySpec(pub)),
                kf.generatePrivate(new PKCS8EncodedKeySpec(priv)));
    }

    /**
     * Does the loaded module SIGN with DSA, or only verify?
     * <p>
     * Asked by attempting the init, because nothing cheaper can answer it: the
     * key imports, the {@code Signature} resolves, and only the sign init is
     * refused (probe: {@code fips-c-review/probes/dsa_gate_probe.c}). 3.1.2
     * signs; OpenSSL's 3.5.x module refuses via its "sign-check" FIPS
     * indicator while continuing to verify.
     * <p>
     * The refusal is pinned here, not merely detected: it must arrive as
     * {@link java.security.InvalidKeyException} — the JCE-canonical initSign
     * failure and the provider-fallback trigger — carrying
     * {@link #DSA_SIGN_REFUSED_MESSAGE}. The module raises nothing on its own
     * error queue for this, so without the typed classification a caller would
     * see "OpenSSL Error: null".
     */
    static synchronized boolean fipsDsaCanSign() throws Exception
    {
        if (fipsDsaSigns == null)
        {
            PrivateKey priv = dsaKeyPair(JostleFIPSProvider.PROVIDER_NAME).getPrivate();
            try
            {
                Signature.getInstance("SHA256withDSA",
                        JostleFIPSProvider.PROVIDER_NAME).initSign(priv);
                fipsDsaSigns = Boolean.TRUE;
            }
            catch (InvalidKeyException e)
            {
                Assertions.assertEquals(DSA_SIGN_REFUSED_MESSAGE, e.getMessage(),
                        "a verify-only module must refuse initSign with the capability message");
                fipsDsaSigns = Boolean.FALSE;
            }
        }
        return fipsDsaSigns;
    }

    /** Memoized {@link #fipsDsaCanGenerate}; null until first asked. */
    private static Boolean fipsDsaGenerates;

    /**
     * Does the loaded module GENERATE DSA domain parameters?
     * <p>
     * Probed separately from {@link #fipsDsaCanSign()} rather than inferred
     * from it. Both are gated by the same "sign-check" FIPS indicator today, so
     * they move together on the two supported modules — but that is an
     * observation about those modules, not a contract, and a test that skips
     * generation coverage because <i>signing</i> was refused would be asserting
     * the wrong thing.
     * <p>
     * The probe is the operation, because nothing cheaper answers it (see the
     * migration plan, task 7). It costs one paramgen on a module that
     * generates — measured 55–331 ms on 3.1.2 — and is memoized.
     */
    static synchronized boolean fipsDsaCanGenerate(DSAServiceNI dsa, RandSource rnd)
    {
        if (fipsDsaGenerates == null)
        {
            try
            {
                long ref = dsa.generateParameters(2048, 256, rnd);
                fipsDsaGenerates = Boolean.TRUE;
                if (ref != 0)
                {
                    FIPSNISelector.SpecNI.dispose(ref);
                }
            }
            catch (ProviderCapabilityException e)
            {
                Assertions.assertEquals(
                        "DSA key generation is not supported by the loaded provider;"
                                + " DSA key import and signature verification remain available",
                        e.getMessage(),
                        "a module that refuses DSA paramgen must say so typed");
                fipsDsaGenerates = Boolean.FALSE;
            }
        }
        return fipsDsaGenerates;
    }

    /**
     * The shared DSA keypair as NI-level handles on {@code dsa}'s interface
     * library: {@code {paramsRef, keyRef}}.
     * <p>
     * Imported through {@code makeParamsFromComponents} /
     * {@code makePrivateFromComponents} rather than generated through
     * {@code generateParameters} / {@code generateKeyPair}, because OpenSSL's
     * 3.5.x FIPS module refuses both generation calls while still importing.
     * The caller owns both handles and must dispose them.
     */
    static long[] dsaNiHandles(DSAServiceNI dsa, RandSource rnd) throws Exception
    {
        DSAPrivateKey priv = (DSAPrivateKey) dsaKeyPair(
                JostleProvider.PROVIDER_NAME).getPrivate();
        byte[] p = magnitude(priv.getParams().getP());
        byte[] q = magnitude(priv.getParams().getQ());
        byte[] g = magnitude(priv.getParams().getG());
        byte[] x = magnitude(priv.getX());

        long paramsRef = dsa.makeParamsFromComponents(p, q, g);
        long keyRef = dsa.makePrivateFromComponents(p, q, g, x, rnd);
        return new long[]{paramsRef, keyRef};
    }

    /**
     * Big-endian unsigned magnitude of a positive BigInteger — BigInteger's own
     * encoding carries a leading zero byte whenever the top bit is set, which
     * the native component importers do not expect.
     */
    private static byte[] magnitude(BigInteger v)
    {
        byte[] b = v.toByteArray();
        if (b.length > 1 && b[0] == 0)
        {
            byte[] trimmed = new byte[b.length - 1];
            System.arraycopy(b, 1, trimmed, 0, trimmed.length);
            return trimmed;
        }
        return b;
    }

    /**
     * The message a module without implicit rejection must carry when a
     * PKCS#1 v1.5 decrypt init is refused. Pinned once — see
     * {@code DefaultServiceNI.baseErrorHandler}'s
     * {@code JO_IMPLICIT_REJECTION_UNAVAILABLE} arm.
     */
    static final String IMPLICIT_REJECTION_UNAVAILABLE_MESSAGE =
            "PKCS#1 v1.5 decryption requires implicit rejection,"
                    + " which the loaded provider does not support";

    /** Memoized {@link #fipsPkcs1CanEncrypt}; null until first asked. */
    private static Boolean fipsPkcs1Encrypts;

    /**
     * Does the loaded module ENCRYPT with PKCS#1 v1.5 padding?
     * <p>
     * The two supported modules mirror each other on this transformation, and
     * neither direction is available on both:
     * <pre>
     *   3.1.2 : encrypt WORKS   / decrypt-init refused (no implicit rejection)
     *   3.5.7 : encrypt REFUSED / decrypt-init works   (implicit rejection present)
     * </pre>
     * 3.5.x gates PKCS#1 v1.5 <i>encryption</i> behind its
     * {@code rsa-pkcs15-pad-disabled} FIPS indicator
     * ({@code rsa_enc.c::rsa_encrypt}) and leaves decryption alone, while
     * 3.1.2 predates the implicit-rejection parameter that
     * {@code rsa_pkcs1_init} refuses to decrypt without. This is why the FIPS
     * PKCS#1 bridge is kept rather than dropped: each module needs one half of
     * it, so removing it would break decryption on 3.5.x and encryption on the
     * currently-validated module.
     * <p>
     * Probed by attempting the operation — a fetch and
     * {@code EVP_PKEY_CTX_set_rsa_padding} both succeed on either module, so
     * only the real call distinguishes them (see the migration plan, task 7).
     * The refusal is loud and self-describing on its own
     * ({@code rsa_encrypt: invalid padding mode}), and no JCE transformation
     * reaches this bridge, so it is deliberately NOT given a typed capability
     * code the way DSA generation is.
     */
    static synchronized boolean fipsPkcs1CanEncrypt(RSAPKCS1CipherNI cipherNI,
                                                    long pubKeyRef, RandSource rnd)
    {
        if (fipsPkcs1Encrypts == null)
        {
            long ref = cipherNI.allocateCipher();
            try
            {
                cipherNI.init(ref, pubKeyRef, RSAPKCS1CipherNI.OP_ENCRYPT, rnd);
                byte[] msg = {1, 2, 3, 4};
                int needed = cipherNI.doFinal(ref, msg, 0, msg.length, null, 0, rnd);
                cipherNI.doFinal(ref, msg, 0, msg.length, new byte[needed], 0, rnd);
                fipsPkcs1Encrypts = Boolean.TRUE;
            }
            catch (OpenSSLException e)
            {
                Assertions.assertTrue(
                        String.valueOf(e.getMessage()).contains("invalid padding mode"),
                        "a module refusing PKCS#1 v1.5 encryption must name the padding mode,"
                                + " got: " + e.getMessage());
                fipsPkcs1Encrypts = Boolean.FALSE;
            }
            finally
            {
                cipherNI.disposeCipher(ref);
            }
        }
        return fipsPkcs1Encrypts;
    }

    /**
     * The loaded module's self-reported name and version, for failure
     * messages. Diagnostics only — never branch on it (see
     * {@code OpenSSLFIPSNI.moduleVersion}).
     */
    static String moduleDescription()
    {
        String v = FIPSNISelector.OpenSSLFIPSNI.moduleVersion();
        return v == null || v.isEmpty() ? "unknown FIPS module" : v;
    }

    /**
     * The FIPS module library file named by {@code TEST_FIPS_LIB}. Only call
     * after {@link #assumeFipsProvider()} (or an equivalent skip guard) has
     * established the variable is set.
     */
    static File fipsModuleFile()
    {
        return new File(TestUtil.fipsLibPath());
    }

    /**
     * The directory containing the FIPS module (and, by convention, its
     * {@code fipsmodule.cnf}).
     */
    static String fipsModuleDir()
    {
        return fipsModuleFile().getParent();
    }
}
