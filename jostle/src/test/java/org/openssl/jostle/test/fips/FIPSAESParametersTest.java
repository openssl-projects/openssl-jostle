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
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.Security;

/**
 * AES parameter/AEAD-state <b>behaviour</b> through the FIPS provider ("JSLFIPS"),
 * mirroring the non-FIPS {@code AESParametersTest}:
 * <ul>
 *   <li>GCM rejects malformed tag lengths at the JCE boundary with
 *       {@link InvalidAlgorithmParameterException}, and accepts the BC-compatible
 *       boundary values;</li>
 *   <li>a GCM encrypt instance cannot be reused without re-init (nonce-reuse
 *       guard) — a second {@code doFinal} throws {@link IllegalStateException};</li>
 *   <li>GCM auto-generates a 12-byte nonce which {@code getIV()} and
 *       {@code getParameters()} agree on, and the recovered parameters drive a
 *       clean decrypt; ECB exposes no parameters;</li>
 *   <li>the GCM/CCM/CBC {@code AlgorithmParameters} registered by the FIPS
 *       provider resolve and encode/decode round-trip (locking
 *       {@code ProvFIPSAES}'s registrations against drop/wrong-OID), with the
 *       CCM RFC 5084 DER pinned;</li>
 *   <li>malformed CCM {@code AlgorithmParameters} DER is rejected with
 *       {@link IOException}.</li>
 * </ul>
 * Keys are generated through the FIPS provider. Gated on TEST_FIPS_LIB; skipped
 * when unset.
 */
public class FIPSAESParametersTest
{
    private static final String FIPS = JostleFIPSProvider.PROVIDER_NAME;

    private static final String GCM = "AES/GCM/NoPadding";
    private static final String CBC = "AES/CBC/NoPadding";
    private static final String CCM = "AES/CCM/NoPadding";
    private static final String ECB = "AES/ECB/NoPadding";

    private static final String AES256_GCM_OID = "2.16.840.1.101.3.4.1.46";
    private static final String AES256_CCM_OID = "2.16.840.1.101.3.4.1.47";
    private static final String AES128_CBC_OID = "2.16.840.1.101.3.4.1.2";
    private static final String AES192_CBC_OID = "2.16.840.1.101.3.4.1.22";
    private static final String AES256_CBC_OID = "2.16.840.1.101.3.4.1.42";

    private static final SecureRandom RANDOM = new SecureRandom();

    private static void ensureProviders()
    {
        FIPSTestUtil.assumeFipsProvider();
    }

    private static SecureRandom seededRandom(String testName)
        throws Exception
    {
        long seed = RANDOM.nextLong();
        System.out.println(testName + " seed=" + seed);
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(seed);
        return sr;
    }

    /**
     * AES-256 key generated through the FIPS provider (convention: FIPS
     * operational keys originate from JSLFIPS).
     */
    private static SecretKey aes256Key(SecureRandom random)
        throws Exception
    {
        KeyGenerator kg = KeyGenerator.getInstance("AES", FIPS);
        kg.init(256, random);
        return kg.generateKey();
    }

    private static byte[] concat(byte[] a, byte[] b)
    {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    /**
     * GCM rejects out-of-range and non-byte-aligned tag lengths at the JCE
     * boundary with the contracted exception type, rather than letting them
     * reach OpenSSL; the BC-compatible boundary values are accepted. Mirrors
     * {@code AESParametersTest.gcmRejectsMalformedTagLength}.
     */
    @Test
    public void gcmMalformedTagLengthRejected()
        throws Exception
    {
        ensureProviders();

        SecureRandom random = seededRandom("gcmMalformedTagLengthRejected");
        SecretKey key = aes256Key(random);
        byte[] iv = new byte[12];
        random.nextBytes(iv);

        // 24/8 are below the BC floor, 100 is not byte-aligned, 136 is above the
        // 128-bit maximum.
        for (int badBits : new int[]{8, 24, 100, 136})
        {
            Cipher c = Cipher.getInstance(GCM, FIPS);
            boolean rejected = false;
            try
            {
                c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(badBits, iv), random);
            }
            catch (InvalidAlgorithmParameterException e)
            {
                rejected = true;
            }
            Assertions.assertTrue(rejected, "malformed GCM tag length " + badBits + " must be rejected");
        }

        // The BC-compatible boundary values are accepted.
        for (int okBits : new int[]{32, 128})
        {
            Cipher c = Cipher.getInstance(GCM, FIPS);
            c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(okBits, iv), random);
            Assertions.assertNotNull(c.getIV(), okBits + "-bit GCM tag must be accepted");
        }
    }

    /**
     * A GCM encrypt instance cannot be reused without re-init: a second
     * {@code doFinal} would reuse the auto-generated nonce (catastrophic) and
     * must throw {@link IllegalStateException}; after re-init the instance
     * round-trips. Mirrors
     * {@code AESParametersTest.gcmEncryptCannotBeReusedWithoutReinit}.
     */
    @Test
    public void gcmEncryptReuseWithoutReinitRejected()
        throws Exception
    {
        ensureProviders();

        SecureRandom random = seededRandom("gcmEncryptReuseWithoutReinitRejected");
        SecretKey key = aes256Key(random);
        byte[] msg = new byte[29];
        random.nextBytes(msg);

        Cipher enc = Cipher.getInstance(GCM, FIPS);
        enc.init(Cipher.ENCRYPT_MODE, key, random);
        enc.doFinal(msg);

        boolean rejected = false;
        try
        {
            enc.doFinal(msg);
        }
        catch (IllegalStateException e)
        {
            rejected = true;
        }
        Assertions.assertTrue(rejected, "GCM encrypt reuse without re-init must throw IllegalStateException");

        // Re-init draws a fresh nonce; the instance is usable again.
        enc.init(Cipher.ENCRYPT_MODE, key, random);
        byte[] ct = enc.doFinal(msg);
        byte[] iv = enc.getIV();
        Cipher dec = Cipher.getInstance(GCM, FIPS);
        dec.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
        Assertions.assertArrayEquals(msg, dec.doFinal(ct), "instance must be reusable after re-init");
    }

    /**
     * GCM with no supplied parameters auto-generates a 12-byte nonce (128-bit
     * default tag); {@code getIV()} and {@code getParameters()} agree, and a
     * decrypt initialised purely from the returned {@link AlgorithmParameters}
     * round-trips (the CMS auto-IV path). ECB exposes no IV/parameters. Mirrors
     * {@code AESParametersTest.gcmEncryptWithoutParamsAutoGeneratesIv} +
     * {@code ecbExposesNoParameters}.
     */
    @Test
    public void gcmAutoIvExposedAndRoundTrips()
        throws Exception
    {
        ensureProviders();

        SecureRandom random = seededRandom("gcmAutoIvExposedAndRoundTrips");
        SecretKey key = aes256Key(random);
        byte[] msg = new byte[40];
        random.nextBytes(msg);

        Cipher enc = Cipher.getInstance(GCM, FIPS);
        enc.init(Cipher.ENCRYPT_MODE, key, random);     // no parameters supplied

        byte[] iv = enc.getIV();
        Assertions.assertNotNull(iv, "GCM must expose an auto-generated IV");
        Assertions.assertEquals(12, iv.length, "GCM nonce must be 12 bytes");

        AlgorithmParameters params = enc.getParameters();
        Assertions.assertNotNull(params, "GCM must expose auto-generated AlgorithmParameters");
        GCMParameterSpec spec = params.getParameterSpec(GCMParameterSpec.class);
        Assertions.assertEquals(128, spec.getTLen(), "default GCM tag length must be 128 bits");
        Assertions.assertArrayEquals(iv, spec.getIV(), "getIV() and getParameters() must agree");

        byte[] ct = enc.doFinal(msg);

        Cipher dec = Cipher.getInstance(GCM, FIPS);
        dec.init(Cipher.DECRYPT_MODE, key, params);
        Assertions.assertArrayEquals(msg, dec.doFinal(ct), "round-trip via getParameters() failed");

        // ECB counterpart: no IV, no parameters.
        Cipher ecb = Cipher.getInstance(ECB, FIPS);
        ecb.init(Cipher.ENCRYPT_MODE, key, random);
        Assertions.assertNull(ecb.getIV(), "ECB has no IV");
        Assertions.assertNull(ecb.getParameters(), "ECB has no parameters");
    }

    /**
     * The GCM/CCM/CBC {@code AlgorithmParameters} registered by the FIPS provider
     * resolve (non-null) and encode/decode round-trip through JSLFIPS — locking
     * {@code ProvFIPSAES}'s AlgorithmParameters registrations against drop or
     * wrong-OID. The CCM RFC 5084 DER (aes-ICVlen omitted at the DEFAULT) is
     * pinned as a differentiator. Mirrors
     * {@code AESParametersTest.gcmAlgorithmParametersResolveByName /
     * ccmAlgorithmParameters_rfc5084Encoding / cbcAlgorithmParametersResolveByOid}.
     */
    @Test
    public void algorithmParametersResolveAndRoundTrip()
        throws Exception
    {
        ensureProviders();

        SecureRandom random = seededRandom("algorithmParametersResolveAndRoundTrip");

        // GCM by bare name and by AES-256-GCM OID.
        for (String name : new String[]{"GCM", AES256_GCM_OID})
        {
            byte[] iv = new byte[12];
            random.nextBytes(iv);

            AlgorithmParameters params = AlgorithmParameters.getInstance(name, FIPS);
            Assertions.assertNotNull(params, name + ": GCM AlgorithmParameters must resolve through JSLFIPS");
            params.init(new GCMParameterSpec(128, iv));
            byte[] encoded = params.getEncoded();

            AlgorithmParameters reparsed = AlgorithmParameters.getInstance(name, FIPS);
            reparsed.init(encoded);
            GCMParameterSpec spec = reparsed.getParameterSpec(GCMParameterSpec.class);
            Assertions.assertArrayEquals(iv, spec.getIV(), name + ": GCM params did not round-trip the nonce");
            Assertions.assertEquals(128, spec.getTLen(), name + ": GCM params did not round-trip the tag length");
        }

        // CCM by bare name and by AES-256-CCM OID: RFC 5084 DER pinned.
        byte[] nonce = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b};
        byte[] octetString = {0x04, 0x0c, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b};
        // SEQUENCE { OCTET STRING nonce } -- ICV 12 (DEFAULT, omitted)
        byte[] expectDefault = concat(new byte[]{0x30, 0x0e}, octetString);
        for (String name : new String[]{"CCM", AES256_CCM_OID})
        {
            AlgorithmParameters params = AlgorithmParameters.getInstance(name, FIPS);
            Assertions.assertNotNull(params, name + ": CCM AlgorithmParameters must resolve through JSLFIPS");
            params.init(new GCMParameterSpec(96, nonce));   // 96-bit tag => 12-byte ICV (DEFAULT)
            byte[] der = params.getEncoded();
            Assertions.assertArrayEquals(expectDefault, der,
                    name + ": CCMParameters DER does not match the RFC 5084 vector");

            AlgorithmParameters reparsed = AlgorithmParameters.getInstance(name, FIPS);
            reparsed.init(der);
            GCMParameterSpec spec = reparsed.getParameterSpec(GCMParameterSpec.class);
            Assertions.assertArrayEquals(nonce, spec.getIV(), name + ": CCMParameters did not round-trip the nonce");
            Assertions.assertEquals(96, spec.getTLen(), name + ": CCMParameters did not round-trip the tag length");
        }

        // CBC by each AES-CBC OID (128/192/256): IV OCTET STRING round-trip.
        for (String oid : new String[]{AES128_CBC_OID, AES192_CBC_OID, AES256_CBC_OID})
        {
            byte[] iv = new byte[16];
            random.nextBytes(iv);

            AlgorithmParameters params = AlgorithmParameters.getInstance(oid, FIPS);
            Assertions.assertNotNull(params, oid + ": AES-CBC AlgorithmParameters must resolve through JSLFIPS");
            params.init(new IvParameterSpec(iv));
            byte[] encoded = params.getEncoded();

            AlgorithmParameters reparsed = AlgorithmParameters.getInstance(oid, FIPS);
            reparsed.init(encoded);
            Assertions.assertArrayEquals(iv, reparsed.getParameterSpec(IvParameterSpec.class).getIV(),
                    oid + ": AES-CBC AlgorithmParameters did not round-trip the IV");
        }
    }

    /**
     * The hand-rolled RFC 5084 CCM decoder must reject malformed DER with
     * {@link IOException}, never silently accept arbitrary bytes; the well-formed
     * baseline parses. Mirrors
     * {@code AESParametersTest.ccmAlgorithmParameters_rejectsMalformedEncodings}.
     */
    @Test
    public void ccmAlgorithmParametersRejectMalformedDer()
        throws Exception
    {
        ensureProviders();

        // OCTET STRING of a valid 12-byte nonce: 04 0C 00..0B
        byte[] octetString = {0x04, 0x0c, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b};
        // A well-formed baseline (ICV default omitted): 30 0E <octetString>.
        byte[] valid = concat(new byte[]{0x30, 0x0e}, octetString);

        byte[][] malformed = {
                // wrong outer tag (SET 0x31 instead of SEQUENCE 0x30)
                concat(new byte[]{0x31, 0x0e}, octetString),
                // trailing byte after a complete CCMParameters
                concat(valid, new byte[]{0x00}),
                // truncated content: SEQUENCE claims 0x0e but only the OCTET STRING header follows
                {0x30, 0x0e, 0x04, 0x0c, 0x00, 0x01},
                // unsupported long-form length on the outer SEQUENCE
                concat(new byte[]{0x30, (byte) 0x81, 0x0e}, octetString),
                // nonce too short (4 bytes < CCM minimum of 7): 30 06 04 04 00 01 02 03
                {0x30, 0x06, 0x04, 0x04, 0x00, 0x01, 0x02, 0x03},
                // invalid ICV length (INTEGER 5 is not in {4,6,8,10,12,14,16})
                concat(concat(new byte[]{0x30, 0x11}, octetString), new byte[]{0x02, 0x01, 0x05}),
                // empty input
                new byte[0],
        };

        for (int i = 0; i < malformed.length; i++)
        {
            final byte[] bad = malformed[i];
            AlgorithmParameters params = AlgorithmParameters.getInstance("CCM", FIPS);
            final int idx = i;
            Assertions.assertThrows(IOException.class, () -> params.init(bad),
                    "malformed CCMParameters encoding #" + idx + " must be rejected");
        }

        // Sanity: the baseline the malformed cases derive from IS accepted.
        AlgorithmParameters ok = AlgorithmParameters.getInstance("CCM", FIPS);
        ok.init(valid);
        Assertions.assertEquals(12, ok.getParameterSpec(GCMParameterSpec.class).getIV().length,
                "the well-formed baseline encoding must parse");
    }

    /**
     * An AEAD cipher's {@code getParameters()} must come from the SAME provider
     * that produced the cipher — including when JSL is registered alongside
     * JSLFIPS.
     *
     * <p>This is a regression guard. The AEAD SPIs originally resolved
     * {@code AlgorithmParameters.getInstance(alg)} unpinned, which handed the
     * object to whichever provider led the JCA search order (SunJCE for "GCM",
     * in a default JVM). Pinning it to "a Jostle provider" then still returned
     * JSL's instance to a JSLFIPS cipher whenever both were registered. The
     * parameters classes carry no cryptography — they are DER codecs — so the
     * bug was invisible to any functional test; only provider attribution
     * exposes it, and only in the dual-provider deployment.</p>
     */
    @Test
    public void aeadParameters_comeFromTheCiphersOwnProvider()
        throws Exception
    {
        ensureProviders();
        // Both providers registered simultaneously — the case that regressed.
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        Assertions.assertNotNull(Security.getProvider(JostleProvider.PROVIDER_NAME),
                "precondition: JSL must be registered alongside JSLFIPS");

        SecureRandom random = seededRandom("aeadParameters_comeFromTheCiphersOwnProvider");
        SecretKey key = aes256Key(random);

        for (String transformation : new String[]{GCM, CCM})
        {
            int tagBits = CCM.equals(transformation) ? 64 : 128;
            byte[] nonce = new byte[12];
            random.nextBytes(nonce);

            Cipher cipher = Cipher.getInstance(transformation, FIPS);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(tagBits, nonce));
            AlgorithmParameters params = cipher.getParameters();

            Assertions.assertNotNull(params, transformation + ": AEAD cipher must expose parameters");
            Assertions.assertEquals(FIPS, params.getProvider().getName(),
                    transformation + ": parameters came from " + params.getProvider().getName()
                            + ", not the cipher's own provider");

            // The parameters must still drive a decrypt on the same provider.
            byte[] msg = new byte[29];
            random.nextBytes(msg);
            byte[] ct = cipher.doFinal(msg);
            Cipher dec = Cipher.getInstance(transformation, FIPS);
            dec.init(Cipher.DECRYPT_MODE, key, params);
            Assertions.assertArrayEquals(msg, dec.doFinal(ct),
                    transformation + ": round-trip through the exposed parameters failed");
        }
    }
}
