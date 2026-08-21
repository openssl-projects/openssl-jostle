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
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.interfaces.OSSLKey;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.jcajce.provider.ProviderCapabilityException;
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.jcajce.provider.rsa.RSAPKCS1CipherNI;
import org.openssl.jostle.jcajce.provider.rsa.RSAServiceNI;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.rand.RandSource;
import org.openssl.jostle.test.TestUtil;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

/**
 * Input-validation limit tests at the FIPS RSA-PKCS#1 v1.5 cipher NI surface
 * ({@link FIPSNISelector#RSAPKCS1CipherNI}). The FIPS JNI glue is the base
 * rsa_pkcs1_ni_jni.c re-included under renamed symbols. Mirrors the base
 * {@code RSAPKCS1CipherLimitTest} where the FIPS contract allows.
 *
 * <p><b>The two supported modules mirror each other here, and neither serves
 * both directions:</b>
 * <pre>
 *   3.1.2 : encrypt WORKS   / decrypt-init refused (no implicit rejection)
 *   3.5.7 : encrypt REFUSED / decrypt-init works   (implicit rejection present)
 * </pre>
 * <b>Decrypt.</b> {@code OSSL_ASYM_CIPHER_PARAM_IMPLICIT_REJECTION} (the
 * Bleichenbacher mitigation) entered OpenSSL 3.2, and
 * {@code EVP_PKEY_CTX_set_params} silently ignores unknown params — so
 * {@code rsa_pkcs1_init} probes {@code EVP_PKEY_CTX_settable_params} for the
 * parameter before initialising any DECRYPT session and refuses with
 * {@code JO_IMPLICIT_REJECTION_UNAVAILABLE} (-135,
 * {@link ProviderCapabilityException}) when the provider cannot honour it.
 * Running decryption without the mitigation would be a padding oracle. That
 * probe fails on 3.1.2 and passes on 3.5.x.
 *
 * <p><b>Encrypt.</b> 3.5.x gates PKCS#1 v1.5 <i>encryption</i> behind its
 * {@code rsa-pkcs15-pad-disabled} FIPS indicator
 * ({@code rsa_enc.c::rsa_encrypt}) and refuses it with
 * {@code invalid padding mode}; 3.1.2 encrypts happily.
 *
 * <p>So the bridge is kept rather than dropped — each module needs one half of
 * it — and this class asserts <b>the contract</b> rather than either module's
 * answer, probing through {@link FIPSTestUtil#fipsPkcs1CanEncrypt}. Round-trip
 * validations pair the FIPS side with the base (JSL) provider, which serves
 * both directions, with the key shared via its PKCS#8 / X.509 encoding.
 *
 * <p>Keygen uses the 2048 module floor; {@link TestUtil#RNDSrc} satisfies the
 * bridge null-check (FIPS entropy path does not consult it).
 *
 * <p>Runs under the {@code integrationTest*} tasks; gated on
 * {@code TEST_FIPS_LIB}. Adds an in-place / aliased-buffer test (testing.md).
 */
public class FIPSRSAPKCS1CipherLimitTest
{
    private static final byte[] PUB_EXP_F4 = {0x01, 0x00, 0x01};
    private static final RandSource RND = TestUtil.RNDSrc;

    private static final String IMPLICIT_REJECTION_UNAVAILABLE_MESSAGE =
            "PKCS#1 v1.5 decryption requires implicit rejection, which the loaded provider does not support";

    @BeforeAll
    public static void beforeAll()
    {
        Assumptions.assumeFalse(TestUtil.skipFipsTests(),
                "TEST_FIPS_LIB not set (full path to the FIPS module library)");
        TestUtil.addFipsProvider();
        // The base provider decrypts what the FIPS NI encrypts (the module
        // refuses PKCS#1 v1.5 decryption — see class Javadoc).
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    private final RSAServiceNI rsaServiceNI = FIPSNISelector.RSAServiceNI;
    private final RSAPKCS1CipherNI cipherNI = FIPSNISelector.RSAPKCS1CipherNI;
    private final SpecNI specNI = FIPSNISelector.SpecNI;

    @Test
    public void init_nullKey()
    {
        long ref = cipherNI.allocateCipher();
        try
        {
            IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                    () -> cipherNI.init(ref, 0, RSAPKCS1CipherNI.OP_ENCRYPT, RND));
            Assertions.assertEquals("key spec is null", e.getMessage());
        }
        finally
        {
            cipherNI.disposeCipher(ref);
        }
    }

    @Test
    public void nullCipherCtx_allEntryPointsRejectedTyped()
    {
        // A 0/null cipher ctx handle at any PKCS#1 cipher entry point must
        // surface the typed JO_CIPHER_CTX_IS_NULL -> IllegalArgumentException
        // ("cipher context is null"), NOT abort the JVM via jo_assert — the
        // FIPS glue re-includes the base bridge, so this pins the same fix
        // through the FIPS library (rsa_pkcs1_ni_jni.c / rsa_pkcs1_ni_ffi.c
        // under interface/fips/). Passing 0 for the key spec as well pins the
        // validation ORDER (ctx before key).
        Assertions.assertEquals("cipher context is null", Assertions.assertThrows(IllegalArgumentException.class,
                () -> cipherNI.init(0, 0, RSAPKCS1CipherNI.OP_ENCRYPT, RND)).getMessage());
        Assertions.assertEquals("cipher context is null", Assertions.assertThrows(IllegalArgumentException.class,
                () -> cipherNI.doFinal(0, new byte[16], 0, 16, null, 0, RND)).getMessage());
    }

    @Test
    public void init_nullRand_encrypt()
    {
        withCipherAndKey((ref, keyRef) ->
        {
            IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                    () -> cipherNI.init(ref, keyRef, RSAPKCS1CipherNI.OP_ENCRYPT, null));
            Assertions.assertEquals("supplied random source was null", e.getMessage());
        });
    }

    @Test
    public void init_nullRand_decrypt()
    {
        // Decrypt also requires a RAND source (RSA blinding). The bridge
        // null-check fires BEFORE the util-layer implicit-rejection probe,
        // so the rejection is the RAND one even though decrypt init could
        // never succeed against this module.
        withCipherAndKey((ref, keyRef) ->
        {
            IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                    () -> cipherNI.init(ref, keyRef, RSAPKCS1CipherNI.OP_DECRYPT, null));
            Assertions.assertEquals("supplied random source was null", e.getMessage());
        });
    }

    // -----------------------------------------------------------------
    // Fail-loud decrypt contract — hard guards (see class Javadoc)
    // -----------------------------------------------------------------

    /**
     * The decrypt-init capability contract, both ways round.
     * <p>
     * A module WITHOUT implicit rejection must refuse every PKCS#1 v1.5
     * decrypt init — {@code ni_init(OP_DECRYPT)} returning the raw
     * {@code JO_IMPLICIT_REJECTION_UNAVAILABLE} code (-135, deliberately
     * carrying no OPS offset) and the wrapped {@code init} surfacing
     * {@link ProviderCapabilityException} with the pinned message. That is the
     * runtime guard referenced by the block comment in
     * {@code interface/fips/util/rsa_pkcs1.c}, and running decryption without
     * the mitigation would be a padding oracle.
     * <p>
     * A module WITH it must accept the init and then actually decrypt — the
     * refusal must not linger as a stale gate once the capability arrives.
     * Asserting only the refusal would let a provider that gained implicit
     * rejection keep being turned away for a reason that no longer holds; the
     * round-trip is what proves the accepted init is real and not merely
     * un-refused.
     */
    @Test
    public void initDecrypt_refusedWithoutImplicitRejection_worksWithIt() throws Exception
    {
        final long ref = cipherNI.allocateCipher();
        try
        {
            KeyPair kp = generateFipsJceKeyPair();
            long pubRef = ((OSSLKey) kp.getPublic()).getSpec().getReference();
            long privRef = ((OSSLKey) kp.getPrivate()).getSpec().getReference();

            int code = cipherNI.ni_init(ref, privRef, RSAPKCS1CipherNI.OP_DECRYPT, RND);
            if (code == -135)
            {
                ProviderCapabilityException e = Assertions.assertThrows(
                        ProviderCapabilityException.class,
                        () -> cipherNI.init(ref, privRef, RSAPKCS1CipherNI.OP_DECRYPT, RND));
                Assertions.assertEquals(
                        FIPSTestUtil.IMPLICIT_REJECTION_UNAVAILABLE_MESSAGE, e.getMessage());
                return;
            }

            Assertions.assertEquals(0, code,
                    "decrypt init must either refuse with -135 or succeed");

            // The capability is present, so decryption must genuinely work.
            // Ciphertext comes from the base provider because this module may
            // be one that refuses to ENCRYPT.
            byte[] msg = {9, 8, 7, 6, 5};
            byte[] ct = baseProviderEncrypt(kp, msg);

            cipherNI.init(ref, privRef, RSAPKCS1CipherNI.OP_DECRYPT, RND);
            int needed = cipherNI.doFinal(ref, ct, 0, ct.length, null, 0, RND);
            byte[] out = new byte[needed];
            int written = cipherNI.doFinal(ref, ct, 0, ct.length, out, 0, RND);
            Assertions.assertArrayEquals(msg, Arrays.copyOf(out, written),
                    "a module with implicit rejection must actually decrypt");
            Assertions.assertNotEquals(0, pubRef);
        }
        finally
        {
            cipherNI.disposeCipher(ref);
        }
    }

    /**
     * Negative-then-positive on one cipher ctx: a refused init must not poison
     * it — a subsequent init in the direction the deployment DOES serve
     * succeeds on the same ref and produces a working result.
     * <p>
     * Which direction is refused is decided at runtime, not assumed. All four
     * combinations are legitimate and this drives whichever it finds:
     * <pre>
     *   encrypt yes / decrypt no   3.1.2 - no implicit rejection
     *   encrypt no  / decrypt yes  3.5.x with rsa-pkcs15-pad-disabled = 1
     *   encrypt yes / decrypt yes  3.5.x at fipsinstall defaults
     *   encrypt no  / decrypt no   not observed; the round-trip is skipped
     * </pre>
     */
    @Test
    public void initRefused_thenTheOtherDirectionSucceeds() throws Exception
    {
        final long ref = cipherNI.allocateCipher();
        try
        {
            KeyPair kp = generateFipsJceKeyPair();
            long pubRef = ((OSSLKey) kp.getPublic()).getSpec().getReference();
            long privRef = ((OSSLKey) kp.getPrivate()).getSpec().getReference();
            byte[] msg = {1, 2, 3, 4};

            boolean encrypts = encryptAvailable(kp);
            // -135 is JO_IMPLICIT_REJECTION_UNAVAILABLE; anything else must be
            // success, since a decrypt init has no other legitimate failure
            // against a freshly generated key.
            int decryptInit = cipherNI.ni_init(ref, privRef, RSAPKCS1CipherNI.OP_DECRYPT, RND);
            boolean decrypts = decryptInit != -135;
            Assertions.assertTrue(decrypts || decryptInit == -135,
                    "unexpected decrypt-init code " + decryptInit);
            if (decrypts)
            {
                Assertions.assertEquals(0, decryptInit,
                        "decrypt init must either refuse with -135 or succeed");
            }

            if (!encrypts)
            {
                // Encrypt is refused. Prove the refusal, then that the ctx is
                // still usable in the other direction.
                cipherNI.init(ref, pubRef, RSAPKCS1CipherNI.OP_ENCRYPT, RND);
                Assertions.assertThrows(OpenSSLException.class,
                        () -> cipherNI.doFinal(ref, msg, 0, msg.length, null, 0, RND));

                Assumptions.assumeTrue(decrypts,
                        "neither direction is served, so there is no recovery to assert");
                assertDecryptsTo(ref, privRef, baseProviderEncrypt(kp, msg), msg,
                        "decrypt after a refused encrypt produced the wrong plaintext");
                return;
            }

            if (!decrypts)
            {
                // Decrypt init is refused (no implicit rejection). Encrypt on
                // the SAME ref must still work.
                cipherNI.init(ref, pubRef, RSAPKCS1CipherNI.OP_ENCRYPT, RND);
                int needed = cipherNI.doFinal(ref, msg, 0, msg.length, null, 0, RND);
                byte[] ct = new byte[needed];
                cipherNI.doFinal(ref, msg, 0, msg.length, ct, 0, RND);
                Assertions.assertArrayEquals(msg, baseProviderDecrypt(kp, ct),
                        "encrypt after a refused decrypt init produced bad ciphertext");
                return;
            }

            // Neither direction is refused. There is no poisoning to test, but
            // the flip between directions on one ctx is still worth pinning:
            // encrypt, then decrypt the result back on the SAME ref.
            cipherNI.init(ref, pubRef, RSAPKCS1CipherNI.OP_ENCRYPT, RND);
            int needed = cipherNI.doFinal(ref, msg, 0, msg.length, null, 0, RND);
            byte[] ct = new byte[needed];
            cipherNI.doFinal(ref, msg, 0, msg.length, ct, 0, RND);

            assertDecryptsTo(ref, privRef, ct, msg,
                    "encrypt then decrypt on one ctx did not round-trip");
        }
        finally
        {
            cipherNI.disposeCipher(ref);
        }
    }

    /** Re-init {@code ref} for decrypt and assert {@code ct} yields {@code expected}. */
    private void assertDecryptsTo(long ref, long privRef, byte[] ct, byte[] expected, String message)
    {
        cipherNI.init(ref, privRef, RSAPKCS1CipherNI.OP_DECRYPT, RND);
        int needed = cipherNI.doFinal(ref, ct, 0, ct.length, null, 0, RND);
        byte[] out = new byte[needed];
        int written = cipherNI.doFinal(ref, ct, 0, ct.length, out, 0, RND);
        Assertions.assertArrayEquals(expected, Arrays.copyOf(out, written), message);
    }

    /**
     * Encrypt/wrap is unaffected by the fail-loud decrypt contract: NI-level
     * encrypt init succeeds against the module and produces ciphertext of
     * exactly the modulus length, which the base (JSL) provider — where
     * implicit rejection IS supported — decrypts back to the plaintext.
     */
    @Test
    public void encrypt_stillSucceeds_ciphertextIsModulusLength() throws Exception
    {
        assumeEncryptAvailable();
        long encRef = 0;
        try
        {
            encRef = cipherNI.allocateCipher();
            KeyPair kp = generateFipsJceKeyPair();
            long keyRef = ((OSSLKey) kp.getPublic()).getSpec().getReference();

            cipherNI.init(encRef, keyRef, RSAPKCS1CipherNI.OP_ENCRYPT, RND);
            byte[] msg = new byte[24];
            new SecureRandom().nextBytes(msg);
            int needed = cipherNI.doFinal(encRef, msg, 0, msg.length, null, 0, RND);
            Assertions.assertEquals(256, needed, "2048-bit modulus → 256-byte ciphertext");
            byte[] ct = new byte[needed];
            Assertions.assertEquals(needed,
                    cipherNI.doFinal(encRef, msg, 0, msg.length, ct, 0, RND));

            Assertions.assertArrayEquals(msg, baseProviderDecrypt(kp, ct),
                    "FIPS-encrypted PKCS#1 ciphertext did not decrypt via the base provider");
        }
        finally
        {
            cipherNI.disposeCipher(encRef);
        }
    }

    /**
     * JCE-level hard guard: the FIPS provider does not serve
     * {@code RSA/ECB/PKCS1Padding} at all — {@code ProvFIPSRSA} deliberately
     * registers no PKCS#1 v1.5 encryption cipher (non-approved service AND
     * the module lacks implicit rejection), and the bare {@code "RSA"}
     * Cipher is OAEP, whose {@code engineSetPadding} rejects the form-4
     * {@code PKCS1Padding} request. So a caller cannot even obtain a PKCS#1
     * v1.5 decrypt (or encrypt) Cipher from JSLFIPS; the typed
     * InvalidKeyException-at-init path exists only where the transformation
     * is served (the base provider against a capability-lacking module).
     */
    @Test
    public void jce_fipsProviderDoesNotServePkcs1CipherTransformation()
    {
        Assertions.assertThrows(NoSuchPaddingException.class,
                () -> Cipher.getInstance("RSA/ECB/PKCS1Padding", JostleFIPSProvider.PROVIDER_NAME));
    }

    @Test
    public void doFinal_notInitialized()
    {
        long ref = cipherNI.allocateCipher();
        try
        {
            IllegalStateException e = Assertions.assertThrows(IllegalStateException.class,
                    () -> cipherNI.doFinal(ref, new byte[1], 0, 1, null, 0, RND));
            Assertions.assertEquals("not initialized", e.getMessage());
        }
        finally
        {
            cipherNI.disposeCipher(ref);
        }
    }

    @Test
    public void doFinal_nullInput()
    {
        withEncryptCipher((ref, keyRef) ->
        {
            NullPointerException e = Assertions.assertThrows(NullPointerException.class,
                    () -> cipherNI.doFinal(ref, null, 0, 0, null, 0, RND));
            Assertions.assertEquals("input is null", e.getMessage());
        });
    }

    @Test
    public void doFinal_offsetNegative()
    {
        withEncryptCipher((ref, keyRef) ->
        {
            for (int off : new int[]{-1, Integer.MIN_VALUE})
            {
                IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                        () -> cipherNI.doFinal(ref, new byte[16], off, 16, null, 0, RND));
                Assertions.assertEquals("input offset is negative", e.getMessage());
            }
        });
    }

    @Test
    public void doFinal_outOfRange()
    {
        withEncryptCipher((ref, keyRef) ->
        {
            IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                    () -> cipherNI.doFinal(ref, new byte[10], 1, 10, null, 0, RND));
            Assertions.assertEquals("input offset + length is out of range", e.getMessage());
        });
    }

    @Test
    public void doFinal_outputTooSmall() throws Exception
    {
        // The bridge asks the module for the output size before comparing it
        // with the caller's buffer, so this check sits behind a working
        // encrypt.
        assumeEncryptAvailable();
        withEncryptCipher((ref, keyRef) ->
        {
            IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                    () -> cipherNI.doFinal(ref, new byte[16], 0, 16, new byte[100], 0, RND));
            Assertions.assertEquals("output too small", e.getMessage());
        });
    }

    @Test
    public void doFinal_writesAtOffsetWithoutClobberingPrefix() throws Exception
    {
        assumeEncryptAvailable();
        long encRef = 0;
        try
        {
            encRef = cipherNI.allocateCipher();
            KeyPair kp = generateFipsJceKeyPair();
            long keyRef = ((OSSLKey) kp.getPublic()).getSpec().getReference();
            cipherNI.init(encRef, keyRef, RSAPKCS1CipherNI.OP_ENCRYPT, RND);

            byte[] msg = {1, 2, 3, 4};
            int needed = cipherNI.doFinal(encRef, msg, 0, msg.length, null, 0, RND);
            Assertions.assertEquals(256, needed);

            int prefix = 5;
            byte[] big = new byte[needed + prefix];
            new SecureRandom().nextBytes(big);
            byte[] expectedPrefix = Arrays.copyOf(big, prefix);

            Assertions.assertEquals(needed, cipherNI.doFinal(encRef, msg, 0, msg.length, big, prefix, RND));

            // (1) prefix untouched.
            Assertions.assertArrayEquals(expectedPrefix, Arrays.copyOf(big, prefix),
                    "prefix bytes were modified");
            // (2) ciphertext at big[prefix..] decrypts to the plaintext —
            // via the base provider (the module refuses PKCS#1 decryption).
            byte[] ct = Arrays.copyOfRange(big, prefix, prefix + needed);
            Assertions.assertArrayEquals(msg, baseProviderDecrypt(kp, ct),
                    "ciphertext at offset did not decrypt to the plaintext");
            // (3) window one byte earlier must NOT decrypt to the plaintext.
            // The base provider's implicit rejection turns a padding failure
            // into deterministic synthetic plaintext (never equal to msg);
            // structural failures (ciphertext >= modulus) throw instead —
            // both are correct outcomes here.
            byte[] shifted = Arrays.copyOfRange(big, prefix - 1, prefix - 1 + needed);
            Assertions.assertFalse(shiftedDecryptsToOriginal(kp, shifted, msg),
                    "shifted-by-one ciphertext decrypted to the plaintext — wrote at outOff-1");
        }
        finally
        {
            cipherNI.disposeCipher(encRef);
        }
    }

    @Test
    public void doFinal_inPlace_sameOffset() throws Exception
    {
        assertInPlaceRoundTrips(0);
    }

    @Test
    public void doFinal_inPlace_atOffset() throws Exception
    {
        assertInPlaceRoundTrips(5);
    }

    /**
     * Encrypt with {@code in == out} (one array), then decrypt the written
     * region (via the base provider — see class Javadoc) and assert it
     * matches the plaintext, with every byte outside the ciphertext region
     * byte-identical to a pre-call snapshot.
     */
    private void assertInPlaceRoundTrips(int outOff) throws Exception
    {
        assumeEncryptAvailable();
        long encRef = 0;
        try
        {
            encRef = cipherNI.allocateCipher();
            KeyPair kp = generateFipsJceKeyPair();
            long keyRef = ((OSSLKey) kp.getPublic()).getSpec().getReference();
            cipherNI.init(encRef, keyRef, RSAPKCS1CipherNI.OP_ENCRYPT, RND);

            byte[] msg = {10, 20, 30, 40, 50};
            int needed = 256;
            int cap = outOff + needed + 8;
            byte[] buf = new byte[cap];
            new SecureRandom().nextBytes(buf);
            System.arraycopy(msg, 0, buf, 0, msg.length);
            byte[] snapshot = buf.clone();

            int written = cipherNI.doFinal(encRef, buf, 0, msg.length, buf, outOff, RND);
            Assertions.assertEquals(needed, written);

            byte[] ct = Arrays.copyOfRange(buf, outOff, outOff + written);
            Assertions.assertArrayEquals(msg, baseProviderDecrypt(kp, ct),
                    "outOff=" + outOff + ": in-place ciphertext did not decrypt to the plaintext");
            Assertions.assertArrayEquals(Arrays.copyOf(snapshot, outOff), Arrays.copyOf(buf, outOff),
                    "outOff=" + outOff + ": bytes before the output offset were clobbered");
            Assertions.assertArrayEquals(
                    Arrays.copyOfRange(snapshot, outOff + written, cap),
                    Arrays.copyOfRange(buf, outOff + written, cap),
                    "outOff=" + outOff + ": bytes after the ciphertext were clobbered");
        }
        catch (Exception e)
        {
            if (e instanceof RuntimeException)
            {
                throw (RuntimeException) e;
            }
            throw new RuntimeException(e);
        }
        finally
        {
            cipherNI.disposeCipher(encRef);
        }
    }

    // -----------------------------------------------------------------
    // helpers
    // -----------------------------------------------------------------

    private boolean shiftedDecryptsToOriginal(KeyPair kp, byte[] shifted, byte[] msg)
    {
        // Some shifted windows fail structurally (ciphertext > n) before the
        // implicit-rejection path; that is also a correct outcome.
        try
        {
            return Arrays.equals(msg, baseProviderDecrypt(kp, shifted));
        }
        catch (Exception expected)
        {
            return false;
        }
    }

    /**
     * A 2048-bit keypair from the module via the JCE surface: the public
     * half's {@code PKEYKeySpec} reference drives the FIPS NI encrypt, and
     * the private half's PKCS#8 encoding crosses to the base provider for
     * decrypt validation (the sanctioned key-sharing route — see
     * {@code FIPSRSAAgreementTest#freshSharedKeys}).
     */
    private KeyPair generateFipsJceKeyPair() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", JostleFIPSProvider.PROVIDER_NAME);
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    /** Encrypt {@code msg} with the base (JSL) provider over the same key. */
    private byte[] baseProviderEncrypt(KeyPair kp, byte[] msg) throws Exception
    {
        KeyFactory kf = KeyFactory.getInstance("RSA", JostleProvider.PROVIDER_NAME);
        java.security.PublicKey pub = kf.generatePublic(
                new java.security.spec.X509EncodedKeySpec(kp.getPublic().getEncoded()));
        Cipher enc = Cipher.getInstance("RSA/ECB/PKCS1Padding", JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, pub);
        return enc.doFinal(msg);
    }

    /**
     * Does the loaded module encrypt with PKCS#1 v1.5?
     * <p>
     * Probed once per JVM through {@link FIPSTestUtil#fipsPkcs1CanEncrypt},
     * which also pins the refusal message. Tests that need a working encrypt
     * skip when it answers false; the refusal itself is asserted by
     * {@link #initRefused_thenTheOtherDirectionSucceeds()}.
     */
    private boolean encryptAvailable(KeyPair kp)
    {
        return FIPSTestUtil.fipsPkcs1CanEncrypt(cipherNI,
                ((OSSLKey) kp.getPublic()).getSpec().getReference(), RND);
    }

    /** Skip the calling test when the module refuses PKCS#1 v1.5 encryption. */
    private void assumeEncryptAvailable() throws Exception
    {
        Assumptions.assumeTrue(encryptAvailable(generateFipsJceKeyPair()),
                "the loaded FIPS module refuses PKCS#1 v1.5 encryption"
                        + " (the refusal is pinned by initRefused_thenTheOtherDirectionSucceeds)");
    }

    /** Decrypt {@code ct} with the base (JSL) provider over the same key. */
    private byte[] baseProviderDecrypt(KeyPair kp, byte[] ct) throws Exception
    {
        KeyFactory kf = KeyFactory.getInstance("RSA", JostleProvider.PROVIDER_NAME);
        PrivateKey priv = kf.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));
        Cipher dec = Cipher.getInstance("RSA/ECB/PKCS1Padding", JostleProvider.PROVIDER_NAME);
        dec.init(Cipher.DECRYPT_MODE, priv);
        return dec.doFinal(ct);
    }

    private long genKey()
    {
        long keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, RND);
        Assertions.assertTrue(keyRef > 0);
        return keyRef;
    }

    private interface PairBody
    {
        void run(long ref, long keyRef) throws Exception;
    }

    private void withCipherAndKey(PairBody body)
    {
        long ref = cipherNI.allocateCipher();
        long keyRef = genKey();
        try
        {
            body.run(ref, keyRef);
        }
        catch (Exception e)
        {
            if (e instanceof RuntimeException)
            {
                throw (RuntimeException) e;
            }
            throw new RuntimeException(e);
        }
        finally
        {
            cipherNI.disposeCipher(ref);
            specNI.dispose(keyRef);
        }
    }

    /**
     * A cipher ctx bound for ENCRYPT over a fresh NI-level key.
     * <p>
     * Bridge-validation checks (null input, negative offset, range) are
     * rejected before any OpenSSL call and so run on either module; the
     * output-size and functional checks need the module to encrypt, and those
     * callers add {@link #assumeEncryptAvailable()} themselves.
     */
    private void withEncryptCipher(PairBody body)
    {
        withCipherAndKey((ref, keyRef) ->
        {
            cipherNI.init(ref, keyRef, RSAPKCS1CipherNI.OP_ENCRYPT, RND);
            body.run(ref, keyRef);
        });
    }
}
