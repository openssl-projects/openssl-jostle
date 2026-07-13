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

package org.openssl.jostle.test.asn1;

import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.interfaces.MLDSAPrivateKey;
import org.openssl.jostle.jcajce.interfaces.MLDSAPublicKey;
import org.openssl.jostle.jcajce.provider.Asn1TrailingDataException;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.test.crypto.TestNISelector;
import org.openssl.jostle.util.asn1.PrivateKeyOptions;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class Asn1LimitTest
{
    private static final SecureRandom RANDOM = new SecureRandom();

    @BeforeAll
    public static void before()
    {
        synchronized (JostleProvider.class)
        {
            if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
            {
                Security.addProvider(new JostleProvider());
            }

            if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
            {
                Security.addProvider(new BouncyCastleProvider());
            }
        }
    }

    @Test
    public void allocDeallocTest() throws Exception
    {
        long ref = TestNISelector.Asn1NI.allocate();
        try
        {
            // Can it cope with null, if not it will SIGSEGV
            TestNISelector.Asn1NI.dispose(0);
        } finally
        {
            TestNISelector.Asn1NI.dispose(ref);
        }
    }

    @Test
    public void encodePrivateKey_keyRefIsZero() throws Exception
    {
        long asn1Ref = TestNISelector.Asn1NI.allocate();

        try
        {
            TestNISelector.Asn1NI.encodePrivateKey(asn1Ref, 0, PrivateKeyOptions.DEFAULT.getValue());

            Assertions.fail("Should have thrown exception");
        } catch (Exception e)
        {
            Assertions.assertEquals("key reference is null", e.getMessage());
        } finally
        {
            TestNISelector.Asn1NI.dispose(asn1Ref);
        }
    }

    @Test
    public void encodePublicKey_keyRefIsZero() throws Exception
    {
        long asn1Ref = TestNISelector.Asn1NI.allocate();

        try
        {
            TestNISelector.Asn1NI.encodePublicKey(asn1Ref, 0);

            Assertions.fail("Should have thrown exception");
        } catch (Exception e)
        {
            Assertions.assertEquals("key reference is null", e.getMessage());
        } finally
        {
            TestNISelector.Asn1NI.dispose(asn1Ref);
        }
    }

    @Test
    public void encode_getData_asn1RefIsZero() throws Exception
    {
        // A 0/null ASN.1 writer ctx handle at every encode/getData entry point
        // must surface the typed JO_ASN1_CTX_IS_NULL -> IllegalArgumentException
        // ("asn1 context is null"), NOT abort the JVM via jo_assert. Passing 0
        // for the key ref as well pins the validation ORDER (asn1 ctx before
        // key). Regression lock for the ctx null-check bridge fix
        // (asn1_ni_jni.c / asn1_ni_ffi.c).
        Assertions.assertEquals("asn1 context is null", Assertions.assertThrows(IllegalArgumentException.class,
                () -> TestNISelector.Asn1NI.encodePublicKey(0, 0)).getMessage());
        Assertions.assertEquals("asn1 context is null", Assertions.assertThrows(IllegalArgumentException.class,
                () -> TestNISelector.Asn1NI.encodePrivateKey(0, 0, PrivateKeyOptions.DEFAULT.getValue())).getMessage());
        Assertions.assertEquals("asn1 context is null", Assertions.assertThrows(IllegalArgumentException.class,
                () -> TestNISelector.Asn1NI.getData(0, new byte[16])).getMessage());
    }

    @Test
    public void encodePublicKey_specNullKeyTest() throws Exception
    {
        long asn1Ref = TestNISelector.Asn1NI.allocate();
        long specRef = TestNISelector.SpecNI.allocate();
        try
        {
            TestNISelector.Asn1NI.encodePublicKey(asn1Ref, specRef);
            Assertions.fail("Should have thrown exception");
        } catch (Exception e)
        {
            Assertions.assertEquals("key spec has null key", e.getMessage());
        } finally
        {
            TestNISelector.Asn1NI.dispose(asn1Ref);
            TestNISelector.SpecNI.dispose(specRef);
        }
    }

    @Test
    public void encodePublicKey_output_wrong_size() throws Exception
    {

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
        keyGen.initialize(org.openssl.jostle.jcajce.spec.MLDSAParameterSpec.ml_dsa_44);
        KeyPair keyPair = keyGen.generateKeyPair();

        MLDSAPublicKey publicKey = (MLDSAPublicKey) keyPair.getPublic();


        long asn1Ref = TestNISelector.Asn1NI.allocate();
        try
        {
            try
            { // Too long by one
                long len = TestNISelector.Asn1NI.encodePublicKey(asn1Ref, publicKey.getSpec().getReference());
                byte[] out = new byte[(int) (len + 1)];
                TestNISelector.Asn1NI.getData(asn1Ref, out);
                Assertions.fail("Should have thrown exception");
            } catch (Exception e)
            {
                Assertions.assertEquals("output offset + length is out of range", e.getMessage());
            }

            try
            { // Too small by one
                long len = TestNISelector.Asn1NI.encodePublicKey(asn1Ref, publicKey.getSpec().getReference());
                byte[] out = new byte[(int) (len - 1)];
                TestNISelector.Asn1NI.getData(asn1Ref, out);
                Assertions.fail("Should have thrown exception");
            } catch (Exception e)
            {
                Assertions.assertEquals("output offset + length is out of range", e.getMessage());
            }


        } finally
        {
            TestNISelector.Asn1NI.dispose(asn1Ref);
        }
    }


    @Test
    public void encodePrivateKey_specNullKeyTest() throws Exception
    {
        long asn1Ref = TestNISelector.Asn1NI.allocate();
        long specRef = TestNISelector.SpecNI.allocate();
        try
        {
            TestNISelector.Asn1NI.encodePrivateKey(asn1Ref, specRef, PrivateKeyOptions.DEFAULT.getValue());
            Assertions.fail("Should have thrown exception");
        } catch (Exception e)
        {
            Assertions.assertEquals("key spec has null key", e.getMessage());
        } finally
        {
            TestNISelector.Asn1NI.dispose(asn1Ref);
            TestNISelector.SpecNI.dispose(specRef);
        }
    }

    @Test
    public void encodePrivateKey_keyNullInSpec() throws Exception
    {
        long asn1Ref = TestNISelector.Asn1NI.allocate();
        long specRef = TestNISelector.SpecNI.allocate();
        try
        {
            TestNISelector.Asn1NI.encodePrivateKey(asn1Ref, specRef, PrivateKeyOptions.DEFAULT.getValue());
            Assertions.fail("Should have thrown exception");
        } catch (Exception e)
        {
            Assertions.assertEquals("key spec has null key", e.getMessage());
        } finally
        {
            TestNISelector.Asn1NI.dispose(asn1Ref);
            TestNISelector.SpecNI.dispose(specRef);
        }
    }


    @Test
    public void encodePrivateKey_output_wrong_size() throws Exception
    {

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
        keyGen.initialize(org.openssl.jostle.jcajce.spec.MLDSAParameterSpec.ml_dsa_44);
        KeyPair keyPair = keyGen.generateKeyPair();


        MLDSAPrivateKey privateKey = (MLDSAPrivateKey) keyPair.getPrivate();

        long asn1Ref = TestNISelector.Asn1NI.allocate();
        try
        {
            try
            { // Too long by one
                long len = TestNISelector.Asn1NI.encodePrivateKey(asn1Ref, privateKey.getSpec().getReference(), PrivateKeyOptions.DEFAULT.getValue());
                byte[] out = new byte[(int) (len + 1)];
                TestNISelector.Asn1NI.getData(asn1Ref, out);
                Assertions.fail("Should have thrown exception");
            } catch (Exception e)
            {
                Assertions.assertEquals("output offset + length is out of range", e.getMessage());
            }

            try
            { // Too small by one
                long len = TestNISelector.Asn1NI.encodePrivateKey(asn1Ref, privateKey.getSpec().getReference(), PrivateKeyOptions.DEFAULT.getValue());
                byte[] out = new byte[(int) (len - 1)];
                TestNISelector.Asn1NI.getData(asn1Ref, out);
                Assertions.fail("Should have thrown exception");
            } catch (Exception e)
            {
                Assertions.assertEquals("output offset + length is out of range", e.getMessage());
            }


        } finally
        {
            TestNISelector.Asn1NI.dispose(asn1Ref);
        }
    }

    @Test
    public void encodePrivateKey_seedOnly_unsupportedAlgorithm() throws Exception
    {
        // seed_only_encoder only handles ML-DSA / ML-KEM. Anything else (e.g.,
        // Ed25519) returns JO_INCORRECT_KEY_TYPE which the bridge surfaces as
        // IllegalArgumentException("invalid key type").

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Ed25519", JostleProvider.PROVIDER_NAME);
        KeyPair keyPair = keyGen.generateKeyPair();

        org.openssl.jostle.jcajce.interfaces.OSSLKey privateKey =
                (org.openssl.jostle.jcajce.interfaces.OSSLKey) keyPair.getPrivate();

        long asn1Ref = TestNISelector.Asn1NI.allocate();
        try
        {
            TestNISelector.Asn1NI.encodePrivateKey(asn1Ref, privateKey.getSpec().getReference(),
                    PrivateKeyOptions.SEED_ONLY.getValue());
            Assertions.fail("Should have thrown exception");
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("invalid key type", e.getMessage());
        }
        finally
        {
            TestNISelector.Asn1NI.dispose(asn1Ref);
        }
    }


    @Test
    public void encodePublicKey_unknown_encoding_option() throws Exception
    {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
        keyGen.initialize(org.openssl.jostle.jcajce.spec.MLDSAParameterSpec.ml_dsa_44);
        KeyPair keyPair = keyGen.generateKeyPair();

        MLDSAPrivateKey privateKey = (MLDSAPrivateKey) keyPair.getPrivate();


        long asn1Ref = TestNISelector.Asn1NI.allocate();
        try
        {
            try
            {
                long len = TestNISelector.Asn1NI.encodePrivateKey(asn1Ref, privateKey.getSpec().getReference(), "unknown");
                byte[] out = new byte[(int) len];
                TestNISelector.Asn1NI.getData(asn1Ref, out);
                Assertions.fail("Should have thrown exception");
            } catch (IllegalArgumentException e)
            {
                Assertions.assertEquals("invalid key encoding option", e.getMessage());
            }

        } finally
        {
            TestNISelector.Asn1NI.dispose(asn1Ref);
        }
    }


    @Test
    public void encodePrivateKey_prefix_encoding_option_rejected() throws Exception
    {
        // A prefix of a valid option must be REJECTED, not accepted: "d" is
        // NOT "default" and "s" is NOT "seed_only". The FFI bridge used to
        // compare with strncmp against the caller-supplied length (a prefix
        // match); it now uses exact strcmp like the JNI twin. Runs on both
        // JNI and FFI via TestNISelector, so it pins that the FFI no longer
        // prefix-accepts.
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
        keyGen.initialize(org.openssl.jostle.jcajce.spec.MLDSAParameterSpec.ml_dsa_44);
        KeyPair keyPair = keyGen.generateKeyPair();

        MLDSAPrivateKey privateKey = (MLDSAPrivateKey) keyPair.getPrivate();

        long asn1Ref = TestNISelector.Asn1NI.allocate();
        try
        {
            for (String prefix : new String[]{"d", "s"})
            {
                try
                {
                    long len = TestNISelector.Asn1NI.encodePrivateKey(
                            asn1Ref, privateKey.getSpec().getReference(), prefix);
                    byte[] out = new byte[(int) len];
                    TestNISelector.Asn1NI.getData(asn1Ref, out);
                    Assertions.fail("prefix option '" + prefix + "' should have been rejected");
                }
                catch (IllegalArgumentException e)
                {
                    Assertions.assertEquals("invalid key encoding option", e.getMessage());
                }
            }
        }
        finally
        {
            TestNISelector.Asn1NI.dispose(asn1Ref);
        }
    }


    @Test
    public void fromPrivateKeyInfo_inIsNull() throws Exception
    {
        try
        {
            TestNISelector.Asn1NI.fromPrivateKeyInfo(null, 0, 0);
            Assertions.fail();
        } catch (NullPointerException ex)
        {
            Assertions.assertEquals("input is null", ex.getMessage());
        }
    }

    @Test
    public void fromPrivateKeyInfo_inOffNeg() throws Exception
    {
        try
        {
            TestNISelector.Asn1NI.fromPrivateKeyInfo(new byte[0], -1, 0);
            Assertions.fail();
        } catch (IllegalArgumentException ex)
        {
            Assertions.assertEquals("input offset is negative", ex.getMessage());
        }
    }

    @Test
    public void fromPrivateKeyInfo_inLenNeg() throws Exception
    {
        try
        {
            TestNISelector.Asn1NI.fromPrivateKeyInfo(new byte[0], 0, -1);
            Assertions.fail();
        } catch (IllegalArgumentException ex)
        {
            Assertions.assertEquals("input len is negative", ex.getMessage());
        }
    }

    @Test
    public void fromPrivateKeyInfo_inOutOfRange() throws Exception
    {
        try
        {
            // Offset causes overflow
            TestNISelector.Asn1NI.fromPrivateKeyInfo(new byte[16], 1, 16);
            Assertions.fail();
        } catch (IllegalArgumentException ex)
        {
            Assertions.assertEquals("input offset + length is out of range", ex.getMessage());
        }

        try
        {
            // too long
            TestNISelector.Asn1NI.fromPrivateKeyInfo(new byte[16], 0, 17);
            Assertions.fail();
        } catch (IllegalArgumentException ex)
        {
            Assertions.assertEquals("input offset + length is out of range", ex.getMessage());
        }

        byte[] validKey;
        {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("MLDSA", "BC");
            keyGen.initialize(MLDSAParameterSpec.ml_dsa_44);
            validKey = keyGen.generateKeyPair().getPrivate().getEncoded();
        }

        // OK
        TestNISelector.Asn1NI.fromPrivateKeyInfo(validKey, 0, validKey.length);
        byte[] offset = new byte[validKey.length + 1];
        System.arraycopy(validKey, 0, offset, 1, validKey.length);
        TestNISelector.Asn1NI.fromPrivateKeyInfo(offset, 1, validKey.length);
    }

    @Test
    public void fromPrivateKey_dodgyData() throws Exception
    {
        byte[] validKey;
        {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("MLDSA", "BC");
            keyGen.initialize(MLDSAParameterSpec.ml_dsa_44);
            validKey = keyGen.generateKeyPair().getPrivate().getEncoded();
        }

        validKey[0] ^= 1;

        try
        {
            TestNISelector.Asn1NI.fromPrivateKeyInfo(validKey, 0, validKey.length);
            Assertions.fail();
        } catch (OpenSSLException ex)
        {
            Assertions.assertEquals(OpenSSLException.class, ex.getClass());
            Assertions.assertTrue(ex.getMessage().contains("No supported data to decode"));
        }
    }

    @Test
    public void fromPrivateKey_dodgyDataTooShort() throws Exception
    {

        //
        // Correct data in array but length too short
        //

        byte[] validKey;
        {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("MLDSA", "BC");
            keyGen.initialize(MLDSAParameterSpec.ml_dsa_44);
            validKey = keyGen.generateKeyPair().getPrivate().getEncoded();
        }

        try
        {
            TestNISelector.Asn1NI.fromPrivateKeyInfo(validKey, 0, validKey.length - 10);
            Assertions.fail();
        } catch (OpenSSLException ex)
        {
            Assertions.assertEquals(OpenSSLException.class, ex.getClass());
            Assertions.assertTrue(ex.getMessage().contains("No supported data to decode"));
        }
    }


    @Test
    public void fromPublicKeyInfo_inIsNull() throws Exception
    {
        try
        {
            TestNISelector.Asn1NI.fromPublicKeyInfo(null, 0, 0);
            Assertions.fail();
        } catch (NullPointerException ex)
        {
            Assertions.assertEquals("input is null", ex.getMessage());
        }
    }

    @Test
    public void fromPublicKeyInfo_inOffNeg() throws Exception
    {
        try
        {
            TestNISelector.Asn1NI.fromPublicKeyInfo(new byte[0], -1, 0);
            Assertions.fail();
        } catch (IllegalArgumentException ex)
        {
            Assertions.assertEquals("input offset is negative", ex.getMessage());
        }
    }

    @Test
    public void fromPublicKeyInfo_inLenNeg() throws Exception
    {
        try
        {
            TestNISelector.Asn1NI.fromPublicKeyInfo(new byte[0], 0, -1);
            Assertions.fail();
        } catch (IllegalArgumentException ex)
        {
            Assertions.assertEquals("input len is negative", ex.getMessage());
        }
    }

    @Test
    public void fromPublicKeyInfo_inOutOfRange() throws Exception
    {
        try
        {
            // Offset causes overflow
            TestNISelector.Asn1NI.fromPublicKeyInfo(new byte[16], 1, 16);
            Assertions.fail();
        } catch (IllegalArgumentException ex)
        {
            Assertions.assertEquals("input offset + length is out of range", ex.getMessage());
        }

        try
        {
            // too long
            TestNISelector.Asn1NI.fromPublicKeyInfo(new byte[16], 0, 17);
            Assertions.fail();
        } catch (IllegalArgumentException ex)
        {
            Assertions.assertEquals("input offset + length is out of range", ex.getMessage());
        }

        byte[] validKey;
        {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("MLDSA", "BC");
            keyGen.initialize(MLDSAParameterSpec.ml_dsa_44);
            validKey = keyGen.generateKeyPair().getPublic().getEncoded();
        }

        // OK
        TestNISelector.Asn1NI.fromPublicKeyInfo(validKey, 0, validKey.length);
        byte[] offset = new byte[validKey.length + 1];
        System.arraycopy(validKey, 0, offset, 1, validKey.length);
        TestNISelector.Asn1NI.fromPublicKeyInfo(offset, 1, validKey.length);
    }


    @Test
    public void fromPublicKey_dodgyData() throws Exception
    {
        byte[] validKey;
        {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("MLDSA", "BC");
            keyGen.initialize(MLDSAParameterSpec.ml_dsa_44);
            validKey = keyGen.generateKeyPair().getPublic().getEncoded();
        }

        validKey[0] ^= 1;

        try
        {
            TestNISelector.Asn1NI.fromPublicKeyInfo(validKey, 0, validKey.length);
            Assertions.fail();
        } catch (OpenSSLException ex)
        {
            Assertions.assertEquals(OpenSSLException.class, ex.getClass());
            Assertions.assertTrue(ex.getMessage().contains("wrong tag"));
        }
    }


    @Test
    public void fromPublicKey_dodgyDataTooShort() throws Exception
    {
        // Valid data in array but length too short.

        byte[] validKey;
        {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("MLDSA", "BC");
            keyGen.initialize(MLDSAParameterSpec.ml_dsa_44);
            validKey = keyGen.generateKeyPair().getPublic().getEncoded();
        }


        try
        {
            TestNISelector.Asn1NI.fromPublicKeyInfo(validKey, 0, validKey.length - 10);
            Assertions.fail();
        } catch (OpenSSLException ex)
        {
            Assertions.assertEquals(OpenSSLException.class, ex.getClass());
            Assertions.assertTrue(ex.getMessage().contains("bad object header"));
        }
    }

    /** Fresh random ML-DSA-44 keypair generated through the Jostle provider. */
    private static KeyPair generateMldsaKeyPair() throws Exception
    {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
        keyGen.initialize(org.openssl.jostle.jcajce.spec.MLDSAParameterSpec.ml_dsa_44);
        return keyGen.generateKeyPair();
    }

    /** Copy of {@code der} with {@code junkLen} random trailing bytes appended. */
    private static byte[] withTrailingJunk(byte[] der, int junkLen)
    {
        byte[] out = new byte[der.length + junkLen];
        byte[] junk = new byte[junkLen];
        RANDOM.nextBytes(junk);
        System.arraycopy(der, 0, out, 0, der.length);
        System.arraycopy(junk, 0, out, der.length, junkLen);
        return out;
    }

    @Test
    public void fromPrivateKeyInfo_trailingData() throws Exception
    {
        byte[] validKey = generateMldsaKeyPair().getPrivate().getEncoded();

        // Positive control: the unmodified encoding decodes cleanly — the
        // rejection boundary is exactly consumed == len (boundary + 1 rule).
        TestNISelector.SpecNI.dispose(
                TestNISelector.Asn1NI.fromPrivateKeyInfo(validKey, 0, validKey.length));

        // One junk byte (boundary + 1), then several.
        for (int junkLen : new int[]{1, 7})
        {
            byte[] withJunk = withTrailingJunk(validKey, junkLen);
            try
            {
                TestNISelector.Asn1NI.fromPrivateKeyInfo(withJunk, 0, withJunk.length);
                Assertions.fail("Should have thrown exception");
            }
            catch (Asn1TrailingDataException ex)
            {
                Assertions.assertEquals("DER encoding has trailing data", ex.getMessage());
            }
        }
    }

    @Test
    public void fromPrivateKeyInfo_paddedBufferExactLenDecodes() throws Exception
    {
        // The trailing-data check must use the caller-passed len, not the
        // array length: a valid encoding at offset 0 of an oversized array
        // still decodes when len is the exact encoding length.
        byte[] validKey = generateMldsaKeyPair().getPrivate().getEncoded();

        byte[] padded = new byte[validKey.length + 16];
        RANDOM.nextBytes(padded);
        System.arraycopy(validKey, 0, padded, 0, validKey.length);

        TestNISelector.SpecNI.dispose(
                TestNISelector.Asn1NI.fromPrivateKeyInfo(padded, 0, validKey.length));
    }

    @Test
    public void fromPublicKeyInfo_trailingData() throws Exception
    {
        byte[] validKey = generateMldsaKeyPair().getPublic().getEncoded();

        // Positive control: the unmodified encoding decodes cleanly.
        TestNISelector.SpecNI.dispose(
                TestNISelector.Asn1NI.fromPublicKeyInfo(validKey, 0, validKey.length));

        for (int junkLen : new int[]{1, 7})
        {
            byte[] withJunk = withTrailingJunk(validKey, junkLen);
            try
            {
                TestNISelector.Asn1NI.fromPublicKeyInfo(withJunk, 0, withJunk.length);
                Assertions.fail("Should have thrown exception");
            }
            catch (Asn1TrailingDataException ex)
            {
                Assertions.assertEquals("DER encoding has trailing data", ex.getMessage());
            }
        }
    }

    @Test
    public void fromPublicKeyInfo_paddedBufferExactLenDecodes() throws Exception
    {
        byte[] validKey = generateMldsaKeyPair().getPublic().getEncoded();

        byte[] padded = new byte[validKey.length + 16];
        RANDOM.nextBytes(padded);
        System.arraycopy(validKey, 0, padded, 0, validKey.length);

        TestNISelector.SpecNI.dispose(
                TestNISelector.Asn1NI.fromPublicKeyInfo(padded, 0, validKey.length));
    }

    @Test
    public void keyFactory_generatePrivate_trailingDataRejected() throws Exception
    {
        byte[] encoded = generateMldsaKeyPair().getPrivate().getEncoded();

        KeyFactory keyFactory = KeyFactory.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);

        // Positive control: the unmodified encoding decodes at the JCE surface.
        Assertions.assertNotNull(keyFactory.generatePrivate(new PKCS8EncodedKeySpec(encoded)));

        for (int junkLen : new int[]{1, 7})
        {
            byte[] withJunk = withTrailingJunk(encoded, junkLen);
            InvalidKeySpecException ex = Assertions.assertThrows(InvalidKeySpecException.class,
                    () -> keyFactory.generatePrivate(new PKCS8EncodedKeySpec(withJunk)));
            Assertions.assertEquals("unable to decode ML-DSA private key", ex.getMessage());
            Assertions.assertEquals(Asn1TrailingDataException.class, ex.getCause().getClass());
        }
    }

    @Test
    public void keyFactory_generatePublic_trailingDataRejected() throws Exception
    {
        byte[] encoded = generateMldsaKeyPair().getPublic().getEncoded();

        KeyFactory keyFactory = KeyFactory.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);

        // Positive control: the unmodified encoding decodes at the JCE surface.
        Assertions.assertNotNull(keyFactory.generatePublic(new X509EncodedKeySpec(encoded)));

        for (int junkLen : new int[]{1, 7})
        {
            byte[] withJunk = withTrailingJunk(encoded, junkLen);
            InvalidKeySpecException ex = Assertions.assertThrows(InvalidKeySpecException.class,
                    () -> keyFactory.generatePublic(new X509EncodedKeySpec(withJunk)));
            Assertions.assertEquals("unable to decode ML-DSA public key", ex.getMessage());
            Assertions.assertEquals(Asn1TrailingDataException.class, ex.getCause().getClass());
        }
    }

}
