package org.openssl.jostle.test.asn1;

import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.interfaces.MLDSAPrivateKey;
import org.openssl.jostle.jcajce.interfaces.MLDSAPublicKey;
import org.openssl.jostle.jcajce.interfaces.OSSLKey;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.OpenSSLException;

import org.openssl.jostle.test.crypto.TestNISelector;

import java.security.*;

public class Asn1LimitTest
{
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
    public void encodePublicKey_specNullTest() throws Exception
    {
        long asn1Ref = TestNISelector.Asn1NI.allocate();

        try
        {
            TestNISelector.Asn1NI.handleErrors(TestNISelector.Asn1NI.encodePrivateKey(asn1Ref, 0));

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
    public void encodePublicKey_specNullKeyTest() throws Exception
    {
        long asn1Ref = TestNISelector.Asn1NI.allocate();
        long specRef = TestNISelector.SpecNI.allocate();
        try
        {
            TestNISelector.Asn1NI.handleErrors(TestNISelector.Asn1NI.encodePublicKey(asn1Ref, specRef));
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
    public void encodePublicKey_keyNullInSpec() throws Exception
    {
        long asn1Ref = TestNISelector.Asn1NI.allocate();
        long specRef = TestNISelector.SpecNI.allocate();
        try
        {
            TestNISelector.Asn1NI.handleErrors(TestNISelector.Asn1NI.encodePublicKey(asn1Ref, specRef));
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
        keyGen.initialize( org.openssl.jostle.jcajce.spec.MLDSAParameterSpec.ml_dsa_44);
        KeyPair keyPair = keyGen.generateKeyPair();

        MLDSAPublicKey publicKey = (MLDSAPublicKey) keyPair.getPublic();
       

        long asn1Ref = TestNISelector.Asn1NI.allocate();
        try
        {
            try
            { // Too long by one
                long len = TestNISelector.Asn1NI.handleErrors(TestNISelector.Asn1NI.encodePublicKey(asn1Ref, publicKey.getSpec().getReference()));
                byte[] out = new byte[(int) (len + 1)];
                TestNISelector.Asn1NI.handleErrors(TestNISelector.Asn1NI.getData(asn1Ref, out));
                Assertions.fail("Should have thrown exception");
            } catch (Exception e)
            {
                Assertions.assertEquals("output is out of range", e.getMessage());
            }

            try
            { // Too small by one
                long len = TestNISelector.Asn1NI.handleErrors(TestNISelector.Asn1NI.encodePublicKey(asn1Ref, publicKey.getSpec().getReference()));
                byte[] out = new byte[(int) (len - 1)];
                TestNISelector.Asn1NI.handleErrors(TestNISelector.Asn1NI.getData(asn1Ref, out));
                Assertions.fail("Should have thrown exception");
            } catch (Exception e)
            {
                Assertions.assertEquals("output is out of range", e.getMessage());
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
            TestNISelector.Asn1NI.handleErrors(TestNISelector.Asn1NI.encodePrivateKey(asn1Ref, specRef));
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
            TestNISelector.Asn1NI.handleErrors(TestNISelector.Asn1NI.encodePrivateKey(asn1Ref, specRef));
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
        keyGen.initialize( org.openssl.jostle.jcajce.spec.MLDSAParameterSpec.ml_dsa_44);
        KeyPair keyPair = keyGen.generateKeyPair();


        MLDSAPrivateKey privateKey = (MLDSAPrivateKey) keyPair.getPrivate();

        long asn1Ref = TestNISelector.Asn1NI.allocate();
        try
        {
            try
            { // Too long by one
                long len = TestNISelector.Asn1NI.handleErrors(TestNISelector.Asn1NI.encodePrivateKey(asn1Ref, privateKey.getSpec().getReference()));
                byte[] out = new byte[(int) (len + 1)];
                TestNISelector.Asn1NI.handleErrors(TestNISelector.Asn1NI.getData(asn1Ref, out));
                Assertions.fail("Should have thrown exception");
            } catch (Exception e)
            {
                Assertions.assertEquals("output is out of range", e.getMessage());
            }

            try
            { // Too small by one
                long len = TestNISelector.Asn1NI.handleErrors(TestNISelector.Asn1NI.encodePrivateKey(asn1Ref, privateKey.getSpec().getReference()));
                byte[] out = new byte[(int) (len - 1)];
                TestNISelector.Asn1NI.handleErrors(TestNISelector.Asn1NI.getData(asn1Ref, out));
                Assertions.fail("Should have thrown exception");
            } catch (Exception e)
            {
                Assertions.assertEquals("output is out of range", e.getMessage());
            }


        } finally
        {
            TestNISelector.Asn1NI.dispose(asn1Ref);
        }
    }


    @Test
    public void fromPrivateKeyInfo_inIsNull() throws Exception
    {
        try
        {
            TestNISelector.Asn1NI.handleErrors(TestNISelector.Asn1NI.fromPrivateKeyInfo(null, 0, 0));
            Assertions.fail();
        } catch (IllegalArgumentException ex)
        {
            Assertions.assertEquals("input is null", ex.getMessage());
        }
    }

    @Test
    public void fromPrivateKeyInfo_inOffNeg() throws Exception
    {
        try
        {
            TestNISelector.Asn1NI.handleErrors(TestNISelector.Asn1NI.fromPrivateKeyInfo(new byte[0], -1, 0));
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
            TestNISelector.Asn1NI.handleErrors(TestNISelector.Asn1NI.fromPrivateKeyInfo(new byte[0], 0, -1));
            Assertions.fail();
        } catch (IllegalArgumentException ex)
        {
            Assertions.assertEquals("input length is negative", ex.getMessage());
        }
    }

    @Test
    public void fromPrivateKeyInfo_inOutOfRange() throws Exception
    {
        try
        {
            // Offset causes overflow
            TestNISelector.Asn1NI.handleErrors(TestNISelector.Asn1NI.fromPrivateKeyInfo(new byte[16], 1, 16));
            Assertions.fail();
        } catch (IllegalArgumentException ex)
        {
            Assertions.assertEquals("input out of range", ex.getMessage());
        }

        try
        {
            // too long
            TestNISelector.Asn1NI.handleErrors(TestNISelector.Asn1NI.fromPrivateKeyInfo(new byte[16], 0, 17));
            Assertions.fail();
        } catch (IllegalArgumentException ex)
        {
            Assertions.assertEquals("input out of range", ex.getMessage());
        }

        byte[] validKey;
        {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("MLDSA", "BC");
            keyGen.initialize(MLDSAParameterSpec.ml_dsa_44);
            validKey = keyGen.generateKeyPair().getPrivate().getEncoded();
        }

        // OK
        TestNISelector.Asn1NI.handleErrors(TestNISelector.Asn1NI.fromPrivateKeyInfo(validKey, 0, validKey.length));
        byte[] offset = new byte[validKey.length + 1];
        System.arraycopy(validKey, 0, offset, 1, validKey.length);
        TestNISelector.Asn1NI.handleErrors(TestNISelector.Asn1NI.fromPrivateKeyInfo(offset, 1, validKey.length));
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
            TestNISelector.Asn1NI.handleErrors(TestNISelector.Asn1NI.fromPrivateKeyInfo(validKey, 0, validKey.length));
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
            TestNISelector.Asn1NI.handleErrors(TestNISelector.Asn1NI.fromPublicKeyInfo(null, 0, 0));
            Assertions.fail();
        } catch (IllegalArgumentException ex)
        {
            Assertions.assertEquals("input is null", ex.getMessage());
        }
    }

    @Test
    public void fromPublicKeyInfo_inOffNeg() throws Exception
    {
        try
        {
            TestNISelector.Asn1NI.handleErrors(TestNISelector.Asn1NI.fromPublicKeyInfo(new byte[0], -1, 0));
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
            TestNISelector.Asn1NI.handleErrors(TestNISelector.Asn1NI.fromPublicKeyInfo(new byte[0], 0, -1));
            Assertions.fail();
        } catch (IllegalArgumentException ex)
        {
            Assertions.assertEquals("input length is negative", ex.getMessage());
        }
    }

    @Test
    public void fromPublicKeyInfo_inOutOfRange() throws Exception
    {
        try
        {
            // Offset causes overflow
            TestNISelector.Asn1NI.handleErrors(TestNISelector.Asn1NI.fromPublicKeyInfo(new byte[16], 1, 16));
            Assertions.fail();
        } catch (IllegalArgumentException ex)
        {
            Assertions.assertEquals("input out of range", ex.getMessage());
        }

        try
        {
            // too long
            TestNISelector.Asn1NI.handleErrors(TestNISelector.Asn1NI.fromPublicKeyInfo(new byte[16], 0, 17));
            Assertions.fail();
        } catch (IllegalArgumentException ex)
        {
            Assertions.assertEquals("input out of range", ex.getMessage());
        }

        byte[] validKey;
        {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("MLDSA", "BC");
            keyGen.initialize(MLDSAParameterSpec.ml_dsa_44);
            validKey = keyGen.generateKeyPair().getPublic().getEncoded();
        }

        // OK
        TestNISelector.Asn1NI.handleErrors(TestNISelector.Asn1NI.fromPublicKeyInfo(validKey, 0, validKey.length));
        byte[] offset = new byte[validKey.length + 1];
        System.arraycopy(validKey, 0, offset, 1, validKey.length);
        TestNISelector.Asn1NI.handleErrors(TestNISelector.Asn1NI.fromPublicKeyInfo(offset, 1, validKey.length));
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
            TestNISelector.Asn1NI.handleErrors(TestNISelector.Asn1NI.fromPublicKeyInfo(validKey, 0, validKey.length));
            Assertions.fail();
        } catch (OpenSSLException ex)
        {
            Assertions.assertEquals(OpenSSLException.class, ex.getClass());
            Assertions.assertTrue(ex.getMessage().contains("wrong tag"));
        }
    }


}
