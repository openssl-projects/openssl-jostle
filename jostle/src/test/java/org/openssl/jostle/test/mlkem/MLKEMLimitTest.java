package org.openssl.jostle.test.mlkem;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.jcajce.provider.mlkem.MLKEMServiceNI;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.test.crypto.TestNISelector;

public class MLKEMLimitTest
{
    static
    {
        CryptoServicesRegistrar.isNativeAvailable(); // Trigger Loading
    }

    MLKEMServiceNI mlkemServiceNI = TestNISelector.getMLKEMNI();
    SpecNI specNI = TestNISelector.getSpecNI();

    @Test
    public void testMLKEMGenerateKeyPair_keyGenWrongType() throws Exception
    {

        for (int type : new int[]{-1, 0, 7})
        {

            try
            {
                mlkemServiceNI.handleErrors(mlkemServiceNI.generateKeyPair(type));
                Assertions.fail();
            } catch (IllegalArgumentException e)
            {
                Assertions.assertEquals("invalid key type for ML-KEM", e.getMessage());
            }

        }
    }

    @Test
    public void MLKEMServiceJNI_generateKeyPair_seedIsNull() throws Exception
    {
        byte[] seed = null;
        int seedLen = 0;

        try
        {
            mlkemServiceNI.handleErrors(
                    mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), seed, seedLen)
            );
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("seed is null", e.getMessage());
        }
    }

    @Test
    public void MLKEMServiceJNI_generateKeyPair_seedLenNegative() throws Exception
    {
        byte[] seed = new byte[64];
        int seedLen = -1;

        try
        {
            mlkemServiceNI.handleErrors(
                    mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_1024.getKsType(), seed, seedLen)
            );
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("seed len is negative", e.getMessage());
        }
    }

    @Test
    public void MLKEMServiceJNI_generateKeyPair_seedLenPastEndOfArray() throws Exception
    {
        byte[] seed = new byte[64];
        int seedLen = 65;

        try
        {
            mlkemServiceNI.handleErrors(
                    mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), seed, seedLen)
            );
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("seed length is out of range", e.getMessage());
        }
    }


    @Test
    public void MLKEMServiceJNI_generateKeyPair_invalidSeedLength() throws Exception
    {
        byte[] seed = new byte[64];
        int seedLen = 63;

        try
        {
            mlkemServiceNI.handleErrors(
                    mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), seed, seedLen)
            );
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("invalid seed length", e.getMessage());
        }
    }


    @Test
    public void MLKEMServiceJNI_generateKeyPair_noSeedButLength() throws Exception
    {
        byte[] seed = null;
        int seedLen = 64;

        try
        {
            mlkemServiceNI.handleErrors(
                    mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), seed, seedLen)
            );
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("seed is null", e.getMessage());
        }
    }


    @Test
    public void MLKEMServiceJNI_generateKeyPair_seedWrongKeyType() throws Exception
    {
        byte[] seed = new byte[64];
        int seedLen = 64;

        try
        {
            mlkemServiceNI.handleErrors(
                    mlkemServiceNI.generateKeyPair(Integer.MAX_VALUE, seed, seedLen)
            );
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("invalid key type for ML-KEM", e.getMessage());
        }
    }


    @Test
    public void MLKEMServiceJNI_getPublicKey_nullKeyRef() throws Exception
    {

        long ref = 0;
        try
        {
            mlkemServiceNI.handleErrors(mlkemServiceNI.getPublicKey(0, new byte[0]));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("key spec is null", e.getMessage());
        } finally
        {
            specNI.dispose(ref);
        }

    }

    @Test
    public void MLKEMServiceJNI_getPublicKey_keyRefNullKey() throws Exception
    {
        long ref = TestNISelector.SpecNI.allocate();
        try
        {
            mlkemServiceNI.handleErrors(mlkemServiceNI.getPublicKey(ref, new byte[0]));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("key spec has null key", e.getMessage());
        } finally
        {
            specNI.dispose(ref);
        }

    }

    @Test
    public void MLKEMServiceJNI_getPublicKey_outLen() throws Exception
    {
        long ref = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType());
        try
        {
            mlkemServiceNI.handleErrors(mlkemServiceNI.getPublicKey(ref, new byte[10]));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("output too small", e.getMessage());
        } finally
        {
            specNI.dispose(ref);
        }
    }

    @Test
    public void MLKEMServiceJNI_getPrivateKey_nullKeyRef() throws Exception
    {

        long ref = 0;
        try
        {
            mlkemServiceNI.handleErrors(mlkemServiceNI.getPrivateKey(0, new byte[0]));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("key spec is null", e.getMessage());
        } finally
        {
            specNI.dispose(ref);
        }

    }

    @Test
    public void MLKEMServiceJNI_getPrivateKey_keyRefNullKey() throws Exception
    {
        long ref = TestNISelector.SpecNI.allocate();
        try
        {
            mlkemServiceNI.handleErrors(mlkemServiceNI.getPrivateKey(ref, new byte[0]));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("key spec has null key", e.getMessage());
        } finally
        {
            specNI.dispose(ref);
        }
    }

    @Test
    public void MLKEMServiceJNI_getPrivateKey_outLen() throws Exception
    {
        long ref = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType());
        try
        {
            mlkemServiceNI.handleErrors(mlkemServiceNI.getPrivateKey(ref, new byte[10]));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("output too small", e.getMessage());
        } finally
        {
            specNI.dispose(ref);
        }
    }

    @Test
    public void MLKEMServiceJNI_getSeed_nullKeyRef() throws Exception
    {

        long ref = 0;
        try
        {
            mlkemServiceNI.handleErrors(mlkemServiceNI.getPrivateKey(0, new byte[0]));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("key spec is null", e.getMessage());
        } finally
        {
            specNI.dispose(ref);
        }

    }

    @Test
    public void MLKEMServiceJNI_getSeed_keyRefNullKey() throws Exception
    {
        long ref = TestNISelector.SpecNI.allocate();
        try
        {
            mlkemServiceNI.handleErrors(mlkemServiceNI.getPrivateKey(ref, new byte[0]));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("key spec has null key", e.getMessage());
        } finally
        {
            specNI.dispose(ref);
        }
    }

    @Test
    public void MLKEMServiceJNI_getSeed_outLen() throws Exception
    {
        long ref = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType());
        try
        {
            mlkemServiceNI.handleErrors(mlkemServiceNI.getPrivateKey(ref, new byte[10]));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("output too small", e.getMessage());
        } finally
        {
            specNI.dispose(ref);
        }
    }


    @Test()
    public void MLKEMServiceJNI_decode_1publicKey_nullKeySpec() throws Exception
    {

        long keyRef = 0;
        try
        {
            mlkemServiceNI.handleErrors(mlkemServiceNI.decode_publicKey(keyRef, OSSLKeyType.ML_KEM_512.getKsType(), new byte[1024], 0, 1024));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("key spec is null", e.getMessage());
        } finally
        {
        }
    }

    @Test()
    public void MLKEMServiceJNI_decode_1publicKey_inputNull() throws Exception
    {

        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);

            mlkemServiceNI.handleErrors(mlkemServiceNI.decode_publicKey(keyRef, OSSLKeyType.ML_KEM_768.getKsType(), null, 0, 0));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input is null", e.getMessage());
        } finally
        {
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void MLKEMServiceJNI_decode_1publicKey_inputOffsetNegative() throws Exception
    {

        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);

            mlkemServiceNI.handleErrors(mlkemServiceNI.decode_publicKey(keyRef, OSSLKeyType.ML_KEM_512.getKsType(), new byte[0], -1, 0));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input offset is negative", e.getMessage());
        } finally
        {
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void MLKEMServiceJNI_decode_1publicKey_inputLenNegative() throws Exception
    {

        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);

            mlkemServiceNI.handleErrors(mlkemServiceNI.decode_publicKey(keyRef, OSSLKeyType.ML_KEM_512.getKsType(), new byte[0], 0, -1));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input len is negative", e.getMessage());
        } finally
        {
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void MLKEMServiceJNI_decode_1publicKey_inputOutOfRange_1() throws Exception
    {

        // offset + len > size
        // 1 + 10 > 10
        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);
            mlkemServiceNI.handleErrors(mlkemServiceNI.decode_publicKey(keyRef, OSSLKeyType.ML_KEM_512.getKsType(), new byte[10], 1, 10));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input offset + length are out of range", e.getMessage());
        } finally
        {
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void MLKEMServiceJNI_decode_1publicKey_inputOutOfRange_2() throws Exception
    {

        // offset + len > size
        // 0 + 11 > 10

        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);
            mlkemServiceNI.handleErrors(mlkemServiceNI.decode_publicKey(keyRef, OSSLKeyType.ML_KEM_512.getKsType(), new byte[10], 0, 11));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input offset + length are out of range", e.getMessage());
        } finally
        {
            specNI.dispose(keyRef);
        }
    }



}

