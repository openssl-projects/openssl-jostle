package org.openssl.jostle.test.mldsa;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.jcajce.provider.mldsa.MLDSAServiceNI;
import org.openssl.jostle.jcajce.provider.mldsa.MLDSASignatureSpi;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.test.crypto.TestNISelector;

public class MLDSALimitTest
{

    static
    {
        CryptoServicesRegistrar.isNativeAvailable(); // Trigger Loading
    }

    MLDSAServiceNI mldsaServiceNI = TestNISelector.getMLDSANI();
    SpecNI specNI = TestNISelector.getSpecNI();


    @Test
    public void testMLDSAGenerateKeyPair_keyGenWrongType() throws Exception
    {

        for (int type : new int[]{-1, 0, 7})
        {

            try
            {
                mldsaServiceNI.handleErrors(mldsaServiceNI.generateKeyPair(type));
                Assertions.fail();
            } catch (IllegalArgumentException e)
            {
                Assertions.assertEquals("invalid key type for ML-DSA", e.getMessage());
            }

        }
    }

    @Test
    public void MLDSAServiceJNI_generateKeyPair_seedIsNull() throws Exception
    {
        byte[] seed = null;
        int seedLen = 0;

        try
        {
            mldsaServiceNI.handleErrors(
                    mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType(), seed, seedLen)
            );
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("seed is null", e.getMessage());
        }
    }

    @Test
    public void MLDSAServiceJNI_generateKeyPair_seedLenNegative() throws Exception
    {
        byte[] seed = new byte[32];
        int seedLen = -1;

        try
        {
            mldsaServiceNI.handleErrors(
                    mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType(), seed, seedLen)
            );
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("seed len is negative", e.getMessage());
        }
    }


    @Test
    public void MLDSAServiceJNI_generateKeyPair_seedLenPastEndOfArray() throws Exception
    {
        byte[] seed = new byte[16];
        int seedLen = 17;

        try
        {
            mldsaServiceNI.handleErrors(
                    mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType(), seed, seedLen)
            );
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("seed length is out of range", e.getMessage());
        }
    }

    @Test
    public void MLDSAServiceJNI_generateKeyPair_invalidSeedLength() throws Exception
    {
        byte[] seed = new byte[32];
        int seedLen = 31;

        try
        {
            mldsaServiceNI.handleErrors(
                    mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType(), seed, seedLen)
            );
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("invalid seed length", e.getMessage());
        }
    }


    @Test
    public void MLDSAServiceJNI_generateKeyPair_noSeedButLength() throws Exception
    {
        byte[] seed = null;
        int seedLen = 32;

        try
        {
            mldsaServiceNI.handleErrors(
                    mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType(), seed, seedLen)
            );
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("seed is null", e.getMessage());
        }
    }

    @Test
    public void MLDSAServiceJNI_generateKeyPair_seedWrongKeyType() throws Exception
    {
        byte[] seed = new byte[32];
        int seedLen = 32;

        try
        {
            mldsaServiceNI.handleErrors(
                    mldsaServiceNI.generateKeyPair(Integer.MAX_VALUE, seed, seedLen)
            );
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("invalid key type for ML-DSA", e.getMessage());
        }
    }


    @Test
    public void MLDSAServiceJNI_getPublicKey_nullKeyRef() throws Exception
    {

        long ref = 0;
        try
        {
            mldsaServiceNI.handleErrors(mldsaServiceNI.getPublicKey(0, new byte[0]));
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
    public void MLDSAServiceJNI_getPublicKey_keyRefNullKey() throws Exception
    {
        long ref = TestNISelector.SpecNI.allocate();
        try
        {
            mldsaServiceNI.handleErrors(mldsaServiceNI.getPublicKey(ref, new byte[0]));
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
    public void MLDSAServiceJNI_getPublicKey_outLen() throws Exception
    {
        long ref = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());
        try
        {
            mldsaServiceNI.handleErrors(mldsaServiceNI.getPublicKey(ref, new byte[10]));
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
    public void MLDSAServiceJNI_getPrivateKey_nullKeyRef() throws Exception
    {

        long ref = 0;
        try
        {
            mldsaServiceNI.handleErrors(mldsaServiceNI.getPrivateKey(0, new byte[0]));
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
    public void MLDSAServiceJNI_getPrivateKey_keyRefNullKey() throws Exception
    {
        long ref = TestNISelector.SpecNI.allocate();
        try
        {
            mldsaServiceNI.handleErrors(mldsaServiceNI.getPrivateKey(ref, new byte[0]));
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
    public void MLDSAServiceJNI_getPrivateKey_outLen() throws Exception
    {
        long ref = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());
        try
        {
            mldsaServiceNI.handleErrors(mldsaServiceNI.getPrivateKey(ref, new byte[10]));
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
    public void MLDSAServiceJNI_getSeed_nullKeyRef() throws Exception
    {

        long ref = 0;
        try
        {
            mldsaServiceNI.handleErrors(mldsaServiceNI.getPrivateKey(0, new byte[0]));
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
    public void MLDSAServiceJNI_getSeed_keyRefNullKey() throws Exception
    {
        long ref = TestNISelector.SpecNI.allocate();
        try
        {
            mldsaServiceNI.handleErrors(mldsaServiceNI.getPrivateKey(ref, new byte[0]));
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
    public void MLDSAServiceJNI_getSeed_outLen() throws Exception
    {
        long ref = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());
        try
        {
            mldsaServiceNI.handleErrors(mldsaServiceNI.getPrivateKey(ref, new byte[10]));
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
    public void MLDSAServiceJNI_decode_1publicKey_nullKeySpec() throws Exception
    {

        long keyRef = 0;
        try
        {
            mldsaServiceNI.handleErrors(mldsaServiceNI.decode_publicKey(keyRef, OSSLKeyType.ML_DSA_44.getKsType(), new byte[1024], 0, 1024));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("key spec is null", e.getMessage());
        } finally
        {
        }
    }

    @Test()
    public void MLDSAServiceJNI_decode_1publicKey_inputNull() throws Exception
    {

        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);

            mldsaServiceNI.handleErrors(mldsaServiceNI.decode_publicKey(keyRef, OSSLKeyType.ML_DSA_44.getKsType(), null, 0, 0));
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
    public void MLDSAServiceJNI_decode_1publicKey_inputOffsetNegative() throws Exception
    {

        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);

            mldsaServiceNI.handleErrors(mldsaServiceNI.decode_publicKey(keyRef, OSSLKeyType.ML_DSA_44.getKsType(), new byte[0], -1, 0));
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
    public void MLDSAServiceJNI_decode_1publicKey_inputLenNegative() throws Exception
    {

        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);

            mldsaServiceNI.handleErrors(mldsaServiceNI.decode_publicKey(keyRef, OSSLKeyType.ML_DSA_44.getKsType(), new byte[0], 0, -1));
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
    public void MLDSAServiceJNI_decode_1publicKey_inputOutOfRange_1() throws Exception
    {

        // offset + len > size
        // 1 + 10 > 10
        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);
            mldsaServiceNI.handleErrors(mldsaServiceNI.decode_publicKey(keyRef, OSSLKeyType.ML_DSA_44.getKsType(), new byte[10], 1, 10));
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
    public void MLDSAServiceJNI_decode_1publicKey_inputOutOfRange_2() throws Exception
    {

        // offset + len > size
        // 0 + 11 > 10

        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);
            mldsaServiceNI.handleErrors(mldsaServiceNI.decode_publicKey(keyRef, OSSLKeyType.ML_DSA_44.getKsType(), new byte[10], 0, 11));
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
    public void MLDSAServiceJNI_decode_1publicKey_keyLength() throws Exception
    {
        // Either side of each valid key len
        for (int len : new int[]{1311, 1313, 1951, 1953, 2951, 2953})
        {
            long keyRef = 0;
            try
            {
                keyRef = TestNISelector.getSpecNI().allocate();
                Assertions.assertTrue(keyRef > 0);
                mldsaServiceNI.handleErrors(mldsaServiceNI.decode_publicKey(keyRef, OSSLKeyType.NONE.getKsType(), new byte[len], 0, len));
                Assertions.fail();
            } catch (IllegalArgumentException e)
            {
                Assertions.assertEquals("unknown key length", e.getMessage());
            } finally
            {
                specNI.dispose(keyRef);
            }
        }
    }

    @Test()
    public void MLDSAServiceJNI_decode_1publicKey_keyType() throws Exception
    {
        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);
            mldsaServiceNI.handleErrors(mldsaServiceNI.decode_publicKey(keyRef, 99, new byte[10], 0, 10));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("invalid key type for ML-DSA", e.getMessage());
        } finally
        {
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void MLDSAServiceJNI_decode_1publicKey_inputWrongSize4KeyType() throws Exception
    {
        long keyRef = 0;

        final Object[][] tuples = new Object[][]{
                {
                        OSSLKeyType.ML_DSA_44.getKsType(),
                        new byte[1311]
                },
                {
                        OSSLKeyType.ML_DSA_44.getKsType(),
                        new byte[1313]
                },
                {
                        OSSLKeyType.ML_DSA_65.getKsType(),
                        new byte[1951]
                },
                {
                        OSSLKeyType.ML_DSA_65.getKsType(),
                        new byte[1953]
                },
                {
                        OSSLKeyType.ML_DSA_87.getKsType(),
                        new byte[2951]
                },
                {
                        OSSLKeyType.ML_DSA_87.getKsType(),
                        new byte[2953]
                }
        };

        for (Object[] tuple : tuples)
        {

            int keyType = (Integer) tuple[0];
            byte[] key = (byte[]) tuple[1];

            try
            {
                keyRef = TestNISelector.getSpecNI().allocate();
                Assertions.assertTrue(keyRef > 0);
                mldsaServiceNI.handleErrors(mldsaServiceNI.decode_publicKey(keyRef, keyType, key, 0, key.length));
                Assertions.fail();
            } catch (IllegalArgumentException e)
            {
                Assertions.assertEquals("incorrect public key length", e.getMessage());
            } finally
            {
                specNI.dispose(keyRef);
            }
        }
    }

    // Boken input for public key is an OpsTest see MLDSAOpsTest class


    @Test()
    public void MLDSAServiceJNI_decode_1privateKey_inputNull() throws Exception
    {

        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);

            mldsaServiceNI.handleErrors(mldsaServiceNI.decode_privateKey(keyRef, OSSLKeyType.ML_DSA_44.getKsType(), null, 0, 0));
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
    public void MLDSAServiceJNI_decode_1privateKey_inputOffsetNegative() throws Exception
    {

        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);

            mldsaServiceNI.handleErrors(mldsaServiceNI.decode_privateKey(keyRef, OSSLKeyType.ML_DSA_44.getKsType(), new byte[0], -1, 0));
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
    public void MLDSAServiceJNI_decode_1privateKey_inputLenNegative() throws Exception
    {

        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);

            mldsaServiceNI.handleErrors(mldsaServiceNI.decode_privateKey(keyRef, OSSLKeyType.ML_DSA_44.getKsType(), new byte[0], 0, -1));
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
    public void MLDSAServiceJNI_decode_1privateKey_inputOutOfRange_1() throws Exception
    {

        // offset + len > size
        // 1 + 10 > 10
        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);
            mldsaServiceNI.handleErrors(mldsaServiceNI.decode_privateKey(keyRef, OSSLKeyType.ML_DSA_44.getKsType(), new byte[10], 1, 10));
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
    public void MLDSAServiceJNI_decode_1privateKey_inputOutOfRange_2() throws Exception
    {

        // offset + len > size
        // 0 + 11 > 10

        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);
            mldsaServiceNI.handleErrors(mldsaServiceNI.decode_privateKey(keyRef, OSSLKeyType.ML_DSA_44.getKsType(), new byte[10], 0, 11));
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
    public void MLDSAServiceJNI_decode_1privateKey_keyLength() throws Exception
    {
        // Either side of each valid key len
        for (int len : new int[]{2559, 2561, 4031, 4033, 4895, 4897})
        {
            long keyRef = 0;
            try
            {
                keyRef = TestNISelector.getSpecNI().allocate();
                Assertions.assertTrue(keyRef > 0);
                mldsaServiceNI.handleErrors(mldsaServiceNI.decode_privateKey(keyRef, OSSLKeyType.NONE.getKsType(), new byte[len], 0, len));
                Assertions.fail();
            } catch (IllegalArgumentException e)
            {
                Assertions.assertEquals("unknown key length", e.getMessage());
            } finally
            {
                specNI.dispose(keyRef);
            }
        }
    }

    @Test()
    public void MLDSAServiceJNI_decode_1privateKey_keyType() throws Exception
    {
        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);
            mldsaServiceNI.handleErrors(mldsaServiceNI.decode_privateKey(keyRef, 99, new byte[10], 0, 10));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("invalid key type for ML-DSA", e.getMessage());
        } finally
        {
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void MLDSAServiceJNI_decode_1privateKey_inputWrongSize4KeyType() throws Exception
    {
        long keyRef = 0;

        final Object[][] tuples = new Object[][]{
                {
                        OSSLKeyType.ML_DSA_44.getKsType(),
                        new byte[2559]
                },
                {
                        OSSLKeyType.ML_DSA_44.getKsType(),
                        new byte[2561]
                },
                {
                        OSSLKeyType.ML_DSA_65.getKsType(),
                        new byte[4031]
                },
                {
                        OSSLKeyType.ML_DSA_65.getKsType(),
                        new byte[4033]
                },
                {
                        OSSLKeyType.ML_DSA_87.getKsType(),
                        new byte[4895]
                },
                {
                        OSSLKeyType.ML_DSA_87.getKsType(),
                        new byte[4897]
                }
        };

        for (Object[] tuple : tuples)
        {

            int keyType = (Integer) tuple[0];
            byte[] key = (byte[]) tuple[1];

            try
            {
                keyRef = TestNISelector.getSpecNI().allocate();
                Assertions.assertTrue(keyRef > 0);
                mldsaServiceNI.handleErrors(mldsaServiceNI.decode_privateKey(keyRef, keyType, key, 0, key.length));
                Assertions.fail();
            } catch (IllegalArgumentException e)
            {
                Assertions.assertEquals("incorrect private key length", e.getMessage());
            } finally
            {
                specNI.dispose(keyRef);
            }
        }
    }

    @Test()
    public void MLDSAServiceJNI_decode_1privateKey_openSSLErrorOnBrokenInput() throws Exception
    {

        long keyRef = 0;

        final Object[][] tuples = new Object[][]{
                {
                        OSSLKeyType.ML_DSA_44.getKsType(),
                        new byte[2560]
                },
                {
                        OSSLKeyType.ML_DSA_65.getKsType(),
                        new byte[4032]
                },
                {
                        OSSLKeyType.ML_DSA_87.getKsType(),
                        new byte[4896]
                }
        };

        for (Object[] tuple : tuples)
        {

            int keyType = (Integer) tuple[0];
            byte[] key = (byte[]) tuple[1];

            try
            {
                keyRef = TestNISelector.getSpecNI().allocate();
                Assertions.assertTrue(keyRef > 0);
                mldsaServiceNI.handleErrors(mldsaServiceNI.decode_privateKey(keyRef, keyType, key, 0, key.length));
                Assertions.fail();
            } catch (OpenSSLException e)
            {
                Assertions.assertTrue(e.getMessage().contains("private key does not match its pubkey"));
            } finally
            {
                specNI.dispose(keyRef);
            }
        }
    }


    // init Verifier

    @Test()
    public void MLDSAServiceJNI_initVerify_nullContextArray() throws Exception
    {

        long mldsaRef = 0;
        long keyRef = 0;
        try
        {
            mldsaRef = TestNISelector.getMLDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = TestNISelector.getMLDSANI().generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());

            Assertions.assertTrue(keyRef > 0);
            mldsaServiceNI.handleErrors(mldsaServiceNI.initVerify(mldsaRef, keyRef, null, 0, 0));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("context array is null but length >=0", e.getMessage());
        } finally
        {
            mldsaServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);
        }
    }

    // negative context len is a valid input so no limit test on negative len


    @Test()
    public void MLDSAServiceJNI_initVerify_ctxLenPastEndOfContext_1() throws Exception
    {

        // Zero length array but declared len of 1

        long mldsaRef = 0;
        long keyRef = 0;
        try
        {
            mldsaRef = TestNISelector.getMLDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = TestNISelector.getMLDSANI().generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());

            Assertions.assertTrue(keyRef > 0);
            mldsaServiceNI.handleErrors(mldsaServiceNI.initVerify(mldsaRef, keyRef, new byte[0], 1, 0));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("context length is past end of context", e.getMessage());
        } finally
        {
            mldsaServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void MLDSAServiceJNI_initVerify_ctxLenPastEndOfContext_2() throws Exception
    {

        // array length of 1  but declared len of 2

        long mldsaRef = 0;
        long keyRef = 0;
        try
        {
            mldsaRef = TestNISelector.getMLDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = TestNISelector.getMLDSANI().generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());

            Assertions.assertTrue(keyRef > 0);
            mldsaServiceNI.handleErrors(mldsaServiceNI.initVerify(mldsaRef, keyRef, new byte[1], 2, 0));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("context length is past end of context", e.getMessage());
        } finally
        {
            mldsaServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void MLDSAServiceJNI_initVerify_ctxTooLong() throws Exception
    {

        // array length of 1  but declared len of 2

        long mldsaRef = 0;
        long keyRef = 0;
        try
        {
            mldsaRef = TestNISelector.getMLDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = TestNISelector.getMLDSANI().generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());

            Assertions.assertTrue(keyRef > 0);
            mldsaServiceNI.handleErrors(mldsaServiceNI.initVerify(mldsaRef, keyRef, new byte[256], 256, 0));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("context length is too long", e.getMessage());
        } finally
        {
            mldsaServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void MLDSAServiceJNI_initVerify_nullKey() throws Exception
    {

        long mldsaRef = 0;
        long keyRef = 0;
        try
        {
            mldsaRef = TestNISelector.getMLDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            mldsaServiceNI.handleErrors(mldsaServiceNI.initVerify(mldsaRef, keyRef, new byte[1], 1, 0));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("key spec is null", e.getMessage());
        } finally
        {
            mldsaServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void MLDSAServiceJNI_initVerify_keySpecNullKey() throws Exception
    {

        long mldsaRef = 0;
        long keyRef = 0;
        try
        {
            mldsaRef = TestNISelector.getMLDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = specNI.allocate();

            Assertions.assertTrue(keyRef > 0);
            mldsaServiceNI.handleErrors(mldsaServiceNI.initVerify(mldsaRef, keyRef, new byte[1], 1, 0));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("key spec has null key", e.getMessage());
        } finally
        {
            mldsaServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void MLDSAServiceJNI_initVerify_unknownMuMode() throws Exception
    {

        long mldsaRef = 0;
        long keyRef = 0;
        try
        {
            mldsaRef = TestNISelector.getMLDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());

            Assertions.assertTrue(keyRef > 0);
            mldsaServiceNI.handleErrors(mldsaServiceNI.initVerify(mldsaRef, keyRef, new byte[1], 1, 3));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("unknown Mu mode", e.getMessage());
        } finally
        {
            mldsaServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void MLDSAServiceJNI_initVerify_invalidMuMode() throws Exception
    {

        long mldsaRef = 0;
        long keyRef = 0;
        try
        {
            mldsaRef = mldsaServiceNI.allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());
            Assertions.assertTrue(keyRef > 0);
            mldsaServiceNI.handleErrors(mldsaServiceNI.initVerify(
                    mldsaRef,
                    keyRef,
                    new byte[1], 1, MLDSASignatureSpi.MuHandling.CALCULATE_MU.ordinal()));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("invalid Mu mode for verify", e.getMessage());
        } finally
        {
            mldsaServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);
        }
    }


    // init Signer

    @Test()
    public void MLDSAServiceJNI_initSign_nullContextArray() throws Exception
    {

        long mldsaRef = 0;
        long keyRef = 0;
        try
        {
            mldsaRef = TestNISelector.getMLDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = TestNISelector.getMLDSANI().generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());

            Assertions.assertTrue(keyRef > 0);
            mldsaServiceNI.handleErrors(mldsaServiceNI.initVerify(mldsaRef, keyRef, null, 0, 0));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("context array is null but length >=0", e.getMessage());
        } finally
        {
            mldsaServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);
        }
    }

    // negative context len is a valid input so no limit test on negative len


    @Test()
    public void MLDSAServiceJNI_initSign_ctxLenPastEndOfContext_1() throws Exception
    {

        // Zero length array but declared len of 1

        long mldsaRef = 0;
        long keyRef = 0;
        try
        {
            mldsaRef = TestNISelector.getMLDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = TestNISelector.getMLDSANI().generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());

            Assertions.assertTrue(keyRef > 0);
            mldsaServiceNI.handleErrors(mldsaServiceNI.initSign(mldsaRef, keyRef, new byte[0], 1, 0));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("context length is past end of context", e.getMessage());
        } finally
        {
            mldsaServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void MLDSAServiceJNI_initSign_ctxLenPastEndOfContext_2() throws Exception
    {

        // array length of 1  but declared len of 2

        long mldsaRef = 0;
        long keyRef = 0;
        try
        {
            mldsaRef = TestNISelector.getMLDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = TestNISelector.getMLDSANI().generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());

            Assertions.assertTrue(keyRef > 0);
            mldsaServiceNI.handleErrors(mldsaServiceNI.initSign(mldsaRef, keyRef, new byte[1], 2, 0));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("context length is past end of context", e.getMessage());
        } finally
        {
            mldsaServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);
        }
    }


    @Test()
    public void MLDSAServiceJNI_initSign_ctxTooLong() throws Exception
    {

        // array length of 1  but declared len of 2

        long mldsaRef = 0;
        long keyRef = 0;
        try
        {
            mldsaRef = TestNISelector.getMLDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = TestNISelector.getMLDSANI().generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());

            Assertions.assertTrue(keyRef > 0);
            mldsaServiceNI.handleErrors(mldsaServiceNI.initSign(mldsaRef, keyRef, new byte[256], 256, 0));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("context length is too long", e.getMessage());
        } finally
        {
            mldsaServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);
        }
    }


    @Test()
    public void MLDSAServiceJNI_initSign_nullKey() throws Exception
    {

        long mldsaRef = 0;
        long keyRef = 0;
        try
        {
            mldsaRef = TestNISelector.getMLDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            mldsaServiceNI.handleErrors(mldsaServiceNI.initSign(mldsaRef, keyRef, new byte[1], 1, 0));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("key spec is null", e.getMessage());
        } finally
        {
            mldsaServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void MLDSAServiceJNI_initSign_keySpecNullKey() throws Exception
    {

        long mldsaRef = 0;
        long keyRef = 0;
        try
        {
            mldsaRef = TestNISelector.getMLDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = specNI.allocate();

            Assertions.assertTrue(keyRef > 0);
            mldsaServiceNI.handleErrors(mldsaServiceNI.initSign(mldsaRef, keyRef, new byte[1], 1, 0));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("key spec has null key", e.getMessage());
        } finally
        {
            mldsaServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void MLDSAServiceJNI_initSign_unknownMuMode() throws Exception
    {

        long mldsaRef = 0;
        long keyRef = 0;
        try
        {
            mldsaRef = TestNISelector.getMLDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());

            Assertions.assertTrue(keyRef > 0);
            mldsaServiceNI.handleErrors(mldsaServiceNI.initSign(mldsaRef, keyRef, new byte[1], 1, 3));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("unknown Mu mode", e.getMessage());
        } finally
        {
            mldsaServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);
        }
    }


    @Test()
    public void MLDSAServiceJNI_mldsa_update_notInitialised() throws Exception
    {
        long mldsaRef = 0;
        long keyRef = 0;
        try
        {
            mldsaRef = TestNISelector.getMLDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());

            Assertions.assertTrue(keyRef > 0);
            //  mldsaServiceNI.handleErrors(mldsaServiceNI.initSign(mldsaRef, keyRef, new byte[1], 1, 3));

            mldsaServiceNI.handleErrors(mldsaServiceNI.update(mldsaRef, new byte[0], 0, 0));

            Assertions.fail();
        } catch (IllegalStateException e)
        {
            Assertions.assertEquals("not initialized", e.getMessage());
        } finally
        {
            mldsaServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);
        }
    }


    @Test()
    public void MLDSAServiceJNI_mldsa_update_nullInput() throws Exception
    {
        long mldsaRef = 0;
        long keyRef = 0;
        try
        {
            mldsaRef = TestNISelector.getMLDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());

            Assertions.assertTrue(keyRef > 0);
            mldsaServiceNI.handleErrors(mldsaServiceNI.initSign(mldsaRef, keyRef, new byte[0], 0, 0));

            mldsaServiceNI.handleErrors(mldsaServiceNI.update(mldsaRef, null, 0, 0));

            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input is null", e.getMessage());
        } finally
        {
            mldsaServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);
        }
    }


    @Test()
    public void MLDSAServiceJNI_mldsa_update_inputOffsetNegative() throws Exception
    {
        long mldsaRef = 0;
        long keyRef = 0;
        try
        {
            mldsaRef = TestNISelector.getMLDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());

            Assertions.assertTrue(keyRef > 0);
            mldsaServiceNI.handleErrors(mldsaServiceNI.initSign(mldsaRef, keyRef, new byte[0], 0, 0));

            mldsaServiceNI.handleErrors(mldsaServiceNI.update(mldsaRef, new byte[0], -1, 0));

            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input offset is negative", e.getMessage());
        } finally
        {
            mldsaServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void MLDSAServiceJNI_mldsa_update_inputLenNegative() throws Exception
    {
        long mldsaRef = 0;
        long keyRef = 0;
        try
        {
            mldsaRef = TestNISelector.getMLDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());

            Assertions.assertTrue(keyRef > 0);
            mldsaServiceNI.handleErrors(mldsaServiceNI.initSign(mldsaRef, keyRef, new byte[0], 0, 0));

            mldsaServiceNI.handleErrors(mldsaServiceNI.update(mldsaRef, new byte[0], 0, -1));

            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input len is negative", e.getMessage());
        } finally
        {
            mldsaServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);
        }
    }


    @Test()
    public void MLDSAServiceJNI_mldsa_update_inputOutOfRange_1() throws Exception
    {

        // 10 byte input
        // 0 offset
        // 11 byte len

        long mldsaRef = 0;
        long keyRef = 0;
        try
        {
            mldsaRef = TestNISelector.getMLDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());

            Assertions.assertTrue(keyRef > 0);
            mldsaServiceNI.handleErrors(mldsaServiceNI.initSign(mldsaRef, keyRef, new byte[0], 0, 0));

            mldsaServiceNI.handleErrors(mldsaServiceNI.update(mldsaRef, new byte[10], 0, 11));

            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input offset + length are out of range", e.getMessage());
        } finally
        {
            mldsaServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);
        }
    }


    @Test()
    public void MLDSAServiceJNI_mldsa_update_inputOutOfRange_2() throws Exception
    {

        // 10 byte input
        // 1 offset
        // 10 byte len

        long mldsaRef = 0;
        long keyRef = 0;
        try
        {
            mldsaRef = TestNISelector.getMLDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());

            Assertions.assertTrue(keyRef > 0);
            mldsaServiceNI.handleErrors(mldsaServiceNI.initSign(mldsaRef, keyRef, new byte[0], 0, 0));

            mldsaServiceNI.handleErrors(mldsaServiceNI.update(mldsaRef, new byte[10], 1, 10));

            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input offset + length are out of range", e.getMessage());
        } finally
        {
            mldsaServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);
        }
    }


    // NB Sign accepts null input, returns length of signature so null input is valid

    @Test()
    public void MLDSAServiceJNI_mldsa_sign_outOffsetNegative() throws Exception
    {

        long mldsaRef = 0;
        long keyRef = 0;
        try
        {
            mldsaRef = TestNISelector.getMLDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());

            Assertions.assertTrue(keyRef > 0);
            mldsaServiceNI.handleErrors(mldsaServiceNI.initSign(mldsaRef, keyRef, new byte[0], 0, 0));

            mldsaServiceNI.handleErrors(mldsaServiceNI.sign(mldsaRef, new byte[0], -1));

            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("output offset is negative", e.getMessage());
        } finally
        {
            mldsaServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void MLDSAServiceJNI_mldsa_sign_outputRange() throws Exception
    {

        long mldsaRef = 0;
        long keyRef = 0;
        try
        {
            mldsaRef = TestNISelector.getMLDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());

            Assertions.assertTrue(keyRef > 0);
            mldsaServiceNI.handleErrors(mldsaServiceNI.initSign(mldsaRef, keyRef, new byte[0], 0, 0));

            mldsaServiceNI.handleErrors(mldsaServiceNI.sign(mldsaRef, new byte[0], 1));

            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("output offset is out of range", e.getMessage());
        } finally
        {
            mldsaServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void MLDSAServiceJNI_mldsa_sign_notInitialized() throws Exception
    {

        long mldsaRef = 0;
        long keyRef = 0;
        try
        {
            mldsaRef = TestNISelector.getMLDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());

            Assertions.assertTrue(keyRef > 0);
            // mldsaServiceNI.handleErrors(mldsaServiceNI.initSign(mldsaRef, keyRef, new byte[0], 0, 0));

            mldsaServiceNI.handleErrors(mldsaServiceNI.sign(mldsaRef, new byte[0], 0));

            Assertions.fail();
        } catch (IllegalStateException e)
        {
            Assertions.assertEquals("not initialized", e.getMessage());
        } finally
        {
            mldsaServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);
        }
    }


    @Test()
    public void MLDSAServiceJNI_mldsa_sign_initVerify() throws Exception
    {

        long mldsaRef = 0;
        long keyRef = 0;
        try
        {
            mldsaRef = TestNISelector.getMLDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());

            Assertions.assertTrue(keyRef > 0);
            mldsaServiceNI.handleErrors(mldsaServiceNI.initVerify(mldsaRef, keyRef, new byte[0], 0, 0));

            mldsaServiceNI.handleErrors(mldsaServiceNI.sign(mldsaRef, new byte[0], 0));

            Assertions.fail();
        } catch (IllegalStateException e)
        {
            Assertions.assertEquals("unexpected state", e.getMessage());
        } finally
        {
            mldsaServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);
        }
    }


    @Test()
    public void MLDSAServiceJNI_mldsa_sign_outputTooSmall_1() throws Exception
    {

        //
        // offset is zero
        //

        long mldsaRef = 0;
        long keyRef = 0;
        try
        {
            mldsaRef = TestNISelector.getMLDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());

            Assertions.assertTrue(keyRef > 0);
            mldsaServiceNI.handleErrors(mldsaServiceNI.initSign(mldsaRef, keyRef, new byte[0], 0, 0));

            long len = mldsaServiceNI.handleErrors(mldsaServiceNI.sign(mldsaRef, null, 0));

            byte[] sig = new byte[(int) len - 1];

            mldsaServiceNI.handleErrors(mldsaServiceNI.sign(mldsaRef, sig, 0));

            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("output too small", e.getMessage());
        } finally
        {
            mldsaServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);
        }
    }


    @Test()
    public void MLDSAServiceJNI_mldsa_sign_outputTooSmall_2() throws Exception
    {

        //
        // offset is 1
        //

        long mldsaRef = 0;
        long keyRef = 0;
        try
        {
            mldsaRef = TestNISelector.getMLDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());

            Assertions.assertTrue(keyRef > 0);
            mldsaServiceNI.handleErrors(mldsaServiceNI.initSign(mldsaRef, keyRef, new byte[0], 0, 0));

            long len = mldsaServiceNI.handleErrors(mldsaServiceNI.sign(mldsaRef, null, 0));

            byte[] sig = new byte[(int) len];

            mldsaServiceNI.handleErrors(mldsaServiceNI.sign(mldsaRef, sig, 1));

            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("output too small", e.getMessage());
        } finally
        {
            mldsaServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void MLDSAServiceJNI_mldsa_sign_outputTooSmall_muOnly_1() throws Exception
    {


        long mldsaRef = 0;
        long keyRef = 0;
        try
        {
            mldsaRef = TestNISelector.getMLDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());

            Assertions.assertTrue(keyRef > 0);
            mldsaServiceNI.handleErrors(mldsaServiceNI.initSign(mldsaRef, keyRef, new byte[0], 0, MLDSASignatureSpi.MuHandling.CALCULATE_MU.ordinal()));

            long len = mldsaServiceNI.handleErrors(mldsaServiceNI.sign(mldsaRef, null, 0));
            Assertions.assertEquals(64L, len);

            byte[] sig = new byte[(int) len - 1];

            mldsaServiceNI.handleErrors(mldsaServiceNI.sign(mldsaRef, sig, 0));

            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("output too small", e.getMessage());
        } finally
        {
            mldsaServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);
        }
    }


    @Test()
    public void MLDSAServiceJNI_mldsa_sign_outputTooSmall_muOnly_2() throws Exception
    {


        long mldsaRef = 0;
        long keyRef = 0;
        try
        {
            mldsaRef = TestNISelector.getMLDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());

            Assertions.assertTrue(keyRef > 0);
            mldsaServiceNI.handleErrors(mldsaServiceNI.initSign(mldsaRef, keyRef, new byte[0], 0, MLDSASignatureSpi.MuHandling.CALCULATE_MU.ordinal()));

            long len = mldsaServiceNI.handleErrors(mldsaServiceNI.sign(mldsaRef, null, 0));

            Assertions.assertEquals(64L, len);

            byte[] sig = new byte[(int) len];

            mldsaServiceNI.handleErrors(mldsaServiceNI.sign(mldsaRef, sig, 1));

            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("output too small", e.getMessage());
        } finally
        {
            mldsaServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);
        }
    }


    @Test()
    public void MLDSAServiceJNI_mldsa_verify_nullSig() throws Exception
    {


        long mldsaRef = 0;
        long keyRef = 0;
        try
        {
            mldsaRef = TestNISelector.getMLDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());

            Assertions.assertTrue(keyRef > 0);
            mldsaServiceNI.handleErrors(mldsaServiceNI.initVerify(mldsaRef, keyRef, new byte[0], 0, MLDSASignatureSpi.MuHandling.INTERNAL.ordinal()));

            mldsaServiceNI.handleErrors(mldsaServiceNI.verify(mldsaRef, null, 0));

            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("sig is null", e.getMessage());
        } finally
        {
            mldsaServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);
        }
    }


    @Test()
    public void MLDSAServiceJNI_mldsa_verify_sigLenZero() throws Exception
    {
        long mldsaRef = 0;
        long keyRef = 0;
        try
        {
            mldsaRef = TestNISelector.getMLDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());

            Assertions.assertTrue(keyRef > 0);
            mldsaServiceNI.handleErrors(mldsaServiceNI.initVerify(mldsaRef, keyRef, new byte[0], 0, MLDSASignatureSpi.MuHandling.INTERNAL.ordinal()));

            long code = mldsaServiceNI.handleErrors(mldsaServiceNI.verify(mldsaRef, new byte[1], 0));
            Assertions.assertEquals(ErrorCode.JO_FAIL.getCode(), code);

        } finally
        {
            mldsaServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void MLDSAServiceJNI_mldsa_verify_sigLenNegative() throws Exception
    {
        long mldsaRef = 0;
        long keyRef = 0;
        try
        {
            mldsaRef = TestNISelector.getMLDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());

            Assertions.assertTrue(keyRef > 0);
            mldsaServiceNI.handleErrors(mldsaServiceNI.initVerify(mldsaRef, keyRef, new byte[0], 0, MLDSASignatureSpi.MuHandling.INTERNAL.ordinal()));

            mldsaServiceNI.handleErrors(mldsaServiceNI.verify(mldsaRef, new byte[1], -1));

            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("sig length is negative", e.getMessage());
        } finally
        {
            mldsaServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);
        }
    }


    @Test()
    public void MLDSAServiceJNI_mldsa_verify_sigLenOutOfRange_1() throws Exception
    {
        long mldsaRef = 0;
        long keyRef = 0;
        try
        {
            mldsaRef = TestNISelector.getMLDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());

            Assertions.assertTrue(keyRef > 0);
            mldsaServiceNI.handleErrors(mldsaServiceNI.initVerify(mldsaRef, keyRef, new byte[0], 0, MLDSASignatureSpi.MuHandling.INTERNAL.ordinal()));

            mldsaServiceNI.handleErrors(mldsaServiceNI.verify(mldsaRef, new byte[10], 11));

            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("sig out of range", e.getMessage());
        } finally
        {
            mldsaServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void MLDSAServiceJNI_mldsa_verify_sigLenOutOfRange_2() throws Exception
    {
        long mldsaRef = 0;
        long keyRef = 0;
        try
        {
            mldsaRef = TestNISelector.getMLDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());

            Assertions.assertTrue(keyRef > 0);
            mldsaServiceNI.handleErrors(mldsaServiceNI.initVerify(mldsaRef, keyRef, new byte[0], 0, MLDSASignatureSpi.MuHandling.INTERNAL.ordinal()));

            mldsaServiceNI.handleErrors(mldsaServiceNI.verify(mldsaRef, new byte[0], 1));

            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("sig out of range", e.getMessage());
        } finally
        {
            mldsaServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void MLDSAServiceJNI_mldsa_verify_initForSigning() throws Exception
    {
        long mldsaRef = 0;
        long keyRef = 0;
        try
        {
            mldsaRef = TestNISelector.getMLDSANI().allocateSigner();
            Assertions.assertTrue(mldsaRef > 0);
            keyRef = mldsaServiceNI.generateKeyPair(OSSLKeyType.ML_DSA_44.getKsType());

            Assertions.assertTrue(keyRef > 0);
            mldsaServiceNI.handleErrors(mldsaServiceNI.initSign(mldsaRef, keyRef, new byte[0], 0, MLDSASignatureSpi.MuHandling.INTERNAL.ordinal()));

            mldsaServiceNI.handleErrors(mldsaServiceNI.verify(mldsaRef, new byte[1], 1));

            Assertions.fail();
        } catch (IllegalStateException e)
        {
            Assertions.assertEquals("unexpected state", e.getMessage());
        } finally
        {
            mldsaServiceNI.disposeSigner(mldsaRef);
            specNI.dispose(keyRef);
        }
    }

}
