package org.openssl.jostle.test.slhdsa;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.SLHDSAServiceNI;
import org.openssl.jostle.jcajce.provider.slhdsa.SLHDSASignatureSpi;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.test.crypto.TestNISelector;

public class SLHDSALimitTest
{
    static
    {
        CryptoServicesRegistrar.isNativeAvailable(); // Trigger Loading
    }

    SLHDSAServiceNI slhdsaServiceNI = TestNISelector.getSLHDSANI();
    SpecNI specNI = TestNISelector.getSpecNI();

    @Test
    public void testSLHDSAGenerateKeyPair_keyGenWrongType() throws Exception
    {
        for (int type : new int[]{-1, 0, 4, 17})
        {
            try
            {
                slhdsaServiceNI.handleErrors(slhdsaServiceNI.generateKeyPair(type));
                Assertions.fail();
            } catch (IllegalArgumentException e)
            {
                Assertions.assertEquals("invalid key type for SLH-DSA", e.getMessage());
            }

        }
    }


    @Test
    public void SLHDSAServiceJNI_generateKeyPair_seedIsNull() throws Exception
    {
        byte[] seed = null;
        int seedLen = 0;

        try
        {
            slhdsaServiceNI.handleErrors(
                    slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_192s.getKsType(), seed, seedLen)
            );
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("seed is null", e.getMessage());
        }
    }

    @Test
    public void SLHDSAServiceJNI_generateKeyPair_seedLenNegative() throws Exception
    {
        byte[] seed = new byte[32];
        int seedLen = -1;

        try
        {
            slhdsaServiceNI.handleErrors(
                    slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_192f.getKsType(), seed, seedLen)
            );
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("seed len is negative", e.getMessage());
        }
    }

    @Test
    public void SLHDSAServiceJNI_generateKeyPair_seedLenPastEndOfArray() throws Exception
    {
        byte[] seed = new byte[16];
        int seedLen = 17;

        try
        {
            slhdsaServiceNI.handleErrors(
                    slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128f.getKsType(), seed, seedLen)
            );
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("seed length is out of range", e.getMessage());
        }
    }

    @Test
    public void SLHDSAServiceJNI_generateKeyPair_invalidSeedLength_128() throws Exception
    {
        byte[] seed = new byte[16 * 3];
        int seedLen = seed.length - 1;

        try
        {
            slhdsaServiceNI.handleErrors(
                    slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128f.getKsType(), seed, seedLen)
            );
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("invalid seed length", e.getMessage());
        }
    }


    @Test
    public void SLHDSAServiceJNI_generateKeyPair_invalidSeedLength_192() throws Exception
    {
        byte[] seed = new byte[24 * 3];
        int seedLen = seed.length - 1;

        try
        {
            slhdsaServiceNI.handleErrors(
                    slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_192f.getKsType(), seed, seedLen)
            );
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("invalid seed length", e.getMessage());
        }
    }

    @Test
    public void SLHDSAServiceJNI_generateKeyPair_invalidSeedLength_256() throws Exception
    {
        byte[] seed = new byte[24 * 3];
        int seedLen = seed.length - 1;

        try
        {
            slhdsaServiceNI.handleErrors(
                    slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_256f.getKsType(), seed, seedLen)
            );
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("invalid seed length", e.getMessage());
        }

    }


    @Test
    public void SLHDSAServiceJNI_generateKeyPair_noSeedButLength() throws Exception
    {
        byte[] seed = null;
        int seedLen = 48;

        try
        {
            slhdsaServiceNI.handleErrors(
                    slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128f.getKsType(), seed, seedLen)
            );
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("seed is null", e.getMessage());
        }
    }

    @Test
    public void SLHDSAServiceJNI_generateKeyPair_seedWrongKeyType() throws Exception
    {
        byte[] seed = new byte[48];
        int seedLen = 48;

        try
        {
            slhdsaServiceNI.handleErrors(
                    slhdsaServiceNI.generateKeyPair(Integer.MAX_VALUE, seed, seedLen)
            );
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("invalid key type for SLH-DSA", e.getMessage());
        }
    }


    @Test
    public void SLHDSAServiceJNI_generateKeyPair_incorrectSeedLen() throws Exception
    {
        for (OSSLKeyType keyType : new OSSLKeyType[]{
                OSSLKeyType.SLH_DSA_SHA2_128f,
                OSSLKeyType.SLH_DSA_SHA2_128s,
                OSSLKeyType.SLH_DSA_SHA2_192f,
                OSSLKeyType.SLH_DSA_SHA2_192s,
                OSSLKeyType.SLH_DSA_SHA2_256f,
                OSSLKeyType.SLH_DSA_SHA2_256s,
                OSSLKeyType.SLH_DSA_SHAKE_128f,
                OSSLKeyType.SLH_DSA_SHAKE_128s,
                OSSLKeyType.SLH_DSA_SHAKE_192f,
                OSSLKeyType.SLH_DSA_SHAKE_192s,
                OSSLKeyType.SLH_DSA_SHAKE_256f,
                OSSLKeyType.SLH_DSA_SHAKE_256s
        })
        {
            int base = 0;
            if (keyType.name().contains("128"))
            {
                base = 16;
            } else if (keyType.name().contains("192"))
            {
                base = 24;
            } else if (keyType.name().contains("256"))
            {
                base = 32;
            } else
            {
                Assertions.fail();
            }

            byte[] seed = new byte[base * 3];
            int seedLen = seed.length - 1;

            try
            {
                slhdsaServiceNI.handleErrors(
                        slhdsaServiceNI.generateKeyPair(keyType.ordinal(), seed, seedLen)
                );
                Assertions.fail();
            } catch (IllegalArgumentException e)
            {
                Assertions.assertEquals("invalid seed length", e.getMessage());
            }
        }
    }


    @Test
    public void SLHDSAServiceJNI_getPublicKey_nullKeyRef() throws Exception
    {

        long ref = 0;
        try
        {
            slhdsaServiceNI.handleErrors(slhdsaServiceNI.getPublicKey(0, new byte[0]));
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
    public void SLHDSAServiceJNI_getPublicKey_keyRefNullKey() throws Exception
    {
        long ref = TestNISelector.SpecNI.allocate();
        try
        {
            slhdsaServiceNI.handleErrors(slhdsaServiceNI.getPublicKey(ref, new byte[0]));
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
    public void SLHDSAServiceJNI_getPublicKey_outLen() throws Exception
    {
        long ref = slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_256f.getKsType());
        try
        {
            slhdsaServiceNI.handleErrors(slhdsaServiceNI.getPublicKey(ref, new byte[10]));
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
    public void SLHDSAServiceJNI_getPrivateKey_nullKeyRef() throws Exception
    {

        long ref = 0;
        try
        {
            slhdsaServiceNI.handleErrors(slhdsaServiceNI.getPrivateKey(0, new byte[0]));
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
    public void SLHDSAServiceJNI_getPrivateKey_keyRefNullKey() throws Exception
    {
        long ref = TestNISelector.SpecNI.allocate();
        try
        {
            slhdsaServiceNI.handleErrors(slhdsaServiceNI.getPrivateKey(ref, new byte[0]));
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
    public void SLHDSAServiceJNI_getPrivateKey_outLen() throws Exception
    {
        long ref = slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType());
        try
        {
            slhdsaServiceNI.handleErrors(slhdsaServiceNI.getPrivateKey(ref, new byte[10]));
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
    public void SLHDSAServiceJNI_getSeed_nullKeyRef() throws Exception
    {

        long ref = 0;
        try
        {
            slhdsaServiceNI.handleErrors(slhdsaServiceNI.getPrivateKey(0, new byte[0]));
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
    public void SLHDSAServiceJNI_getSeed_keyRefNullKey() throws Exception
    {
        long ref = TestNISelector.SpecNI.allocate();
        try
        {
            slhdsaServiceNI.handleErrors(slhdsaServiceNI.getPrivateKey(ref, new byte[0]));
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
    public void SLHDSAServiceJNI_getSeed_outLen() throws Exception
    {
        long ref = slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType());
        try
        {
            slhdsaServiceNI.handleErrors(slhdsaServiceNI.getPrivateKey(ref, new byte[10]));
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
    public void SLHDSAServiceJNI_decode_1publicKey_nullKeySpec() throws Exception
    {

        long keyRef = 0;
        try
        {
            slhdsaServiceNI.handleErrors(slhdsaServiceNI.decode_publicKey(keyRef, OSSLKeyType.SLH_DSA_SHA2_128s.getKsType(), new byte[1024], 0, 1024));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("key spec is null", e.getMessage());
        } finally
        {
        }
    }

    @Test()
    public void SLHDSAServiceJNI_decode_1publicKey_inputNull() throws Exception
    {

        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);

            slhdsaServiceNI.handleErrors(slhdsaServiceNI.decode_publicKey(keyRef, OSSLKeyType.SLH_DSA_SHA2_128s.getKsType(), null, 0, 0));
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
    public void SLHDSAServiceJNI_decode_1publicKey_inputOffsetNegative() throws Exception
    {

        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);

            slhdsaServiceNI.handleErrors(slhdsaServiceNI.decode_publicKey(keyRef, OSSLKeyType.SLH_DSA_SHA2_128s.getKsType(), new byte[0], -1, 0));
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
    public void SLHDSAServiceJNI_decode_1publicKey_inputLenNegative() throws Exception
    {

        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);

            slhdsaServiceNI.handleErrors(slhdsaServiceNI.decode_publicKey(keyRef, OSSLKeyType.SLH_DSA_SHA2_128s.getKsType(), new byte[0], 0, -1));
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
    public void SLHDSAServiceJNI_decode_1publicKey_inputOutOfRange_1() throws Exception
    {

        // offset + len > size
        // 1 + 10 > 10
        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);
            slhdsaServiceNI.handleErrors(slhdsaServiceNI.decode_publicKey(keyRef, OSSLKeyType.SLH_DSA_SHA2_128s.getKsType(), new byte[10], 1, 10));
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
    public void SLHDSAServiceJNI_decode_1publicKey_inputOutOfRange_2() throws Exception
    {

        // offset + len > size
        // 0 + 11 > 10

        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);
            slhdsaServiceNI.handleErrors(slhdsaServiceNI.decode_publicKey(keyRef, OSSLKeyType.SLH_DSA_SHA2_128s.getKsType(), new byte[10], 0, 11));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input offset + length are out of range", e.getMessage());
        } finally
        {
            specNI.dispose(keyRef);
        }
    }

    //TODO  @Test()
    public void SLHDSAServiceJNI_decode_1publicKey_keyLength() throws Exception
    {
        // Either side of each valid key len
        for (int len : new int[]{1311, 1313, 1951, 1953, 2951, 2953})
        {
            long keyRef = 0;
            try
            {
                keyRef = TestNISelector.getSpecNI().allocate();
                Assertions.assertTrue(keyRef > 0);
                slhdsaServiceNI.handleErrors(slhdsaServiceNI.decode_publicKey(keyRef, OSSLKeyType.NONE.getKsType(), new byte[len], 0, len));
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
    public void SLHDSAServiceJNI_decode_1publicKey_keyType() throws Exception
    {
        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);
            slhdsaServiceNI.handleErrors(slhdsaServiceNI.decode_publicKey(keyRef, 99, new byte[10], 0, 10));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("invalid key type for SLH-DSA", e.getMessage());
        } finally
        {
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void SLHDSAServiceJNI_decode_1publicKey_inputWrongSize4KeyType() throws Exception
    {
        long keyRef = 0;


        for (OSSLKeyType keyType : new OSSLKeyType[]{
                OSSLKeyType.SLH_DSA_SHA2_128f,
                OSSLKeyType.SLH_DSA_SHA2_128s,
                OSSLKeyType.SLH_DSA_SHA2_192f,
                OSSLKeyType.SLH_DSA_SHA2_192s,
                OSSLKeyType.SLH_DSA_SHA2_256f,
                OSSLKeyType.SLH_DSA_SHA2_256s,
                OSSLKeyType.SLH_DSA_SHAKE_128f,
                OSSLKeyType.SLH_DSA_SHAKE_128s,
                OSSLKeyType.SLH_DSA_SHAKE_192f,
                OSSLKeyType.SLH_DSA_SHAKE_192s,
                OSSLKeyType.SLH_DSA_SHAKE_256f,
                OSSLKeyType.SLH_DSA_SHAKE_256s
        })
        {
            int base = 0;
            if (keyType.name().contains("128"))
            {
                base = 16;
            } else if (keyType.name().contains("192"))
            {
                base = 24;
            } else if (keyType.name().contains("256"))
            {
                base = 32;
            } else
            {
                Assertions.fail();
            }


            { // too short
                byte[] key = (byte[]) new byte[(base * 2) - 1];

                try
                {
                    keyRef = TestNISelector.getSpecNI().allocate();
                    Assertions.assertTrue(keyRef > 0);
                    slhdsaServiceNI.handleErrors(slhdsaServiceNI.decode_publicKey(keyRef, keyType.ordinal(), key, 0, key.length));
                    Assertions.fail();
                } catch (IllegalArgumentException e)
                {
                    Assertions.assertEquals("incorrect public key length", e.getMessage());
                } finally
                {
                    specNI.dispose(keyRef);
                }
            }


            { // ok
                byte[] key = (byte[]) new byte[(base * 2)];

                try
                {
                    keyRef = TestNISelector.getSpecNI().allocate();
                    Assertions.assertTrue(keyRef > 0);
                    slhdsaServiceNI.handleErrors(slhdsaServiceNI.decode_publicKey(keyRef, keyType.ordinal(), key, 0, key.length));
                } finally
                {
                    specNI.dispose(keyRef);
                }
            }


            { // too long
                byte[] key = (byte[]) new byte[(base * 2) + 1];

                try
                {
                    keyRef = TestNISelector.getSpecNI().allocate();
                    Assertions.assertTrue(keyRef > 0);
                    slhdsaServiceNI.handleErrors(slhdsaServiceNI.decode_publicKey(keyRef, keyType.ordinal(), key, 0, key.length));
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

    }

    // Boken input for public key is an OpsTest see SLHDSAOpsTest class


    @Test()
    public void SLHDSAServiceJNI_decode_1privateKey_inputNull() throws Exception
    {

        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);

            slhdsaServiceNI.handleErrors(slhdsaServiceNI.decode_privateKey(keyRef, OSSLKeyType.SLH_DSA_SHA2_128s.getKsType(), null, 0, 0));
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
    public void SLHDSAServiceJNI_decode_1privateKey_inputOffsetNegative() throws Exception
    {

        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);

            slhdsaServiceNI.handleErrors(slhdsaServiceNI.decode_privateKey(keyRef, OSSLKeyType.SLH_DSA_SHA2_128s.getKsType(), new byte[0], -1, 0));
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
    public void SLHDSAServiceJNI_decode_1privateKey_inputLenNegative() throws Exception
    {

        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);

            slhdsaServiceNI.handleErrors(slhdsaServiceNI.decode_privateKey(keyRef, OSSLKeyType.SLH_DSA_SHA2_128s.getKsType(), new byte[0], 0, -1));
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
    public void SLHDSAServiceJNI_decode_1privateKey_inputOutOfRange_1() throws Exception
    {

        // offset + len > size
        // 1 + 10 > 10
        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);
            slhdsaServiceNI.handleErrors(slhdsaServiceNI.decode_privateKey(keyRef, OSSLKeyType.SLH_DSA_SHA2_128s.getKsType(), new byte[10], 1, 10));
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
    public void SLHDSAServiceJNI_decode_1privateKey_inputOutOfRange_2() throws Exception
    {

        // offset + len > size
        // 0 + 11 > 10

        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);
            slhdsaServiceNI.handleErrors(slhdsaServiceNI.decode_privateKey(keyRef, OSSLKeyType.SLH_DSA_SHA2_128s.getKsType(), new byte[10], 0, 11));
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
    public void SLHDSAServiceJNI_decode_1privateKey_keyLength() throws Exception
    {
        long keyRef = 0;


        for (OSSLKeyType keyType : new OSSLKeyType[]{
                OSSLKeyType.SLH_DSA_SHA2_128f,
                OSSLKeyType.SLH_DSA_SHA2_128s,
                OSSLKeyType.SLH_DSA_SHA2_192f,
                OSSLKeyType.SLH_DSA_SHA2_192s,
                OSSLKeyType.SLH_DSA_SHA2_256f,
                OSSLKeyType.SLH_DSA_SHA2_256s,
                OSSLKeyType.SLH_DSA_SHAKE_128f,
                OSSLKeyType.SLH_DSA_SHAKE_128s,
                OSSLKeyType.SLH_DSA_SHAKE_192f,
                OSSLKeyType.SLH_DSA_SHAKE_192s,
                OSSLKeyType.SLH_DSA_SHAKE_256f,
                OSSLKeyType.SLH_DSA_SHAKE_256s
        })
        {
            int base = 0;
            if (keyType.name().contains("128"))
            {
                base = 16;
            } else if (keyType.name().contains("192"))
            {
                base = 24;
            } else if (keyType.name().contains("256"))
            {
                base = 32;
            } else
            {
                Assertions.fail();
            }


            { // too short
                byte[] key = (byte[]) new byte[(base * 4) - 1];

                try
                {
                    keyRef = TestNISelector.getSpecNI().allocate();
                    Assertions.assertTrue(keyRef > 0);
                    slhdsaServiceNI.handleErrors(slhdsaServiceNI.decode_privateKey(keyRef, keyType.ordinal(), key, 0, key.length));
                    Assertions.fail();
                } catch (IllegalArgumentException e)
                {
                    Assertions.assertEquals("incorrect private key length", e.getMessage());
                } finally
                {
                    specNI.dispose(keyRef);
                }
            }


            { // ok
                byte[] key = (byte[]) new byte[(base * 4)];

                try
                {
                    keyRef = TestNISelector.getSpecNI().allocate();
                    Assertions.assertTrue(keyRef > 0);
                    slhdsaServiceNI.handleErrors(slhdsaServiceNI.decode_privateKey(keyRef, keyType.ordinal(), key, 0, key.length));
                } finally
                {
                    specNI.dispose(keyRef);
                }
            }


            { // too long
                byte[] key = (byte[]) new byte[(base * 4) + 1];

                try
                {
                    keyRef = TestNISelector.getSpecNI().allocate();
                    Assertions.assertTrue(keyRef > 0);
                    slhdsaServiceNI.handleErrors(slhdsaServiceNI.decode_privateKey(keyRef, keyType.ordinal(), key, 0, key.length));
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
    }

    @Test()
    public void SLHDSAServiceJNI_decode_1privateKey_keyType() throws Exception
    {
        long keyRef = 0;
        try
        {
            keyRef = TestNISelector.getSpecNI().allocate();
            Assertions.assertTrue(keyRef > 0);
            slhdsaServiceNI.handleErrors(slhdsaServiceNI.decode_privateKey(keyRef, 99, new byte[10], 0, 10));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("invalid key type for SLH-DSA", e.getMessage());
        } finally
        {
            specNI.dispose(keyRef);
        }
    }


    // init Verifier

    @Test()
    public void SLHDSAServiceJNI_initVerify_nullContextArray() throws Exception
    {
        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = TestNISelector.getSLHDSANI().generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType());

            Assertions.assertTrue(keyRef > 0);
            slhdsaServiceNI.handleErrors(slhdsaServiceNI.initVerify(slhdsaRef, keyRef, null, 0, 0, 0));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("context array is null but length >=0", e.getMessage());
        } finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }

    // negative context len is a valid input so no limit test on negative len


    @Test()
    public void SLHDSAServiceJNI_initVerify_ctxLenPastEndOfContext_1() throws Exception
    {


        // Zero length array but declared len of 1

        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = TestNISelector.getSLHDSANI().generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType());

            Assertions.assertTrue(keyRef > 0);
            slhdsaServiceNI.handleErrors(slhdsaServiceNI.initVerify(slhdsaRef, keyRef, new byte[0], 1, 0, 0));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("context length is past end of context", e.getMessage());
        } finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void SLHDSAServiceJNI_initVerify_ctxLenPastEndOfContext_2() throws Exception
    {

        // array length of 1  but declared len of 2

        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = TestNISelector.getSLHDSANI().generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType());

            Assertions.assertTrue(keyRef > 0);
            slhdsaServiceNI.handleErrors(slhdsaServiceNI.initVerify(slhdsaRef, keyRef, new byte[1], 2, 0, 0));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("context length is past end of context", e.getMessage());
        } finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void SLHDSAServiceJNI_initVerify_ctxTooLong() throws Exception
    {

        // array length of 1  but declared len of 2

        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = TestNISelector.getSLHDSANI().generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType());

            Assertions.assertTrue(keyRef > 0);
            slhdsaServiceNI.handleErrors(slhdsaServiceNI.initVerify(slhdsaRef, keyRef, new byte[256], 256, 0, 0));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("context length is too long", e.getMessage());
        } finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void SLHDSAServiceJNI_initVerify_nullKey() throws Exception
    {

        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            slhdsaServiceNI.handleErrors(slhdsaServiceNI.initVerify(slhdsaRef, keyRef, new byte[1], 1, 0, 0));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("key spec is null", e.getMessage());
        } finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void SLHDSAServiceJNI_initVerify_keySpecNullKey() throws Exception
    {

        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = specNI.allocate();

            Assertions.assertTrue(keyRef > 0);
            slhdsaServiceNI.handleErrors(slhdsaServiceNI.initVerify(slhdsaRef, keyRef, new byte[1], 1, 0, 0));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("key spec has null key", e.getMessage());
        } finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void SLHDSAServiceJNI_initVerify_unknownMessageEncodingParam() throws Exception
    {
        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType());

            Assertions.assertTrue(keyRef > 0);
            slhdsaServiceNI.handleErrors(slhdsaServiceNI.initVerify(slhdsaRef, keyRef, new byte[1], 1, 3, 0));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("invalid message encoding param", e.getMessage());
        } finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void SLHDSAServiceJNI_initVerify_unknownDetParam() throws Exception
    {
        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType());

            Assertions.assertTrue(keyRef > 0);
            slhdsaServiceNI.handleErrors(slhdsaServiceNI.initVerify(slhdsaRef, keyRef, new byte[1], 1, 0, 3));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("invalid deterministic param", e.getMessage());
        } finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }



    // init Signer

    @Test()
    public void SLHDSAServiceJNI_initSign_nullContextArray() throws Exception
    {

        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = TestNISelector.getSLHDSANI().generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType());

            Assertions.assertTrue(keyRef > 0);
            slhdsaServiceNI.handleErrors(slhdsaServiceNI.initVerify(slhdsaRef, keyRef, null, 0, 0, 0));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("context array is null but length >=0", e.getMessage());
        } finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }

    // negative context len is a valid input so no limit test on negative len


    @Test()
    public void SLHDSAServiceJNI_initSign_ctxLenPastEndOfContext_1() throws Exception
    {

        // Zero length array but declared len of 1

        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = TestNISelector.getSLHDSANI().generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType());

            Assertions.assertTrue(keyRef > 0);
            slhdsaServiceNI.handleErrors(slhdsaServiceNI.initSign(slhdsaRef, keyRef, new byte[0], 1, 0, 0));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("context length is past end of context", e.getMessage());
        } finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void SLHDSAServiceJNI_initSign_ctxLenPastEndOfContext_2() throws Exception
    {

        // array length of 1  but declared len of 2

        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = TestNISelector.getSLHDSANI().generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType());

            Assertions.assertTrue(keyRef > 0);
            slhdsaServiceNI.handleErrors(slhdsaServiceNI.initSign(slhdsaRef, keyRef, new byte[1], 2, 0, 0));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("context length is past end of context", e.getMessage());
        } finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void SLHDSAServiceJNI_initSign_ctxTooLong() throws Exception
    {

        // array length of 1  but declared len of 2

        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = TestNISelector.getSLHDSANI().generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType());

            Assertions.assertTrue(keyRef > 0);
            slhdsaServiceNI.handleErrors(slhdsaServiceNI.initSign(slhdsaRef, keyRef, new byte[256], 256, 0, 0));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("context length is too long", e.getMessage());
        } finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }


    @Test()
    public void SLHDSAServiceJNI_initSign_nullKey() throws Exception
    {

        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            slhdsaServiceNI.handleErrors(slhdsaServiceNI.initSign(slhdsaRef, keyRef, new byte[1], 1, 0, 0));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("key spec is null", e.getMessage());
        } finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void SLHDSAServiceJNI_initSign_keySpecNullKey() throws Exception
    {

        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = specNI.allocate();

            Assertions.assertTrue(keyRef > 0);
            slhdsaServiceNI.handleErrors(slhdsaServiceNI.initSign(slhdsaRef, keyRef, new byte[1], 1, 0, 0));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("key spec has null key", e.getMessage());
        } finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void SLHDSAServiceJNI_initSign_unknownMessageEncoding() throws Exception
    {

        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType());

            Assertions.assertTrue(keyRef > 0);
            slhdsaServiceNI.handleErrors(slhdsaServiceNI.initSign(slhdsaRef, keyRef, new byte[1], 1, 3, 0));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("invalid message encoding param", e.getMessage());
        } finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }


    @Test()
    public void SLHDSAServiceJNI_initSign_unknownDeterminisiticParam() throws Exception
    {
        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType());

            Assertions.assertTrue(keyRef > 0);
            slhdsaServiceNI.handleErrors(slhdsaServiceNI.initSign(slhdsaRef, keyRef, new byte[1], 1, 0, 3));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("invalid deterministic param", e.getMessage());
        } finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }


    @Test()
    public void SLHDSAServiceJNI_slhdsa_update_notInitialised() throws Exception
    {
        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType());

            Assertions.assertTrue(keyRef > 0);
            //  slhdsaServiceNI.handleErrors(slhdsaServiceNI.initSign(slhdsaRef, keyRef, new byte[1], 1, 3));

            slhdsaServiceNI.handleErrors(slhdsaServiceNI.update(slhdsaRef, new byte[0], 0, 0));

            Assertions.fail();
        } catch (IllegalStateException e)
        {
            Assertions.assertEquals("not initialized", e.getMessage());
        } finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }


    @Test()
    public void SLHDSAServiceJNI_slhdsa_update_nullInput() throws Exception
    {
        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType());

            Assertions.assertTrue(keyRef > 0);
            slhdsaServiceNI.handleErrors(slhdsaServiceNI.initSign(slhdsaRef, keyRef, new byte[0], 0, 0, 0));

            slhdsaServiceNI.handleErrors(slhdsaServiceNI.update(slhdsaRef, null, 0, 0));

            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input is null", e.getMessage());
        } finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }


    @Test()
    public void SLHDSAServiceJNI_slhdsa_update_inputOffsetNegative() throws Exception
    {
        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType());

            Assertions.assertTrue(keyRef > 0);
            slhdsaServiceNI.handleErrors(slhdsaServiceNI.initSign(slhdsaRef, keyRef, new byte[0], 0, 0, 0));

            slhdsaServiceNI.handleErrors(slhdsaServiceNI.update(slhdsaRef, new byte[0], -1, 0));

            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input offset is negative", e.getMessage());
        } finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void SLHDSAServiceJNI_slhdsa_update_inputLenNegative() throws Exception
    {
        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType());

            Assertions.assertTrue(keyRef > 0);
            slhdsaServiceNI.handleErrors(slhdsaServiceNI.initSign(slhdsaRef, keyRef, new byte[0], 0, 0, 0));

            slhdsaServiceNI.handleErrors(slhdsaServiceNI.update(slhdsaRef, new byte[0], 0, -1));

            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input len is negative", e.getMessage());
        } finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }


    @Test()
    public void SLHDSAServiceJNI_slhdsa_update_inputOutOfRange_1() throws Exception
    {

        // 10 byte input
        // 0 offset
        // 11 byte len

        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType());

            Assertions.assertTrue(keyRef > 0);
            slhdsaServiceNI.handleErrors(slhdsaServiceNI.initSign(slhdsaRef, keyRef, new byte[0], 0, 0, 0));

            slhdsaServiceNI.handleErrors(slhdsaServiceNI.update(slhdsaRef, new byte[10], 0, 11));

            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input offset + length are out of range", e.getMessage());
        } finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }


    @Test()
    public void SLHDSAServiceJNI_slhdsa_update_inputOutOfRange_2() throws Exception
    {

        // 10 byte input
        // 1 offset
        // 10 byte len

        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType());

            Assertions.assertTrue(keyRef > 0);
            slhdsaServiceNI.handleErrors(slhdsaServiceNI.initSign(slhdsaRef, keyRef, new byte[0], 0, 0, 0));

            slhdsaServiceNI.handleErrors(slhdsaServiceNI.update(slhdsaRef, new byte[10], 1, 10));

            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input offset + length are out of range", e.getMessage());
        } finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }


    // NB Sign accepts null input, returns length of signature so null input is valid

    @Test()
    public void SLHDSAServiceJNI_slhdsa_sign_outOffsetNegative() throws Exception
    {

        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType());

            Assertions.assertTrue(keyRef > 0);
            slhdsaServiceNI.handleErrors(slhdsaServiceNI.initSign(slhdsaRef, keyRef, new byte[0], 0, 0, 0));

            slhdsaServiceNI.handleErrors(slhdsaServiceNI.sign(slhdsaRef, new byte[0], -1));

            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("output offset is negative", e.getMessage());
        } finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void SLHDSAServiceJNI_slhdsa_sign_outputRange() throws Exception
    {

        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType());

            Assertions.assertTrue(keyRef > 0);
            slhdsaServiceNI.handleErrors(slhdsaServiceNI.initSign(slhdsaRef, keyRef, new byte[0], 0, 0, 0));

            slhdsaServiceNI.handleErrors(slhdsaServiceNI.sign(slhdsaRef, new byte[0], 1));

            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("output offset is out of range", e.getMessage());
        } finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void SLHDSAServiceJNI_slhdsa_sign_notInitialized() throws Exception
    {

        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType());

            Assertions.assertTrue(keyRef > 0);
            // slhdsaServiceNI.handleErrors(slhdsaServiceNI.initSign(slhdsaRef, keyRef, new byte[0], 0, 0));

            slhdsaServiceNI.handleErrors(slhdsaServiceNI.sign(slhdsaRef, new byte[0], 0));

            Assertions.fail();
        } catch (IllegalStateException e)
        {
            Assertions.assertEquals("not initialized", e.getMessage());
        } finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }


    @Test()
    public void SLHDSAServiceJNI_slhdsa_sign_initVerify() throws Exception
    {

        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType());

            Assertions.assertTrue(keyRef > 0);
            slhdsaServiceNI.handleErrors(slhdsaServiceNI.initVerify(slhdsaRef, keyRef, new byte[0], 0, 0, 0));

            slhdsaServiceNI.handleErrors(slhdsaServiceNI.sign(slhdsaRef, new byte[0], 0));

            Assertions.fail();
        } catch (IllegalStateException e)
        {
            Assertions.assertEquals("unexpected state", e.getMessage());
        } finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }


    @Test()
    public void SLHDSAServiceJNI_slhdsa_sign_outputTooSmall_1() throws Exception
    {

        //
        // offset is zero
        //

        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType());

            Assertions.assertTrue(keyRef > 0);
            slhdsaServiceNI.handleErrors(slhdsaServiceNI.initSign(slhdsaRef, keyRef, new byte[0], 0, 0, 0));

            long len = slhdsaServiceNI.handleErrors(slhdsaServiceNI.sign(slhdsaRef, null, 0));

            byte[] sig = new byte[(int) len - 1];

            slhdsaServiceNI.handleErrors(slhdsaServiceNI.sign(slhdsaRef, sig, 0));

            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("output too small", e.getMessage());
        } finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }


    @Test()
    public void SLHDSAServiceJNI_slhdsa_sign_outputTooSmall_2() throws Exception
    {

        //
        // offset is 1
        //

        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType());

            Assertions.assertTrue(keyRef > 0);
            slhdsaServiceNI.handleErrors(slhdsaServiceNI.initSign(slhdsaRef, keyRef, new byte[0], 0, 0, 0));

            long len = slhdsaServiceNI.handleErrors(slhdsaServiceNI.sign(slhdsaRef, null, 0));

            byte[] sig = new byte[(int) len];

            slhdsaServiceNI.handleErrors(slhdsaServiceNI.sign(slhdsaRef, sig, 1));

            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("output too small", e.getMessage());
        } finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }


    @Test()
    public void SLHDSAServiceJNI_slhdsa_verify_nullSig() throws Exception
    {


        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType());

            Assertions.assertTrue(keyRef > 0);
            slhdsaServiceNI.handleErrors(slhdsaServiceNI.initVerify(slhdsaRef, keyRef, new byte[0], 0, SLHDSASignatureSpi.MessageEncoding.PURE.ordinal(), SLHDSASignatureSpi.Deterministic.DETERMINISTIC.ordinal()));

            slhdsaServiceNI.handleErrors(slhdsaServiceNI.verify(slhdsaRef, null, 0));

            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("sig is null", e.getMessage());
        } finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }


    @Test()
    public void SLHDSAServiceJNI_slhdsa_verify_sigLenZero() throws Exception
    {
        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType());

            Assertions.assertTrue(keyRef > 0);
            slhdsaServiceNI.handleErrors(slhdsaServiceNI.initVerify(slhdsaRef, keyRef, new byte[0], 0, SLHDSASignatureSpi.MessageEncoding.PURE.ordinal(), SLHDSASignatureSpi.Deterministic.DETERMINISTIC.ordinal()));

            long code = slhdsaServiceNI.handleErrors(slhdsaServiceNI.verify(slhdsaRef, new byte[1], 0));
            Assertions.assertEquals(ErrorCode.JO_FAIL.getCode(), code);

        } finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void SLHDSAServiceJNI_slhdsa_verify_sigLenNegative() throws Exception
    {
        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType());

            Assertions.assertTrue(keyRef > 0);
            slhdsaServiceNI.handleErrors(slhdsaServiceNI.initVerify(slhdsaRef, keyRef, new byte[0], 0, SLHDSASignatureSpi.MessageEncoding.PURE.ordinal(), SLHDSASignatureSpi.Deterministic.DETERMINISTIC.ordinal()));

            slhdsaServiceNI.handleErrors(slhdsaServiceNI.verify(slhdsaRef, new byte[1], -1));

            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("sig length is negative", e.getMessage());
        } finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }


    @Test()
    public void SLHDSAServiceJNI_slhdsa_verify_sigLenOutOfRange_1() throws Exception
    {
        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType());

            Assertions.assertTrue(keyRef > 0);
            slhdsaServiceNI.handleErrors(slhdsaServiceNI.initVerify(slhdsaRef, keyRef, new byte[0], 0, SLHDSASignatureSpi.MessageEncoding.PURE.ordinal(), SLHDSASignatureSpi.Deterministic.DETERMINISTIC.ordinal()));

            slhdsaServiceNI.handleErrors(slhdsaServiceNI.verify(slhdsaRef, new byte[10], 11));

            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("sig out of range", e.getMessage());
        } finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void SLHDSAServiceJNI_slhdsa_verify_sigLenOutOfRange_2() throws Exception
    {
        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType());

            Assertions.assertTrue(keyRef > 0);
            slhdsaServiceNI.handleErrors(slhdsaServiceNI.initVerify(slhdsaRef, keyRef, new byte[0], 0, SLHDSASignatureSpi.MessageEncoding.PURE.ordinal(), SLHDSASignatureSpi.Deterministic.DETERMINISTIC.ordinal()));

            slhdsaServiceNI.handleErrors(slhdsaServiceNI.verify(slhdsaRef, new byte[0], 1));

            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("sig out of range", e.getMessage());
        } finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }

    @Test()
    public void SLHDSAServiceJNI_slhdsa_verify_initForSigning() throws Exception
    {
        long slhdsaRef = 0;
        long keyRef = 0;
        try
        {
            slhdsaRef = TestNISelector.getSLHDSANI().allocateSigner();
            Assertions.assertTrue(slhdsaRef > 0);
            keyRef = slhdsaServiceNI.generateKeyPair(OSSLKeyType.SLH_DSA_SHA2_128s.getKsType());

            Assertions.assertTrue(keyRef > 0);
            slhdsaServiceNI.handleErrors(slhdsaServiceNI.initSign(slhdsaRef, keyRef, new byte[0], 0, SLHDSASignatureSpi.MessageEncoding.PURE.ordinal(), SLHDSASignatureSpi.Deterministic.DETERMINISTIC.ordinal()));

            slhdsaServiceNI.handleErrors(slhdsaServiceNI.verify(slhdsaRef, new byte[1], 1));

            Assertions.fail();
        } catch (IllegalStateException e)
        {
            Assertions.assertEquals("unexpected state", e.getMessage());
        } finally
        {
            slhdsaServiceNI.disposeSigner(slhdsaRef);
            specNI.dispose(keyRef);
        }
    }

}
