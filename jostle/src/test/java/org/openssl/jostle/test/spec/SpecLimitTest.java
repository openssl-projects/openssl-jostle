package org.openssl.jostle.test.spec;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.jcajce.provider.mlkem.MLKEMServiceNI;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.test.crypto.TestNISelector;

public class SpecLimitTest
{
    static
    {
        CryptoServicesRegistrar.isNativeAvailable(); // Trigger Loading
    }


    SpecNI specNI = TestNISelector.getSpecNI();
    MLKEMServiceNI mlkemServiceNI = TestNISelector.getMLKEMNI();

    @Test
    public void encap_nullKeySpec() throws Exception
    {
        try
        {
            specNI.handleErrors(
                    specNI.encap(0, null, new byte[0], 0, 0, new byte[0], 0, 0));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("key spec is null", e.getMessage());
        }
    }

    @Test
    public void encap_keySpecWithNullKey() throws Exception
    {
        long req = specNI.allocate();
        try
        {

            specNI.handleErrors(
                    specNI.encap(req, null, new byte[0], 0, 0, new byte[0], 0, 0));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("key spec has null key", e.getMessage());
        } finally
        {
            specNI.dispose(req);
        }
    }

    @Test
    public void encap_inOffsetNegative() throws Exception
    {
        long spec = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType());
        try
        {
            specNI.handleErrors(
                    specNI.encap(spec, null, new byte[0], -1, 0, new byte[0], 0, 0));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input offset is negative", e.getMessage());
        } finally
        {
            specNI.dispose(spec);
        }
    }

    @Test
    public void encap_inLenNegative() throws Exception
    {
        long spec = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType());
        try
        {
            specNI.handleErrors(
                    specNI.encap(spec, null, new byte[0], 0, -1, new byte[0], 0, 0));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input len is negative", e.getMessage());
        } finally
        {
            specNI.dispose(spec);
        }
    }

    @Test
    public void encap_inputRangeCheck_1() throws Exception
    {
        long spec = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType());
        try
        {
            specNI.handleErrors(
                    specNI.encap(spec, null, new byte[10], 1, 10, new byte[0], 0, 0));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input offset + length are out of range", e.getMessage());
        } finally
        {
            specNI.dispose(spec);
        }
    }


    @Test
    public void encap_inputRangeCheck_2() throws Exception
    {
        long spec = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType());
        try
        {
            specNI.handleErrors(
                    specNI.encap(spec, null, new byte[10], 0, 11, new byte[0], 0, 0));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input offset + length are out of range", e.getMessage());
        } finally
        {
            specNI.dispose(spec);
        }
    }

    @Test
    public void encap_inputRangeCheck_3() throws Exception
    {
        long spec = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType());
        try
        {
            specNI.handleErrors(
                    specNI.encap(spec, null, new byte[10], 10, 1, new byte[0], 0, 0));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input offset + length are out of range", e.getMessage());
        } finally
        {
            specNI.dispose(spec);
        }
    }

    //
    //

    @Test
    public void encap_outputOffsetNegative() throws Exception
    {
        long spec = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType());
        try
        {
            specNI.handleErrors(
                    specNI.encap(spec, null, new byte[0], 0, 0, new byte[0], -1, 0));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("output offset is negative", e.getMessage());
        } finally
        {
            specNI.dispose(spec);
        }
    }


    @Test
    public void encap_outputLenNegative() throws Exception
    {
        long spec = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType());
        try
        {
            specNI.handleErrors(
                    specNI.encap(spec, null, new byte[0], 0, 0, new byte[0], 0, -1));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("output len is negative", e.getMessage());
        } finally
        {
            specNI.dispose(spec);
        }
    }


    @Test
    public void encap_outputRangeCheck_1() throws Exception
    {
        long spec = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType());
        try
        {
            specNI.handleErrors(
                    specNI.encap(spec, null, new byte[10], 0, 10, new byte[10], 1, 10));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("output offset + length are out of range", e.getMessage());
        } finally
        {
            specNI.dispose(spec);
        }
    }


    @Test
    public void encap_outputRangeCheck_2() throws Exception
    {
        long spec = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType());
        try
        {
            specNI.handleErrors(
                    specNI.encap(spec, null, new byte[10], 0, 10, new byte[10], 0, 11));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("output offset + length are out of range", e.getMessage());
        } finally
        {
            specNI.dispose(spec);
        }
    }

    @Test
    public void encap_outputRangeCheck_3() throws Exception
    {
        long spec = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType());
        try
        {
            specNI.handleErrors(
                    specNI.encap(spec, null, new byte[10], 0, 10, new byte[10], 10, 1));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("output offset + length are out of range", e.getMessage());
        } finally
        {
            specNI.dispose(spec);
        }
    }


    @Test
    public void encap_outputTooSmall_3() throws Exception
    {
        long spec = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType());
        try
        {
            specNI.handleErrors(
                    specNI.encap(spec, null, new byte[32], 0, 10, new byte[700], 0, 700));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("output too small", e.getMessage());
        } finally
        {
            specNI.dispose(spec);
        }
    }


    //
    // OpenSSL doesn't fail when presented with an invalid option on EVP_PKEY_CTX_set_kem_op for,
    // I assume PKEYs that don't actually have options
    //
    // There is an OPS test to check that if it were to fail it would be reported, see
    // encap_EVP_PKEY_CTX_set_kem_op() and
    // decap_EVP_PKEY_CTX_set_kem_op() in SpecOpsTest
    //


    @Test
    public void decap_nullKeySpec() throws Exception
    {
        try
        {
            specNI.handleErrors(
                    specNI.decap(0, null, new byte[0], 0, 0, new byte[0], 0, 0));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("key spec is null", e.getMessage());
        }
    }

    @Test
    public void decap_keySpecWithNullKey() throws Exception
    {
        long req = specNI.allocate();
        try
        {

            specNI.handleErrors(
                    specNI.decap(req, null, new byte[0], 0, 0, new byte[0], 0, 0));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("key spec has null key", e.getMessage());
        } finally
        {
            specNI.dispose(req);
        }
    }

    @Test
    public void decap_inOffsetNegative() throws Exception
    {
        long spec = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType());
        try
        {
            specNI.handleErrors(
                    specNI.decap(spec, null, new byte[0], -1, 0, new byte[0], 0, 0));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input offset is negative", e.getMessage());
        } finally
        {
            specNI.dispose(spec);
        }
    }

    @Test
    public void decap_inLenNegative() throws Exception
    {
        long spec = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType());
        try
        {
            specNI.handleErrors(
                    specNI.decap(spec, null, new byte[0], 0, -1, new byte[0], 0, 0));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input len is negative", e.getMessage());
        } finally
        {
            specNI.dispose(spec);
        }
    }

    @Test
    public void decap_inputRangeCheck_1() throws Exception
    {
        long spec = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType());
        try
        {
            specNI.handleErrors(
                    specNI.decap(spec, null, new byte[10], 1, 10, new byte[0], 0, 0));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input offset + length are out of range", e.getMessage());
        } finally
        {
            specNI.dispose(spec);
        }
    }


    @Test
    public void decap_inputRangeCheck_2() throws Exception
    {
        long spec = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType());
        try
        {
            specNI.handleErrors(
                    specNI.decap(spec, null, new byte[10], 0, 11, new byte[0], 0, 0));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input offset + length are out of range", e.getMessage());
        } finally
        {
            specNI.dispose(spec);
        }
    }

    @Test
    public void decap_inputRangeCheck_3() throws Exception
    {
        long spec = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType());
        try
        {
            specNI.handleErrors(
                    specNI.decap(spec, null, new byte[10], 10, 1, new byte[0], 0, 0));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input offset + length are out of range", e.getMessage());
        } finally
        {
            specNI.dispose(spec);
        }
    }

    //
    //

    @Test
    public void decap_outputOffsetNegative() throws Exception
    {
        long spec = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType());
        try
        {
            specNI.handleErrors(
                    specNI.decap(spec, null, new byte[0], 0, 0, new byte[0], -1, 0));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("output offset is negative", e.getMessage());
        } finally
        {
            specNI.dispose(spec);
        }
    }


    @Test
    public void decap_outputLenNegative() throws Exception
    {
        long spec = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType());
        try
        {
            specNI.handleErrors(
                    specNI.decap(spec, null, new byte[0], 0, 0, new byte[0], 0, -1));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("output len is negative", e.getMessage());
        } finally
        {
            specNI.dispose(spec);
        }
    }


    @Test
    public void decap_outputRangeCheck_1() throws Exception
    {
        long spec = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType());
        try
        {
            specNI.handleErrors(
                    specNI.decap(spec, null, new byte[10], 0, 10, new byte[10], 1, 10));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("output offset + length are out of range", e.getMessage());
        } finally
        {
            specNI.dispose(spec);
        }
    }


    @Test
    public void decap_outputRangeCheck_2() throws Exception
    {
        long spec = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType());
        try
        {
            specNI.handleErrors(
                    specNI.decap(spec, null, new byte[10], 0, 10, new byte[10], 0, 11));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("output offset + length are out of range", e.getMessage());
        } finally
        {
            specNI.dispose(spec);
        }
    }

    @Test
    public void decap_outputRangeCheck_3() throws Exception
    {
        long spec = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType());
        try
        {
            specNI.handleErrors(
                    specNI.decap(spec, null, new byte[10], 0, 10, new byte[10], 10, 1));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("output offset + length are out of range", e.getMessage());
        } finally
        {
            specNI.dispose(spec);
        }
    }


    @Test
    public void decap_outputTooSmall_3() throws Exception
    {
        long spec = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType());

        //
        // Create a valid encapsulation
        //

        byte[] validEncap = null;
        long len = specNI.encap(spec, null, new byte[32], 0, 32, validEncap, 0, 0);
        validEncap = new byte[(int) len];
        len = specNI.encap(spec, null, new byte[32], 0, 32, validEncap, 0, validEncap.length);

        Assertions.assertEquals(validEncap.length, (int) len);

        try
        {
            specNI.handleErrors(
                    specNI.decap(spec, null, validEncap, 0, validEncap.length, new byte[32], 0, 31));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("output too small", e.getMessage());
        }

        try
        {
            specNI.handleErrors(
                    specNI.decap(spec, null, validEncap, 0, validEncap.length, new byte[33], 1, 31));
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("output too small", e.getMessage());
        } finally
        {
            specNI.dispose(spec);
        }
    }


}
