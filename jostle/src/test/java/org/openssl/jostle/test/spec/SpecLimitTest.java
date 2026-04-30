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

package org.openssl.jostle.test.spec;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.mlkem.MLKEMServiceNI;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.test.crypto.TestNISelector;

import java.security.Security;

public class SpecLimitTest
{


    SpecNI specNI = TestNISelector.getSpecNI();
    MLKEMServiceNI mlkemServiceNI = TestNISelector.getMLKEMNI();

    @BeforeAll
    public static void beforeAll()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    @Test
    public void encap_nullKeySpec() throws Exception
    {
        try
        {

            specNI.encap(0, null, new byte[0], 0, 0, new byte[0], 0, 0, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
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


            specNI.encap(req, null, new byte[0], 0, 0, new byte[0], 0, 0, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("key spec has null key", e.getMessage());
        }
        finally
        {
            specNI.dispose(req);
        }
    }

    @Test
    public void encap_inOffsetNegative() throws Exception
    {
        long spec = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), TestUtil.RNDSrc);
        try
        {

            specNI.encap(spec, null, new byte[0], -1, 0, new byte[0], 0, 0, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input offset is negative", e.getMessage());
        }
        finally
        {
            specNI.dispose(spec);
        }
    }

    @Test
    public void encap_inLenNegative() throws Exception
    {
        long spec = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), TestUtil.RNDSrc);
        try
        {

            specNI.encap(spec, null, new byte[0], 0, -1, new byte[0], 0, 0, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input len is negative", e.getMessage());
        }
        finally
        {
            specNI.dispose(spec);
        }
    }

    @Test
    public void encap_inputRangeCheck_1() throws Exception
    {
        long spec = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), TestUtil.RNDSrc);
        try
        {

            specNI.encap(spec, null, new byte[10], 1, 10, new byte[0], 0, 0, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input offset + length is out of range", e.getMessage());
        }
        finally
        {
            specNI.dispose(spec);
        }
    }


    @Test
    public void encap_inputRangeCheck_2() throws Exception
    {
        long spec = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), TestUtil.RNDSrc);
        try
        {

            specNI.encap(spec, null, new byte[10], 0, 11, new byte[0], 0, 0, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input offset + length is out of range", e.getMessage());
        }
        finally
        {
            specNI.dispose(spec);
        }
    }

    @Test
    public void encap_inputRangeCheck_3() throws Exception
    {
        long spec = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), TestUtil.RNDSrc);
        try
        {

            specNI.encap(spec, null, new byte[10], 10, 1, new byte[0], 0, 0, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input offset + length is out of range", e.getMessage());
        }
        finally
        {
            specNI.dispose(spec);
        }
    }

    //
    //

    @Test
    public void encap_outputOffsetNegative() throws Exception
    {
        long spec = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), TestUtil.RNDSrc);
        try
        {

            specNI.encap(spec, null, new byte[0], 0, 0, new byte[0], -1, 0, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("output offset is negative", e.getMessage());
        }
        finally
        {
            specNI.dispose(spec);
        }
    }


    @Test
    public void encap_outputLenNegative() throws Exception
    {
        long spec = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), TestUtil.RNDSrc);
        try
        {

            specNI.encap(spec, null, new byte[0], 0, 0, new byte[0], 0, -1, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("output len negative", e.getMessage());
        }
        finally
        {
            specNI.dispose(spec);
        }
    }


    @Test
    public void encap_outputRangeCheck_1() throws Exception
    {
        long spec = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), TestUtil.RNDSrc);
        try
        {

            specNI.encap(spec, null, new byte[10], 0, 10, new byte[10], 1, 10, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("output offset + length is out of range", e.getMessage());
        }
        finally
        {
            specNI.dispose(spec);
        }
    }


    @Test
    public void encap_outputRangeCheck_2() throws Exception
    {
        long spec = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), TestUtil.RNDSrc);
        try
        {

            specNI.encap(spec, null, new byte[10], 0, 10, new byte[10], 0, 11, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("output offset + length is out of range", e.getMessage());
        }
        finally
        {
            specNI.dispose(spec);
        }
    }

    @Test
    public void encap_outputRangeCheck_3() throws Exception
    {
        long spec = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), TestUtil.RNDSrc);
        try
        {

            specNI.encap(spec, null, new byte[10], 0, 10, new byte[10], 10, 1, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("output offset + length is out of range", e.getMessage());
        }
        finally
        {
            specNI.dispose(spec);
        }
    }


    @Test
    public void encap_outputTooSmall_3() throws Exception
    {
        long spec = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), TestUtil.RNDSrc);
        try
        {

            specNI.encap(spec, null, new byte[32], 0, 10, new byte[700], 0, 700, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("output too small", e.getMessage());
        }
        finally
        {
            specNI.dispose(spec);
        }
    }


    @Test
    public void encap_secretBufferTooSmall() throws Exception
    {
        // ML-KEM-512 produces a 768-byte ciphertext and a 32-byte shared
        // secret. A 768-byte ciphertext buffer passes the existing
        // out_len < min_len check; a 16-byte secret buffer then trips the
        // post-size-query secret-size validation in encap().
        long spec = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), TestUtil.RNDSrc);
        try
        {
            specNI.encap(spec, null, new byte[16], 0, 16, new byte[768], 0, 768, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("output too small", e.getMessage());
        }
        finally
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

            specNI.decap(0, null, new byte[0], 0, 0, new byte[0], 0, 0);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
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


            specNI.decap(req, null, new byte[0], 0, 0, new byte[0], 0, 0);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("key spec has null key", e.getMessage());
        }
        finally
        {
            specNI.dispose(req);
        }
    }

    @Test
    public void decap_inOffsetNegative() throws Exception
    {
        long spec = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), TestUtil.RNDSrc);
        try
        {

            specNI.decap(spec, null, new byte[0], -1, 0, new byte[0], 0, 0);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input offset is negative", e.getMessage());
        }
        finally
        {
            specNI.dispose(spec);
        }
    }

    @Test
    public void decap_inLenNegative() throws Exception
    {
        long spec = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), TestUtil.RNDSrc);
        try
        {

            specNI.decap(spec, null, new byte[0], 0, -1, new byte[0], 0, 0);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input len is negative", e.getMessage());
        }
        finally
        {
            specNI.dispose(spec);
        }
    }

    @Test
    public void decap_inputRangeCheck_1() throws Exception
    {
        long spec = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), TestUtil.RNDSrc);
        try
        {

            specNI.decap(spec, null, new byte[10], 1, 10, new byte[0], 0, 0);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input offset + length is out of range", e.getMessage());
        }
        finally
        {
            specNI.dispose(spec);
        }
    }


    @Test
    public void decap_inputRangeCheck_2() throws Exception
    {
        long spec = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), TestUtil.RNDSrc);
        try
        {

            specNI.decap(spec, null, new byte[10], 0, 11, new byte[0], 0, 0);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input offset + length is out of range", e.getMessage());
        }
        finally
        {
            specNI.dispose(spec);
        }
    }

    @Test
    public void decap_inputRangeCheck_3() throws Exception
    {
        long spec = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), TestUtil.RNDSrc);
        try
        {

            specNI.decap(spec, null, new byte[10], 10, 1, new byte[0], 0, 0);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input offset + length is out of range", e.getMessage());
        }
        finally
        {
            specNI.dispose(spec);
        }
    }

    //
    //

    @Test
    public void decap_outputOffsetNegative() throws Exception
    {
        long spec = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), TestUtil.RNDSrc);
        try
        {

            specNI.decap(spec, null, new byte[0], 0, 0, new byte[0], -1, 0);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("output offset is negative", e.getMessage());
        }
        finally
        {
            specNI.dispose(spec);
        }
    }


    @Test
    public void decap_outputLenNegative() throws Exception
    {
        long spec = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), TestUtil.RNDSrc);
        try
        {

            specNI.decap(spec, null, new byte[0], 0, 0, new byte[0], 0, -1);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("output len negative", e.getMessage());
        }
        finally
        {
            specNI.dispose(spec);
        }
    }


    @Test
    public void decap_outputRangeCheck_1() throws Exception
    {
        long spec = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), TestUtil.RNDSrc);
        try
        {

            specNI.decap(spec, null, new byte[10], 0, 10, new byte[10], 1, 10);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("output offset + length is out of range", e.getMessage());
        }
        finally
        {
            specNI.dispose(spec);
        }
    }


    @Test
    public void decap_outputRangeCheck_2() throws Exception
    {
        long spec = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), TestUtil.RNDSrc);
        try
        {

            specNI.decap(spec, null, new byte[10], 0, 10, new byte[10], 0, 11);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("output offset + length is out of range", e.getMessage());
        }
        finally
        {
            specNI.dispose(spec);
        }
    }

    @Test
    public void decap_outputRangeCheck_3() throws Exception
    {
        long spec = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), TestUtil.RNDSrc);
        try
        {

            specNI.decap(spec, null, new byte[10], 0, 10, new byte[10], 10, 1);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("output offset + length is out of range", e.getMessage());
        }
        finally
        {
            specNI.dispose(spec);
        }
    }


    @Test
    public void decap_outputTooSmall_3() throws Exception
    {
        long spec = mlkemServiceNI.generateKeyPair(OSSLKeyType.ML_KEM_512.getKsType(), TestUtil.RNDSrc);

        //
        // Create a valid encapsulation
        //

        byte[] validEncap = null;
        long len = specNI.encap(spec, null, new byte[32], 0, 32, validEncap, 0, 0, TestUtil.RNDSrc);
        validEncap = new byte[(int) len];
        len = specNI.encap(spec, null, new byte[32], 0, 32, validEncap, 0, validEncap.length, TestUtil.RNDSrc);

        Assertions.assertEquals(validEncap.length, (int) len);

        try
        {

            specNI.decap(spec, null, validEncap, 0, validEncap.length, new byte[32], 0, 31);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("output too small", e.getMessage());
        }

        try
        {

            specNI.decap(spec, null, validEncap, 0, validEncap.length, new byte[33], 1, 3);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("output too small", e.getMessage());
        }
        finally
        {
            specNI.dispose(spec);
        }
    }


}
