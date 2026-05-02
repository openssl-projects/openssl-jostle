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

package org.openssl.jostle.test.crypto;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.blockcipher.BlockCipherNI;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

/**
 * Tests for triggering error codes mostly
 */
public class BlockCipherLimitTest
{


    BlockCipherNI blockCipherNI = TestNISelector.getBlockCipher();

    @BeforeAll
    public static void beforeAll()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    @Test
    public void BlockCipher_keyIsNull() throws Exception
    {
        long ref = 0;
        try
        {
            ref = blockCipherNI.makeInstance(8, 1, 1); // AES128, CBC, 1
            int code = blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, null, new byte[16], 0);
            Assertions.fail("expected exception");
        }
        catch (Exception e)
        {
            Assertions.assertTrue(e instanceof InvalidKeyException);
            Assertions.assertEquals("key is null", e.getMessage());
        }
        finally
        {
            TestNISelector.getBlockCipher().dispose(ref);
        }
    }

    @Test
    public void BlockCipher_modeDoesNotTakeIV() throws Exception
    {
        long ref = 0;
        try
        {
            ref = blockCipherNI.makeInstance(8, 0, 1); // AES128, ECB, 1
            int code = blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, new byte[16], new byte[16], 0);
            Assertions.fail("expected exception");
        }
        catch (Exception e)
        {
            Assertions.assertTrue(e instanceof InvalidAlgorithmParameterException);
            Assertions.assertEquals("mode takes no iv", e.getMessage());
        }
        finally
        {
            TestNISelector.getBlockCipher().dispose(ref);
        }
    }

    @Test
    public void BlockCipher_ivIsNull_ArrayNull() throws Exception
    {
        long ref = 0;
        try
        {
            ref = blockCipherNI.makeInstance(8, 1, 1); // AES128, CBC, 1
            int code = blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, new byte[16], null, 0);
            Assertions.fail("expected exception");
        }
        catch (Exception e)
        {
            Assertions.assertTrue(e instanceof InvalidAlgorithmParameterException);
            Assertions.assertEquals("iv is null", e.getMessage());
        }
        finally
        {
            TestNISelector.getBlockCipher().dispose(ref);
        }
    }

    @Test
    public void BlockCipher_ivIsNull_ArrayZeroLen() throws Exception
    {
        long ref = 0;
        try
        {
            ref = blockCipherNI.makeInstance(8, 1, 1); // AES128, CBC, 1
            int code = blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, new byte[16], new byte[0], 0);

            Assertions.fail("expected exception");
        }
        catch (Exception e)
        {
            Assertions.assertTrue(e instanceof InvalidAlgorithmParameterException);
            Assertions.assertEquals("iv is null", e.getMessage());
        }
        finally
        {
            TestNISelector.getBlockCipher().dispose(ref);
        }
    }

    @Test
    public void testUnsupportedCipher()
    {
        long ref = 0;
        try
        {
            ref = blockCipherNI.makeInstance(7, 0, 1); // AES128, CBC, 1
            int code = blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, new byte[16], new byte[0], 0);

            Assertions.fail("expected exception");
        }
        catch (Exception e)
        {
            Assertions.assertTrue(e instanceof IllegalStateException);
            Assertions.assertEquals("cipher not supported", e.getMessage());
        }
        finally
        {
            TestNISelector.getBlockCipher().dispose(ref);
        }
    }

    @Test
    public void testAESInitParams() throws Exception
    {
        List<InitParamTestVector> tests = new ArrayList<InitParamTestVector>()
        {
            {
                // AES ECB Key Lengths
                add(new InitParamTestVector("AES128 incorrect key short", 8, 0, 1, new byte[15], null, InvalidKeyException.class, "invalid key length"));
                add(new InitParamTestVector("AES128 correct key", 8, 0, 1, new byte[16], null));
                add(new InitParamTestVector("AES128 incorrect key long", 8, 0, 1, new byte[17], null, InvalidKeyException.class, "invalid key length"));

                add(new InitParamTestVector("AES192 incorrect key short", 9, 0, 1, new byte[23], null, InvalidKeyException.class, "invalid key length"));
                add(new InitParamTestVector("AES192 correct key", 9, 0, 1, new byte[24], null));
                add(new InitParamTestVector("AES192 incorrect key long", 9, 0, 1, new byte[25], null, InvalidKeyException.class, "invalid key length"));

                add(new InitParamTestVector("AES256 incorrect key short", 10, 0, 1, new byte[31], null, InvalidKeyException.class, "invalid key length"));
                add(new InitParamTestVector("AES256 correct key", 10, 0, 1, new byte[32], null));
                add(new InitParamTestVector("AES256 incorrect key long", 10, 0, 1, new byte[33], null, InvalidKeyException.class, "invalid key length"));

                for (int cipher : new int[]{8, 9, 10})
                {
                    byte[] key = null;
                    switch (cipher)
                    {
                        case 8:
                            key = new byte[16];
                            break;
                        case 9:
                            key = new byte[24];
                            break;
                        case 10:
                            key = new byte[32];
                            break;
                        default:
                            Assertions.fail("unexpected cipher " + cipher);
                            break;
                    }

                    // Invalid mode
                    add(new InitParamTestVector(String.format("AES %d invalid mode", key.length * 8), cipher, 100, 1, key, new byte[15], InvalidAlgorithmParameterException.class, "mode not supported for cipher"));

                    // CBC
                    add(new InitParamTestVector(String.format("AES %d null IV CBC", key.length * 8), cipher, 1, 1, key, null, InvalidAlgorithmParameterException.class, "iv is null"));
                    add(new InitParamTestVector(String.format("AES %d short IV CBC", key.length * 8), cipher, 1, 1, key, new byte[15], InvalidAlgorithmParameterException.class, "invalid iv length"));
                    add(new InitParamTestVector(String.format("AES %d long IV CBC", key.length * 8), cipher, 1, 1, key, new byte[17], InvalidAlgorithmParameterException.class, "invalid iv length"));
                    add(new InitParamTestVector(String.format("AES %d okay IV CBC", key.length * 8), cipher, 1, 1, key, new byte[16]));

                    // CFB1
                    add(new InitParamTestVector(String.format("AES %d null IV CFB1", key.length * 8), cipher, 2, 1, key, null, InvalidAlgorithmParameterException.class, "iv is null"));
                    add(new InitParamTestVector(String.format("AES %d short IV CFB1", key.length * 8), cipher, 2, 1, key, new byte[15], InvalidAlgorithmParameterException.class, "invalid iv length"));
                    add(new InitParamTestVector(String.format("AES %d long IV CFB1", key.length * 8), cipher, 2, 1, key, new byte[17], InvalidAlgorithmParameterException.class, "invalid iv length"));
                    add(new InitParamTestVector(String.format("AES %d okay IV CFB1", key.length * 8), cipher, 2, 1, key, new byte[16]));

                    // CFB8
                    add(new InitParamTestVector(String.format("AES %d null IV CFB8", key.length * 8), cipher, 3, 1, key, null, InvalidAlgorithmParameterException.class, "iv is null"));
                    add(new InitParamTestVector(String.format("AES %d short IV CFB8", key.length * 8), cipher, 3, 1, key, new byte[15], InvalidAlgorithmParameterException.class, "invalid iv length"));
                    add(new InitParamTestVector(String.format("AES %d long IV CFB8", key.length * 8), cipher, 3, 1, key, new byte[17], InvalidAlgorithmParameterException.class, "invalid iv length"));
                    add(new InitParamTestVector(String.format("AES %d okay IV CFB8", key.length * 8), cipher, 3, 1, key, new byte[16]));


                    // CFB128
                    add(new InitParamTestVector(String.format("AES %d null IV CFB128", key.length * 8), cipher, 5, 1, key, null, InvalidAlgorithmParameterException.class, "iv is null"));
                    add(new InitParamTestVector(String.format("AES %d short IV CFB128", key.length * 8), cipher, 5, 1, key, new byte[15], InvalidAlgorithmParameterException.class, "invalid iv length"));
                    add(new InitParamTestVector(String.format("AES %d long IV CFB128", key.length * 8), cipher, 5, 1, key, new byte[17], InvalidAlgorithmParameterException.class, "invalid iv length"));
                    add(new InitParamTestVector(String.format("AES %d okay IV CFB128", key.length * 8), cipher, 5, 1, key, new byte[16]));


                    // OFB
                    add(new InitParamTestVector(String.format("AES %d null IV OFB", key.length * 8), cipher, 9, 1, key, null, InvalidAlgorithmParameterException.class, "iv is null"));
                    add(new InitParamTestVector(String.format("AES %d short IV OFB", key.length * 8), cipher, 9, 1, key, new byte[15], InvalidAlgorithmParameterException.class, "invalid iv length"));
                    add(new InitParamTestVector(String.format("AES %d long IV OFB", key.length * 8), cipher, 9, 1, key, new byte[17], InvalidAlgorithmParameterException.class, "invalid iv length"));
                    add(new InitParamTestVector(String.format("AES %d okay IV OFB", key.length * 8), cipher, 9, 1, key, new byte[16]));


                    // CTR Valid
                    add(new InitParamTestVector(String.format("AES %d long IV (null) CTR", key.length * 8), cipher, 6, 1, key, null, InvalidAlgorithmParameterException.class, "iv is null"));
                    for (int ivLen : new int[]{1, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17})
                    {
                        if (ivLen < 8 || ivLen > 16)
                        {
                            add(new InitParamTestVector(String.format("AES %d long IV (%d) CTR", key.length * 8, ivLen), cipher, 6, 1, key, new byte[ivLen], InvalidAlgorithmParameterException.class, "invalid iv length"));
                        }
                        else
                        {
                            add(new InitParamTestVector(String.format("AES %d okay IV (%d) CTR", key.length * 8, ivLen), cipher, 6, 1, key, new byte[ivLen]));
                        }
                    }


                }


            }
        };
        for (InitParamTestVector test : tests)
        {

            long ref = 0;
            try
            {
                ref = blockCipherNI.makeInstance(test.cipher, test.mode, test.padding);
                int code = blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, test.key, test.iv, 0);


                if (!test.passing)
                {
                    Assertions.fail(test.name + " failed");
                }
            }
            catch (Exception e)
            {
                Assertions.assertEquals(test.expectedExceptionClass, e.getClass());
                Assertions.assertEquals(test.expectedExceptionMessage, e.getMessage());
            }
            finally
            {
                TestNISelector.getBlockCipher().dispose(ref);
            }

        }


    }

    @Test
    public void testARIAInitParams() throws Exception
    {
        List<InitParamTestVector> tests = new ArrayList<InitParamTestVector>()
        {
            {
                // AES ECB Key Lengths
                add(new InitParamTestVector("ARIA128 incorrect key short", 11, 0, 1, new byte[15], null, InvalidKeyException.class, "invalid key length"));
                add(new InitParamTestVector("ARIA128 correct key", 11, 0, 1, new byte[16], null));
                add(new InitParamTestVector("ARIA128 incorrect key long", 11, 0, 1, new byte[17], null, InvalidKeyException.class, "invalid key length"));

                add(new InitParamTestVector("ARIA192 incorrect key short", 12, 0, 1, new byte[23], null, InvalidKeyException.class, "invalid key length"));
                add(new InitParamTestVector("ARIA192 correct key", 12, 0, 1, new byte[24], null));
                add(new InitParamTestVector("ARIA192 incorrect key long", 12, 0, 1, new byte[25], null, InvalidKeyException.class, "invalid key length"));

                add(new InitParamTestVector("ARIA256 incorrect key short", 13, 0, 1, new byte[31], null, InvalidKeyException.class, "invalid key length"));
                add(new InitParamTestVector("ARIA256 correct key", 13, 0, 1, new byte[32], null));
                add(new InitParamTestVector("ARIA256 incorrect key long", 13, 0, 1, new byte[33], null, InvalidKeyException.class, "invalid key length"));

                for (int cipher : new int[]{11, 12, 13})
                {
                    byte[] key = null;
                    switch (cipher)
                    {
                        case 11:
                            key = new byte[16];
                            break;
                        case 12:
                            key = new byte[24];
                            break;
                        case 13:
                            key = new byte[32];
                            break;
                        default:
                            Assertions.fail("unexpected cipher " + cipher);
                            break;
                    }

                    // Invalid mode
                    add(new InitParamTestVector(String.format("ARIA %d invalid mode", key.length * 8), cipher, 100, 1, key, new byte[16], InvalidAlgorithmParameterException.class, "mode not supported for cipher"));

                    // CBC
                    add(new InitParamTestVector(String.format("ARIA %d null IV CBC", key.length * 8), cipher, 1, 1, key, null, InvalidAlgorithmParameterException.class, "iv is null"));
                    add(new InitParamTestVector(String.format("ARIA %d short IV CBC", key.length * 8), cipher, 1, 1, key, new byte[15], InvalidAlgorithmParameterException.class, "invalid iv length"));
                    add(new InitParamTestVector(String.format("ARIA %d long IV CBC", key.length * 8), cipher, 1, 1, key, new byte[17], InvalidAlgorithmParameterException.class, "invalid iv length"));
                    add(new InitParamTestVector(String.format("ARIA %d okay IV CBC", key.length * 8), cipher, 1, 1, key, new byte[16]));

                    // CFB1

                    add(new InitParamTestVector(String.format("ARIA %d null IV CFB1", key.length * 8), cipher, 2, 1, key, null, InvalidAlgorithmParameterException.class, "iv is null"));
                    add(new InitParamTestVector(String.format("ARIA %d short IV CFB1", key.length * 8), cipher, 2, 1, key, new byte[15], InvalidAlgorithmParameterException.class, "invalid iv length"));
                    add(new InitParamTestVector(String.format("ARIA %d long IV CFB1", key.length * 8), cipher, 2, 1, key, new byte[17], InvalidAlgorithmParameterException.class, "invalid iv length"));
                    add(new InitParamTestVector(String.format("ARIA %d okay IV CFB1", key.length * 8), cipher, 2, 1, key, new byte[16]));

                    // CFB8
                    add(new InitParamTestVector(String.format("ARIA %d null IV CFB8", key.length * 8), cipher, 3, 1, key, null, InvalidAlgorithmParameterException.class, "iv is null"));
                    add(new InitParamTestVector(String.format("ARIA %d short IV CFB8", key.length * 8), cipher, 3, 1, key, new byte[15], InvalidAlgorithmParameterException.class, "invalid iv length"));
                    add(new InitParamTestVector(String.format("ARIA %d long IV CFB8", key.length * 8), cipher, 3, 1, key, new byte[17], InvalidAlgorithmParameterException.class, "invalid iv length"));
                    add(new InitParamTestVector(String.format("ARIA %d okay IV CFB8", key.length * 8), cipher, 3, 1, key, new byte[16]));


                    // CFB128
                    add(new InitParamTestVector(String.format("ARIA %d null IV CFB128", key.length * 8), cipher, 5, 1, key, null, InvalidAlgorithmParameterException.class, "iv is null"));
                    add(new InitParamTestVector(String.format("ARIA %d short IV CFB128", key.length * 8), cipher, 5, 1, key, new byte[15], InvalidAlgorithmParameterException.class, "invalid iv length"));
                    add(new InitParamTestVector(String.format("ARIA %d long IV CFB128", key.length * 8), cipher, 5, 1, key, new byte[17], InvalidAlgorithmParameterException.class, "invalid iv length"));
                    add(new InitParamTestVector(String.format("ARIA %d okay IV CFB128", key.length * 8), cipher, 5, 1, key, new byte[16]));

                    // CTR Valid
                    add(new InitParamTestVector(String.format("ARIA %d long IV (null) CTR", key.length * 8), cipher, 6, 1, key, null, InvalidAlgorithmParameterException.class, "iv is null"));
                    for (int ivLen : new int[]{1, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17})
                    {
                        if (ivLen < 8 || ivLen > 16)
                        {
                            add(new InitParamTestVector(String.format("ARIA %d long IV (%d) CTR", key.length * 8, ivLen), cipher, 6, 1, key, new byte[ivLen], InvalidAlgorithmParameterException.class, "invalid iv length"));
                        }
                        else
                        {
                            add(new InitParamTestVector(String.format("ARIA %d okay IV (%d) CTR", key.length * 8, ivLen), cipher, 6, 1, key, new byte[ivLen]));
                        }
                    }


                }


            }
        };
        for (InitParamTestVector test : tests)
        {

            long ref = 0;
            try
            {
                ref = blockCipherNI.makeInstance(test.cipher, test.mode, test.padding);
                int code = blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, test.key, test.iv, 0);


                if (!test.passing)
                {
                    Assertions.fail(test.name + " failed");
                }
            }
            catch (Exception e)
            {
                Assertions.assertEquals(test.expectedExceptionClass, e.getClass());
                Assertions.assertEquals(test.expectedExceptionMessage, e.getMessage());
            }
            finally
            {
                TestNISelector.getBlockCipher().dispose(ref);
            }

        }


    }

    @Test
    public void testCAMELLIAInitParams() throws Exception
    {
        List<InitParamTestVector> tests = new ArrayList<InitParamTestVector>()
        {
            {
                // AES ECB Key Lengths
                add(new InitParamTestVector("CAMELLIA128 incorrect key short", 14, 0, 1, new byte[15], null, InvalidKeyException.class, "invalid key length"));
                add(new InitParamTestVector("CAMELLIA128 correct key", 14, 0, 1, new byte[16], null));
                add(new InitParamTestVector("CAMELLIA128 incorrect key long", 14, 0, 1, new byte[17], null, InvalidKeyException.class, "invalid key length"));

                add(new InitParamTestVector("CAMELLIA192 incorrect key short", 15, 0, 1, new byte[23], null, InvalidKeyException.class, "invalid key length"));
                add(new InitParamTestVector("CAMELLIA192 correct key", 15, 0, 1, new byte[24], null));
                add(new InitParamTestVector("CAMELLIA192 incorrect key long", 15, 0, 1, new byte[25], null, InvalidKeyException.class, "invalid key length"));

                add(new InitParamTestVector("CAMELLIA256 incorrect key short", 16, 0, 1, new byte[31], null, InvalidKeyException.class, "invalid key length"));
                add(new InitParamTestVector("CAMELLIA256 correct key", 16, 0, 1, new byte[32], null));
                add(new InitParamTestVector("CAMELLIA256 incorrect key long", 16, 0, 1, new byte[33], null, InvalidKeyException.class, "invalid key length"));

                for (int cipher : new int[]{14, 15, 16})
                {
                    byte[] key = null;
                    switch (cipher)
                    {
                        case 14:
                            key = new byte[16];
                            break;
                        case 15:
                            key = new byte[24];
                            break;
                        case 16:
                            key = new byte[32];
                            break;
                        default:
                            Assertions.fail("unexpected cipher " + cipher);
                            break;
                    }

                    // Invalid mode
                    add(new InitParamTestVector(String.format("CAMELLIA %d invalid mode", key.length * 8), cipher, 100, 1, key, new byte[15], InvalidAlgorithmParameterException.class, "mode not supported for cipher"));

                    // CBC
                    add(new InitParamTestVector(String.format("CAMELLIA %d null IV CBC", key.length * 8), cipher, 1, 1, key, null, InvalidAlgorithmParameterException.class, "iv is null"));
                    add(new InitParamTestVector(String.format("CAMELLIA %d short IV CBC", key.length * 8), cipher, 1, 1, key, new byte[15], InvalidAlgorithmParameterException.class, "invalid iv length"));
                    add(new InitParamTestVector(String.format("CAMELLIA %d long IV CBC", key.length * 8), cipher, 1, 1, key, new byte[17], InvalidAlgorithmParameterException.class, "invalid iv length"));
                    add(new InitParamTestVector(String.format("CAMELLIA %d okay IV CBC", key.length * 8), cipher, 1, 1, key, new byte[16]));

                    // CFB1
                    add(new InitParamTestVector(String.format("CAMELLIA %d null IV CFB1", key.length * 8), cipher, 2, 1, key, null, InvalidAlgorithmParameterException.class, "iv is null"));
                    add(new InitParamTestVector(String.format("CAMELLIA %d short IV CFB1", key.length * 8), cipher, 2, 1, key, new byte[15], InvalidAlgorithmParameterException.class, "invalid iv length"));
                    add(new InitParamTestVector(String.format("CAMELLIA %d long IV CFB1", key.length * 8), cipher, 2, 1, key, new byte[17], InvalidAlgorithmParameterException.class, "invalid iv length"));
                    add(new InitParamTestVector(String.format("CAMELLIA %d okay IV CFB1", key.length * 8), cipher, 2, 1, key, new byte[16]));


                    // CFB8
                    add(new InitParamTestVector(String.format("CAMELLIA %d null IV CFB8", key.length * 8), cipher, 3, 1, key, null, InvalidAlgorithmParameterException.class, "iv is null"));
                    add(new InitParamTestVector(String.format("CAMELLIA %d short IV CFB8", key.length * 8), cipher, 3, 1, key, new byte[15], InvalidAlgorithmParameterException.class, "invalid iv length"));
                    add(new InitParamTestVector(String.format("CAMELLIA %d long IV CFB8", key.length * 8), cipher, 3, 1, key, new byte[17], InvalidAlgorithmParameterException.class, "invalid iv length"));
                    add(new InitParamTestVector(String.format("CAMELLIA %d okay IV CFB8", key.length * 8), cipher, 3, 1, key, new byte[16]));


                    // CFB128
                    add(new InitParamTestVector(String.format("CAMELLIA %d null IV CFB128", key.length * 8), cipher, 5, 1, key, null, InvalidAlgorithmParameterException.class, "iv is null"));
                    add(new InitParamTestVector(String.format("CAMELLIA %d short IV CFB128", key.length * 8), cipher, 5, 1, key, new byte[15], InvalidAlgorithmParameterException.class, "invalid iv length"));
                    add(new InitParamTestVector(String.format("CAMELLIA %d long IV CFB128", key.length * 8), cipher, 5, 1, key, new byte[17], InvalidAlgorithmParameterException.class, "invalid iv length"));
                    add(new InitParamTestVector(String.format("CAMELLIA %d okay IV CFB128", key.length * 8), cipher, 5, 1, key, new byte[16]));

                    // OFB
                    add(new InitParamTestVector(String.format("CAMELLIA %d null IV OFB", key.length * 8), cipher, 9, 1, key, null, InvalidAlgorithmParameterException.class, "iv is null"));
                    add(new InitParamTestVector(String.format("CAMELLIA %d short IV OFB", key.length * 8), cipher, 9, 1, key, new byte[15], InvalidAlgorithmParameterException.class, "invalid iv length"));
                    add(new InitParamTestVector(String.format("CAMELLIA %d long IV OFB", key.length * 8), cipher, 9, 1, key, new byte[17], InvalidAlgorithmParameterException.class, "invalid iv length"));
                    add(new InitParamTestVector(String.format("CAMELLIA %d okay IV OFB", key.length * 8), cipher, 9, 1, key, new byte[16]));


                    // CTR Valid
                    add(new InitParamTestVector(String.format("CAMELLIA %d long IV (null) CTR", key.length * 8), cipher, 6, 1, key, null, InvalidAlgorithmParameterException.class, "iv is null"));
                    for (int ivLen : new int[]{1, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17})
                    {
                        if (ivLen < 8 || ivLen > 16)
                        {
                            add(new InitParamTestVector(String.format("CAMELLIA %d long IV (%d) CTR", key.length * 8, ivLen), cipher, 6, 1, key, new byte[ivLen], InvalidAlgorithmParameterException.class, "invalid iv length"));
                        }
                        else
                        {
                            add(new InitParamTestVector(String.format("CAMELLIA %d okay IV (%d) CTR", key.length * 8, ivLen), cipher, 6, 1, key, new byte[ivLen]));
                        }
                    }
                }
            }
        };
        for (InitParamTestVector test : tests)
        {

            long ref = 0;
            try
            {
                ref = blockCipherNI.makeInstance(test.cipher, test.mode, test.padding);
                blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, test.key, test.iv, 0);

                if (!test.passing)
                {
                    Assertions.fail(test.name + " failed");
                }
            }
            catch (Exception e)
            {
                Assertions.assertEquals(test.expectedExceptionClass, e.getClass());
                Assertions.assertEquals(test.expectedExceptionMessage, e.getMessage());
            }
            finally
            {
                TestNISelector.getBlockCipher().dispose(ref);
            }

        }


    }

    @Test
    public void testSM4InitParams() throws Exception
    {
        List<InitParamTestVector> tests = new ArrayList<InitParamTestVector>()
        {
            {
                // SM4 ECB Key Lengths
                add(new InitParamTestVector("SM4 incorrect key short", 20, 0, 1, new byte[15], null, InvalidKeyException.class, "invalid key length"));
                add(new InitParamTestVector("SM4 correct key", 20, 0, 1, new byte[16], null));
                add(new InitParamTestVector("SM4 incorrect key long", 20, 0, 1, new byte[17], null, InvalidKeyException.class, "invalid key length"));

                for (int cipher : new int[]{20})
                {
                    byte[] key = new byte[16];

                    // Invalid mode
                    add(new InitParamTestVector(String.format("SM4 %d invalid mode", key.length * 8), cipher, 100, 1, key, new byte[15], InvalidAlgorithmParameterException.class, "mode not supported for cipher"));

                    // CBC
                    add(new InitParamTestVector(String.format("SM4 %d null IV CBC", key.length * 8), cipher, 1, 1, key, null, InvalidAlgorithmParameterException.class, "iv is null"));
                    add(new InitParamTestVector(String.format("SM4 %d short IV CBC", key.length * 8), cipher, 1, 1, key, new byte[15], InvalidAlgorithmParameterException.class, "invalid iv length"));
                    add(new InitParamTestVector(String.format("SM4 %d long IV CBC", key.length * 8), cipher, 1, 1, key, new byte[17], InvalidAlgorithmParameterException.class, "invalid iv length"));
                    add(new InitParamTestVector(String.format("SM4 %d okay IV CBC", key.length * 8), cipher, 1, 1, key, new byte[16]));

                    // CFB128
                    add(new InitParamTestVector(String.format("SM4 %d null IV CFB128", key.length * 8), cipher, 5, 1, key, null, InvalidAlgorithmParameterException.class, "iv is null"));
                    add(new InitParamTestVector(String.format("SM4 %d short IV CFB128", key.length * 8), cipher, 5, 1, key, new byte[15], InvalidAlgorithmParameterException.class, "invalid iv length"));
                    add(new InitParamTestVector(String.format("SM4 %d long IV CFB128", key.length * 8), cipher, 5, 1, key, new byte[17], InvalidAlgorithmParameterException.class, "invalid iv length"));
                    add(new InitParamTestVector(String.format("SM4 %d okay IV CFB128", key.length * 8), cipher, 5, 1, key, new byte[16]));

                    // OFB
                    add(new InitParamTestVector(String.format("SM4 %d null IV OFB", key.length * 8), cipher, 9, 1, key, null, InvalidAlgorithmParameterException.class, "iv is null"));
                    add(new InitParamTestVector(String.format("SM4 %d short IV OFB", key.length * 8), cipher, 9, 1, key, new byte[15], InvalidAlgorithmParameterException.class, "invalid iv length"));
                    add(new InitParamTestVector(String.format("SM4 %d long IV OFB", key.length * 8), cipher, 9, 1, key, new byte[17], InvalidAlgorithmParameterException.class, "invalid iv length"));
                    add(new InitParamTestVector(String.format("SM4 %d okay IV OFB", key.length * 8), cipher, 9, 1, key, new byte[16]));

                    add(new InitParamTestVector(String.format("SM4 %d long IV (null) CTR", key.length * 8), cipher, 6, 1, key, null, InvalidAlgorithmParameterException.class, "iv is null"));
                    for (int ivLen : new int[]{1, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17})
                    {
                        if (ivLen < 8 || ivLen > 16)
                        {
                            add(new InitParamTestVector(String.format("SM4 %d long IV (%d) CTR", key.length * 8, ivLen), cipher, 6, 1, key, new byte[ivLen], InvalidAlgorithmParameterException.class, "invalid iv length"));
                        }
                        else
                        {
                            add(new InitParamTestVector(String.format("SM4 %d okay IV (%d) CTR", key.length * 8, ivLen), cipher, 6, 1, key, new byte[ivLen]));
                        }
                    }

                }
            }
        };
        for (InitParamTestVector test : tests)
        {

            long ref = 0;
            try
            {
                ref = blockCipherNI.makeInstance(test.cipher, test.mode, test.padding);
                int code = blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, test.key, test.iv, 0);


                if (!test.passing)
                {
                    Assertions.fail(test.name + " failed");
                }
            }
            catch (Exception e)
            {
                Assertions.assertEquals(test.expectedExceptionClass, e.getClass());
                Assertions.assertEquals(test.expectedExceptionMessage, e.getMessage());
            }
            finally
            {
                TestNISelector.getBlockCipher().dispose(ref);
            }

        }


    }

    @Test
    public void testBlockCipherUpdate_nullInputArray() throws Exception
    {

        long ref = 0;
        try
        {
            byte[] input = null;
            int inOff = 0;
            int inLen = 0;

            byte[] output = new byte[16];
            int outOff = 0;


            ref = blockCipherNI.makeInstance(8, 1, 1);
            int code = blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, new byte[16], new byte[16], 0);


            code = blockCipherNI.update(ref, output, outOff, input, inOff, inLen);


            Assertions.fail("expected exception");

        }
        catch (Exception e)
        {
            Assertions.assertSame(NullPointerException.class, e.getClass(), "unexpected exception class");
            Assertions.assertEquals("input is null", e.getMessage(), "unexpected exception message");
        }
        finally
        {
            TestNISelector.getBlockCipher().dispose(ref);
        }
    }

    @Test
    public void testBlockCipherUpdate_nullOutputArray() throws Exception
    {

        long ref = 0;
        try
        {
            byte[] input = new byte[16];
            int inOff = 0;
            int inLen = 16;

            byte[] output = null;
            int outOff = 0;

            ref = blockCipherNI.makeInstance(8, 1, 1);
            int code = blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, new byte[16], new byte[16], 0);


            code = blockCipherNI.update(ref, output, outOff, input, inOff, inLen);


            Assertions.fail("expected exception");

        }
        catch (Exception e)
        {
            Assertions.assertSame(NullPointerException.class, e.getClass(), "unexpected exception class");
            Assertions.assertEquals("output is null", e.getMessage(), "unexpected exception message");
        }
        finally
        {
            TestNISelector.getBlockCipher().dispose(ref);
        }
    }

    @Test
    public void testBlockCipherUpdate_outputOffsetNegative() throws Exception
    {

        long ref = 0;
        try
        {
            byte[] input = new byte[16];
            int inOff = 0;
            int inLen = 16;

            byte[] output = new byte[16];
            int outOff = -1;


            ref = blockCipherNI.makeInstance(8, 1, 1);
            int code = blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, new byte[16], new byte[16], 0);


            code = blockCipherNI.update(ref, output, outOff, input, inOff, inLen);

            Assertions.fail("expected exception");

        }
        catch (Exception e)
        {
            Assertions.assertSame(IllegalArgumentException.class, e.getClass(), "unexpected exception class");
            Assertions.assertEquals("output offset is negative", e.getMessage(), "unexpected exception message");
        }
        finally
        {
            TestNISelector.getBlockCipher().dispose(ref);
        }
    }

    @Test
    public void testBlockCipherUpdate_inputOffsetNegative() throws Exception
    {

        long ref = 0;
        try
        {
            byte[] input = new byte[16];
            int inOff = -1;
            int inLen = 16;

            byte[] output = new byte[16];
            int outOff = 0;


            ref = blockCipherNI.makeInstance(8, 1, 1);
            int code = blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, new byte[16], new byte[16], 0);


            code = blockCipherNI.update(ref, output, outOff, input, inOff, inLen);

            Assertions.fail("expected exception");

        }
        catch (Exception e)
        {
            Assertions.assertSame(IllegalArgumentException.class, e.getClass(), "unexpected exception class");
            Assertions.assertEquals("input offset is negative", e.getMessage(), "unexpected exception message");
        }
        finally
        {
            TestNISelector.getBlockCipher().dispose(ref);
        }
    }

    @Test
    public void testBlockCipherUpdate_inputLenNegative() throws Exception
    {

        long ref = 0;
        try
        {
            byte[] input = new byte[16];
            int inOff = 0;
            int inLen = -1;

            byte[] output = new byte[16];
            int outOff = 0;


            ref = blockCipherNI.makeInstance(8, 1, 1);
            int code = blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, new byte[16], new byte[16], 0);


            code = blockCipherNI.update(ref, output, outOff, input, inOff, inLen);

            Assertions.fail("expected exception");

        }
        catch (Exception e)
        {
            Assertions.assertSame(IllegalArgumentException.class, e.getClass(), "unexpected exception class");
            Assertions.assertEquals("input len is negative", e.getMessage(), "unexpected exception message");
        }
        finally
        {
            TestNISelector.getBlockCipher().dispose(ref);
        }
    }

    @Test
    public void testBlockCipherUpdate_inputOutOfRange_offset() throws Exception
    {
        long ref = 0;
        try
        {
            byte[] input = new byte[16];
            int inOff = 1;
            int inLen = 16; // len 16 but started at 1 in a 16 byte array

            byte[] output = new byte[16];
            int outOff = 0;

            ref = blockCipherNI.makeInstance(8, 1, 1);
            blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, new byte[16], new byte[16], 0);
            blockCipherNI.update(ref, output, outOff, input, inOff, inLen);

            Assertions.fail("expected exception");

        }
        catch (Exception e)
        {
            Assertions.assertSame(IllegalArgumentException.class, e.getClass(), "unexpected exception class");
            Assertions.assertEquals("input offset + length is out of range", e.getMessage(), "unexpected exception message");
        }
        finally
        {
            TestNISelector.getBlockCipher().dispose(ref);
        }
    }

    @Test
    public void testBlockCipherUpdate_inputOutOfRange_length() throws Exception
    {
        long ref = 0;
        try
        {
            byte[] input = new byte[16];
            int inOff = 0;
            int inLen = 17;

            byte[] output = new byte[16];
            int outOff = 0;


            ref = blockCipherNI.makeInstance(8, 1, 1);
            blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, new byte[16], new byte[16], 0);
            blockCipherNI.update(ref, output, outOff, input, inOff, inLen);


            Assertions.fail("expected exception");

        }
        catch (Exception e)
        {
            Assertions.assertSame(IllegalArgumentException.class, e.getClass(), "unexpected exception class");
            Assertions.assertEquals("input offset + length is out of range", e.getMessage(), "unexpected exception message");
        }
        finally
        {
            TestNISelector.getBlockCipher().dispose(ref);
        }
    }

    @Test
    public void testBlockCipherUpdate_outputOutOfRange() throws Exception
    {
        long ref = 0;
        try
        {
            byte[] input = new byte[16];
            int inOff = 0;
            int inLen = 16;

            byte[] output = new byte[32];
            int outOff = 33;


            ref = blockCipherNI.makeInstance(8, 1, 1);
            blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, new byte[16], new byte[16], 0);
            blockCipherNI.update(ref, output, outOff, input, inOff, inLen);

            Assertions.fail("expected exception");

        }
        catch (Exception e)
        {
            Assertions.assertSame(IllegalArgumentException.class, e.getClass(), "unexpected exception class");
            Assertions.assertEquals("output offset + length is out of range", e.getMessage(), "unexpected exception message");
        }
        finally
        {
            TestNISelector.getBlockCipher().dispose(ref);
        }
    }


    @Test
    public void testBlockCipherUpdate_blockAlignment() throws Exception
    {
        long ref = 0;
        try
        {
            byte[] input = new byte[16];
            int inOff = 0;
            int inLen = 15;

            byte[] output = new byte[32];
            int outOff = 0;


            ref = blockCipherNI.makeInstance(8, 1, 0);
            blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, new byte[16], new byte[16], 0);
            blockCipherNI.update(ref, output, outOff, input, inOff, inLen);


            Assertions.fail("expected exception");

        }
        catch (Exception e)
        {
            Assertions.assertSame(IllegalBlockSizeException.class, e.getClass(), "unexpected exception class");
            Assertions.assertEquals("data not block size aligned", e.getMessage(), "unexpected exception message");
        }
        finally
        {
            TestNISelector.getBlockCipher().dispose(ref);
        }
    }


    @Test
    public void testBlockCipherUpdate_outputTooSmall_offSetCaused() throws Exception
    {
        long ref = 0;
        try
        {
            byte[] input = new byte[16];
            int inOff = 0;
            int inLen = 16;

            byte[] output = new byte[32];
            int outOff = 17; // 15 bytes remaining


            ref = blockCipherNI.makeInstance(8, 1, 1);
            blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, new byte[16], new byte[16], 0);
            blockCipherNI.update(ref, output, outOff, input, inOff, inLen);


            Assertions.fail("expected exception");

        }
        catch (Exception e)
        {
            Assertions.assertSame(ShortBufferException.class, e.getClass(), "unexpected exception class");
            Assertions.assertEquals("output too small", e.getMessage(), "unexpected exception message");
        }
        finally
        {
            TestNISelector.getBlockCipher().dispose(ref);
        }
    }

    @Test
    public void testBlockCipherUpdate_outputTooSmall_offSetCaused_Edge1() throws Exception
    {
        long ref = 0;
        try
        {
            byte[] input = new byte[16];
            int inOff = 0;
            int inLen = 16;

            byte[] output = new byte[32];
            int outOff = 32;


            ref = blockCipherNI.makeInstance(8, 1, 1);
            blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, new byte[16], new byte[16], 0);
            blockCipherNI.update(ref, output, outOff, input, inOff, inLen);
            Assertions.fail("expected exception");

        }
        catch (Exception e)
        {
            Assertions.assertSame(ShortBufferException.class, e.getClass(), "unexpected exception class");
            Assertions.assertEquals("output too small", e.getMessage(), "unexpected exception message");
        }
        finally
        {
            TestNISelector.getBlockCipher().dispose(ref);
        }
    }

    @Test
    public void testBlockCipherUpdate_outputTooSmall_lenCaused() throws Exception
    {
        long ref = 0;
        try
        {
            byte[] input = new byte[16];
            int inOff = 0;
            int inLen = 16;

            byte[] output = new byte[15];
            int outOff = 0;


            ref = blockCipherNI.makeInstance(8, 1, 1);
            blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, new byte[16], new byte[16], 0);
            blockCipherNI.update(ref, output, outOff, input, inOff, inLen);


            Assertions.fail("expected exception");

        }
        catch (Exception e)
        {
            Assertions.assertSame(ShortBufferException.class, e.getClass(), "unexpected exception class");
            Assertions.assertEquals("output too small", e.getMessage(), "unexpected exception message");
        }
        finally
        {
            TestNISelector.getBlockCipher().dispose(ref);
        }
    }


    @Test
    public void testBlockCipherFinal_outputNull() throws Exception
    {
        long ref = 0;
        try
        {


            byte[] output = null;
            int outOff = 0;


            ref = blockCipherNI.makeInstance(8, 1, 1);
            blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, new byte[16], new byte[16], 0);
            blockCipherNI.doFinal(ref, output, outOff);
            Assertions.fail("expected exception");

        }
        catch (Throwable e)
        {
            Assertions.assertSame(NullPointerException.class, e.getClass(), "unexpected exception class");
            Assertions.assertEquals("output is null", e.getMessage(), "unexpected exception message");
        }
        finally
        {
            TestNISelector.getBlockCipher().dispose(ref);
        }
    }

    @Test
    public void testBlockCipherFinal_outOffNegative() throws Exception
    {
        long ref = 0;
        try
        {


            byte[] output = new byte[16];
            int outOff = -1;


            ref = blockCipherNI.makeInstance(8, 1, 1);
            blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, new byte[16], new byte[16], 0);
            blockCipherNI.doFinal(ref, output, outOff);

            Assertions.fail("expected exception");

        }
        catch (Exception e)
        {
            Assertions.assertSame(IllegalArgumentException.class, e.getClass(), "unexpected exception class");
            Assertions.assertEquals("output offset is negative", e.getMessage(), "unexpected exception message");
        }
        finally
        {
            TestNISelector.getBlockCipher().dispose(ref);
        }
    }

    @Test
    public void testBlockCipherFinal_outOffOutOfRange() throws Exception
    {
        long ref = 0;
        try
        {


            byte[] output = new byte[16];
            int outOff = 17;

            ref = blockCipherNI.makeInstance(8, 1, 1);
            blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, new byte[16], new byte[16], 0);
            blockCipherNI.doFinal(ref, output, outOff);

            Assertions.fail("expected exception");

        }
        catch (Exception e)
        {
            Assertions.assertSame(IllegalArgumentException.class, e.getClass(), "unexpected exception class");
            Assertions.assertEquals("output offset + length is out of range", e.getMessage(), "unexpected exception message");
        }
        finally
        {
            TestNISelector.getBlockCipher().dispose(ref);
        }
    }


    @Test
    public void testBlockCipherFinal_basicCtrOverflow() throws Exception
    {
        long ref = 0;
        try
        {


            ref = blockCipherNI.makeInstance(8, 6, 1);

            //
            // 15 byte IV, so can only handle 256 blocks.
            //
            int code = blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, new byte[16], new byte[15], 0);

            // We can process [0,254] blocks of data successfully.
            code = blockCipherNI.update(ref, new byte[255 * 16], 0, new byte[254 * 16], 0, 254 * 16);

            Assertions.assertEquals(254 * 16, code);

            // Next 15 bytes would be ok, and leave one byte in the last available block, asserts [0,255]
            code = blockCipherNI.update(ref, new byte[15], 0, new byte[15], 0, 15);

            // Next 1 byte would be ok, and leave 0 in the last available block, asserts [0,255]
            code = blockCipherNI.update(ref, new byte[1], 0, new byte[1], 0, 1);


            // Next 1 byte would exceed the 8 bit block counter as [0,256) is asserted
            code = blockCipherNI.update(ref, new byte[1], 0, new byte[1], 0, 1);

            Assertions.fail("expected exception");
        }
        catch (Exception e)
        {
            Assertions.assertSame(IllegalStateException.class, e.getClass(), "unexpected exception class");
            Assertions.assertEquals("ctr mode overflow", e.getMessage(), "unexpected exception message");
        }
        finally
        {
            TestNISelector.getBlockCipher().dispose(ref);
        }
    }


    @Test
    public void testBlockCipherUpdateAAD_nullInputArray() throws Exception
    {

        long ref = 0;
        try
        {
            byte[] input = null;
            int inOff = 0;
            int inLen = 0;


            ref = blockCipherNI.makeInstance(8, 1, 1);
            blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, new byte[16], new byte[16], 0);
            blockCipherNI.updateAAD(ref, input, inOff, inLen);


            Assertions.fail("expected exception");

        }
        catch (Exception e)
        {
            Assertions.assertSame(NullPointerException.class, e.getClass(), "unexpected exception class");
            Assertions.assertEquals("input is null", e.getMessage(), "unexpected exception message");
        }
        finally
        {
            TestNISelector.getBlockCipher().dispose(ref);
        }
    }

    @Test
    public void testBlockCipherUpdateAAD_inputOffsetNegative() throws Exception
    {

        long ref = 0;
        try
        {
            byte[] input = new byte[16];
            int inOff = -1;
            int inLen = 16;


            ref = blockCipherNI.makeInstance(8, 1, 1);
            blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, new byte[16], new byte[16], 0);
            blockCipherNI.updateAAD(ref, input, inOff, inLen);


            Assertions.fail("expected exception");

        }
        catch (Exception e)
        {
            Assertions.assertSame(IllegalArgumentException.class, e.getClass(), "unexpected exception class");
            Assertions.assertEquals("input offset is negative", e.getMessage(), "unexpected exception message");
        }
        finally
        {
            TestNISelector.getBlockCipher().dispose(ref);
        }
    }

    @Test
    public void testBlockCipherUpdateAAD_inputLenNegative() throws Exception
    {

        long ref = 0;
        try
        {
            byte[] input = new byte[16];
            int inOff = 0;
            int inLen = -1;


            ref = blockCipherNI.makeInstance(8, 1, 1);
            blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, new byte[16], new byte[16], 0);
            blockCipherNI.updateAAD(ref, input, inOff, inLen);


            Assertions.fail("expected exception");

        }
        catch (Exception e)
        {
            Assertions.assertSame(IllegalArgumentException.class, e.getClass(), "unexpected exception class");
            Assertions.assertEquals("input len is negative", e.getMessage(), "unexpected exception message");
        }
        finally
        {
            TestNISelector.getBlockCipher().dispose(ref);
        }
    }

    @Test
    public void testBlockCipherUpdateAAD_inputOutOfRange_offset() throws Exception
    {
        long ref = 0;
        try
        {
            byte[] input = new byte[16];
            int inOff = 1;
            int inLen = 16; // len 16 but started at 1 in a 16 byte array


            ref = blockCipherNI.makeInstance(8, 1, 1);
            blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, new byte[16], new byte[16], 0);
            blockCipherNI.updateAAD(ref, input, inOff, inLen);


            Assertions.fail("expected exception");

        }
        catch (Exception e)
        {
            Assertions.assertSame(IllegalArgumentException.class, e.getClass(), "unexpected exception class");
            Assertions.assertEquals("input offset + length is out of range", e.getMessage(), "unexpected exception message");
        }
        finally
        {
            TestNISelector.getBlockCipher().dispose(ref);
        }
    }

    @Test
    public void testBlockCipherUpdateAAD_inputOutOfRange_length() throws Exception
    {
        long ref = 0;
        try
        {
            byte[] input = new byte[16];
            int inOff = 0;
            int inLen = 17;


            ref = blockCipherNI.makeInstance(8, 1, 1);
            blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, new byte[16], new byte[16], 0);
            blockCipherNI.updateAAD(ref, input, inOff, inLen);


            Assertions.fail("expected exception");

        }
        catch (Exception e)
        {
            Assertions.assertSame(IllegalArgumentException.class, e.getClass(), "unexpected exception class");
            Assertions.assertEquals("input offset + length is out of range", e.getMessage(), "unexpected exception message");
        }
        finally
        {
            TestNISelector.getBlockCipher().dispose(ref);
        }
    }


    private static class InitParamTestVector
    {
        String name;
        public int cipher = 0;
        public int mode = 0;
        public int padding = 0;
        public byte[] key;
        public byte[] iv;
        public Class expectedExceptionClass;
        public String expectedExceptionMessage;
        public boolean passing = false;

        public InitParamTestVector(String name, int cipher, int mode, int padding, byte[] key, byte[] iv, Class expectedExceptionClass, String expectedExceptionMessage)
        {
            this.name = name;
            this.cipher = cipher;
            this.mode = mode;
            this.padding = padding;
            this.key = key;
            this.iv = iv;
            this.expectedExceptionClass = expectedExceptionClass;
            this.expectedExceptionMessage = expectedExceptionMessage;
            passing = false;
        }

        public InitParamTestVector(String name, int cipher, int mode, int padding, byte[] key, byte[] iv)
        {
            this.name = name;
            this.cipher = cipher;
            this.mode = mode;
            this.padding = padding;
            this.key = key;
            this.iv = iv;
            passing = true;
        }
    }

    @Test
    public void testCtrOverflowPoisonsCtx() throws Exception
    {
        // Drive AES128/CTR with a 15-byte IV (limit = 256 blocks = 4096 bytes)
        // past the legal counter range. Verify:
        //   1. update returns ctr-overflow.
        //   2. subsequent updates keep returning ctr-overflow.
        //   3. doFinal cannot rescue the cipher — its auto-reset hits the
        //      poison check in init and surfaces "cipher is poisoned".

        long ref = 0;
        try
        {
            ref = blockCipherNI.makeInstance(8, 6, 0); // AES128, CTR, NO_PADDING

            byte[] key = new byte[16];
            byte[] iv = new byte[15];
            for (int i = 0; i < 16; i++) key[i] = (byte) i;
            for (int i = 0; i < 15; i++) iv[i] = (byte) (i + 100);

            Assertions.assertEquals(0, blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, key, iv, 0));

            // 4097 bytes — past the 256-block legal range.
            byte[] input = new byte[4097];
            byte[] output = new byte[4097];

            try
            {
                blockCipherNI.update(ref, output, 0, input, 0, input.length);
                Assertions.fail("expected ctr overflow");
            }
            catch (IllegalStateException ex)
            {
                Assertions.assertEquals("ctr mode overflow", ex.getMessage());
            }

            // Subsequent ops fail fast with the poisoned error — the
            // initial overflow flagged the ctx, and every entry point
            // (update / final / set_tag) checks the flag at the top.
            try
            {
                blockCipherNI.update(ref, output, 0, new byte[16], 0, 16);
                Assertions.fail("expected cipher poisoned on retry");
            }
            catch (IllegalStateException ex)
            {
                Assertions.assertTrue(ex.getMessage().contains("poisoned"));
            }

            try
            {
                blockCipherNI.doFinal(ref, output, 0);
                Assertions.fail("expected cipher poisoned");
            }
            catch (IllegalStateException ex)
            {
                Assertions.assertTrue(ex.getMessage().contains("poisoned"));
            }
        }
        finally
        {
            blockCipherNI.dispose(ref);
        }
    }

    @Test
    public void testGetUpdateSize() throws Exception
    {
        // Drives block_cipher_get_update_size across the three branches it
        // exposes: streaming pass-through, non-streaming PADDED block-rounding,
        // and the !initialized early-return.
        long ref = 0;
        try
        {
            ref = blockCipherNI.makeInstance(8, 1, 1); // AES128, CBC, PADDED

            // Pre-init: returns JO_NOT_INITIALIZED -> IllegalStateException.
            try
            {
                blockCipherNI.getUpdateSize(ref, 16);
                Assertions.fail("expected !initialized to fail");
            }
            catch (IllegalStateException ex)
            {
                Assertions.assertEquals("not initialized", ex.getMessage());
            }

            // PADDED non-streaming branch: result rounds down to block boundary
            // including any partial-block carry from prior update. Fresh ctx
            // has processed=0, so for input 32 we expect 32 (2 full blocks).
            blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, new byte[16], new byte[16], 0);
            Assertions.assertEquals(32, blockCipherNI.getUpdateSize(ref, 32));
            // input 17 → 16 (one whole block, byte 17 carries to next call).
            Assertions.assertEquals(16, blockCipherNI.getUpdateSize(ref, 17));

            blockCipherNI.dispose(ref);
            ref = 0;

            // Streaming branch: returns len unchanged.
            ref = blockCipherNI.makeInstance(8, 6, 0); // AES128, CTR, NO_PADDING
            blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, new byte[16], new byte[16], 0);
            Assertions.assertEquals(13, blockCipherNI.getUpdateSize(ref, 13));
        }
        finally
        {
            blockCipherNI.dispose(ref);
        }
    }

    @Test
    public void testUpdateAAD_nonGcmMode() throws Exception
    {
        // updateAAD requires a GCM ctx; non-GCM modes must reject before the
        // EVP layer silently swallows the AAD. The underlying exception is
        // InvalidAlgorithmParameterException; updateAAD wraps it in a
        // RuntimeException since it isn't part of its declared throws set.
        long ref = 0;
        try
        {
            ref = blockCipherNI.makeInstance(8, 1, 1); // AES128, CBC, PADDED
            blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, new byte[16], new byte[16], 0);
            blockCipherNI.updateAAD(ref, new byte[16], 0, 16);
            Assertions.fail("expected non-GCM updateAAD to fail");
        }
        catch (RuntimeException ex)
        {
            Assertions.assertEquals("mode not supported for cipher", ex.getMessage());
            Assertions.assertTrue(ex.getCause() instanceof InvalidAlgorithmParameterException);
        }
        finally
        {
            blockCipherNI.dispose(ref);
        }
    }

    @Test
    public void testUpdateAAD_notInitialized() throws Exception
    {
        // Calling updateAAD before init must surface as JO_NOT_INITIALIZED.
        long ref = 0;
        try
        {
            ref = blockCipherNI.makeInstance(8, 8, 0); // AES128, GCM, NO_PADDING
            blockCipherNI.updateAAD(ref, new byte[16], 0, 16);
            Assertions.fail("expected !initialized updateAAD to fail");
        }
        catch (IllegalStateException ex)
        {
            Assertions.assertEquals("not initialized", ex.getMessage());
        }
        finally
        {
            blockCipherNI.dispose(ref);
        }
    }

    @Test
    public void testUpdateAAD_zeroLen() throws Exception
    {
        // Zero-length AAD is a documented no-op: returns 0, no error.
        long ref = 0;
        try
        {
            ref = blockCipherNI.makeInstance(8, 8, 0); // AES128, GCM, NO_PADDING
            blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, new byte[16], new byte[12], 16);
            int result = blockCipherNI.updateAAD(ref, new byte[16], 0, 0);
            Assertions.assertEquals(0, result);
        }
        finally
        {
            blockCipherNI.dispose(ref);
        }
    }

    private static byte[] parseHex(String hex)
    {
        int n = hex.length() / 2;
        byte[] out = new byte[n];
        for (int i = 0; i < n; i++)
        {
            out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    @Test
    public void testGetBlockSize_notInitialized() throws Exception
    {
        // get_block_size now gates on initialized; pre-init the cached
        // cipher_block_size may carry stale values from a failed init.
        long ref = 0;
        try
        {
            ref = blockCipherNI.makeInstance(8, 1, 0); // AES128, CBC, NO_PADDING
            blockCipherNI.getBlockSize(ref);
            Assertions.fail("expected !initialized to fail");
        }
        catch (IllegalStateException ex)
        {
            Assertions.assertEquals("not initialized", ex.getMessage());
        }
        finally
        {
            blockCipherNI.dispose(ref);
        }
    }

    @Test
    public void testGetFinalSize_notInitialized() throws Exception
    {
        long ref = 0;
        try
        {
            ref = blockCipherNI.makeInstance(8, 1, 0);
            blockCipherNI.getFinalSize(ref, 16);
            Assertions.fail("expected !initialized to fail");
        }
        catch (IllegalStateException ex)
        {
            Assertions.assertEquals("not initialized", ex.getMessage());
        }
        finally
        {
            blockCipherNI.dispose(ref);
        }
    }

    @Test
    public void testFinal_notInitialized() throws Exception
    {
        // doFinal must reject pre-init: the EVP ctx has no cipher / key set.
        long ref = 0;
        try
        {
            ref = blockCipherNI.makeInstance(8, 1, 0);
            blockCipherNI.doFinal(ref, new byte[16], 0);
            Assertions.fail("expected !initialized doFinal to fail");
        }
        catch (IllegalStateException ex)
        {
            Assertions.assertEquals("not initialized", ex.getMessage());
        }
        finally
        {
            blockCipherNI.dispose(ref);
        }
    }

    @Test
    public void testFinal_outputTooSmall_encryptPadded() throws Exception
    {
        // PADDED CBC encrypt requires at least one block in the doFinal
        // output buffer for the trailing padding block. Passing a 0-byte
        // output should surface JO_OUTPUT_TOO_SMALL → ShortBufferException.
        long ref = 0;
        try
        {
            ref = blockCipherNI.makeInstance(8, 1, 1); // AES128, CBC, PADDED
            blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, new byte[16], new byte[16], 0);
            blockCipherNI.doFinal(ref, new byte[0], 0);
            Assertions.fail("expected output too small");
        }
        catch (ShortBufferException ex)
        {
            Assertions.assertEquals("output too small", ex.getMessage());
        }
        finally
        {
            blockCipherNI.dispose(ref);
        }
    }

    @Test
    public void testInit_invalidTagLen_overMax() throws Exception
    {
        // Bridge validates tag_len < 0; the > MAX_TAG_LEN check is C-side.
        long ref = 0;
        try
        {
            ref = blockCipherNI.makeInstance(8, 8, 0); // AES128, GCM, NO_PADDING
            blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, new byte[16], new byte[12], 17);
            Assertions.fail("expected invalid tag len");
        }
        catch (IllegalArgumentException ex)
        {
            Assertions.assertEquals("invalid tag len", ex.getMessage());
        }
        finally
        {
            blockCipherNI.dispose(ref);
        }
    }

    @Test
    public void testInit_onPoisonedCtx() throws Exception
    {
        // Poison via CTR overflow, then call init explicitly. The poisoned
        // check at the top of init must reject — recovery is destroy + create.
        long ref = 0;
        try
        {
            ref = blockCipherNI.makeInstance(8, 6, 0); // AES128, CTR, NO_PADDING
            byte[] key = new byte[16];
            byte[] iv = new byte[15];
            for (int i = 0; i < 16; i++) key[i] = (byte) i;
            for (int i = 0; i < 15; i++) iv[i] = (byte) (i + 100);

            Assertions.assertEquals(0, blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, key, iv, 0));

            // 4097 bytes — past the 256-block legal range for 15-byte IV.
            try
            {
                blockCipherNI.update(ref, new byte[4097], 0, new byte[4097], 0, 4097);
                Assertions.fail("expected ctr overflow");
            }
            catch (IllegalStateException ex)
            {
                Assertions.assertEquals("ctr mode overflow", ex.getMessage());
            }

            // Now ctx is poisoned. Calling init must surface that.
            try
            {
                blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, key, new byte[16], 0);
                Assertions.fail("expected poisoned ctx to reject init");
            }
            catch (IllegalStateException ex)
            {
                Assertions.assertTrue(ex.getMessage().contains("poisoned"));
            }
        }
        finally
        {
            blockCipherNI.dispose(ref);
        }
    }

    @Test
    public void testInit_aes128Gcm_invalidIvLen() throws Exception
    {
        long ref = 0;
        try
        {
            ref = blockCipherNI.makeInstance(8, 8, 0); // AES128, GCM
            blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, new byte[16], new byte[11], 16);
            Assertions.fail("expected invalid iv length");
        }
        catch (InvalidAlgorithmParameterException ex)
        {
            Assertions.assertEquals("invalid iv length", ex.getMessage());
        }
        finally
        {
            blockCipherNI.dispose(ref);
        }
    }

    @Test
    public void testInit_aes192Gcm_invalidIvLen() throws Exception
    {
        long ref = 0;
        try
        {
            ref = blockCipherNI.makeInstance(9, 8, 0); // AES192, GCM
            blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, new byte[24], new byte[11], 16);
            Assertions.fail("expected invalid iv length");
        }
        catch (InvalidAlgorithmParameterException ex)
        {
            Assertions.assertEquals("invalid iv length", ex.getMessage());
        }
        finally
        {
            blockCipherNI.dispose(ref);
        }
    }

    @Test
    public void testInit_aes256Gcm_invalidIvLen() throws Exception
    {
        long ref = 0;
        try
        {
            ref = blockCipherNI.makeInstance(10, 8, 0); // AES256, GCM
            blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, new byte[32], new byte[11], 16);
            Assertions.fail("expected invalid iv length");
        }
        catch (InvalidAlgorithmParameterException ex)
        {
            Assertions.assertEquals("invalid iv length", ex.getMessage());
        }
        finally
        {
            blockCipherNI.dispose(ref);
        }
    }

    @Test
    public void testAes128Xts_ieee1619Vector2() throws Exception
    {
        // IEEE Std 1619-2007 Annex B, Vector 2.
        //   K1     = 0x11 * 16
        //   K2     = 0x22 * 16
        //   tweak  = data unit sequence number 0x3333333333 as 128-bit LE
        //   pt     = 0x44 * 32
        //   ct     = c454185e6a16936e39334038acef838bfb186fff7480adc4289382ecd6d394f0
        // (Vector 1 from the same annex has K1 == K2 == 0; modern OpenSSL
        //  rejects that as a security-policy violation, so Vector 2 is used.)
        long ref = 0;
        try
        {
            ref = blockCipherNI.makeInstance(8, 11, 0); // AES128, XTS, NO_PADDING
            byte[] key = new byte[32];
            for (int i = 0; i < 16; i++) key[i] = 0x11;
            for (int i = 16; i < 32; i++) key[i] = 0x22;
            byte[] iv = new byte[16];
            for (int i = 0; i < 5; i++) iv[i] = 0x33;
            byte[] pt = new byte[32];
            for (int i = 0; i < 32; i++) pt[i] = 0x44;
            byte[] expectedCt = parseHex(
                    "c454185e6a16936e39334038acef838bfb186fff7480adc4289382ecd6d394f0");

            Assertions.assertEquals(0, blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, key, iv, 0));

            byte[] ct = new byte[32];
            int produced = blockCipherNI.update(ref, ct, 0, pt, 0, 32);
            int finalProduced = blockCipherNI.doFinal(ref, ct, produced);

            Assertions.assertEquals(32, produced + finalProduced);
            Assertions.assertArrayEquals(expectedCt, ct);
        }
        finally
        {
            blockCipherNI.dispose(ref);
        }
    }

    @Test
    public void testAes256Xts_kat() throws Exception
    {
        // Regression KAT for AES-256-XTS. Inputs are deterministic byte
        // patterns; the expected ciphertext was computed against the
        // bundled OpenSSL via EVP_aes_256_xts() and pinned here. Failure
        // means either our wrapper or the linked OpenSSL diverged from
        // the value at the time of authoring.
        //
        //   K1     = bytes 0..31
        //   K2     = bytes 32..63
        //   tweak  = bytes 100..115
        //   pt[i]  = (i*3 + 7) & 0xff,  32 bytes
        //   ct     = a7399efea2c66376055c1acd97933a8c6ac8dd3005f3396c3959b3ad323a3db4
        long encRef = 0, decRef = 0;
        try
        {
            byte[] key = new byte[64];
            for (int i = 0; i < 64; i++) key[i] = (byte) i;
            byte[] iv = new byte[16];
            for (int i = 0; i < 16; i++) iv[i] = (byte) (i + 100);
            byte[] pt = new byte[32];
            for (int i = 0; i < 32; i++) pt[i] = (byte) (i * 3 + 7);
            byte[] expectedCt = parseHex(
                    "a7399efea2c66376055c1acd97933a8c6ac8dd3005f3396c3959b3ad323a3db4");

            // Encrypt: KAT.
            encRef = blockCipherNI.makeInstance(10, 11, 0); // AES256, XTS
            Assertions.assertEquals(0, blockCipherNI.init(encRef, Cipher.ENCRYPT_MODE, key, iv, 0));
            byte[] ct = new byte[32];
            int produced = blockCipherNI.update(encRef, ct, 0, pt, 0, 32);
            int finalProduced = blockCipherNI.doFinal(encRef, ct, produced);
            Assertions.assertEquals(32, produced + finalProduced);
            Assertions.assertArrayEquals(expectedCt, ct);

            // Decrypt: round-trip back to plaintext.
            decRef = blockCipherNI.makeInstance(10, 11, 0);
            Assertions.assertEquals(0, blockCipherNI.init(decRef, Cipher.DECRYPT_MODE, key, iv, 0));
            byte[] decrypted = new byte[32];
            int dProduced = blockCipherNI.update(decRef, decrypted, 0, ct, 0, 32);
            int dFinal = blockCipherNI.doFinal(decRef, decrypted, dProduced);
            Assertions.assertEquals(32, dProduced + dFinal);
            Assertions.assertArrayEquals(pt, decrypted);
        }
        finally
        {
            blockCipherNI.dispose(encRef);
            blockCipherNI.dispose(decRef);
        }
    }

    @Test
    public void testAes128Xts_invalidKeyLen() throws Exception
    {
        // XTS now requires a 32-byte key for AES-128. A 16-byte key (the
        // pre-fix accepted length) must now be rejected.
        long ref = 0;
        try
        {
            ref = blockCipherNI.makeInstance(8, 11, 0); // AES128, XTS
            blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, new byte[16], new byte[16], 0);
            Assertions.fail("expected invalid key length");
        }
        catch (InvalidKeyException ex)
        {
            Assertions.assertEquals("invalid key length", ex.getMessage());
        }
        finally
        {
            blockCipherNI.dispose(ref);
        }
    }

    @Test
    public void testGcmTag_naturallyInvalid() throws Exception
    {
        // End-to-end natural tag-failure path (no OPS): encrypt, flip a tag
        // byte, decrypt. Verifies AEADBadTagException is raised AND the
        // doFinal output buffer is OPENSSL_cleanse'd to zeros (best-effort
        // plaintext scrubbing on tag failure).
        long encRef = 0, decRef = 0;
        try
        {
            byte[] key = new byte[16];
            byte[] iv = new byte[12];
            for (int i = 0; i < 16; i++) key[i] = (byte) i;
            for (int i = 0; i < 12; i++) iv[i] = (byte) (i + 100);

            // Encrypt 16 bytes of plaintext → 16 bytes ciphertext + 16 bytes tag.
            encRef = blockCipherNI.makeInstance(8, 8, 0); // AES128, GCM
            blockCipherNI.init(encRef, Cipher.ENCRYPT_MODE, key, iv, 16);

            byte[] plaintext = new byte[16];
            for (int i = 0; i < 16; i++) plaintext[i] = (byte) (i + 1);

            byte[] ctAndTag = new byte[32];
            int produced = blockCipherNI.update(encRef, ctAndTag, 0, plaintext, 0, 16);
            int finalProduced = blockCipherNI.doFinal(encRef, ctAndTag, produced);
            Assertions.assertEquals(32, produced + finalProduced);

            // Flip the last (tag) byte to invalidate the tag.
            ctAndTag[31] ^= (byte) 0xFF;

            // Decrypt path: feed corrupted ct+tag, doFinal should reject.
            decRef = blockCipherNI.makeInstance(8, 8, 0);
            blockCipherNI.init(decRef, Cipher.DECRYPT_MODE, key, iv, 16);

            byte[] plaintextOut = new byte[16];
            blockCipherNI.update(decRef, plaintextOut, 0, ctAndTag, 0, 32);

            // Pre-fill the doFinal output buffer with sentinel bytes; the
            // cleanse path should zero them out on tag failure.
            byte[] finalOut = new byte[16];
            for (int i = 0; i < 16; i++) finalOut[i] = (byte) 0xAA;

            try
            {
                blockCipherNI.doFinal(decRef, finalOut, 0);
                Assertions.fail("expected tag failure");
            }
            catch (BadPaddingException ex)
            {
                Assertions.assertEquals("bad tag", ex.getMessage());
            }

            // Verify the cleanse fired — every byte of finalOut should be 0.
            for (int i = 0; i < 16; i++)
            {
                Assertions.assertEquals(0, finalOut[i], "finalOut[" + i + "] not cleansed");
            }
        }
        finally
        {
            blockCipherNI.dispose(encRef);
            blockCipherNI.dispose(decRef);
        }
    }

}
