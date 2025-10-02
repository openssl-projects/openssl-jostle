package org.openssl.jostle.test.crypto;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.jcajce.provider.BlockCipherNI;
import org.openssl.jostle.jcajce.provider.ErrorCode;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.util.ArrayList;
import java.util.List;

/**
 * Tests for triggering error codes mostly
 */
public class BlockCipherLimitTest
{

    static
    {
        CryptoServicesRegistrar.isNativeAvailable(); // Trigger Loading
    }

    BlockCipherNI blockCipherNI = TestNISelector.getBlockCipher();


    @Test
    public void BlockCipher_keyIsNull() throws Exception
    {
        long ref = 0;
        try
        {
            ref = blockCipherNI.makeInstance(8, 1, 1); // AES128, CBC, 1
            int code = blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, null, new byte[16], 0);
            BlockCipherNI.handleInitErrorCodes(ErrorCode.forCode(code), 0, 16);
            Assertions.fail("expected exception");
        } catch (Exception e)
        {
            Assertions.assertTrue(e instanceof InvalidKeyException);
            Assertions.assertEquals("key is null", e.getMessage());
        } finally
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
            BlockCipherNI.handleInitErrorCodes(ErrorCode.forCode(code), 0, 16);
            Assertions.fail("expected exception");
        } catch (Exception e)
        {
            Assertions.assertTrue(e instanceof InvalidAlgorithmParameterException);
            Assertions.assertEquals("mode takes no iv", e.getMessage());
        } finally
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
            BlockCipherNI.handleInitErrorCodes(ErrorCode.forCode(code), 0, 16);
            Assertions.fail("expected exception");
        } catch (Exception e)
        {
            Assertions.assertTrue(e instanceof InvalidAlgorithmParameterException);
            Assertions.assertEquals("iv is null", e.getMessage());
        } finally
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
            BlockCipherNI.handleInitErrorCodes(ErrorCode.forCode(code), 0, 16);
            Assertions.fail("expected exception");
        } catch (Exception e)
        {
            Assertions.assertTrue(e instanceof InvalidAlgorithmParameterException);
            Assertions.assertEquals("iv is null", e.getMessage());
        } finally
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
            BlockCipherNI.handleInitErrorCodes(ErrorCode.forCode(code), 0, 16);
            Assertions.fail("expected exception");
        } catch (Exception e)
        {
            Assertions.assertTrue(e instanceof IllegalStateException);
            Assertions.assertEquals("cipher not supported", e.getMessage());
        } finally
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
                add(new InitParamTestVector("AES128 incorrect key short", 8, 0, 1, new byte[15], null, InvalidKeyException.class, "key length 15 is invalid"));
                add(new InitParamTestVector("AES128 correct key", 8, 0, 1, new byte[16], null));
                add(new InitParamTestVector("AES128 incorrect key long", 8, 0, 1, new byte[17], null, InvalidKeyException.class, "key length 17 is invalid"));

                add(new InitParamTestVector("AES192 incorrect key short", 9, 0, 1, new byte[23], null, InvalidKeyException.class, "key length 23 is invalid"));
                add(new InitParamTestVector("AES192 correct key", 9, 0, 1, new byte[24], null));
                add(new InitParamTestVector("AES192 incorrect key long", 9, 0, 1, new byte[25], null, InvalidKeyException.class, "key length 25 is invalid"));

                add(new InitParamTestVector("AES256 incorrect key short", 10, 0, 1, new byte[31], null, InvalidKeyException.class, "key length 31 is invalid"));
                add(new InitParamTestVector("AES256 correct key", 10, 0, 1, new byte[32], null));
                add(new InitParamTestVector("AES256 incorrect key long", 10, 0, 1, new byte[33], null, InvalidKeyException.class, "key length 33 is invalid"));

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
                    add(new InitParamTestVector(String.format("AES %d short IV CBC", key.length * 8), cipher, 1, 1, key, new byte[15], InvalidAlgorithmParameterException.class, "iv len is invalid: 15"));
                    add(new InitParamTestVector(String.format("AES %d long IV CBC", key.length * 8), cipher, 1, 1, key, new byte[17], InvalidAlgorithmParameterException.class, "iv len is invalid: 17"));
                    add(new InitParamTestVector(String.format("AES %d okay IV CBC", key.length * 8), cipher, 1, 1, key, new byte[16]));

                    // CFB1
                    add(new InitParamTestVector(String.format("AES %d null IV CFB1", key.length * 8), cipher, 2, 1, key, null, InvalidAlgorithmParameterException.class, "iv is null"));
                    add(new InitParamTestVector(String.format("AES %d short IV CFB1", key.length * 8), cipher, 2, 1, key, new byte[15], InvalidAlgorithmParameterException.class, "iv len is invalid: 15"));
                    add(new InitParamTestVector(String.format("AES %d long IV CFB1", key.length * 8), cipher, 2, 1, key, new byte[17], InvalidAlgorithmParameterException.class, "iv len is invalid: 17"));
                    add(new InitParamTestVector(String.format("AES %d okay IV CFB1", key.length * 8), cipher, 2, 1, key, new byte[16]));

                    // CFB8
                    add(new InitParamTestVector(String.format("AES %d null IV CFB8", key.length * 8), cipher, 3, 1, key, null, InvalidAlgorithmParameterException.class, "iv is null"));
                    add(new InitParamTestVector(String.format("AES %d short IV CFB8", key.length * 8), cipher, 3, 1, key, new byte[15], InvalidAlgorithmParameterException.class, "iv len is invalid: 15"));
                    add(new InitParamTestVector(String.format("AES %d long IV CFB8", key.length * 8), cipher, 3, 1, key, new byte[17], InvalidAlgorithmParameterException.class, "iv len is invalid: 17"));
                    add(new InitParamTestVector(String.format("AES %d okay IV CFB8", key.length * 8), cipher, 3, 1, key, new byte[16]));


                    // CFB128
                    add(new InitParamTestVector(String.format("AES %d null IV CFB128", key.length * 8), cipher, 5, 1, key, null, InvalidAlgorithmParameterException.class, "iv is null"));
                    add(new InitParamTestVector(String.format("AES %d short IV CFB128", key.length * 8), cipher, 5, 1, key, new byte[15], InvalidAlgorithmParameterException.class, "iv len is invalid: 15"));
                    add(new InitParamTestVector(String.format("AES %d long IV CFB128", key.length * 8), cipher, 5, 1, key, new byte[17], InvalidAlgorithmParameterException.class, "iv len is invalid: 17"));
                    add(new InitParamTestVector(String.format("AES %d okay IV CFB128", key.length * 8), cipher, 5, 1, key, new byte[16]));


                    // OFB
                    add(new InitParamTestVector(String.format("AES %d null IV OFB", key.length * 8), cipher, 9, 1, key, null, InvalidAlgorithmParameterException.class, "iv is null"));
                    add(new InitParamTestVector(String.format("AES %d short IV OFB", key.length * 8), cipher, 9, 1, key, new byte[15], InvalidAlgorithmParameterException.class, "iv len is invalid: 15"));
                    add(new InitParamTestVector(String.format("AES %d long IV OFB", key.length * 8), cipher, 9, 1, key, new byte[17], InvalidAlgorithmParameterException.class, "iv len is invalid: 17"));
                    add(new InitParamTestVector(String.format("AES %d okay IV OFB", key.length * 8), cipher, 9, 1, key, new byte[16]));


                    // CTR Valid
                    add(new InitParamTestVector(String.format("AES %d long IV (null) CTR", key.length * 8), cipher, 6, 1, key, null, InvalidAlgorithmParameterException.class, "iv is null"));
                    for (int ivLen : new int[]{1, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17})
                    {
                        if (ivLen < 8 || ivLen > 16)
                        {
                            add(new InitParamTestVector(String.format("AES %d long IV (%d) CTR", key.length * 8, ivLen), cipher, 6, 1, key, new byte[ivLen], InvalidAlgorithmParameterException.class, "iv len is invalid: " + ivLen));
                        } else
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
                BlockCipherNI.handleInitErrorCodes(ErrorCode.forCode(code), test.key != null ? test.key.length : 0, test.iv != null ? test.iv.length : 0);

                if (!test.passing)
                {
                    Assertions.fail(test.name + " failed");
                }
            } catch (Exception e)
            {
                Assertions.assertSame(test.expectedExceptionClass, e.getClass(), test.name + ": Expected '" + test.expectedExceptionClass + "' but got '" + e.getClass().getName() + "'");
                Assertions.assertEquals(test.expectedExceptionMessage, e.getMessage(), test.name + ": Expected '" + test.expectedExceptionMessage + "' but got '" + e.getMessage() + "'");
            } finally
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
                add(new InitParamTestVector("ARIA128 incorrect key short", 11, 0, 1, new byte[15], null, InvalidKeyException.class, "key length 15 is invalid"));
                add(new InitParamTestVector("ARIA128 correct key", 11, 0, 1, new byte[16], null));
                add(new InitParamTestVector("ARIA128 incorrect key long", 11, 0, 1, new byte[17], null, InvalidKeyException.class, "key length 17 is invalid"));

                add(new InitParamTestVector("ARIA192 incorrect key short", 12, 0, 1, new byte[23], null, InvalidKeyException.class, "key length 23 is invalid"));
                add(new InitParamTestVector("ARIA192 correct key", 12, 0, 1, new byte[24], null));
                add(new InitParamTestVector("ARIA192 incorrect key long", 12, 0, 1, new byte[25], null, InvalidKeyException.class, "key length 25 is invalid"));

                add(new InitParamTestVector("ARIA256 incorrect key short", 13, 0, 1, new byte[31], null, InvalidKeyException.class, "key length 31 is invalid"));
                add(new InitParamTestVector("ARIA256 correct key", 13, 0, 1, new byte[32], null));
                add(new InitParamTestVector("ARIA256 incorrect key long", 13, 0, 1, new byte[33], null, InvalidKeyException.class, "key length 33 is invalid"));

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
                    add(new InitParamTestVector(String.format("ARIA %d short IV CBC", key.length * 8), cipher, 1, 1, key, new byte[15], InvalidAlgorithmParameterException.class, "iv len is invalid: 15"));
                    add(new InitParamTestVector(String.format("ARIA %d long IV CBC", key.length * 8), cipher, 1, 1, key, new byte[17], InvalidAlgorithmParameterException.class, "iv len is invalid: 17"));
                    add(new InitParamTestVector(String.format("ARIA %d okay IV CBC", key.length * 8), cipher, 1, 1, key, new byte[16]));

                    // CFB1

                    add(new InitParamTestVector(String.format("ARIA %d null IV CFB1", key.length * 8), cipher, 2, 1, key, null, InvalidAlgorithmParameterException.class, "iv is null"));
                    add(new InitParamTestVector(String.format("ARIA %d short IV CFB1", key.length * 8), cipher, 2, 1, key, new byte[15], InvalidAlgorithmParameterException.class, "iv len is invalid: 15"));
                    add(new InitParamTestVector(String.format("ARIA %d long IV CFB1", key.length * 8), cipher, 2, 1, key, new byte[17], InvalidAlgorithmParameterException.class, "iv len is invalid: 17"));
                    add(new InitParamTestVector(String.format("ARIA %d okay IV CFB1", key.length * 8), cipher, 2, 1, key, new byte[16]));

                    // CFB8
                    add(new InitParamTestVector(String.format("ARIA %d null IV CFB8", key.length * 8), cipher, 3, 1, key, null, InvalidAlgorithmParameterException.class, "iv is null"));
                    add(new InitParamTestVector(String.format("ARIA %d short IV CFB8", key.length * 8), cipher, 3, 1, key, new byte[15], InvalidAlgorithmParameterException.class, "iv len is invalid: 15"));
                    add(new InitParamTestVector(String.format("ARIA %d long IV CFB8", key.length * 8), cipher, 3, 1, key, new byte[17], InvalidAlgorithmParameterException.class, "iv len is invalid: 17"));
                    add(new InitParamTestVector(String.format("ARIA %d okay IV CFB8", key.length * 8), cipher, 3, 1, key, new byte[16]));


                    // CFB128
                    add(new InitParamTestVector(String.format("ARIA %d null IV CFB128", key.length * 8), cipher, 5, 1, key, null, InvalidAlgorithmParameterException.class, "iv is null"));
                    add(new InitParamTestVector(String.format("ARIA %d short IV CFB128", key.length * 8), cipher, 5, 1, key, new byte[15], InvalidAlgorithmParameterException.class, "iv len is invalid: 15"));
                    add(new InitParamTestVector(String.format("ARIA %d long IV CFB128", key.length * 8), cipher, 5, 1, key, new byte[17], InvalidAlgorithmParameterException.class, "iv len is invalid: 17"));
                    add(new InitParamTestVector(String.format("ARIA %d okay IV CFB128", key.length * 8), cipher, 5, 1, key, new byte[16]));

                    // CTR Valid
                    add(new InitParamTestVector(String.format("ARIA %d long IV (null) CTR", key.length * 8), cipher, 6, 1, key, null, InvalidAlgorithmParameterException.class, "iv is null"));
                    for (int ivLen : new int[]{1, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17})
                    {
                        if (ivLen < 8 || ivLen > 16)
                        {
                            add(new InitParamTestVector(String.format("ARIA %d long IV (%d) CTR", key.length * 8, ivLen), cipher, 6, 1, key, new byte[ivLen], InvalidAlgorithmParameterException.class, "iv len is invalid: " + ivLen));
                        } else
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
                BlockCipherNI.handleInitErrorCodes(ErrorCode.forCode(code), test.key != null ? test.key.length : 0, test.iv != null ? test.iv.length : 0);

                if (!test.passing)
                {
                    Assertions.fail(test.name + " failed");
                }
            } catch (Exception e)
            {
                Assertions.assertSame(test.expectedExceptionClass, e.getClass(), test.name + ": Expected '" + test.expectedExceptionClass + "' but got '" + e.getClass().getName() + "'");
                Assertions.assertEquals(test.expectedExceptionMessage, e.getMessage(), test.name + ": Expected '" + test.expectedExceptionMessage + "' but got '" + e.getMessage() + "'");
            } finally
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
                add(new InitParamTestVector("CAMELLIA128 incorrect key short", 14, 0, 1, new byte[15], null, InvalidKeyException.class, "key length 15 is invalid"));
                add(new InitParamTestVector("CAMELLIA128 correct key", 14, 0, 1, new byte[16], null));
                add(new InitParamTestVector("CAMELLIA128 incorrect key long", 14, 0, 1, new byte[17], null, InvalidKeyException.class, "key length 17 is invalid"));

                add(new InitParamTestVector("CAMELLIA192 incorrect key short", 15, 0, 1, new byte[23], null, InvalidKeyException.class, "key length 23 is invalid"));
                add(new InitParamTestVector("CAMELLIA192 correct key", 15, 0, 1, new byte[24], null));
                add(new InitParamTestVector("CAMELLIA192 incorrect key long", 15, 0, 1, new byte[25], null, InvalidKeyException.class, "key length 25 is invalid"));

                add(new InitParamTestVector("CAMELLIA256 incorrect key short", 16, 0, 1, new byte[31], null, InvalidKeyException.class, "key length 31 is invalid"));
                add(new InitParamTestVector("CAMELLIA256 correct key", 16, 0, 1, new byte[32], null));
                add(new InitParamTestVector("CAMELLIA256 incorrect key long", 16, 0, 1, new byte[33], null, InvalidKeyException.class, "key length 33 is invalid"));

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
                    add(new InitParamTestVector(String.format("CAMELLIA %d short IV CBC", key.length * 8), cipher, 1, 1, key, new byte[15], InvalidAlgorithmParameterException.class, "iv len is invalid: 15"));
                    add(new InitParamTestVector(String.format("CAMELLIA %d long IV CBC", key.length * 8), cipher, 1, 1, key, new byte[17], InvalidAlgorithmParameterException.class, "iv len is invalid: 17"));
                    add(new InitParamTestVector(String.format("CAMELLIA %d okay IV CBC", key.length * 8), cipher, 1, 1, key, new byte[16]));

                    // CFB1
                    add(new InitParamTestVector(String.format("CAMELLIA %d null IV CFB1", key.length * 8), cipher, 2, 1, key, null, InvalidAlgorithmParameterException.class, "iv is null"));
                    add(new InitParamTestVector(String.format("CAMELLIA %d short IV CFB1", key.length * 8), cipher, 2, 1, key, new byte[15], InvalidAlgorithmParameterException.class, "iv len is invalid: 15"));
                    add(new InitParamTestVector(String.format("CAMELLIA %d long IV CFB1", key.length * 8), cipher, 2, 1, key, new byte[17], InvalidAlgorithmParameterException.class, "iv len is invalid: 17"));
                    add(new InitParamTestVector(String.format("CAMELLIA %d okay IV CFB1", key.length * 8), cipher, 2, 1, key, new byte[16]));


                    // CFB8
                    add(new InitParamTestVector(String.format("CAMELLIA %d null IV CFB8", key.length * 8), cipher, 3, 1, key, null, InvalidAlgorithmParameterException.class, "iv is null"));
                    add(new InitParamTestVector(String.format("CAMELLIA %d short IV CFB8", key.length * 8), cipher, 3, 1, key, new byte[15], InvalidAlgorithmParameterException.class, "iv len is invalid: 15"));
                    add(new InitParamTestVector(String.format("CAMELLIA %d long IV CFB8", key.length * 8), cipher, 3, 1, key, new byte[17], InvalidAlgorithmParameterException.class, "iv len is invalid: 17"));
                    add(new InitParamTestVector(String.format("CAMELLIA %d okay IV CFB8", key.length * 8), cipher, 3, 1, key, new byte[16]));


                    // CFB128
                    add(new InitParamTestVector(String.format("CAMELLIA %d null IV CFB128", key.length * 8), cipher, 5, 1, key, null, InvalidAlgorithmParameterException.class, "iv is null"));
                    add(new InitParamTestVector(String.format("CAMELLIA %d short IV CFB128", key.length * 8), cipher, 5, 1, key, new byte[15], InvalidAlgorithmParameterException.class, "iv len is invalid: 15"));
                    add(new InitParamTestVector(String.format("CAMELLIA %d long IV CFB128", key.length * 8), cipher, 5, 1, key, new byte[17], InvalidAlgorithmParameterException.class, "iv len is invalid: 17"));
                    add(new InitParamTestVector(String.format("CAMELLIA %d okay IV CFB128", key.length * 8), cipher, 5, 1, key, new byte[16]));

                    // OFB
                    add(new InitParamTestVector(String.format("CAMELLIA %d null IV OFB", key.length * 8), cipher, 9, 1, key, null, InvalidAlgorithmParameterException.class, "iv is null"));
                    add(new InitParamTestVector(String.format("CAMELLIA %d short IV OFB", key.length * 8), cipher, 9, 1, key, new byte[15], InvalidAlgorithmParameterException.class, "iv len is invalid: 15"));
                    add(new InitParamTestVector(String.format("CAMELLIA %d long IV OFB", key.length * 8), cipher, 9, 1, key, new byte[17], InvalidAlgorithmParameterException.class, "iv len is invalid: 17"));
                    add(new InitParamTestVector(String.format("CAMELLIA %d okay IV OFB", key.length * 8), cipher, 9, 1, key, new byte[16]));


                    // CTR Valid
                    add(new InitParamTestVector(String.format("CAMELLIA %d long IV (null) CTR", key.length * 8), cipher, 6, 1, key, null, InvalidAlgorithmParameterException.class, "iv is null"));
                    for (int ivLen : new int[]{1, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17})
                    {
                        if (ivLen < 8 || ivLen > 16)
                        {
                            add(new InitParamTestVector(String.format("CAMELLIA %d long IV (%d) CTR", key.length * 8, ivLen), cipher, 6, 1, key, new byte[ivLen], InvalidAlgorithmParameterException.class, "iv len is invalid: " + ivLen));
                        } else
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
                int code = blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, test.key, test.iv, 0);
                BlockCipherNI.handleInitErrorCodes(ErrorCode.forCode(code), test.key != null ? test.key.length : 0, test.iv != null ? test.iv.length : 0);

                if (!test.passing)
                {
                    Assertions.fail(test.name + " failed");
                }
            } catch (Exception e)
            {
                Assertions.assertSame(test.expectedExceptionClass, e.getClass(), test.name + ": Expected '" + test.expectedExceptionClass + "' but got '" + e.getClass().getName() + "'");
                Assertions.assertEquals(test.expectedExceptionMessage, e.getMessage(), test.name + ": Expected '" + test.expectedExceptionMessage + "' but got '" + e.getMessage() + "'");
            } finally
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
                add(new InitParamTestVector("SM4 incorrect key short", 20, 0, 1, new byte[15], null, InvalidKeyException.class, "key length 15 is invalid"));
                add(new InitParamTestVector("SM4 correct key", 20, 0, 1, new byte[16], null));
                add(new InitParamTestVector("SM4 incorrect key long", 20, 0, 1, new byte[17], null, InvalidKeyException.class, "key length 17 is invalid"));

                for (int cipher : new int[]{20})
                {
                    byte[] key = new byte[16];

                    // Invalid mode
                    add(new InitParamTestVector(String.format("SM4 %d invalid mode", key.length * 8), cipher, 100, 1, key, new byte[15], InvalidAlgorithmParameterException.class, "mode not supported for cipher"));

                    // CBC
                    add(new InitParamTestVector(String.format("SM4 %d null IV CBC", key.length * 8), cipher, 1, 1, key, null, InvalidAlgorithmParameterException.class, "iv is null"));
                    add(new InitParamTestVector(String.format("SM4 %d short IV CBC", key.length * 8), cipher, 1, 1, key, new byte[15], InvalidAlgorithmParameterException.class, "iv len is invalid: 15"));
                    add(new InitParamTestVector(String.format("SM4 %d long IV CBC", key.length * 8), cipher, 1, 1, key, new byte[17], InvalidAlgorithmParameterException.class, "iv len is invalid: 17"));
                    add(new InitParamTestVector(String.format("SM4 %d okay IV CBC", key.length * 8), cipher, 1, 1, key, new byte[16]));

                    // CFB128
                    add(new InitParamTestVector(String.format("SM4 %d null IV CFB128", key.length * 8), cipher, 5, 1, key, null, InvalidAlgorithmParameterException.class, "iv is null"));
                    add(new InitParamTestVector(String.format("SM4 %d short IV CFB128", key.length * 8), cipher, 5, 1, key, new byte[15], InvalidAlgorithmParameterException.class, "iv len is invalid: 15"));
                    add(new InitParamTestVector(String.format("SM4 %d long IV CFB128", key.length * 8), cipher, 5, 1, key, new byte[17], InvalidAlgorithmParameterException.class, "iv len is invalid: 17"));
                    add(new InitParamTestVector(String.format("SM4 %d okay IV CFB128", key.length * 8), cipher, 5, 1, key, new byte[16]));

                    // OFB
                    add(new InitParamTestVector(String.format("SM4 %d null IV OFB", key.length * 8), cipher, 9, 1, key, null, InvalidAlgorithmParameterException.class, "iv is null"));
                    add(new InitParamTestVector(String.format("SM4 %d short IV OFB", key.length * 8), cipher, 9, 1, key, new byte[15], InvalidAlgorithmParameterException.class, "iv len is invalid: 15"));
                    add(new InitParamTestVector(String.format("SM4 %d long IV OFB", key.length * 8), cipher, 9, 1, key, new byte[17], InvalidAlgorithmParameterException.class, "iv len is invalid: 17"));
                    add(new InitParamTestVector(String.format("SM4 %d okay IV OFB", key.length * 8), cipher, 9, 1, key, new byte[16]));

                    add(new InitParamTestVector(String.format("SM4 %d long IV (null) CTR", key.length * 8), cipher, 6, 1, key, null, InvalidAlgorithmParameterException.class, "iv is null"));
                    for (int ivLen : new int[]{1, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17})
                    {
                        if (ivLen < 8 || ivLen > 16)
                        {
                            add(new InitParamTestVector(String.format("SM4 %d long IV (%d) CTR", key.length * 8, ivLen), cipher, 6, 1, key, new byte[ivLen], InvalidAlgorithmParameterException.class, "iv len is invalid: " + ivLen));
                        } else
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
                BlockCipherNI.handleInitErrorCodes(ErrorCode.forCode(code), test.key != null ? test.key.length : 0, test.iv != null ? test.iv.length : 0);

                if (!test.passing)
                {
                    Assertions.fail(test.name + " failed");
                }
            } catch (Exception e)
            {
                Assertions.assertSame(e.getClass(), test.expectedExceptionClass, test.name + ": Expected '" + test.expectedExceptionClass + "' but got '" + e.getClass().getName() + "' " + e.getMessage());
                Assertions.assertEquals(test.expectedExceptionMessage, e.getMessage(), test.name + ": Expected '" + test.expectedExceptionMessage + "' but got '" + e.getMessage() + "'");
            } finally
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
            BlockCipherNI.handleInitErrorCodes(ErrorCode.forCode(code), 16, 16);

            code = blockCipherNI.update(ref, output, outOff, input, inOff, inLen);
            BlockCipherNI.handleUpdateErrorCodes(ErrorCode.forCode(code));

            Assertions.fail("expected exception");

        } catch (Exception e)
        {
            Assertions.assertSame(IllegalArgumentException.class, e.getClass(), "unexpected exception class");
            Assertions.assertEquals("input is null", e.getMessage(), "unexpected exception message");
        } finally
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
            BlockCipherNI.handleInitErrorCodes(ErrorCode.forCode(code), 16, 16);

            code = blockCipherNI.update(ref, output, outOff, input, inOff, inLen);
            BlockCipherNI.handleUpdateErrorCodes(ErrorCode.forCode(code));

            Assertions.fail("expected exception");

        } catch (Exception e)
        {
            Assertions.assertSame(IllegalArgumentException.class, e.getClass(), "unexpected exception class");
            Assertions.assertEquals("output is null", e.getMessage(), "unexpected exception message");
        } finally
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
            BlockCipherNI.handleInitErrorCodes(ErrorCode.forCode(code), 16, 16);

            code = blockCipherNI.update(ref, output, outOff, input, inOff, inLen);
            BlockCipherNI.handleUpdateErrorCodes(ErrorCode.forCode(code));

            Assertions.fail("expected exception");

        } catch (Exception e)
        {
            Assertions.assertSame(IllegalArgumentException.class, e.getClass(), "unexpected exception class");
            Assertions.assertEquals("output offset is negative", e.getMessage(), "unexpected exception message");
        } finally
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
            BlockCipherNI.handleInitErrorCodes(ErrorCode.forCode(code), 16, 16);

            code = blockCipherNI.update(ref, output, outOff, input, inOff, inLen);
            BlockCipherNI.handleUpdateErrorCodes(ErrorCode.forCode(code));

            Assertions.fail("expected exception");

        } catch (Exception e)
        {
            Assertions.assertSame(IllegalArgumentException.class, e.getClass(), "unexpected exception class");
            Assertions.assertEquals("input offset is negative", e.getMessage(), "unexpected exception message");
        } finally
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
            BlockCipherNI.handleInitErrorCodes(ErrorCode.forCode(code), 16, 16);

            code = blockCipherNI.update(ref, output, outOff, input, inOff, inLen);
            BlockCipherNI.handleUpdateErrorCodes(ErrorCode.forCode(code));

            Assertions.fail("expected exception");

        } catch (Exception e)
        {
            Assertions.assertSame(IllegalArgumentException.class, e.getClass(), "unexpected exception class");
            Assertions.assertEquals("input length is negative", e.getMessage(), "unexpected exception message");
        } finally
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
            int code = blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, new byte[16], new byte[16], 0);
            BlockCipherNI.handleInitErrorCodes(ErrorCode.forCode(code), 16, 16);

            code = blockCipherNI.update(ref, output, outOff, input, inOff, inLen);
            BlockCipherNI.handleUpdateErrorCodes(ErrorCode.forCode(code));

            Assertions.fail("expected exception");

        } catch (Exception e)
        {
            Assertions.assertSame(IllegalArgumentException.class, e.getClass(), "unexpected exception class");
            Assertions.assertEquals("input out of range", e.getMessage(), "unexpected exception message");
        } finally
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
            int code = blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, new byte[16], new byte[16], 0);
            BlockCipherNI.handleInitErrorCodes(ErrorCode.forCode(code), 16, 16);

            code = blockCipherNI.update(ref, output, outOff, input, inOff, inLen);
            BlockCipherNI.handleUpdateErrorCodes(ErrorCode.forCode(code));

            Assertions.fail("expected exception");

        } catch (Exception e)
        {
            Assertions.assertSame(IllegalArgumentException.class, e.getClass(), "unexpected exception class");
            Assertions.assertEquals("input out of range", e.getMessage(), "unexpected exception message");
        } finally
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
            int code = blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, new byte[16], new byte[16], 0);
            BlockCipherNI.handleInitErrorCodes(ErrorCode.forCode(code), 16, 16);

            code = blockCipherNI.update(ref, output, outOff, input, inOff, inLen);
            BlockCipherNI.handleUpdateErrorCodes(ErrorCode.forCode(code));

            Assertions.fail("expected exception");

        } catch (Exception e)
        {
            Assertions.assertSame(ShortBufferException.class, e.getClass(), "unexpected exception class");
            Assertions.assertEquals("output out of range", e.getMessage(), "unexpected exception message");
        } finally
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
            int code = blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, new byte[16], new byte[16], 0);
            BlockCipherNI.handleInitErrorCodes(ErrorCode.forCode(code), 16, 16);

            code = blockCipherNI.update(ref, output, outOff, input, inOff, inLen);
            BlockCipherNI.handleUpdateErrorCodes(ErrorCode.forCode(code));

            Assertions.fail("expected exception");

        } catch (Exception e)
        {
            Assertions.assertSame(IllegalBlockSizeException.class, e.getClass(), "unexpected exception class");
            Assertions.assertEquals("data not block size aligned", e.getMessage(), "unexpected exception message");
        } finally
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
            int code = blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, new byte[16], new byte[16], 0);
            BlockCipherNI.handleInitErrorCodes(ErrorCode.forCode(code), 16, 16);

            code = blockCipherNI.update(ref, output, outOff, input, inOff, inLen);
            BlockCipherNI.handleUpdateErrorCodes(ErrorCode.forCode(code));

            Assertions.fail("expected exception");

        } catch (Exception e)
        {
            Assertions.assertSame(ShortBufferException.class, e.getClass(), "unexpected exception class");
            Assertions.assertEquals("output too small", e.getMessage(), "unexpected exception message");
        } finally
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
            int code = blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, new byte[16], new byte[16], 0);
            BlockCipherNI.handleInitErrorCodes(ErrorCode.forCode(code), 16, 16);

            code = blockCipherNI.update(ref, output, outOff, input, inOff, inLen);
            BlockCipherNI.handleUpdateErrorCodes(ErrorCode.forCode(code));

            Assertions.fail("expected exception");

        } catch (Exception e)
        {
            Assertions.assertSame(ShortBufferException.class, e.getClass(), "unexpected exception class");
            Assertions.assertEquals("output too small", e.getMessage(), "unexpected exception message");
        } finally
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
            int code = blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, new byte[16], new byte[16], 0);
            BlockCipherNI.handleInitErrorCodes(ErrorCode.forCode(code), 16, 16);

            code = blockCipherNI.update(ref, output, outOff, input, inOff, inLen);
            BlockCipherNI.handleUpdateErrorCodes(ErrorCode.forCode(code));

            Assertions.fail("expected exception");

        } catch (Exception e)
        {
            Assertions.assertSame(ShortBufferException.class, e.getClass(), "unexpected exception class");
            Assertions.assertEquals("output too small", e.getMessage(), "unexpected exception message");
        } finally
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
            int code = blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, new byte[16], new byte[16], 0);
            BlockCipherNI.handleInitErrorCodes(ErrorCode.forCode(code), 16, 16);

            code = blockCipherNI.doFinal(ref, output, outOff);
            BlockCipherNI.handleFinalErrorCodes(ErrorCode.forCode(code));

            Assertions.fail("expected exception");

        } catch (Exception e)
        {
            Assertions.assertSame(IllegalArgumentException.class, e.getClass(), "unexpected exception class");
            Assertions.assertEquals("output is null", e.getMessage(), "unexpected exception message");
        } finally
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
            int code = blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, new byte[16], new byte[16], 0);
            BlockCipherNI.handleInitErrorCodes(ErrorCode.forCode(code), 16, 16);

            code = blockCipherNI.doFinal(ref, output, outOff);
            BlockCipherNI.handleFinalErrorCodes(ErrorCode.forCode(code));

            Assertions.fail("expected exception");

        } catch (Exception e)
        {
            Assertions.assertSame(IllegalArgumentException.class, e.getClass(), "unexpected exception class");
            Assertions.assertEquals("output offset is negative", e.getMessage(), "unexpected exception message");
        } finally
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
            int code = blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, new byte[16], new byte[16], 0);
            BlockCipherNI.handleInitErrorCodes(ErrorCode.forCode(code), 16, 16);

            code = blockCipherNI.doFinal(ref, output, outOff);
            BlockCipherNI.handleFinalErrorCodes(ErrorCode.forCode(code));

            Assertions.fail("expected exception");

        } catch (Exception e)
        {
            Assertions.assertSame(IllegalArgumentException.class, e.getClass(), "unexpected exception class");
            Assertions.assertEquals("output out of range", e.getMessage(), "unexpected exception message");
        } finally
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
            BlockCipherNI.handleInitErrorCodes(ErrorCode.forCode(code), 16, 16);

            // We can process [0,254] blocks of data successfully.
            code = blockCipherNI.update(ref, new byte[255 * 16], 0, new byte[254 * 16], 0, 254 * 16);
            BlockCipherNI.handleUpdateErrorCodes(ErrorCode.forCode(code));
            Assertions.assertEquals(254 * 16, code);

            // Next 15 bytes would be ok, and leave one byte in the last available block, asserts [0,255]
            code = blockCipherNI.update(ref, new byte[15], 0, new byte[15], 0, 15);
            BlockCipherNI.handleUpdateErrorCodes(ErrorCode.forCode(code));

            // Next 1 byte would be ok, and leave 0 in the last available block, asserts [0,255]
            code = blockCipherNI.update(ref, new byte[1], 0, new byte[1], 0, 1);
            BlockCipherNI.handleUpdateErrorCodes(ErrorCode.forCode(code));

            // Next 1 byte would exceed the 8 bit block counter as [0,256) is asserted
            code = blockCipherNI.update(ref, new byte[1], 0, new byte[1], 0, 1);
            BlockCipherNI.handleUpdateErrorCodes(ErrorCode.forCode(code));

            Assertions.fail("expected exception");
        } catch (Exception e)
        {
            Assertions.assertSame(IllegalStateException.class, e.getClass(), "unexpected exception class");
            Assertions.assertEquals("ctr mode overflow", e.getMessage(), "unexpected exception message");
        } finally
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
            int code = blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, new byte[16], new byte[16], 0);
            BlockCipherNI.handleInitErrorCodes(ErrorCode.forCode(code), 16, 16);

            code = blockCipherNI.updateAAD(ref, input, inOff, inLen);
            BlockCipherNI.handleUpdateErrorCodes(ErrorCode.forCode(code));

            Assertions.fail("expected exception");

        } catch (Exception e)
        {
            Assertions.assertSame(IllegalArgumentException.class, e.getClass(), "unexpected exception class");
            Assertions.assertEquals("input is null", e.getMessage(), "unexpected exception message");
        } finally
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
            int code = blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, new byte[16], new byte[16], 0);
            BlockCipherNI.handleInitErrorCodes(ErrorCode.forCode(code), 16, 16);

            code = blockCipherNI.updateAAD(ref, input, inOff, inLen);
            BlockCipherNI.handleUpdateErrorCodes(ErrorCode.forCode(code));

            Assertions.fail("expected exception");

        } catch (Exception e)
        {
            Assertions.assertSame(IllegalArgumentException.class, e.getClass(), "unexpected exception class");
            Assertions.assertEquals("input offset is negative", e.getMessage(), "unexpected exception message");
        } finally
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
            int code = blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, new byte[16], new byte[16], 0);
            BlockCipherNI.handleInitErrorCodes(ErrorCode.forCode(code), 16, 16);

            code = blockCipherNI.updateAAD(ref, input, inOff, inLen);
            BlockCipherNI.handleUpdateErrorCodes(ErrorCode.forCode(code));

            Assertions.fail("expected exception");

        } catch (Exception e)
        {
            Assertions.assertSame(IllegalArgumentException.class, e.getClass(), "unexpected exception class");
            Assertions.assertEquals("input length is negative", e.getMessage(), "unexpected exception message");
        } finally
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
            int code = blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, new byte[16], new byte[16], 0);
            BlockCipherNI.handleInitErrorCodes(ErrorCode.forCode(code), 16, 16);

            code = blockCipherNI.updateAAD(ref, input, inOff, inLen);
            BlockCipherNI.handleUpdateErrorCodes(ErrorCode.forCode(code));

            Assertions.fail("expected exception");

        } catch (Exception e)
        {
            Assertions.assertSame(IllegalArgumentException.class, e.getClass(), "unexpected exception class");
            Assertions.assertEquals("input out of range", e.getMessage(), "unexpected exception message");
        } finally
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
            int code = blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, new byte[16], new byte[16], 0);
            BlockCipherNI.handleInitErrorCodes(ErrorCode.forCode(code), 16, 16);

            code = blockCipherNI.updateAAD(ref, input, inOff, inLen);
            BlockCipherNI.handleUpdateErrorCodes(ErrorCode.forCode(code));

            Assertions.fail("expected exception");

        } catch (Exception e)
        {
            Assertions.assertSame(IllegalArgumentException.class, e.getClass(), "unexpected exception class");
            Assertions.assertEquals("input out of range", e.getMessage(), "unexpected exception message");
        } finally
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

}
