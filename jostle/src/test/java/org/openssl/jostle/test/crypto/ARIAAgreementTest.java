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

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.encoders.Hex;

import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.*;

/**
 * Test agreement between BC Java and Jostle.
 * Official vector tests elsewhere
 */
public class ARIAAgreementTest
{
    /**
     * Class-level seeding random — used to derive each test's local
     * SHA1PRNG seed. Per CLAUDE.md: "cache one SecureRandom per test
     * class, not per @Test method."
     */
    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * Per-test seeded random. The seed is logged on every call so a
     * flaky failure can be reproduced by re-running with the same
     * seed (per CLAUDE.md).
     */
    private static SecureRandom seededRandom(String testName) throws Exception
    {
        long seed = RANDOM.nextLong();
        System.out.println(testName + " seed=" + seed);
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(seed);
        return sr;
    }

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }


    private void exercise_simpleDoFinal(String xform, int[] keys, int top, int step, int ivLen, SecureRandom sr) throws Exception
    {

        for (int keySize : keys)
        {
            for (int t = 0; t < top; t += step)
            {
                byte[] msg = new byte[t];
                sr.nextBytes(msg);

                byte[] key = new byte[keySize];
                sr.nextBytes(key);

                byte[] iv = null;
                IvParameterSpec ivSpec = null;
                if (ivLen > -1)
                {
                    iv = new byte[ivLen];
                    sr.nextBytes(iv);
                    ivSpec = new IvParameterSpec(iv);
                }


                SecretKey secretKey = new SecretKeySpec(key, "ARIA");

                Cipher javaEncrypt = Cipher.getInstance(xform, BouncyCastleProvider.PROVIDER_NAME);
                javaEncrypt.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
                Cipher javaDecrypt = Cipher.getInstance(xform, BouncyCastleProvider.PROVIDER_NAME);
                javaDecrypt.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);


                Cipher jostleEnc = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
                jostleEnc.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

                Cipher jostleDec = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
                jostleDec.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

                byte[] javaCt = javaEncrypt.doFinal(msg);
                byte[] josteCt = jostleEnc.doFinal(msg);

                if (!Arrays.areEqual(javaCt, josteCt))
                {
                    System.out.println(String.format("Encrypt Key Size: %d, Msg Size: %d", keySize, msg.length));
                    System.out.println("MSG:    " + Hex.toHexString(msg));
                    System.out.println("JAVA  : " + Hex.toHexString(javaCt));
                    System.out.println("JOSTLE: " + Hex.toHexString(josteCt));
                }

                Assertions.assertArrayEquals(javaCt, josteCt);

                byte[] javaPt = javaDecrypt.doFinal(javaCt);
                byte[] jostlePt = jostleDec.doFinal(josteCt);


                if (!Arrays.areEqual(javaPt, jostlePt))
                {
                    System.out.println(String.format("Decrypt Key Size: %d, Msg Size: %d", keySize, msg.length));
                    System.out.println("JAVA  : " + Hex.toHexString(javaPt));
                    System.out.println("JOSTLE: " + Hex.toHexString(jostlePt));
                }

                Assertions.assertArrayEquals(jostlePt, javaPt);
                Assertions.assertArrayEquals(jostlePt, msg);

            }
        }
    }


    private void exercise_complexDoFinal(String xform, int[] keys, int top, int step, int ivLen, SecureRandom sr) throws Exception
    {

        for (int keySize : keys)
        {
            for (int t = 0; t < top; t += step)
            {

                for (int jitterOutput : new int[]{1, 0})
                {

                    for (int jitterInput : new int[]{0, 1})
                    {

                        byte[] msg = new byte[t];
                        sr.nextBytes(msg);

                        byte[] key = new byte[keySize];
                        sr.nextBytes(key);

                        byte[] iv = null;
                        IvParameterSpec ivSpec = null;
                        if (ivLen > -1)
                        {
                            iv = new byte[ivLen];
                            sr.nextBytes(iv);
                            ivSpec = new IvParameterSpec(iv);
                        }

                        byte[] intputJava = new byte[msg.length + jitterInput];
                        byte[] intputJostle = new byte[msg.length + jitterInput];

                        System.arraycopy(msg, 0, intputJava, jitterInput, msg.length);
                        System.arraycopy(msg, 0, intputJostle, jitterInput, msg.length);

                        if (jitterInput > 0)
                        {
                            intputJava[0] = (byte) 0xFF;
                            intputJostle[0] = (byte) 0xFF;
                        }

                        SecretKey secretKey = new SecretKeySpec(key, "ARIA");

                        Cipher javaEncrypt = Cipher.getInstance(xform, BouncyCastleProvider.PROVIDER_NAME);
                        javaEncrypt.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
                        Cipher javaDecrypt = Cipher.getInstance(xform, BouncyCastleProvider.PROVIDER_NAME);
                        javaDecrypt.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);


                        Cipher jostleEnc = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
                        jostleEnc.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

                        Cipher jostleDec = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
                        jostleDec.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

                        int expectedLenCt = javaEncrypt.getOutputSize(msg.length);

                        Assertions.assertEquals(expectedLenCt, jostleEnc.getOutputSize(msg.length));

                        byte[] outputJavaCt = new byte[expectedLenCt + jitterOutput];
                        byte[] outputJostleCt = new byte[expectedLenCt + jitterOutput];

                        sr.nextBytes(outputJavaCt);
                        sr.nextBytes(outputJostleCt);

                        Byte leader = null;
                        if (jitterOutput > 0)
                        {
                            //
                            // Make them the same, we are checking the implementation honours the output offset
                            // So the values should remain unchanged!
                            outputJavaCt[0] = outputJostleCt[0];
                            leader = outputJavaCt[0];
                        }

                        Assertions.assertEquals(expectedLenCt, javaEncrypt.doFinal(intputJava, jitterInput, msg.length, outputJavaCt, jitterOutput));
                        Assertions.assertEquals(expectedLenCt, jostleEnc.doFinal(intputJostle, jitterInput, msg.length, outputJostleCt, jitterOutput));

                        if (leader != null)
                        {
                            // if we have jitter, ie start writing at position 1 in the array
                            // the leader byte should be untouched.
                            Assertions.assertEquals(leader.byteValue(), outputJavaCt[0]);
                            Assertions.assertEquals(leader.byteValue(), outputJostleCt[0]);
                        }


                        if (!Arrays.areEqual(outputJavaCt, outputJostleCt))
                        {
                            System.out.println(String.format("Encrypt Key Size: %d, Msg Size: %d", keySize, msg.length));
                            System.out.println("MSG:    " + Hex.toHexString(msg));
                            System.out.println("JITTER  : " + jitterOutput);
                            System.out.println("JAVA  : " + Hex.toHexString(outputJavaCt));
                            System.out.println("JOSTLE: " + Hex.toHexString(outputJostleCt));
                        }

                        Assertions.assertArrayEquals(outputJavaCt, outputJostleCt);


                        byte[] outputJavaPt = new byte[expectedLenCt + jitterInput];
                        byte[] outputJostlePt = new byte[expectedLenCt + jitterInput];

                        sr.nextBytes(outputJavaPt);
                        sr.nextBytes(outputJostlePt);
                        leader = null;
                        if (jitterInput > 0)
                        {
                            outputJavaPt[0] = outputJostlePt[0];
                            leader = outputJavaPt[0];
                        }

                        Assertions.assertEquals(msg.length, javaDecrypt.doFinal(outputJavaCt, jitterOutput, outputJavaCt.length - jitterOutput, outputJavaPt, jitterInput));
                        Assertions.assertEquals(msg.length, jostleDec.doFinal(outputJostleCt, jitterOutput, outputJostleCt.length - jitterOutput, outputJostlePt, jitterInput));


                        int startPos = jitterInput;
                        int endPos = msg.length + jitterInput - 1;

                        if (leader != null)
                        {
                            // if we have jitter, ie start writing at position 1 in the array
                            // the leader byte should be untouched.
                            Assertions.assertEquals(leader.byteValue(), outputJavaPt[0]);
                            Assertions.assertEquals(leader.byteValue(), outputJostlePt[0]);
                        }

                        if (!Arrays.areEqual(outputJavaPt, startPos, endPos, outputJostlePt, startPos, endPos))
                        {
                            System.out.println(String.format("Decrypt Key Size: %d, Msg Size: %d", keySize, msg.length));
                            System.out.println("JITTER  : " + jitterOutput);
                            System.out.println("JAVA  : " + Hex.toHexString(outputJavaPt));
                            System.out.println("JOSTLE: " + Hex.toHexString(outputJostlePt));
                            Assertions.fail("decrypt failed to agree");
                        }

                        Assertions.assertTrue(Arrays.areEqual(outputJavaPt, startPos, endPos, outputJostlePt, startPos, endPos));

                        Assertions.assertTrue(Arrays.areEqual(outputJavaPt, startPos, endPos, msg, 0, msg.length - 1));
                    }
                }
            }
        }
    }


    private void exercise_complexUpdateDoFinal(String xform, int[] keys, int top, int step, int ivLen, SecureRandom sr) throws Exception
    {

        for (int keySize : keys)
        {
            for (int t = 0; t < top; t += step)
            {

                for (int offsetOutput : new int[]{1, 0})
                {

                    for (int offsetInput : new int[]{0, 1})
                    {

                        byte[] msg = new byte[t];
                        sr.nextBytes(msg);

                        //
                        // Split the original message between update and do final.
                        //


                        byte[] key = new byte[keySize];
                        sr.nextBytes(key);

                        byte[] iv = null;
                        IvParameterSpec ivSpec = null;
                        if (ivLen > -1)
                        {
                            iv = new byte[ivLen];
                            sr.nextBytes(iv);
                            ivSpec = new IvParameterSpec(iv);
                        }

                        byte[] intputJava = new byte[msg.length + offsetInput];
                        byte[] intputJostle = new byte[msg.length + offsetInput];

                        System.arraycopy(msg, 0, intputJava, offsetInput, msg.length);
                        System.arraycopy(msg, 0, intputJostle, offsetInput, msg.length);

                        if (offsetInput > 0)
                        {
                            intputJava[0] = (byte) 0xFF;
                            intputJostle[0] = (byte) 0xFF;
                        }

                        SecretKey secretKey = new SecretKeySpec(key, "ARIA");

                        Cipher javaEncrypt = Cipher.getInstance(xform, BouncyCastleProvider.PROVIDER_NAME);
                        javaEncrypt.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
                        Cipher javaDecrypt = Cipher.getInstance(xform, BouncyCastleProvider.PROVIDER_NAME);
                        javaDecrypt.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);


                        Cipher jostleEnc = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
                        jostleEnc.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

                        Cipher jostleDec = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
                        jostleDec.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

                        int expectedLenCt = javaEncrypt.getOutputSize(msg.length);

                        Assertions.assertEquals(expectedLenCt, jostleEnc.getOutputSize(msg.length));

                        byte[] outputJavaCt = new byte[expectedLenCt + offsetOutput];
                        byte[] outputJostleCt = new byte[expectedLenCt + offsetOutput];

                        sr.nextBytes(outputJavaCt);
                        sr.nextBytes(outputJostleCt);

                        Byte leader = null;
                        if (offsetOutput > 0)
                        {
                            //
                            // Make them the same, we are checking the implementation honours the output offset
                            // So the values should remain unchanged!
                            outputJavaCt[0] = outputJostleCt[0];
                            leader = outputJavaCt[0];
                        }


                        if (msg.length == 0)
                        {

                            //
                            // Special case for zero length message
                            //

                            int javaLen = javaEncrypt.update(intputJava, offsetInput, 0, outputJavaCt, offsetOutput);
                            javaLen += javaEncrypt.doFinal(intputJava, offsetInput, 0, outputJavaCt, offsetOutput + javaLen);

                            int jostleLen = jostleEnc.update(intputJostle, offsetInput, 0, outputJostleCt, offsetOutput);
                            jostleLen += jostleEnc.doFinal(intputJostle, offsetInput, 0, outputJostleCt, offsetOutput + jostleLen);

                            Assertions.assertEquals(expectedLenCt, javaLen);
                            Assertions.assertEquals(expectedLenCt, jostleLen);

                            if (leader != null)
                            {
                                // if we have jitter, ie start writing at position 1 in the array
                                // the leader byte should be untouched.
                                Assertions.assertEquals(leader.byteValue(), outputJavaCt[0]);
                                Assertions.assertEquals(leader.byteValue(), outputJostleCt[0]);
                            }


                            if (!Arrays.areEqual(outputJavaCt, outputJostleCt))
                            {
                                System.out.println(String.format("Encrypt Key Size: %d, Msg Size: %d", keySize, msg.length));
                                System.out.println("MSG:    " + Hex.toHexString(msg));
                                System.out.println("JITTER  : " + offsetOutput);
                                System.out.println("JAVA  : " + Hex.toHexString(outputJavaCt));
                                System.out.println("JOSTLE: " + Hex.toHexString(outputJostleCt));
                            }

                            Assertions.assertArrayEquals(outputJavaCt, outputJostleCt);


                        }


                        for (int splitAt = 0; splitAt < msg.length; splitAt += step)
                        {

                            int javaLen = javaEncrypt.update(intputJava, offsetInput, splitAt, outputJavaCt, offsetOutput);
                            javaLen += javaEncrypt.doFinal(intputJava, offsetInput + splitAt, msg.length - splitAt, outputJavaCt, offsetOutput + javaLen);

                            int jostleLen = jostleEnc.update(intputJostle, offsetInput, splitAt, outputJostleCt, offsetOutput);
                            jostleLen += jostleEnc.doFinal(intputJostle, offsetInput + splitAt, msg.length - splitAt, outputJostleCt, offsetOutput + jostleLen);

                            Assertions.assertEquals(expectedLenCt, javaLen);
                            Assertions.assertEquals(expectedLenCt, jostleLen);

                            if (leader != null)
                            {
                                // if we have jitter, ie start writing at position 1 in the array
                                // the leader byte should be untouched.
                                Assertions.assertEquals(leader.byteValue(), outputJavaCt[0]);
                                Assertions.assertEquals(leader.byteValue(), outputJostleCt[0]);
                            }


                            if (!Arrays.areEqual(outputJavaCt, outputJostleCt))
                            {
                                System.out.println(String.format("Encrypt Key Size: %d, Msg Size: %d", keySize, msg.length));
                                System.out.println("MSG:    " + Hex.toHexString(msg));
                                System.out.println("JITTER  : " + offsetOutput);
                                System.out.println("JAVA  : " + Hex.toHexString(outputJavaCt));
                                System.out.println("JOSTLE: " + Hex.toHexString(outputJostleCt));
                            }

                            Assertions.assertArrayEquals(outputJavaCt, outputJostleCt);
                        }

                        byte[] outputJavaPt = new byte[expectedLenCt + offsetInput];
                        byte[] outputJostlePt = new byte[expectedLenCt + offsetInput];

                        sr.nextBytes(outputJavaPt);
                        sr.nextBytes(outputJostlePt);
                        leader = null;
                        if (offsetInput > 0)
                        {
                            outputJavaPt[0] = outputJostlePt[0];
                            leader = outputJavaPt[0];
                        }


                        int ctLen = outputJavaCt.length - offsetOutput;

                        for (int splitAt = 0; splitAt < ctLen; splitAt += step)
                        {


                            int javaLen = javaDecrypt.update(outputJavaCt, offsetOutput, splitAt, outputJavaPt, offsetInput);
                            javaLen += javaDecrypt.doFinal(outputJavaCt, offsetOutput + splitAt, ctLen - splitAt, outputJavaPt, offsetInput + javaLen);


                            int jostleLen = jostleDec.update(outputJostleCt, offsetOutput, splitAt, outputJostlePt, offsetInput);
                            jostleLen += jostleDec.doFinal(outputJostleCt, offsetOutput + splitAt, ctLen - splitAt, outputJostlePt, offsetInput + jostleLen);

                            Assertions.assertEquals(msg.length, javaLen);
                            Assertions.assertEquals(msg.length, jostleLen);


                            int startPos = offsetInput;
                            int endPos = msg.length + offsetInput - 1;

                            if (leader != null)
                            {
                                // if we have jitter, ie start writing at position 1 in the array
                                // the leader byte should be untouched.
                                Assertions.assertEquals(leader.byteValue(), outputJavaPt[0]);
                                Assertions.assertEquals(leader.byteValue(), outputJostlePt[0]);
                            }

                            if (!Arrays.areEqual(outputJavaPt, startPos, endPos, outputJostlePt, startPos, endPos))
                            {
                                System.out.println(String.format("Decrypt Key Size: %d, Msg Size: %d", keySize, msg.length));
                                System.out.println("JITTER  : " + offsetOutput);
                                System.out.println("JAVA  : " + Hex.toHexString(outputJavaPt));
                                System.out.println("JOSTLE: " + Hex.toHexString(outputJostlePt));
                                Assertions.fail("decrypt failed to agree");
                            }

                            Assertions.assertTrue(Arrays.areEqual(outputJavaPt, startPos, endPos, outputJostlePt, startPos, endPos));
                            Assertions.assertTrue(Arrays.areEqual(outputJavaPt, startPos, endPos, msg, 0, msg.length - 1));
                        }
                    }
                }
            }
        }
    }

    private void exercise_complexDoFinalSameArray(String xform, int[] keys, int top, int step, int ivLen, SecureRandom sr) throws Exception
    {
        for (int keySize : keys)
        {
            int msgLen = top;


            byte[] msg = new byte[msgLen];
            sr.nextBytes(msg);

            //
            // Split the original message between update and do final.
            //


            byte[] key = new byte[keySize];
            sr.nextBytes(key);

            byte[] iv = null;
            IvParameterSpec ivSpec = null;
            if (ivLen > -1)
            {
                iv = new byte[ivLen];
                //     sr.nextBytes(iv);
                ivSpec = new IvParameterSpec(iv);
            }


            SecretKey secretKey = new SecretKeySpec(key, "ARIA");

            Cipher javaEncrypt = Cipher.getInstance(xform, BouncyCastleProvider.PROVIDER_NAME);
            javaEncrypt.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
            Cipher javaDecrypt = Cipher.getInstance(xform, BouncyCastleProvider.PROVIDER_NAME);
            javaDecrypt.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);


            Cipher jostleEnc = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
            jostleEnc.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

            Cipher jostleDec = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
            jostleDec.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

            int expectedLenCt = javaEncrypt.getOutputSize(msg.length);

            Assertions.assertEquals(expectedLenCt, jostleEnc.getOutputSize(msg.length));


            byte[] workingArrayJostle = new byte[msg.length + expectedLenCt];

            //  sr.nextBytes(workingArrayJava);

            System.arraycopy(msg, 0, workingArrayJostle, 0, msg.length);


            byte[] originalWorkingArray = new byte[workingArrayJostle.length];


            // Encryption side.

            for (int offsetInput = 0; offsetInput < msgLen; offsetInput++)
            {

                // Flood array and create backup
                sr.nextBytes(workingArrayJostle);
                System.arraycopy(workingArrayJostle, 0, originalWorkingArray, 0, workingArrayJostle.length);

                //
                // Create correct cipher text
                //
                byte[] expectedOutput = javaEncrypt.doFinal(workingArrayJostle, offsetInput, msgLen);


                for (int offsetOutput = 0; offsetOutput < msgLen; offsetOutput++)
                {

                    int jostleLen = jostleEnc.doFinal(workingArrayJostle, offsetInput, msgLen, workingArrayJostle, offsetOutput);

                    Assertions.assertEquals(expectedOutput.length, jostleLen);
                    int i = 0;
                    for (int j = offsetOutput; j < offsetOutput + jostleLen; j++)
                    {
                        Assertions.assertEquals(expectedOutput[i++], workingArrayJostle[j]);
                    }

                    // Reset working array
                    System.arraycopy(originalWorkingArray, 0, workingArrayJostle, 0, originalWorkingArray.length);
                }

            }


            if (!xform.endsWith("NoPadding"))
            {
                // Extend working array to hold padding etc.
                workingArrayJostle = new byte[(msgLen * 2) + (javaEncrypt.getBlockSize() * 2)];
                originalWorkingArray = new byte[workingArrayJostle.length];
            }


            int bs = javaEncrypt.getBlockSize();

            // Decryption side

            for (int offsetInput = 0; offsetInput < msgLen - bs; offsetInput++)
            {

                // Flood array and create backup
                sr.nextBytes(workingArrayJostle);
                System.arraycopy(workingArrayJostle, 0, originalWorkingArray, 0, workingArrayJostle.length);

                //
                // Create correct cipher text
                //
                byte[] cipherText = javaEncrypt.doFinal(workingArrayJostle, offsetInput, msgLen);


                for (int offsetOutput = 0; offsetOutput < msgLen - bs; offsetOutput++)
                {
                    // Reset working array
                    System.arraycopy(originalWorkingArray, 0, workingArrayJostle, 0, originalWorkingArray.length);

                    // Embed cipher text, at input pos
                    System.arraycopy(cipherText, 0, workingArrayJostle, offsetInput, cipherText.length);


                    int jostleLen = jostleDec.doFinal(workingArrayJostle, offsetInput, cipherText.length, workingArrayJostle, offsetOutput);

                    Assertions.assertEquals(msgLen, jostleLen);
                    int i = offsetInput;
                    for (int j = offsetOutput; j < offsetOutput + jostleLen; j++)
                    {
                        if (originalWorkingArray[i] != workingArrayJostle[j])
                        {

                            System.out.println("ORIG:  " + Hex.toHexString(originalWorkingArray, offsetInput, originalWorkingArray.length - offsetInput));
                            System.out.println("WORK:  " + Hex.toHexString(workingArrayJostle, offsetOutput, workingArrayJostle.length - offsetInput));
                            System.out.println();
                        }
                        Assertions.assertEquals(originalWorkingArray[i++], workingArrayJostle[j]);
                    }
                }
            }
        }
    }


    @Test
    public void testRejectIncorrectKeyAlgorithm() throws Exception
    {
        SecretKeySpec wrongSpec = new SecretKeySpec(new byte[16], "AES");

        try
        {
            Cipher cipher = Cipher.getInstance("ARIA/ECB/NoPadding", JostleProvider.PROVIDER_NAME);
            cipher.init(Cipher.ENCRYPT_MODE, wrongSpec);
            Assertions.fail("Should have thrown an exception");
        } catch (InvalidKeyException ikes)
        {
            Assertions.assertEquals("unsupported key algorithm AES", ikes.getMessage());
        }

        try
        {
            Cipher cipher = Cipher.getInstance("ARIA/CBC/NoPadding", JostleProvider.PROVIDER_NAME);
            cipher.init(Cipher.ENCRYPT_MODE, wrongSpec, new IvParameterSpec(new byte[16]));
            Assertions.fail("Should have thrown an exception");
        } catch (InvalidKeyException ikes)
        {
            Assertions.assertEquals("unsupported key algorithm AES", ikes.getMessage());
        }

        try
        {
            Cipher cipher = Cipher.getInstance("ARIA/CBC/NoPadding", JostleProvider.PROVIDER_NAME);
            DummyParams params = new DummyParams();
            params.init(new byte[16]);
            cipher.init(Cipher.ENCRYPT_MODE, wrongSpec, params);
            Assertions.fail("Should have thrown an exception");
        } catch (InvalidKeyException ikes)
        {
            Assertions.assertEquals("unsupported key algorithm AES", ikes.getMessage());
        }

        // Correct spec
        Cipher cipher = Cipher.getInstance("ARIA/ECB/NoPadding", JostleProvider.PROVIDER_NAME);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[16], "ARIA"));

        cipher = Cipher.getInstance("ARIA/CBC/NoPadding", JostleProvider.PROVIDER_NAME);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[16], "ARIA"), new IvParameterSpec(new byte[16]));

        cipher = Cipher.getInstance("ARIA/CBC/NoPadding", JostleProvider.PROVIDER_NAME);
        DummyParams params = new DummyParams();
        params.init(new byte[16]);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[16], "ARIA"), params);

    }

    @Test
    public void testAria() throws Exception
    {
        SecureRandom sr = seededRandom("testAria");
        //
        // The doFinal that returns a byte[]
        //
        exercise_simpleDoFinal("ARIA/ECB/NoPadding", new int[]{16, 24, 32}, 5 * 16, 16, -1, sr);
        exercise_simpleDoFinal("ARIA/ECB/PKCS7Padding", new int[]{16, 24, 32}, (5 * 16) + 1, 1, -1, sr);

        exercise_simpleDoFinal("ARIA/CBC/NoPadding", new int[]{16, 24, 32}, 5 * 16, 16, 16, sr);
        exercise_simpleDoFinal("ARIA/CBC/PKCS7Padding", new int[]{16, 24, 32}, (5 * 16) + 1, 1, 16, sr);
        exercise_simpleDoFinal("ARIA/CBC/PKCS5Padding", new int[]{16, 24, 32}, (5 * 16) + 1, 1, 16, sr);
        exercise_simpleDoFinal("ARIA/CFB128/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 16, sr);
        exercise_simpleDoFinal("ARIA/CFB8/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 16, sr);
//        exercise_simpleDoFinal("ARIA/OFB/NoPadding", new int[]{16, 24, 32}, 5 * 16, 1, 16, sr);

        exercise_simpleDoFinal("ARIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 8, sr);
        exercise_simpleDoFinal("ARIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 9, sr);
        exercise_simpleDoFinal("ARIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 10, sr);
        exercise_simpleDoFinal("ARIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 11, sr);
        exercise_simpleDoFinal("ARIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 12, sr);
        exercise_simpleDoFinal("ARIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 13, sr);
        exercise_simpleDoFinal("ARIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 14, sr);
        exercise_simpleDoFinal("ARIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 15, sr);
        exercise_simpleDoFinal("ARIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 16, sr);


        //
        // Complex doFinal, that takes input and output arrays.
        //


        exercise_complexDoFinal("ARIA/ECB/NoPadding", new int[]{16, 24, 32}, 5 * 16, 16, -1, sr);
        exercise_complexDoFinal("ARIA/ECB/PKCS7Padding", new int[]{16, 24, 32}, (5 * 16) + 1, 1, -1, sr);

        exercise_complexDoFinal("ARIA/CBC/NoPadding", new int[]{16, 24, 32}, 5 * 16, 16, 16, sr);
        exercise_complexDoFinal("ARIA/CBC/PKCS7Padding", new int[]{16, 24, 32}, (5 * 16) + 1, 1, 16, sr);
        exercise_complexDoFinal("ARIA/CBC/PKCS5Padding", new int[]{16, 24, 32}, (5 * 16) + 1, 1, 16, sr);
        exercise_complexDoFinal("ARIA/CFB128/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 16, sr);
        exercise_complexDoFinal("ARIA/CFB8/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 16, sr);
        exercise_complexDoFinal("ARIA/OFB/NoPadding", new int[]{16, 24, 32}, 5 * 16, 1, 16, sr);

        exercise_complexDoFinal("ARIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 8, sr);
        exercise_complexDoFinal("ARIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 9, sr);
        exercise_complexDoFinal("ARIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 10, sr);
        exercise_complexDoFinal("ARIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 11, sr);
        exercise_complexDoFinal("ARIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 12, sr);
        exercise_complexDoFinal("ARIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 13, sr);
        exercise_complexDoFinal("ARIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 14, sr);
        exercise_complexDoFinal("ARIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 15, sr);
        exercise_complexDoFinal("ARIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 16, sr);


        //
        // Spread message between update and doFinal calls.
        //
        exercise_complexUpdateDoFinal("ARIA/ECB/NoPadding", new int[]{16, 24, 32}, 5 * 16, 16, -1, sr);
        exercise_complexUpdateDoFinal("ARIA/ECB/PKCS7Padding", new int[]{16, 24, 32}, (5 * 16) + 1, 1, -1, sr);

        exercise_complexUpdateDoFinal("ARIA/CBC/NoPadding", new int[]{16, 24, 32}, 5 * 16, 16, 16, sr);
        exercise_complexUpdateDoFinal("ARIA/CBC/PKCS7Padding", new int[]{16, 24, 32}, (5 * 16) + 1, 1, 16, sr);
        exercise_complexUpdateDoFinal("ARIA/CBC/PKCS5Padding", new int[]{16, 24, 32}, (5 * 16) + 1, 1, 16, sr);
        exercise_complexUpdateDoFinal("ARIA/CFB128/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 16, sr);
        exercise_complexUpdateDoFinal("ARIA/CFB8/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 16, sr);
        exercise_complexUpdateDoFinal("ARIA/OFB/NoPadding", new int[]{16, 24, 32}, 5 * 16, 1, 16, sr);

        exercise_complexUpdateDoFinal("ARIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 8, sr);
        exercise_complexUpdateDoFinal("ARIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 9, sr);
        exercise_complexUpdateDoFinal("ARIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 10, sr);
        exercise_complexUpdateDoFinal("ARIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 11, sr);
        exercise_complexUpdateDoFinal("ARIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 12, sr);
        exercise_complexUpdateDoFinal("ARIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 13, sr);
        exercise_complexUpdateDoFinal("ARIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 14, sr);
        exercise_complexUpdateDoFinal("ARIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 15, sr);
        exercise_complexUpdateDoFinal("ARIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 16, sr);


        //
        // Where input and output array is the same.
        //

        exercise_complexDoFinalSameArray("ARIA/ECB/NoPadding", new int[]{16, 24, 32}, 16 * 17, 16, -1, sr);
        exercise_complexDoFinalSameArray("ARIA/ECB/PKCS7Padding", new int[]{16, 24, 32}, (5 * 16) + 1, 1, -1, sr);

        exercise_complexDoFinalSameArray("ARIA/CBC/NoPadding", new int[]{16, 24, 32}, 16 * 17, 16, 16, sr);
        exercise_complexDoFinalSameArray("ARIA/CBC/PKCS7Padding", new int[]{16, 24, 32}, (5 * 16) + 1, 1, 16, sr);
        exercise_complexDoFinalSameArray("ARIA/CBC/PKCS5Padding", new int[]{16, 24, 32}, (5 * 16) + 1, 1, 16, sr);
        exercise_complexDoFinalSameArray("ARIA/CFB128/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 16, sr);
        exercise_complexDoFinalSameArray("ARIA/CFB8/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 16, sr);
        exercise_complexDoFinalSameArray("ARIA/OFB/NoPadding", new int[]{16, 24, 32}, 5 * 16, 1, 16, sr);

        exercise_complexDoFinalSameArray("ARIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 8, sr);
        exercise_complexDoFinalSameArray("ARIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 9, sr);
        exercise_complexDoFinalSameArray("ARIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 10, sr);
        exercise_complexDoFinalSameArray("ARIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 11, sr);
        exercise_complexDoFinalSameArray("ARIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 12, sr);
        exercise_complexDoFinalSameArray("ARIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 13, sr);
        exercise_complexDoFinalSameArray("ARIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 14, sr);
        exercise_complexDoFinalSameArray("ARIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 15, sr);
        exercise_complexDoFinalSameArray("ARIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 16, sr);


    }


    private String pad(int len)
    {
        char[] buf = new char[len];
        Arrays.fill(buf, ' ');
        return new String(buf);
    }

    private String showDiff(byte[] left, byte[] right)
    {
        StringBuffer sb = new StringBuffer();
        if (left.length != right.length)
        {
            System.out.println("Not same length");
        }

        for (int i = 0; i < left.length; i++)
        {
            if (left[i] != right[i])
            {
                sb.append("^^");
            } else
            {
                sb.append("  ");
            }
        }
        return sb.toString();
    }


    // -----------------------------------------------------------------
    // Negative path: tampered ciphertext / wrong key must not roundtrip.
    // Per CLAUDE.md "Tests must exercise the negative path" — BC byte
    // equality already rules out a stub Jostle implementation, but the
    // explicit tamper/wrong-key tests catch the same-buggy-mode-in-both-
    // libs class of bug that BC parity alone can't.
    // -----------------------------------------------------------------

    @Test
    public void testTamperedCiphertext_doesNotRoundTrip() throws Exception
    {
        SecureRandom sr = seededRandom("testTamperedCiphertext_doesNotRoundTrip");
        // ARIA is a 128-bit block cipher. Use CBC/NoPadding so the
        // decrypt path produces wrong-but-non-throwing plaintext.
        byte[] key = new byte[16];
        sr.nextBytes(key);
        byte[] iv = new byte[16];
        sr.nextBytes(iv);
        byte[] msg = new byte[3 * 16]; // 3 blocks, no padding
        sr.nextBytes(msg);

        Cipher enc = Cipher.getInstance("ARIA/CBC/NoPadding", JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "ARIA"), new IvParameterSpec(iv));
        byte[] ct = enc.doFinal(msg);

        // Flip a bit in the middle block — CBC error propagation
        // corrupts that block AND the next decrypted block.
        byte[] tampered = ct.clone();
        tampered[16] ^= (byte) 0x01;

        Cipher dec = Cipher.getInstance("ARIA/CBC/NoPadding", JostleProvider.PROVIDER_NAME);
        dec.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "ARIA"), new IvParameterSpec(iv));
        byte[] decoded = dec.doFinal(tampered);

        Assertions.assertFalse(Arrays.areEqual(msg, decoded),
                "tampered ciphertext must not decrypt to the original plaintext");
    }

    @Test
    public void testTamperedPadding_rejectsAtDoFinal() throws Exception
    {
        SecureRandom sr = seededRandom("testTamperedPadding_rejectsAtDoFinal");
        // PKCS7 padding integrity-style check: tampering the last
        // ciphertext block should yield BadPaddingException with high
        // probability. Loop so a lucky padding accident isn't flaky.
        byte[] key = new byte[16];
        sr.nextBytes(key);
        byte[] iv = new byte[16];
        sr.nextBytes(iv);

        boolean sawBadPadding = false;
        for (int trial = 0; trial < 20; trial++)
        {
            byte[] msg = new byte[37]; // not a block multiple → padding present
            sr.nextBytes(msg);

            Cipher enc = Cipher.getInstance("ARIA/CBC/PKCS7Padding", JostleProvider.PROVIDER_NAME);
            enc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "ARIA"), new IvParameterSpec(iv));
            byte[] ct = enc.doFinal(msg);

            byte[] tampered = ct.clone();
            tampered[tampered.length - 1] ^= (byte) 0xFF;

            Cipher dec = Cipher.getInstance("ARIA/CBC/PKCS7Padding", JostleProvider.PROVIDER_NAME);
            dec.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "ARIA"), new IvParameterSpec(iv));
            try
            {
                byte[] out = dec.doFinal(tampered);
                // Didn't throw — only legitimate if the corrupted byte
                // still parses as valid padding. Result MUST differ.
                Assertions.assertFalse(Arrays.areEqual(msg, out),
                        "tampered ciphertext that didn't throw still must not roundtrip");
            }
            catch (BadPaddingException expected)
            {
                sawBadPadding = true;
            }
        }
        Assertions.assertTrue(sawBadPadding,
                "expected at least one BadPaddingException across 20 tampering trials");
    }

    @Test
    public void testWrongKey_doesNotRoundTrip() throws Exception
    {
        SecureRandom sr = seededRandom("testWrongKey_doesNotRoundTrip");
        // Encrypt with k1, decrypt with k2 — plaintext must diverge.
        // A stub cipher that ignored the key entirely would roundtrip.
        byte[] k1 = new byte[16];
        byte[] k2 = new byte[16];
        do
        {
            sr.nextBytes(k1);
            sr.nextBytes(k2);
        }
        while (Arrays.areEqual(k1, k2));

        byte[] iv = new byte[16];
        sr.nextBytes(iv);
        byte[] msg = new byte[3 * 16];
        sr.nextBytes(msg);

        Cipher enc = Cipher.getInstance("ARIA/CBC/NoPadding", JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(k1, "ARIA"), new IvParameterSpec(iv));
        byte[] ct = enc.doFinal(msg);

        Cipher dec = Cipher.getInstance("ARIA/CBC/NoPadding", JostleProvider.PROVIDER_NAME);
        dec.init(Cipher.DECRYPT_MODE, new SecretKeySpec(k2, "ARIA"), new IvParameterSpec(iv));
        byte[] decoded = dec.doFinal(ct);

        Assertions.assertFalse(Arrays.areEqual(msg, decoded),
                "decrypting with the wrong key must not yield the original plaintext");
    }


    // -----------------------------------------------------------------
    // ARIA-GCM (AEAD) — agreement with BouncyCastle, tag-length variation,
    // AAD handling, tamper rejection.
    // -----------------------------------------------------------------

    /**
     * Random key / IV / AAD / plaintext agreement with BC across all three
     * ARIA key sizes. Covers no-AAD AND AAD-bearing paths in one loop.
     */
    @Test
    public void ariaGCM_agreesWithBC() throws Exception
    {
        SecureRandom sr = seededRandom("ariaGCM_agreesWithBC");
        String xform = "ARIA/GCM/NoPadding";
        for (int keySize : new int[]{16, 24, 32})
        {
            byte[] key = new byte[keySize];
            sr.nextBytes(key);
            byte[] iv = new byte[12];
            sr.nextBytes(iv);
            byte[] aad = new byte[sr.nextInt(64)];
            sr.nextBytes(aad);
            byte[] msg = new byte[1 + sr.nextInt(512)];
            sr.nextBytes(msg);

            SecretKey secretKey = new SecretKeySpec(key, "ARIA");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);

            Cipher javaEnc = Cipher.getInstance(xform, BouncyCastleProvider.PROVIDER_NAME);
            javaEnc.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);
            javaEnc.updateAAD(aad);
            byte[] javaCT = javaEnc.doFinal(msg);

            Cipher jostleEnc = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
            jostleEnc.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);
            jostleEnc.updateAAD(aad);
            byte[] jostleCT = jostleEnc.doFinal(msg);

            Assertions.assertArrayEquals(javaCT, jostleCT,
                    "keySize=" + keySize + ": ARIA-GCM ciphertext+tag diverged");

            Cipher jostleDec = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
            jostleDec.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec);
            jostleDec.updateAAD(aad);
            byte[] jostlePT = jostleDec.doFinal(jostleCT);
            Assertions.assertArrayEquals(msg, jostlePT, "keySize=" + keySize + ": ARIA-GCM roundtrip");
        }
    }

    /**
     * Tag-length variation for ARIA-GCM. All NIST-permitted tag lengths
     * (32, 64, 96, 104, 112, 120, 128 bits) must agree with BC.
     */
    @Test
    public void ariaGCM_tagLengthVariation_agreesWithBC() throws Exception
    {
        SecureRandom sr = seededRandom("ariaGCM_tagLengthVariation_agreesWithBC");
        String xform = "ARIA/GCM/NoPadding";
        byte[] key = new byte[32];
        sr.nextBytes(key);
        byte[] iv = new byte[12];
        sr.nextBytes(iv);
        byte[] aad = new byte[sr.nextInt(64)];
        sr.nextBytes(aad);
        byte[] msg = new byte[1 + sr.nextInt(256)];
        sr.nextBytes(msg);

        for (int tagBits : new int[]{32, 64, 96, 104, 112, 120, 128})
        {
            SecretKey secretKey = new SecretKeySpec(key, "ARIA");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(tagBits, iv);

            Cipher javaEnc = Cipher.getInstance(xform, BouncyCastleProvider.PROVIDER_NAME);
            javaEnc.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);
            javaEnc.updateAAD(aad);
            byte[] javaCT = javaEnc.doFinal(msg);

            Cipher jostleEnc = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
            jostleEnc.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);
            jostleEnc.updateAAD(aad);
            byte[] jostleCT = jostleEnc.doFinal(msg);

            Assertions.assertArrayEquals(javaCT, jostleCT,
                    "tagBits=" + tagBits + ": ARIA-GCM ciphertext+tag diverged");

            // Roundtrip: Jostle decrypt of Jostle ciphertext.
            Cipher jostleDec = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
            jostleDec.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec);
            jostleDec.updateAAD(aad);
            byte[] jostlePT = jostleDec.doFinal(jostleCT);
            Assertions.assertArrayEquals(msg, jostlePT, "tagBits=" + tagBits + ": ARIA-GCM roundtrip");
        }
    }

    /**
     * Tampering either the ciphertext, the tag, or the AAD must cause
     * decryption to reject. Guards against any AEAD-tag-check bypass.
     */
    @Test
    public void ariaGCM_tamperedCiphertext_isRejected() throws Exception
    {
        SecureRandom sr = seededRandom("ariaGCM_tamperedCiphertext_isRejected");
        String xform = "ARIA/GCM/NoPadding";
        byte[] key = new byte[32];
        sr.nextBytes(key);
        byte[] iv = new byte[12];
        sr.nextBytes(iv);
        byte[] aad = new byte[32];
        sr.nextBytes(aad);
        byte[] msg = new byte[64];
        sr.nextBytes(msg);

        SecretKey secretKey = new SecretKeySpec(key, "ARIA");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);

        Cipher enc = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);
        enc.updateAAD(aad);
        byte[] ct = enc.doFinal(msg);

        // Tamper ciphertext byte.
        byte[] tampered = ct.clone();
        tampered[0] ^= 0x01;
        Cipher dec = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
        dec.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec);
        dec.updateAAD(aad);
        try
        {
            dec.doFinal(tampered);
            Assertions.fail("ARIA-GCM must reject tampered ciphertext");
        }
        catch (AEADBadTagException expected) { }

        // Tamper tag byte (last 16 bytes of ct).
        byte[] tagFlip = ct.clone();
        tagFlip[tagFlip.length - 1] ^= 0xFF;
        dec = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
        dec.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec);
        dec.updateAAD(aad);
        try
        {
            dec.doFinal(tagFlip);
            Assertions.fail("ARIA-GCM must reject tampered tag");
        }
        catch (AEADBadTagException expected) { }

        // Tamper AAD.
        byte[] tamperedAad = aad.clone();
        tamperedAad[0] ^= 0x01;
        dec = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
        dec.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec);
        dec.updateAAD(tamperedAad);
        try
        {
            dec.doFinal(ct);
            Assertions.fail("ARIA-GCM must reject tampered AAD");
        }
        catch (AEADBadTagException expected) { }
    }


    // -----------------------------------------------------------------
    // ARIA-CCM (AEAD, NIST SP 800-38C) — see AESAgreementTest comments
    // on the dedicated CCM SPI.
    // -----------------------------------------------------------------

    @Test
    public void ariaCCM_agreesWithBC() throws Exception
    {
        SecureRandom sr = seededRandom("ariaCCM_agreesWithBC");
        String xform = "ARIA/CCM/NoPadding";
        for (int keySize : new int[]{16, 24, 32})
        {
            byte[] key = new byte[keySize];
            sr.nextBytes(key);
            byte[] iv = new byte[12];
            sr.nextBytes(iv);
            byte[] aad = new byte[sr.nextInt(64)];
            sr.nextBytes(aad);
            byte[] msg = new byte[1 + sr.nextInt(512)];
            sr.nextBytes(msg);

            SecretKey secretKey = new SecretKeySpec(key, "ARIA");
            GCMParameterSpec spec = new GCMParameterSpec(128, iv);

            Cipher javaEnc = Cipher.getInstance(xform, BouncyCastleProvider.PROVIDER_NAME);
            javaEnc.init(Cipher.ENCRYPT_MODE, secretKey, spec);
            javaEnc.updateAAD(aad);
            byte[] javaCT = javaEnc.doFinal(msg);

            Cipher jostleEnc = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
            jostleEnc.init(Cipher.ENCRYPT_MODE, secretKey, spec);
            jostleEnc.updateAAD(aad);
            byte[] jostleCT = jostleEnc.doFinal(msg);

            Assertions.assertArrayEquals(javaCT, jostleCT,
                    "keySize=" + keySize + ": ARIA-CCM ciphertext+tag diverged");

            Cipher jostleDec = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
            jostleDec.init(Cipher.DECRYPT_MODE, secretKey, spec);
            jostleDec.updateAAD(aad);
            Assertions.assertArrayEquals(msg, jostleDec.doFinal(jostleCT),
                    "keySize=" + keySize + ": ARIA-CCM roundtrip");
        }
    }

    @Test
    public void ariaCCM_tagLengthVariation_agreesWithBC() throws Exception
    {
        SecureRandom sr = seededRandom("ariaCCM_tagLengthVariation_agreesWithBC");
        String xform = "ARIA/CCM/NoPadding";
        byte[] key = new byte[32];
        sr.nextBytes(key);
        byte[] iv = new byte[12];
        sr.nextBytes(iv);
        byte[] aad = new byte[24];
        sr.nextBytes(aad);
        byte[] msg = new byte[1 + sr.nextInt(256)];
        sr.nextBytes(msg);

        for (int tagBits : new int[]{32, 48, 64, 80, 96, 112, 128})
        {
            SecretKey secretKey = new SecretKeySpec(key, "ARIA");
            GCMParameterSpec spec = new GCMParameterSpec(tagBits, iv);

            Cipher javaEnc = Cipher.getInstance(xform, BouncyCastleProvider.PROVIDER_NAME);
            javaEnc.init(Cipher.ENCRYPT_MODE, secretKey, spec);
            javaEnc.updateAAD(aad);
            byte[] javaCT = javaEnc.doFinal(msg);

            Cipher jostleEnc = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
            jostleEnc.init(Cipher.ENCRYPT_MODE, secretKey, spec);
            jostleEnc.updateAAD(aad);
            byte[] jostleCT = jostleEnc.doFinal(msg);

            Assertions.assertArrayEquals(javaCT, jostleCT,
                    "tagBits=" + tagBits + ": ARIA-CCM ciphertext+tag diverged");
        }
    }

    @Test
    public void ariaCCM_tamperedCiphertext_isRejected() throws Exception
    {
        SecureRandom sr = seededRandom("ariaCCM_tamperedCiphertext_isRejected");
        String xform = "ARIA/CCM/NoPadding";
        byte[] key = new byte[32];
        sr.nextBytes(key);
        byte[] iv = new byte[12];
        sr.nextBytes(iv);
        byte[] aad = new byte[32];
        sr.nextBytes(aad);
        byte[] msg = new byte[64];
        sr.nextBytes(msg);

        SecretKey secretKey = new SecretKeySpec(key, "ARIA");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);

        Cipher enc = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        enc.updateAAD(aad);
        byte[] ct = enc.doFinal(msg);

        byte[] tampered = ct.clone();
        tampered[0] ^= 0x01;
        Cipher dec = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
        dec.init(Cipher.DECRYPT_MODE, secretKey, spec);
        dec.updateAAD(aad);
        try
        {
            dec.doFinal(tampered);
            Assertions.fail("ARIA-CCM must reject tampered ciphertext");
        }
        catch (AEADBadTagException expected) { }
    }

    @Test
    public void ariaCCM_incrementalAAD_throwsIllegalState() throws Exception
    {
        SecureRandom sr = seededRandom("ariaCCM_incrementalAAD_throwsIllegalState");
        byte[] key = new byte[16]; sr.nextBytes(key);
        byte[] iv = new byte[12]; sr.nextBytes(iv);

        Cipher c = Cipher.getInstance("ARIA/CCM/NoPadding", JostleProvider.PROVIDER_NAME);
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "ARIA"), new GCMParameterSpec(128, iv));
        c.updateAAD(new byte[]{0x01, 0x02, 0x03});
        try
        {
            c.updateAAD(new byte[]{0x04});
            Assertions.fail("second updateAAD on CCM must throw");
        }
        catch (IllegalStateException expected)
        {
            Assertions.assertTrue(expected.getMessage().toLowerCase().contains("ccm"));
        }
    }

    // --- CCM SPI-machinery parity (shared CCMCipherSpi paths driven
    //     through the ARIA family) ---

    private static byte[] ariaCcmEncChunked(SecretKey key, GCMParameterSpec spec,
                                            byte[] aad, byte[] msg, int chunk) throws Exception
    {
        Cipher c = Cipher.getInstance("ARIA/CCM/NoPadding", JostleProvider.PROVIDER_NAME);
        c.init(Cipher.ENCRYPT_MODE, key, spec);
        if (aad != null)
        {
            c.updateAAD(aad);
        }
        if (chunk <= 0)
        {
            return c.doFinal(msg);
        }
        for (int off = 0; off < msg.length; off += chunk)
        {
            c.update(msg, off, Math.min(chunk, msg.length - off));
        }
        return c.doFinal();
    }

    private static byte[] ariaCcmDec(SecretKey key, GCMParameterSpec spec, byte[] aad, byte[] ct) throws Exception
    {
        Cipher c = Cipher.getInstance("ARIA/CCM/NoPadding", JostleProvider.PROVIDER_NAME);
        c.init(Cipher.DECRYPT_MODE, key, spec);
        if (aad != null)
        {
            c.updateAAD(aad);
        }
        return c.doFinal(ct);
    }

    @Test
    public void ariaCCM_chunkingMatrix_byteIdentical() throws Exception
    {
        SecureRandom sr = seededRandom("ariaCCM_chunkingMatrix_byteIdentical");
        byte[] key = new byte[32]; sr.nextBytes(key);
        byte[] iv = new byte[12]; sr.nextBytes(iv);
        byte[] aad = new byte[40]; sr.nextBytes(aad);
        byte[] msg = new byte[200 + sr.nextInt(120)]; sr.nextBytes(msg);
        SecretKey secretKey = new SecretKeySpec(key, "ARIA");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);

        byte[] reference = ariaCcmEncChunked(secretKey, spec, aad, msg, 0);
        Assertions.assertArrayEquals(reference, ariaCcmEncChunked(secretKey, spec, aad, msg, 1),
                "byte-by-byte diverged");
        for (int chunk : new int[]{15, 16, 17, 31, 32, 33})
        {
            Assertions.assertArrayEquals(reference, ariaCcmEncChunked(secretKey, spec, aad, msg, chunk),
                    "chunk=" + chunk + " diverged");
        }
        Assertions.assertArrayEquals(msg, ariaCcmDec(secretKey, spec, aad, reference), "roundtrip failed");
    }

    @Test
    public void ariaCCM_offsetWrite_roundTripsWithoutClobberingPrefix() throws Exception
    {
        SecureRandom sr = seededRandom("ariaCCM_offsetWrite_roundTripsWithoutClobberingPrefix");
        byte[] key = new byte[32]; sr.nextBytes(key);
        byte[] iv = new byte[12]; sr.nextBytes(iv);
        byte[] aad = new byte[24]; sr.nextBytes(aad);
        byte[] msg = new byte[80]; sr.nextBytes(msg);
        SecretKey secretKey = new SecretKeySpec(key, "ARIA");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);

        int prefix = 7;
        Cipher sizing = Cipher.getInstance("ARIA/CCM/NoPadding", JostleProvider.PROVIDER_NAME);
        sizing.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        int needed = sizing.getOutputSize(msg.length);

        byte[] big = new byte[prefix + needed + 5];
        sr.nextBytes(big);
        byte[] expectedPrefix = new byte[prefix];
        System.arraycopy(big, 0, expectedPrefix, 0, prefix);

        Cipher enc = Cipher.getInstance("ARIA/CCM/NoPadding", JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        enc.updateAAD(aad);
        int written = enc.doFinal(msg, 0, msg.length, big, prefix);

        byte[] actualPrefix = new byte[prefix];
        System.arraycopy(big, 0, actualPrefix, 0, prefix);
        Assertions.assertArrayEquals(expectedPrefix, actualPrefix, "prefix clobbered");

        byte[] ct = new byte[written];
        System.arraycopy(big, prefix, ct, 0, written);
        Assertions.assertArrayEquals(msg, ariaCcmDec(secretKey, spec, aad, ct), "extracted ct failed roundtrip");

        byte[] shifted = new byte[written];
        System.arraycopy(big, prefix - 1, shifted, 0, written);
        try
        {
            byte[] bad = ariaCcmDec(secretKey, spec, aad, shifted);
            Assertions.assertFalse(Arrays.areEqual(msg, bad), "shifted window must not recover plaintext");
        }
        catch (AEADBadTagException expected) { }
    }

    @Test
    public void ariaCCM_offsetWrite_shortBufferRejected() throws Exception
    {
        SecureRandom sr = seededRandom("ariaCCM_offsetWrite_shortBufferRejected");
        byte[] key = new byte[16]; sr.nextBytes(key);
        byte[] iv = new byte[12]; sr.nextBytes(iv);
        byte[] msg = new byte[48]; sr.nextBytes(msg);
        SecretKey secretKey = new SecretKeySpec(key, "ARIA");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);

        Cipher enc = Cipher.getInstance("ARIA/CCM/NoPadding", JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        try
        {
            enc.doFinal(msg, 0, msg.length, new byte[msg.length], 0);
            Assertions.fail("expected ShortBufferException");
        }
        catch (ShortBufferException expected) { }
    }

    @Test
    public void ariaCCM_resetReuse_acrossOperations() throws Exception
    {
        SecureRandom sr = seededRandom("ariaCCM_resetReuse_acrossOperations");
        byte[] key = new byte[32]; sr.nextBytes(key);
        byte[] iv = new byte[12]; sr.nextBytes(iv);
        SecretKey secretKey = new SecretKeySpec(key, "ARIA");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);

        Cipher enc = Cipher.getInstance("ARIA/CCM/NoPadding", JostleProvider.PROVIDER_NAME);
        byte[] m1 = new byte[33]; sr.nextBytes(m1);
        enc.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        byte[] c1 = enc.doFinal(m1);
        Assertions.assertArrayEquals(m1, ariaCcmDec(secretKey, spec, null, c1));

        byte[] iv2 = new byte[12]; sr.nextBytes(iv2);
        GCMParameterSpec spec2 = new GCMParameterSpec(128, iv2);
        byte[] m2 = new byte[64]; sr.nextBytes(m2);
        enc.init(Cipher.ENCRYPT_MODE, secretKey, spec2);
        byte[] c2 = enc.doFinal(m2);
        Assertions.assertArrayEquals(m2, ariaCcmDec(secretKey, spec2, null, c2));

        Cipher dec = Cipher.getInstance("ARIA/CCM/NoPadding", JostleProvider.PROVIDER_NAME);
        byte[] tampered = c2.clone();
        tampered[0] ^= 0x01;
        dec.init(Cipher.DECRYPT_MODE, secretKey, spec2);
        try
        {
            dec.doFinal(tampered);
            Assertions.fail("expected AEADBadTagException");
        }
        catch (AEADBadTagException expected) { }
        dec.init(Cipher.DECRYPT_MODE, secretKey, spec2);
        Assertions.assertArrayEquals(m2, dec.doFinal(c2), "instance poisoned after tamper failure");
    }

    @Test
    public void ariaCCM_emptyPlaintext_agreesWithBC() throws Exception
    {
        SecureRandom sr = seededRandom("ariaCCM_emptyPlaintext_agreesWithBC");
        byte[] key = new byte[16]; sr.nextBytes(key);
        byte[] iv = new byte[12]; sr.nextBytes(iv);
        byte[] aad = new byte[40]; sr.nextBytes(aad);
        SecretKey secretKey = new SecretKeySpec(key, "ARIA");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);

        Cipher bc = Cipher.getInstance("ARIA/CCM/NoPadding", BouncyCastleProvider.PROVIDER_NAME);
        bc.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        bc.updateAAD(aad);
        byte[] bcCt = bc.doFinal(new byte[0]);

        Cipher jo = Cipher.getInstance("ARIA/CCM/NoPadding", JostleProvider.PROVIDER_NAME);
        jo.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        jo.updateAAD(aad);
        byte[] joCt = jo.doFinal(new byte[0]);

        Assertions.assertArrayEquals(bcCt, joCt, "empty-plaintext tag diverged");
        Assertions.assertEquals(0, ariaCcmDec(secretKey, spec, aad, joCt).length);
    }

    @Test
    public void ariaCCM_tamperedTagAndAAD_rejected() throws Exception
    {
        SecureRandom sr = seededRandom("ariaCCM_tamperedTagAndAAD_rejected");
        byte[] key = new byte[32]; sr.nextBytes(key);
        byte[] iv = new byte[12]; sr.nextBytes(iv);
        byte[] aad = new byte[32]; sr.nextBytes(aad);
        byte[] msg = new byte[64]; sr.nextBytes(msg);
        SecretKey secretKey = new SecretKeySpec(key, "ARIA");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);

        Cipher enc = Cipher.getInstance("ARIA/CCM/NoPadding", JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        enc.updateAAD(aad);
        byte[] ct = enc.doFinal(msg);

        // Tamper the tag (last 16 bytes).
        byte[] tagFlip = ct.clone();
        tagFlip[tagFlip.length - 1] ^= 0xFF;
        try
        {
            ariaCcmDec(secretKey, spec, aad, tagFlip);
            Assertions.fail("ARIA-CCM must reject tampered tag");
        }
        catch (AEADBadTagException expected) { }

        // Tamper the AAD.
        byte[] tamperedAad = aad.clone();
        tamperedAad[0] ^= 0x01;
        try
        {
            ariaCcmDec(secretKey, spec, tamperedAad, ct);
            Assertions.fail("ARIA-CCM must reject tampered AAD");
        }
        catch (AEADBadTagException expected) { }
    }

    @Test
    public void ariaCCM_nonceLengthBoundaries() throws Exception
    {
        SecureRandom sr = seededRandom("ariaCCM_nonceLengthBoundaries");
        byte[] key = new byte[32]; sr.nextBytes(key);
        SecretKey secretKey = new SecretKeySpec(key, "ARIA");
        byte[] aad = new byte[16]; sr.nextBytes(aad);
        byte[] msg = new byte[64]; sr.nextBytes(msg);

        for (int ivLen = 7; ivLen <= 13; ivLen++)
        {
            byte[] iv = new byte[ivLen]; sr.nextBytes(iv);
            GCMParameterSpec spec = new GCMParameterSpec(128, iv);

            Cipher bc = Cipher.getInstance("ARIA/CCM/NoPadding", BouncyCastleProvider.PROVIDER_NAME);
            bc.init(Cipher.ENCRYPT_MODE, secretKey, spec);
            bc.updateAAD(aad);
            byte[] bcCt = bc.doFinal(msg);

            Cipher jo = Cipher.getInstance("ARIA/CCM/NoPadding", JostleProvider.PROVIDER_NAME);
            jo.init(Cipher.ENCRYPT_MODE, secretKey, spec);
            jo.updateAAD(aad);
            Assertions.assertArrayEquals(bcCt, jo.doFinal(msg), "ivLen=" + ivLen + " diverged from BC");
        }

        for (int badLen : new int[]{6, 14, 16})
        {
            byte[] iv = new byte[badLen]; sr.nextBytes(iv);
            try
            {
                Cipher c = Cipher.getInstance("ARIA/CCM/NoPadding", JostleProvider.PROVIDER_NAME);
                c.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(128, iv));
                c.updateAAD(aad);
                c.doFinal(msg);
                Assertions.fail("ARIA-CCM must reject nonce length " + badLen);
            }
            // CCMCipherSpi validates nonce length at engineInit, so the
            // rejection is the JCE-correct InvalidAlgorithmParameterException.
            catch (InvalidAlgorithmParameterException expected) { }
        }
    }

    /**
     * Key-length boundary: valid ARIA sizes {16,24,32} accepted
     * (exercising ARIA-128/192/256-CCM), and each length one byte to
     * either side — plus 1 and well-above-max — rejected. (0 isn't probed:
     * SecretKeySpec rejects an empty key before init.)
     */
    @Test
    public void ariaCCM_wrongKeyLength_rejected() throws Exception
    {
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        for (int len : new int[]{16, 24, 32})
        {
            Cipher c = Cipher.getInstance("ARIA/CCM/NoPadding", JostleProvider.PROVIDER_NAME);
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[len], "ARIA"),
                    new GCMParameterSpec(128, iv));
        }
        for (int badLen : new int[]{1, 15, 17, 23, 25, 31, 33, 64})
        {
            Cipher c = Cipher.getInstance("ARIA/CCM/NoPadding", JostleProvider.PROVIDER_NAME);
            try
            {
                c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[badLen], "ARIA"),
                        new GCMParameterSpec(128, iv));
                Assertions.fail("ARIA-CCM must reject key length " + badLen);
            }
            catch (InvalidKeyException expected) { }
        }
    }

    /**
     * Tag lengths that are multiples of 8 bits but NOT in the CCM valid
     * set {32,48,64,80,96,112,128} must be rejected at engineInit with
     * InvalidAlgorithmParameterException.
     */
    @Test
    public void ariaCCM_invalidTagLength_rejected() throws Exception
    {
        byte[] key = new byte[16];
        new SecureRandom().nextBytes(key);
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        SecretKey secretKey = new SecretKeySpec(key, "ARIA");
        // 16=2 bytes (<min), 40=5 bytes (odd), 144=18 bytes (>max).
        for (int badTagBits : new int[]{16, 40, 144})
        {
            Cipher c = Cipher.getInstance("ARIA/CCM/NoPadding", JostleProvider.PROVIDER_NAME);
            try
            {
                c.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(badTagBits, iv));
                Assertions.fail("ARIA-CCM must reject tag length " + badTagBits + " bits");
            }
            catch (InvalidAlgorithmParameterException expected) { }
        }
    }

    /**
     * ARIA-CCM accepts an IvParameterSpec (nonce only); the tag defaults
     * to 64 bits to match BouncyCastle's CCM IV-only default, so the
     * output agrees with BC byte-for-byte.
     */
    @Test
    public void ariaCCM_ivParameterSpec_agreesWithBC() throws Exception
    {
        SecureRandom sr = seededRandom("ariaCCM_ivParameterSpec_agreesWithBC");
        String xform = "ARIA/CCM/NoPadding";
        byte[] key = new byte[32]; sr.nextBytes(key);
        byte[] iv = new byte[12]; sr.nextBytes(iv);
        byte[] aad = new byte[sr.nextInt(48)]; sr.nextBytes(aad);
        byte[] msg = new byte[1 + sr.nextInt(256)]; sr.nextBytes(msg);

        SecretKey secretKey = new SecretKeySpec(key, "ARIA");
        IvParameterSpec spec = new IvParameterSpec(iv);

        Cipher bcEnc = Cipher.getInstance(xform, BouncyCastleProvider.PROVIDER_NAME);
        bcEnc.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        bcEnc.updateAAD(aad);
        byte[] bcCt = bcEnc.doFinal(msg);

        Cipher joEnc = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
        joEnc.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        joEnc.updateAAD(aad);
        byte[] joCt = joEnc.doFinal(msg);

        Assertions.assertArrayEquals(bcCt, joCt,
                "ARIA-CCM IvParameterSpec diverged from BC (default tag length mismatch?)");
        Assertions.assertEquals(msg.length + 8, joCt.length, "expected 8-byte default CCM tag");

        Cipher joDec = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
        joDec.init(Cipher.DECRYPT_MODE, secretKey, spec);
        joDec.updateAAD(aad);
        Assertions.assertArrayEquals(msg, joDec.doFinal(joCt), "ARIA-CCM IvParameterSpec roundtrip failed");
    }


    /**
     * ARIA-CTR accepts IVs in the range [block_size/2, block_size] —
     * i.e. 8..16 bytes for the 128-bit ARIA block size. Every valid
     * length must agree with BC byte-for-byte; lengths outside the
     * range must be rejected by both.
     */
    @Test
    public void ariaCtr_nonceLengthBoundaries() throws Exception
    {
        SecureRandom sr = seededRandom("ariaCtr_nonceLengthBoundaries");
        String xform = "ARIA/CTR/NoPadding";
        byte[] key = new byte[32];
        sr.nextBytes(key);
        SecretKey secretKey = new SecretKeySpec(key, "ARIA");
        byte[] msg = new byte[64];
        sr.nextBytes(msg);

        for (int ivLen = 8; ivLen <= 16; ivLen++)
        {
            byte[] iv = new byte[ivLen];
            sr.nextBytes(iv);
            IvParameterSpec spec = new IvParameterSpec(iv);

            Cipher javaEnc = Cipher.getInstance(xform, BouncyCastleProvider.PROVIDER_NAME);
            javaEnc.init(Cipher.ENCRYPT_MODE, secretKey, spec);
            byte[] javaCT = javaEnc.doFinal(msg);

            Cipher jostleEnc = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
            jostleEnc.init(Cipher.ENCRYPT_MODE, secretKey, spec);
            byte[] jostleCT = jostleEnc.doFinal(msg);

            Assertions.assertArrayEquals(javaCT, jostleCT,
                    "ivLen=" + ivLen + ": ARIA-CTR ciphertext diverged from BC");

            Cipher jostleDec = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
            jostleDec.init(Cipher.DECRYPT_MODE, secretKey, spec);
            Assertions.assertArrayEquals(msg, jostleDec.doFinal(jostleCT),
                    "ivLen=" + ivLen + ": ARIA-CTR roundtrip failed");
        }

        for (int badLen : new int[]{0, 1, 7, 17, 32})
        {
            byte[] iv = new byte[badLen];
            sr.nextBytes(iv);
            Cipher c = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
            try
            {
                c.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
                Assertions.fail("ARIA-CTR must reject IV length " + badLen);
            }
            catch (InvalidAlgorithmParameterException expected) { }
        }
    }

}
