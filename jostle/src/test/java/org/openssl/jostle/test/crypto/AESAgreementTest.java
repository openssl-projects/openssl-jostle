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
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;

import static org.junit.jupiter.api.Assertions.fail;

/**
 * Test agreement between BC Java and Jostle.
 * Official vector tests elsewhere
 */
public class AESAgreementTest
{
    static SecureRandom secRand = new SecureRandom();

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


    private void exercise_simpleDoFinal(String xform, int[] keys, int top, int step, int ivLen) throws Exception
    {

        for (int keySize : keys)
        {
            for (int t = 0; t < top; t += step)
            {
                byte[] msg = new byte[t];
                secRand.nextBytes(msg);

                byte[] key = new byte[keySize];
                secRand.nextBytes(key);

                byte[] iv = null;
                IvParameterSpec ivSpec = null;
                if (ivLen > -1)
                {
                    iv = new byte[ivLen];
                    secRand.nextBytes(iv);
                    ivSpec = new IvParameterSpec(iv);
                }


                SecretKey secretKey = new SecretKeySpec(key, "AES");

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


    private void exercise_complexDoFinal(String xform, int[] keys, int top, int step, int ivLen) throws Exception
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
                        secRand.nextBytes(msg);

                        byte[] key = new byte[keySize];
                        secRand.nextBytes(key);

                        byte[] iv = null;
                        IvParameterSpec ivSpec = null;
                        if (ivLen > -1)
                        {
                            iv = new byte[ivLen];
                            secRand.nextBytes(iv);
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

                        SecretKey secretKey = new SecretKeySpec(key, "AES");

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

                        secRand.nextBytes(outputJavaCt);
                        secRand.nextBytes(outputJostleCt);

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

                        secRand.nextBytes(outputJavaPt);
                        secRand.nextBytes(outputJostlePt);
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
                            fail("decrypt failed to agree");
                        }

                        Assertions.assertTrue(Arrays.areEqual(outputJavaPt, startPos, endPos, outputJostlePt, startPos, endPos));

                        Assertions.assertTrue(Arrays.areEqual(outputJavaPt, startPos, endPos, msg, 0, msg.length - 1));
                    }
                }
            }
        }
    }


    private void exercise_complexUpdateDoFinal(String xform, int[] keys, int top, int step, int ivLen) throws Exception
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
                        secRand.nextBytes(msg);

                        //
                        // Split the original message between update and do final.
                        //


                        byte[] key = new byte[keySize];
                        secRand.nextBytes(key);

                        byte[] iv = null;
                        IvParameterSpec ivSpec = null;
                        if (ivLen > -1)
                        {
                            iv = new byte[ivLen];
                            secRand.nextBytes(iv);
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

                        SecretKey secretKey = new SecretKeySpec(key, "AES");

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

                        secRand.nextBytes(outputJavaCt);
                        secRand.nextBytes(outputJostleCt);

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

                        secRand.nextBytes(outputJavaPt);
                        secRand.nextBytes(outputJostlePt);
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
                                fail("decrypt failed to agree");
                            }

                            Assertions.assertTrue(Arrays.areEqual(outputJavaPt, startPos, endPos, outputJostlePt, startPos, endPos));
                            Assertions.assertTrue(Arrays.areEqual(outputJavaPt, startPos, endPos, msg, 0, msg.length - 1));
                        }
                    }
                }
            }
        }
    }

    private void exercise_complexDoFinalSameArray(String xform, int[] keys, int top, int step, int ivLen) throws Exception
    {
        for (int keySize : keys)
        {
            int msgLen = top;


            byte[] msg = new byte[msgLen];
            secRand.nextBytes(msg);

            //
            // Split the original message between update and do final.
            //


            byte[] key = new byte[keySize];
            secRand.nextBytes(key);

            byte[] iv = null;
            IvParameterSpec ivSpec = null;
            if (ivLen > -1)
            {
                iv = new byte[ivLen];
                secRand.nextBytes(iv);
                ivSpec = new IvParameterSpec(iv);
            }


            SecretKey secretKey = new SecretKeySpec(key, "AES");

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

            //  secRand.nextBytes(workingArrayJava);

            System.arraycopy(msg, 0, workingArrayJostle, 0, msg.length);


            byte[] originalWorkingArray = new byte[workingArrayJostle.length];


            // Encryption side.

            for (int offsetInput = 0; offsetInput < msgLen; offsetInput++)
            {

                // Flood array and create backup
                secRand.nextBytes(workingArrayJostle);
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
                secRand.nextBytes(workingArrayJostle);
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
                        Assertions.assertEquals(originalWorkingArray[i++], workingArrayJostle[j]);
                    }

                }

            }


        }


    }


    @Test
    public void testAes() throws Exception
    {


        //
        // The doFinal that returns a byte[]
        //

        exercise_simpleDoFinal("AES/ECB/NoPadding", new int[]{16, 24, 32}, 5 * 16, 16, -1);
        exercise_simpleDoFinal("AES/ECB/PKCS7Padding", new int[]{16, 24, 32}, (5 * 16) + 1, 1, -1);

        exercise_simpleDoFinal("AES/CBC/NoPadding", new int[]{16, 24, 32}, 5 * 16, 16, 16);
        exercise_simpleDoFinal("AES/CBC/PKCS7Padding", new int[]{16, 24, 32}, (5 * 16) + 1, 1, 16);
        exercise_simpleDoFinal("AES/CBC/PKCS5Padding", new int[]{16, 24, 32}, (5 * 16) + 1, 1, 16);
        exercise_simpleDoFinal("AES/CFB128/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 16);
        exercise_simpleDoFinal("AES/CFB8/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 16);
        exercise_simpleDoFinal("AES/OFB/NoPadding", new int[]{16, 24, 32}, 5 * 16, 1, 16);

        exercise_simpleDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 8);
        exercise_simpleDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 9);
        exercise_simpleDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 10);
        exercise_simpleDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 11);
        exercise_simpleDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 12);
        exercise_simpleDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 13);
        exercise_simpleDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 14);
        exercise_simpleDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 15);
        exercise_simpleDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 16);


        //
        // Complex doFinal, that takes input and output arrays.
        //


        exercise_complexDoFinal("AES/ECB/NoPadding", new int[]{16, 24, 32}, 5 * 16, 16, -1);
        exercise_complexDoFinal("AES/ECB/PKCS7Padding", new int[]{16, 24, 32}, (5 * 16) + 1, 1, -1);

        exercise_complexDoFinal("AES/CBC/NoPadding", new int[]{16, 24, 32}, 5 * 16, 16, 16);
        exercise_complexDoFinal("AES/CBC/PKCS7Padding", new int[]{16, 24, 32}, (5 * 16) + 1, 1, 16);
        exercise_complexDoFinal("AES/CBC/PKCS5Padding", new int[]{16, 24, 32}, (5 * 16) + 1, 1, 16);
        exercise_complexDoFinal("AES/CFB128/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 16);
        exercise_complexDoFinal("AES/CFB8/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 16);
        exercise_complexDoFinal("AES/OFB/NoPadding", new int[]{16, 24, 32}, 5 * 16, 1, 16);

        exercise_complexDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 8);
        exercise_complexDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 9);
        exercise_complexDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 10);
        exercise_complexDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 11);
        exercise_complexDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 12);
        exercise_complexDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 13);
        exercise_complexDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 14);
        exercise_complexDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 15);
        exercise_complexDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 16);


        //
        // Spread message between update and doFinal calls.
        //
        exercise_complexUpdateDoFinal("AES/ECB/NoPadding", new int[]{16, 24, 32}, 5 * 16, 16, -1);
        exercise_complexUpdateDoFinal("AES/ECB/PKCS7Padding", new int[]{16, 24, 32}, (5 * 16) + 1, 1, -1);

        exercise_complexUpdateDoFinal("AES/CBC/NoPadding", new int[]{16, 24, 32}, 5 * 16, 16, 16);
        exercise_complexUpdateDoFinal("AES/CBC/PKCS7Padding", new int[]{16, 24, 32}, (5 * 16) + 1, 1, 16);
        exercise_complexUpdateDoFinal("AES/CBC/PKCS5Padding", new int[]{16, 24, 32}, (5 * 16) + 1, 1, 16);
        exercise_complexUpdateDoFinal("AES/CFB128/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 16);
        exercise_complexUpdateDoFinal("AES/CFB8/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 16);
        exercise_complexUpdateDoFinal("AES/OFB/NoPadding", new int[]{16, 24, 32}, 5 * 16, 1, 16);

        exercise_complexUpdateDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 8);
        exercise_complexUpdateDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 9);
        exercise_complexUpdateDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 10);
        exercise_complexUpdateDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 11);
        exercise_complexUpdateDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 12);
        exercise_complexUpdateDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 13);
        exercise_complexUpdateDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 14);
        exercise_complexUpdateDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 15);
        exercise_complexUpdateDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 16);


        //
        // Where input and output array is the same.
        //

        exercise_complexDoFinalSameArray("AES/ECB/NoPadding", new int[]{16, 24, 32}, 16 * 17, 16, -1);
        exercise_complexDoFinalSameArray("AES/ECB/PKCS7Padding", new int[]{16, 24, 32}, (5 * 16) + 1, 1, -1);

        exercise_complexDoFinalSameArray("AES/CBC/NoPadding", new int[]{16, 24, 32}, 5 * 16, 16, 16);
        exercise_complexDoFinalSameArray("AES/CBC/PKCS7Padding", new int[]{16, 24, 32}, (5 * 16) + 1, 1, 16);
        exercise_complexDoFinalSameArray("AES/CBC/PKCS5Padding", new int[]{16, 24, 32}, (5 * 16) + 1, 1, 16);
        exercise_complexDoFinalSameArray("AES/CFB128/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 16);
        exercise_complexDoFinalSameArray("AES/CFB8/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 16);
        exercise_complexDoFinalSameArray("AES/OFB/NoPadding", new int[]{16, 24, 32}, 5 * 16, 1, 16);

        exercise_complexDoFinalSameArray("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 8);
        exercise_complexDoFinalSameArray("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 9);
        exercise_complexDoFinalSameArray("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 10);
        exercise_complexDoFinalSameArray("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 11);
        exercise_complexDoFinalSameArray("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 12);
        exercise_complexDoFinalSameArray("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 13);
        exercise_complexDoFinalSameArray("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 14);
        exercise_complexDoFinalSameArray("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 15);
        exercise_complexDoFinalSameArray("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 16);


    }


    @Test
    public void aesGCMSpread() throws Exception
    {
        SecureRandom random = new SecureRandom();


        String xform = "AES/GCM/NoPadding";

        int maxLen = 1 + 16 * 17;

        int ivLen = 12; // Only support 12
        {
            byte[] iv = new byte[ivLen];

            for (int ksLen : new int[]{16, 24, 32})
            {
                byte[] key = new byte[ksLen];
                random.nextBytes(key);
                for (int mLen = 16; mLen < maxLen; mLen++)
                {
                    random.nextBytes(iv); // IV reuse

                    byte[] msg = new byte[mLen];
                    random.nextBytes(msg);

                    SecretKey secretKey = new SecretKeySpec(key, "AES");
                    IvParameterSpec ivSpec = new IvParameterSpec(iv);

                    Cipher javaEnc = Cipher.getInstance(xform, BouncyCastleProvider.PROVIDER_NAME);
                    javaEnc.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

                    Cipher javaDec = Cipher.getInstance(xform, BouncyCastleProvider.PROVIDER_NAME);
                    javaDec.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

                    Cipher jostleEnc = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
                    jostleEnc.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

                    Cipher jostleDec = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
                    jostleDec.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

                    //
                    // Encrypt
                    //

                    byte[] javaCT = javaEnc.doFinal(msg);
                    byte[] josteCT = jostleEnc.doFinal(msg);

                    if (!Arrays.areEqual(javaCT, josteCT))
                    {
                        System.out.println("msg len: " + msg.length);
                        System.out.println("JA " + Hex.toHexString(javaCT));
                        System.out.println("JO " + Hex.toHexString(josteCT));
                    }

                    Assertions.assertArrayEquals(javaCT, josteCT);

                    //
                    // Decrypt
                    //

                    byte[] javaPT = javaDec.doFinal(javaCT);
                    byte[] jostePT = jostleDec.doFinal(josteCT);

                    if (!Arrays.areEqual(javaPT, jostePT))
                    {
                        System.out.println("msg len: " + msg.length);
                        System.out.println("JA " + Hex.toHexString(javaPT));
                        System.out.println("JO " + Hex.toHexString(jostePT));
                    }


                    Assertions.assertArrayEquals(javaPT, jostePT);
                    Assertions.assertArrayEquals(msg, jostePT);

                    try
                    {
                        josteCT[0] ^= 1;
                        jostePT = jostleDec.doFinal(josteCT);
                        fail("damaged cipher text not detected");
                    } catch (AEADBadTagException ex)
                    {
                        Assertions.assertEquals("bad tag", ex.getMessage());
                    }

                }
            }
        }

    }


    @Test
    public void aesGCMSpreadSplitUpdateDoFinal() throws Exception
    {
        SecureRandom random = new SecureRandom();


        String xform = "AES/GCM/NoPadding";

        int maxLen = 1 + 16 * 17;
        int tagLen = 16;
        int ivLen = 12; // Only support 12
        {
            byte[] iv = new byte[ivLen];

            for (int ksLen : new int[]{16, 24, 32})
            {
                byte[] key = new byte[ksLen];
                random.nextBytes(key);
                ArrayList<Integer> splitPoints = new ArrayList<>();

                for (int mLen = 3; mLen < maxLen; mLen++) // zero length input
                {


                    splitPoints.add(0);
                    splitPoints.add(1);
                    if (mLen >= 17)
                    {
                        splitPoints.add(15);
                        splitPoints.add(16);
                        splitPoints.add(17);
                    } else
                    {
                        splitPoints.add(random.nextInt(mLen));
                    }

                    for (int splitPoint : splitPoints)
                    {


                        random.nextBytes(iv); // IV reuse

                        byte[] msg = new byte[mLen];
                        random.nextBytes(msg);

                        SecretKey secretKey = new SecretKeySpec(key, "AES");
                        IvParameterSpec ivSpec = new IvParameterSpec(iv);

                        Cipher javaEnc = Cipher.getInstance(xform, BouncyCastleProvider.PROVIDER_NAME);
                        javaEnc.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

                        Cipher javaDec = Cipher.getInstance(xform, BouncyCastleProvider.PROVIDER_NAME);
                        javaDec.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

                        Cipher jostleEnc = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
                        jostleEnc.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

                        Cipher jostleDec = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
                        jostleDec.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

                        //
                        // Encrypt
                        //


                        byte[] javaCT = new byte[msg.length + tagLen];
                        int p = javaEnc.update(msg, 0, splitPoint, javaCT);
                        p += javaEnc.doFinal(msg, splitPoint, msg.length - splitPoint, javaCT, p);


                        byte[] jostleCT = new byte[msg.length + tagLen];
                        p = jostleEnc.update(msg, 0, splitPoint, jostleCT);
                        p += jostleEnc.doFinal(msg, splitPoint, msg.length - splitPoint, jostleCT, p);


                        if (!Arrays.areEqual(javaCT, jostleCT))
                        {
                            System.out.println("msg len: " + msg.length);
                            System.out.println("JA " + Hex.toHexString(javaCT));
                            System.out.println("JO " + Hex.toHexString(jostleCT));
                        }

                        Assertions.assertArrayEquals(javaCT, jostleCT);

                        //
                        // Decrypt
                        //

                        byte[] javaPT = new byte[msg.length];
                        p = javaDec.update(javaCT, 0, splitPoint, javaPT);
                        javaDec.doFinal(javaCT, splitPoint, jostleCT.length - splitPoint, javaPT, p);


                        byte[] jostlePT = new byte[msg.length];
                        p = jostleDec.update(jostleCT, 0, splitPoint, jostlePT);
                        jostleDec.doFinal(jostleCT, splitPoint, jostleCT.length - splitPoint, jostlePT, p);


                        if (!Arrays.areEqual(javaPT, jostlePT))
                        {
                            System.out.println("msg len: " + msg.length);
                            System.out.println("JA " + Hex.toHexString(javaPT));
                            System.out.println("JO " + Hex.toHexString(jostlePT));
                        }


                        Assertions.assertArrayEquals(javaPT, jostlePT);
                        Assertions.assertArrayEquals(msg, jostlePT);
                    }
                }
            }
        }

    }


    @Test
    public void aesGCMWithAAD() throws Exception
    {

        SecureRandom random = new SecureRandom();

        String xform = "AES/GCM/NoPadding";
        byte[] iv = new byte[12];
        random.nextBytes(iv); // IV reuse


        int mLen = 1 + 16 * 17;

        for (int aadLen = 0; aadLen < 129; aadLen++)
        {
            byte[] aad = new byte[aadLen];
            random.nextBytes(aad);

            byte[] key = new byte[32];
            random.nextBytes(key);
            byte[] msg = new byte[mLen];
            random.nextBytes(msg);


            SecretKey secretKey = new SecretKeySpec(key, "AES");
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            Cipher javaEnc = Cipher.getInstance(xform, BouncyCastleProvider.PROVIDER_NAME);
            javaEnc.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

            Cipher javaDec = Cipher.getInstance(xform, BouncyCastleProvider.PROVIDER_NAME);
            javaDec.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

            Cipher jostleEnc = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
            jostleEnc.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

            Cipher jostleDec = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
            jostleDec.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);


            javaEnc.updateAAD(aad, 0, aad.length);
            jostleEnc.updateAAD(aad, 0, aad.length);
            //
            // Encrypt
            //

            byte[] javaCT = javaEnc.doFinal(msg);
            byte[] josteCT = jostleEnc.doFinal(msg);

            if (!Arrays.areEqual(javaCT, josteCT))
            {
                System.out.println("msg len: " + msg.length);
                System.out.println("JA " + Hex.toHexString(javaCT));
                System.out.println("JO " + Hex.toHexString(josteCT));
            }

            Assertions.assertArrayEquals(javaCT, josteCT);

            //
            // Decrypt
            //


            javaDec.updateAAD(aad, 0, aad.length);
            jostleDec.updateAAD(aad, 0, aad.length);

            byte[] javaPT = javaDec.doFinal(javaCT);
            byte[] jostePT = jostleDec.doFinal(josteCT);

            Assertions.assertArrayEquals(javaPT, jostePT);
            Assertions.assertArrayEquals(msg, jostePT);


            //
            // Check fails without AAD
            //
            if (aadLen > 0)
            {
                // Can only run when there is actual aad not a zero length array.
                try
                {
                    jostleDec = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
                    jostleDec.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

                    byte[] jostlePTWithoutAAD = jostleDec.doFinal(josteCT);
                    fail("no aad");
                } catch (AEADBadTagException ex)
                {
                    Assertions.assertEquals("bad tag", ex.getMessage());
                }
            }


            try
            {
                jostleDec.updateAAD(aad, 0, aad.length);
                josteCT[0] ^= 1;
                jostePT = jostleDec.doFinal(josteCT);
                fail("damaged cipher text not detected");
            } catch (AEADBadTagException ex)
            {
                Assertions.assertEquals("bad tag", ex.getMessage());
            }
        }
    }


    @Test
    public void aesGCMWithTagLen() throws Exception
    {

        SecureRandom random = new SecureRandom();

        String xform = "AES/GCM/NoPadding";
        byte[] iv = new byte[12];
        random.nextBytes(iv); // IV reuse


        for (int tagLen = 64; tagLen < 128; tagLen += 8)
        {

            for (int mlen = 0; mlen < 1 + 5 * 16; )
            {

                byte[] key = new byte[32];
                random.nextBytes(key);
                byte[] msg = new byte[mlen];
                random.nextBytes(msg);


                SecretKey secretKey = new SecretKeySpec(key, "AES");
                GCMParameterSpec gcmSpec = new GCMParameterSpec(tagLen, iv);

                Cipher javaEnc = Cipher.getInstance(xform, BouncyCastleProvider.PROVIDER_NAME);
                javaEnc.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);

                Cipher javaDec = Cipher.getInstance(xform, BouncyCastleProvider.PROVIDER_NAME);
                javaDec.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec);

                Cipher jostleEnc = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
                jostleEnc.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);

                Cipher jostleDec = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
                jostleDec.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec);


                //
                // Encrypt
                //

                byte[] javaCT = javaEnc.doFinal(msg);
                byte[] josteCT = jostleEnc.doFinal(msg);

                Assertions.assertEquals(mlen + (tagLen >> 3), josteCT.length);

                if (!Arrays.areEqual(javaCT, josteCT))
                {
                    System.out.println("msg len: " + msg.length);
                    System.out.println("JA " + Hex.toHexString(javaCT));
                    System.out.println("JO " + Hex.toHexString(josteCT));
                }

                Assertions.assertArrayEquals(javaCT, josteCT);

                //
                // Decrypt
                //


                byte[] javaPT = javaDec.doFinal(javaCT);
                byte[] jostePT = jostleDec.doFinal(josteCT);

                Assertions.assertArrayEquals(javaPT, jostePT);
                Assertions.assertArrayEquals(msg, jostePT);


                //
                // Check fails without AAD
                //

                try
                {
                    josteCT[0] ^= 1;
                    jostePT = jostleDec.doFinal(josteCT);
                    fail("damaged cipher text not detected");
                } catch (AEADBadTagException ex)
                {
                    Assertions.assertEquals("bad tag", ex.getMessage());
                }

                if (mlen < 64)
                {
                    mlen++;
                } else
                {
                    mlen += 16;
                }

            }
        }
    }

    @Test
    public void testRejectIncorrectKeyAlgorithm() throws Exception
    {
        SecretKeySpec wrongSpec = new SecretKeySpec(new byte[16], "ARIA");

        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding",JostleProvider.PROVIDER_NAME);
            cipher.init(Cipher.ENCRYPT_MODE, wrongSpec);
            Assertions.fail("Should have thrown an exception");
        } catch (InvalidKeyException ikes) {
            Assertions.assertEquals("unsupported key algorithm ARIA",ikes.getMessage());
        }

        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding",JostleProvider.PROVIDER_NAME);
            cipher.init(Cipher.ENCRYPT_MODE, wrongSpec, new IvParameterSpec(new byte[16]));
            Assertions.fail("Should have thrown an exception");
        } catch (InvalidKeyException ikes) {
            Assertions.assertEquals("unsupported key algorithm ARIA",ikes.getMessage());
        }

        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding",JostleProvider.PROVIDER_NAME);
            org.openssl.jostle.test.crypto.DummyParams params = new org.openssl.jostle.test.crypto.DummyParams();
            params.init(new byte[16]);
            cipher.init(Cipher.ENCRYPT_MODE, wrongSpec, params);
            Assertions.fail("Should have thrown an exception");
        } catch (InvalidKeyException ikes) {
            Assertions.assertEquals("unsupported key algorithm ARIA",ikes.getMessage());
        }


        // Correct spec
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding", JostleProvider.PROVIDER_NAME);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[16], "AES"));

        cipher = Cipher.getInstance("AES/CBC/NoPadding", JostleProvider.PROVIDER_NAME);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[16], "AES"), new IvParameterSpec(new byte[16]));

        cipher = Cipher.getInstance("AES/CBC/NoPadding", JostleProvider.PROVIDER_NAME);
        org.openssl.jostle.test.crypto.DummyParams params = new org.openssl.jostle.test.crypto.DummyParams();
        params.init(new byte[16]);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[16], "AES"), params);
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


    @Test
    public void testJce_aes128Xts_ieee1619Vector2() throws Exception
    {
        // JCE-level KAT for AES-128-XTS via Jostle. Mirrors the native-layer
        // KAT in BlockCipherLimitTest, exercising the full provider pipeline:
        //   Cipher.getInstance("AES/XTS/NoPadding") → engineSetMode("XTS") →
        //   determineOSSLCipher(32 → AES128 because mode==XTS) → native init.
        //
        // IEEE Std 1619-2007 Annex B Vector 2:
        //   K = 0x11 * 16 || 0x22 * 16
        //   tweak = 0x33 * 5 || 0x00 * 11
        //   pt = 0x44 * 32
        //   ct = c454185e6a16936e39334038acef838bfb186fff7480adc4289382ecd6d394f0
        byte[] key = new byte[32];
        for (int i = 0; i < 16; i++) key[i] = 0x11;
        for (int i = 16; i < 32; i++) key[i] = 0x22;
        byte[] iv = new byte[16];
        for (int i = 0; i < 5; i++) iv[i] = 0x33;
        byte[] pt = new byte[32];
        for (int i = 0; i < 32; i++) pt[i] = 0x44;
        byte[] expectedCt = Hex.decode("c454185e6a16936e39334038acef838bfb186fff7480adc4289382ecd6d394f0");

        Cipher c = Cipher.getInstance("AES/XTS/NoPadding", JostleProvider.PROVIDER_NAME);
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        byte[] ct = c.doFinal(pt);
        Assertions.assertArrayEquals(expectedCt, ct);

        // Round-trip: decrypt and verify we get pt back.
        Cipher d = Cipher.getInstance("AES/XTS/NoPadding", JostleProvider.PROVIDER_NAME);
        d.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        byte[] decrypted = d.doFinal(ct);
        Assertions.assertArrayEquals(pt, decrypted);
    }

    @Test
    public void testJce_aes256Xts_kat() throws Exception
    {
        // JCE-level KAT for AES-256-XTS. Exercises the keySize=64 path in
        // determineOSSLCipher. KAT vector matches the native-layer test.
        byte[] key = new byte[64];
        for (int i = 0; i < 64; i++) key[i] = (byte) i;
        byte[] iv = new byte[16];
        for (int i = 0; i < 16; i++) iv[i] = (byte) (i + 100);
        byte[] pt = new byte[32];
        for (int i = 0; i < 32; i++) pt[i] = (byte) (i * 3 + 7);
        byte[] expectedCt = Hex.decode("a7399efea2c66376055c1acd97933a8c6ac8dd3005f3396c3959b3ad323a3db4");

        Cipher c = Cipher.getInstance("AES/XTS/NoPadding", JostleProvider.PROVIDER_NAME);
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        byte[] ct = c.doFinal(pt);
        Assertions.assertArrayEquals(expectedCt, ct);

        Cipher d = Cipher.getInstance("AES/XTS/NoPadding", JostleProvider.PROVIDER_NAME);
        d.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        byte[] decrypted = d.doFinal(ct);
        Assertions.assertArrayEquals(pt, decrypted);
    }

    @Test
    public void testJce_aes128Xts_ciphertextStealing() throws Exception
    {
        // NIST SP 800-38E section 4 mandates XTS-AES support for data unit
        // lengths that aren't a multiple of the block size, via ciphertext
        // stealing (CTS). Output length matches input length.
        //   K = 0x55 * 16 || (0x66, 0x67, ..., 0x75)
        //   tweak = (0x80, 0x81, ..., 0x8f)
        //   pt = (0x01, 0x02, ..., 0x25)  (37 bytes — 2 full blocks + 5)
        //   ct = fe263bf4e6119b10f2ec7da6e3235c33cf107db237efa93f05db27c499d478ca47d1fa01fa
        // Computed against the bundled OpenSSL EVP_aes_128_xts.
        byte[] key = new byte[32];
        for (int i = 0; i < 16; i++) key[i] = 0x55;
        for (int i = 16; i < 32; i++) key[i] = (byte) (0x66 + i - 16);
        byte[] iv = new byte[16];
        for (int i = 0; i < 16; i++) iv[i] = (byte) (0x80 + i);
        byte[] pt = new byte[37];
        for (int i = 0; i < 37; i++) pt[i] = (byte) (i + 1);
        byte[] expectedCt = Hex.decode(
                "fe263bf4e6119b10f2ec7da6e3235c33cf107db237efa93f05db27c499d478ca47d1fa01fa");

        Cipher c = Cipher.getInstance("AES/XTS/NoPadding", JostleProvider.PROVIDER_NAME);
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        byte[] ct = c.doFinal(pt);
        Assertions.assertEquals(37, ct.length);
        Assertions.assertArrayEquals(expectedCt, ct);

        // Round-trip.
        Cipher d = Cipher.getInstance("AES/XTS/NoPadding", JostleProvider.PROVIDER_NAME);
        d.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        byte[] decrypted = d.doFinal(ct);
        Assertions.assertArrayEquals(pt, decrypted);
    }

    @Test
    public void testJce_aesXts_subBlockInputRejected() throws Exception
    {
        // XTS-AES requires at least one full block (16 bytes); sub-block
        // input is undefined per NIST SP 800-38E. We reject early.
        Cipher c = Cipher.getInstance("AES/XTS/NoPadding", JostleProvider.PROVIDER_NAME);
        byte[] key = new byte[32];
        for (int i = 0; i < 16; i++) key[i] = 0x55;
        for (int i = 16; i < 32; i++) key[i] = 0x66;
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(new byte[16]));
        try
        {
            c.doFinal(new byte[7]);
            fail("expected XTS to reject sub-block input");
        }
        catch (IllegalBlockSizeException ex)
        {
            // expected — JO_NOT_BLOCK_ALIGNED → IllegalBlockSizeException.
        }
    }

    @Test
    public void testJce_aesCbcNoPadding_doFinalRejectsNonAligned() throws Exception
    {
        // CBC/NO_PADDING is block-only: doFinal with sub-block (or partial-
        // block-after-aligned) input must fail with IllegalBlockSizeException
        // rather than silently truncating, padding, or producing garbage.
        Cipher c = Cipher.getInstance("AES/CBC/NoPadding", JostleProvider.PROVIDER_NAME);
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[16], "AES"), new IvParameterSpec(new byte[16]));
        try
        {
            c.doFinal(new byte[15]);
            fail("expected non-aligned CBC/NoPadding doFinal to fail");
        }
        catch (IllegalBlockSizeException ex)
        {
            Assertions.assertEquals("data not block size aligned", ex.getMessage());
        }
    }

    @Test
    public void testJce_aesEcbNoPadding_doFinalRejectsNonAligned() throws Exception
    {
        // Same contract for ECB.
        Cipher c = Cipher.getInstance("AES/ECB/NoPadding", JostleProvider.PROVIDER_NAME);
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[16], "AES"));
        try
        {
            c.doFinal(new byte[17]);
            fail("expected non-aligned ECB/NoPadding doFinal to fail");
        }
        catch (IllegalBlockSizeException ex)
        {
            Assertions.assertEquals("data not block size aligned", ex.getMessage());
        }
    }

    @Test
    public void testJce_aes256CbcNoPadding_doFinalRejectsNonAligned() throws Exception
    {
        // Verify the rejection fires for the AES-256 cipher_id dispatch too,
        // not just AES-128 (different switch arm in the native init).
        Cipher c = Cipher.getInstance("AES/CBC/NoPadding", JostleProvider.PROVIDER_NAME);
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[32], "AES"), new IvParameterSpec(new byte[16]));
        try
        {
            c.doFinal(new byte[20]);
            fail("expected non-aligned CBC/NoPadding doFinal to fail");
        }
        catch (IllegalBlockSizeException ex)
        {
            Assertions.assertEquals("data not block size aligned", ex.getMessage());
        }
    }

    @Test
    public void testJce_aesCbcNoPadding_residualAfterAlignedUpdate() throws Exception
    {
        // A more subtle misuse: caller feeds a block-aligned chunk via
        // update(), then a sub-block residual via doFinal(). The aligned
        // update succeeds; the doFinal must fail rather than discard the
        // trailing bytes or produce garbage.
        Cipher c = Cipher.getInstance("AES/CBC/NoPadding", JostleProvider.PROVIDER_NAME);
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[16], "AES"), new IvParameterSpec(new byte[16]));

        byte[] partial = c.update(new byte[16]);
        Assertions.assertEquals(16, partial.length);

        try
        {
            c.doFinal(new byte[5]);
            fail("expected residual doFinal to fail");
        }
        catch (IllegalBlockSizeException ex)
        {
            Assertions.assertEquals("data not block size aligned", ex.getMessage());
        }
    }

    @Test
    public void testJce_aesCbcNoPadding_updateRejectsNonAligned() throws Exception
    {
        // Cipher.update has no checked-exception throws clause, so the SPI
        // wraps the underlying error in a RuntimeException. The cause is
        // ShortBufferException: getUpdateSize(15) returns 0 for a sub-block
        // CBC/NoPadding input (no full blocks to output), so the native
        // out_len < in_len guard fires before the alignment guard. Pin
        // the wrapping behavior — silent success or a bare NPE would be
        // the dangerous failure modes.
        Cipher c = Cipher.getInstance("AES/CBC/NoPadding", JostleProvider.PROVIDER_NAME);
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[16], "AES"), new IvParameterSpec(new byte[16]));
        try
        {
            c.update(new byte[15]);
            fail("expected non-aligned update to fail");
        }
        catch (RuntimeException ex)
        {
            Assertions.assertTrue(ex.getCause() instanceof ShortBufferException,
                    "expected ShortBufferException cause, got "
                            + (ex.getCause() == null ? "null" : ex.getCause().getClass().getName()));
        }
    }

    @Test
    public void testJce_aesCbcPkcs5_acceptsNonAligned() throws Exception
    {
        // Sanity check: PADDED CBC must NOT reject non-aligned input — the
        // padding mode exists precisely to handle it.
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding", JostleProvider.PROVIDER_NAME);
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[16], "AES"), new IvParameterSpec(new byte[16]));
        byte[] ct = c.doFinal(new byte[15]);
        // 15 bytes pad to one full block of 16.
        Assertions.assertEquals(16, ct.length);
    }

    @Test
    public void testJce_aesCtrNoPadding_acceptsNonAligned() throws Exception
    {
        // Sanity: CTR turns AES into a stream cipher; any input length OK.
        Cipher c = Cipher.getInstance("AES/CTR/NoPadding", JostleProvider.PROVIDER_NAME);
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[16], "AES"), new IvParameterSpec(new byte[16]));
        byte[] ct = c.doFinal(new byte[3]);
        Assertions.assertEquals(3, ct.length);
    }

    @Test
    public void testJce_aesCfb_aliasesToCfb128() throws Exception
    {
        // JCE convention: the bare "CFB" mode in a transformation string
        // means CFB128 — the most common variant. Verify the alias works
        // and produces the same ciphertext as the explicit "CFB128" form.
        byte[] key = new byte[16];
        byte[] iv = new byte[16];
        for (int i = 0; i < 16; i++) { key[i] = (byte) i; iv[i] = (byte) (i + 16); }
        byte[] pt = new byte[37];
        for (int i = 0; i < 37; i++) pt[i] = (byte) (i + 1);

        Cipher cAlias = Cipher.getInstance("AES/CFB/NoPadding", JostleProvider.PROVIDER_NAME);
        cAlias.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        byte[] ctAlias = cAlias.doFinal(pt);

        Cipher cExplicit = Cipher.getInstance("AES/CFB128/NoPadding", JostleProvider.PROVIDER_NAME);
        cExplicit.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        byte[] ctExplicit = cExplicit.doFinal(pt);

        Assertions.assertArrayEquals(ctExplicit, ctAlias);
        Assertions.assertEquals(37, ctAlias.length); // CFB is streaming
    }

    @Test
    public void testJce_unknownMode_throwsNoSuchAlgorithm() throws Exception
    {
        // Unknown mode strings must surface as NoSuchAlgorithmException
        // (the JCE-contracted exception type), not the IllegalArgumentException
        // that OSSLMode.valueOf would have thrown bare.
        try
        {
            Cipher.getInstance("AES/NOTAREALMODE/NoPadding", JostleProvider.PROVIDER_NAME);
            fail("expected unknown mode to be rejected");
        }
        catch (NoSuchAlgorithmException ex)
        {
            // expected
        }
    }

    @Test
    public void testJce_byteBufferUpdate_arrayBacked() throws Exception
    {
        // ByteBuffer engineUpdate path with both buffers array-backed.
        // Verifies positions advance correctly and round-trip works.
        Cipher enc = Cipher.getInstance("AES/CTR/NoPadding", JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[16], "AES"), new IvParameterSpec(new byte[16]));

        ByteBuffer in = ByteBuffer.allocate(64);
        for (int i = 0; i < 64; i++) in.put((byte) i);
        in.flip();

        ByteBuffer out = ByteBuffer.allocate(64);
        int produced = enc.update(in, out);
        Assertions.assertEquals(64, produced);
        Assertions.assertEquals(64, in.position(), "input position should advance fully");
        Assertions.assertEquals(64, out.position(), "output position should advance by produced");
        Assertions.assertEquals(0, in.remaining());

        // Round-trip via doFinal (which CipherSpi's default ByteBuffer path
        // handles via our byte[] engineDoFinal).
        byte[] ct = new byte[64];
        out.flip();
        out.get(ct);

        Cipher dec = Cipher.getInstance("AES/CTR/NoPadding", JostleProvider.PROVIDER_NAME);
        dec.init(Cipher.DECRYPT_MODE, new SecretKeySpec(new byte[16], "AES"), new IvParameterSpec(new byte[16]));
        byte[] pt = dec.doFinal(ct);

        for (int i = 0; i < 64; i++) Assertions.assertEquals((byte) i, pt[i]);
    }

    @Test
    public void testJce_byteBufferUpdate_directBuffer() throws Exception
    {
        // Direct (non-array-backed) ByteBuffers exercise the staging-buffer
        // branch of engineUpdate(ByteBuffer, ByteBuffer).
        Cipher enc = Cipher.getInstance("AES/CTR/NoPadding", JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[16], "AES"), new IvParameterSpec(new byte[16]));

        ByteBuffer in = ByteBuffer.allocateDirect(48);
        for (int i = 0; i < 48; i++) in.put((byte) (i + 5));
        in.flip();

        ByteBuffer out = ByteBuffer.allocateDirect(48);
        int produced = enc.update(in, out);
        Assertions.assertEquals(48, produced);
        Assertions.assertEquals(48, in.position());
        Assertions.assertEquals(48, out.position());

        // Round-trip
        out.flip();
        byte[] ct = new byte[48];
        out.get(ct);

        Cipher dec = Cipher.getInstance("AES/CTR/NoPadding", JostleProvider.PROVIDER_NAME);
        dec.init(Cipher.DECRYPT_MODE, new SecretKeySpec(new byte[16], "AES"), new IvParameterSpec(new byte[16]));
        byte[] pt = dec.doFinal(ct);

        for (int i = 0; i < 48; i++) Assertions.assertEquals((byte) (i + 5), pt[i]);
    }

    @Test
    public void testJce_byteBufferUpdate_shortOutputBufferLeavesPositionsUnchanged() throws Exception
    {
        // ShortBufferException must not advance either buffer's position —
        // JCE contract for the ByteBuffer overload.
        Cipher enc = Cipher.getInstance("AES/CTR/NoPadding", JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[16], "AES"), new IvParameterSpec(new byte[16]));

        ByteBuffer in = ByteBuffer.allocate(32);
        for (int i = 0; i < 32; i++) in.put((byte) i);
        in.flip();

        ByteBuffer out = ByteBuffer.allocate(8); // too small

        int inPosBefore = in.position();
        int outPosBefore = out.position();
        try
        {
            enc.update(in, out);
            fail("expected ShortBufferException");
        }
        catch (ShortBufferException ex)
        {
            // expected
        }
        Assertions.assertEquals(inPosBefore, in.position(), "input position must be unchanged");
        Assertions.assertEquals(outPosBefore, out.position(), "output position must be unchanged");
    }

    @Test
    public void testJce_aesXts_invalidKeySize() throws Exception
    {
        // Anything other than 32 or 64 bytes must be rejected up front by
        // the SPI's mode-aware key dispatch.
        Cipher c = Cipher.getInstance("AES/XTS/NoPadding", JostleProvider.PROVIDER_NAME);
        try
        {
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[16], "AES"), new IvParameterSpec(new byte[16]));
            fail("expected XTS to reject 16-byte key");
        }
        catch (InvalidKeyException ex)
        {
            Assertions.assertTrue(ex.getMessage().contains("XTS"));
        }
    }


}
