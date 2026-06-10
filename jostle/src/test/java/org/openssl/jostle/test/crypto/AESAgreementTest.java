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
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
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
                            fail("decrypt failed to agree");
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
                sr.nextBytes(iv);
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
                        Assertions.assertEquals(originalWorkingArray[i++], workingArrayJostle[j]);
                    }

                }

            }


        }


    }


    @Test
    public void testAes() throws Exception
    {
        SecureRandom sr = seededRandom("testAes");


        //
        // The doFinal that returns a byte[]
        //

        exercise_simpleDoFinal("AES/ECB/NoPadding", new int[]{16, 24, 32}, 5 * 16, 16, -1, sr);
        exercise_simpleDoFinal("AES/ECB/PKCS7Padding", new int[]{16, 24, 32}, (5 * 16) + 1, 1, -1, sr);

        exercise_simpleDoFinal("AES/CBC/NoPadding", new int[]{16, 24, 32}, 5 * 16, 16, 16, sr);
        exercise_simpleDoFinal("AES/CBC/PKCS7Padding", new int[]{16, 24, 32}, (5 * 16) + 1, 1, 16, sr);
        exercise_simpleDoFinal("AES/CBC/PKCS5Padding", new int[]{16, 24, 32}, (5 * 16) + 1, 1, 16, sr);
        exercise_simpleDoFinal("AES/CFB128/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 16, sr);
        exercise_simpleDoFinal("AES/CFB8/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 16, sr);
        exercise_simpleDoFinal("AES/OFB/NoPadding", new int[]{16, 24, 32}, 5 * 16, 1, 16, sr);

        exercise_simpleDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 8, sr);
        exercise_simpleDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 9, sr);
        exercise_simpleDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 10, sr);
        exercise_simpleDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 11, sr);
        exercise_simpleDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 12, sr);
        exercise_simpleDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 13, sr);
        exercise_simpleDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 14, sr);
        exercise_simpleDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 15, sr);
        exercise_simpleDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 16, sr);


        //
        // Complex doFinal, that takes input and output arrays.
        //


        exercise_complexDoFinal("AES/ECB/NoPadding", new int[]{16, 24, 32}, 5 * 16, 16, -1, sr);
        exercise_complexDoFinal("AES/ECB/PKCS7Padding", new int[]{16, 24, 32}, (5 * 16) + 1, 1, -1, sr);

        exercise_complexDoFinal("AES/CBC/NoPadding", new int[]{16, 24, 32}, 5 * 16, 16, 16, sr);
        exercise_complexDoFinal("AES/CBC/PKCS7Padding", new int[]{16, 24, 32}, (5 * 16) + 1, 1, 16, sr);
        exercise_complexDoFinal("AES/CBC/PKCS5Padding", new int[]{16, 24, 32}, (5 * 16) + 1, 1, 16, sr);
        exercise_complexDoFinal("AES/CFB128/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 16, sr);
        exercise_complexDoFinal("AES/CFB8/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 16, sr);
        exercise_complexDoFinal("AES/OFB/NoPadding", new int[]{16, 24, 32}, 5 * 16, 1, 16, sr);

        exercise_complexDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 8, sr);
        exercise_complexDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 9, sr);
        exercise_complexDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 10, sr);
        exercise_complexDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 11, sr);
        exercise_complexDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 12, sr);
        exercise_complexDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 13, sr);
        exercise_complexDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 14, sr);
        exercise_complexDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 15, sr);
        exercise_complexDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 16, sr);


        //
        // Spread message between update and doFinal calls.
        //
        exercise_complexUpdateDoFinal("AES/ECB/NoPadding", new int[]{16, 24, 32}, 5 * 16, 16, -1, sr);
        exercise_complexUpdateDoFinal("AES/ECB/PKCS7Padding", new int[]{16, 24, 32}, (5 * 16) + 1, 1, -1, sr);

        exercise_complexUpdateDoFinal("AES/CBC/NoPadding", new int[]{16, 24, 32}, 5 * 16, 16, 16, sr);
        exercise_complexUpdateDoFinal("AES/CBC/PKCS7Padding", new int[]{16, 24, 32}, (5 * 16) + 1, 1, 16, sr);
        exercise_complexUpdateDoFinal("AES/CBC/PKCS5Padding", new int[]{16, 24, 32}, (5 * 16) + 1, 1, 16, sr);
        exercise_complexUpdateDoFinal("AES/CFB128/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 16, sr);
        exercise_complexUpdateDoFinal("AES/CFB8/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 16, sr);
        exercise_complexUpdateDoFinal("AES/OFB/NoPadding", new int[]{16, 24, 32}, 5 * 16, 1, 16, sr);

        exercise_complexUpdateDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 8, sr);
        exercise_complexUpdateDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 9, sr);
        exercise_complexUpdateDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 10, sr);
        exercise_complexUpdateDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 11, sr);
        exercise_complexUpdateDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 12, sr);
        exercise_complexUpdateDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 13, sr);
        exercise_complexUpdateDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 14, sr);
        exercise_complexUpdateDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 15, sr);
        exercise_complexUpdateDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 16, sr);


        //
        // Where input and output array is the same.
        //

        exercise_complexDoFinalSameArray("AES/ECB/NoPadding", new int[]{16, 24, 32}, 16 * 17, 16, -1, sr);
        exercise_complexDoFinalSameArray("AES/ECB/PKCS7Padding", new int[]{16, 24, 32}, (5 * 16) + 1, 1, -1, sr);

        exercise_complexDoFinalSameArray("AES/CBC/NoPadding", new int[]{16, 24, 32}, 5 * 16, 16, 16, sr);
        exercise_complexDoFinalSameArray("AES/CBC/PKCS7Padding", new int[]{16, 24, 32}, (5 * 16) + 1, 1, 16, sr);
        exercise_complexDoFinalSameArray("AES/CBC/PKCS5Padding", new int[]{16, 24, 32}, (5 * 16) + 1, 1, 16, sr);
        exercise_complexDoFinalSameArray("AES/CFB128/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 16, sr);
        exercise_complexDoFinalSameArray("AES/CFB8/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 16, sr);
        exercise_complexDoFinalSameArray("AES/OFB/NoPadding", new int[]{16, 24, 32}, 5 * 16, 1, 16, sr);

        exercise_complexDoFinalSameArray("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 8, sr);
        exercise_complexDoFinalSameArray("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 9, sr);
        exercise_complexDoFinalSameArray("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 10, sr);
        exercise_complexDoFinalSameArray("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 11, sr);
        exercise_complexDoFinalSameArray("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 12, sr);
        exercise_complexDoFinalSameArray("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 13, sr);
        exercise_complexDoFinalSameArray("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 14, sr);
        exercise_complexDoFinalSameArray("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 15, sr);
        exercise_complexDoFinalSameArray("AES/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 16, sr);


    }


    @Test
    public void aesGCMSpread() throws Exception
    {
        SecureRandom random = seededRandom("aesGCMSpread");


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
        SecureRandom random = seededRandom("aesGCMSpreadSplitUpdateDoFinal");


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

        SecureRandom random = seededRandom("aesGCMWithAAD");

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

        SecureRandom random = seededRandom("aesGCMWithTagLen");

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

    @Test
    public void testAcceptsWrapNameAndCaseInsensitiveKeyAlgorithms() throws Exception
    {
        // validateKeyAlg accepts the cipher's own algorithm, its JCE key-wrap
        // spellings (a CEK recovered via Cipher.unwrap on the CMS KEM/KTS path is
        // tagged with the wrap name, not the bare "AES"), and case variants. Each
        // accepted alias must not only init without throwing but key the cipher
        // identically to a plain "AES" key — proving the prefix match selects AES
        // key material, not merely that init was permissive.
        SecureRandom rng = seededRandom("testAcceptsWrapNameAndCaseInsensitiveKeyAlgorithms");
        byte[] keyBytes = new byte[16];
        rng.nextBytes(keyBytes);
        byte[] pt = new byte[32];
        rng.nextBytes(pt);

        Cipher ref = Cipher.getInstance("AES/ECB/NoPadding", JostleProvider.PROVIDER_NAME);
        ref.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, "AES"));
        byte[] refCt = ref.doFinal(pt);

        String[] acceptedAliases = {"AESWrap", "AESWRAP", "AESKW", "aes", "Aes"};
        for (String alias : acceptedAliases)
        {
            Cipher enc = Cipher.getInstance("AES/ECB/NoPadding", JostleProvider.PROVIDER_NAME);
            enc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, alias));   // must not throw
            byte[] ct = enc.doFinal(pt);
            Assertions.assertArrayEquals(refCt, ct,
                    alias + ": key did not encrypt identically to an AES-tagged key");

            Cipher dec = Cipher.getInstance("AES/ECB/NoPadding", JostleProvider.PROVIDER_NAME);
            dec.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keyBytes, alias));
            Assertions.assertArrayEquals(pt, dec.doFinal(ct),
                    alias + ": round-trip failed for accepted key algorithm");
        }

        // A genuinely different family shares no prefix and is still rejected,
        // so the looser match is not a blanket accept-anything.
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding", JostleProvider.PROVIDER_NAME);
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, "ARIA"));
            Assertions.fail("ARIA key must not be accepted by an AES cipher");
        } catch (InvalidKeyException ikes) {
            Assertions.assertEquals("unsupported key algorithm ARIA", ikes.getMessage());
        }
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
        // wraps the underlying error in a RuntimeException. After the
        // get_update_size fix that widens the buffer to max(aligned,
        // in_len), the sub-block input now passes the out_len >= in_len
        // guard and reaches the more-accurate alignment check; the cause
        // is now IllegalBlockSizeException ("data not block size aligned"),
        // which is the right semantic failure for non-aligned input to
        // an unpadded mode. Pin the wrapping behavior — silent success
        // or a bare NPE would be the dangerous failure modes.
        Cipher c = Cipher.getInstance("AES/CBC/NoPadding", JostleProvider.PROVIDER_NAME);
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[16], "AES"), new IvParameterSpec(new byte[16]));
        try
        {
            c.update(new byte[15]);
            fail("expected non-aligned update to fail");
        }
        catch (RuntimeException ex)
        {
            Assertions.assertTrue(ex.getCause() instanceof IllegalBlockSizeException,
                    "expected IllegalBlockSizeException cause, got "
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


    // -----------------------------------------------------------------
    // AES-GCM: adversarial AAD-chunking matrix per CLAUDE.md "AAD
    // chunking is independent of plaintext chunking — vary them
    // separately." Existing aesGCMSpreadSplitUpdateDoFinal varies
    // plaintext chunking but always calls updateAAD(aad, 0, aad.length)
    // as a one-shot. This test fills that gap.
    // -----------------------------------------------------------------

    /**
     * Drive the SAME (key, IV, plaintext, AAD) through different
     * updateAAD chunking strategies; the resulting tag and ciphertext
     * must be byte-identical regardless of how AAD was fed.
     *
     * The AAD-handling code in OpenSSL's GCM has a separate state
     * machine from the plaintext-handling code; a bug in the AAD
     * buffering layer wouldn't surface in tests that only ever pass
     * AAD as one-shot.
     */
    @Test
    public void aesGCM_AADChunkingMatrix_byteIdentical() throws Exception
    {
        SecureRandom sr = seededRandom("aesGCM_AADChunkingMatrix_byteIdentical");
        String xform = "AES/GCM/NoPadding";

        byte[] key = new byte[32];
        sr.nextBytes(key);
        byte[] iv = new byte[12];
        sr.nextBytes(iv);
        byte[] aad = new byte[256 + sr.nextInt(256)];
        sr.nextBytes(aad);
        byte[] msg = new byte[256 + sr.nextInt(256)];
        sr.nextBytes(msg);

        SecretKey secretKey = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        byte[] reference = encryptWithAADChunking(xform, secretKey, ivSpec, aad, msg, aad.length);

        // byte-by-byte AAD
        Assertions.assertArrayEquals(reference,
                encryptWithAADChunking(xform, secretKey, ivSpec, aad, msg, 1),
                "byte-by-byte AAD diverged from one-shot AAD");

        // Adversarial offsets around the AES block size (16) — GCM
        // processes AAD in 16-byte blocks via GHASH.
        for (int chunk : new int[]{15, 16, 17, 31, 32, 33, 63, 64, 65})
        {
            Assertions.assertArrayEquals(reference,
                    encryptWithAADChunking(xform, secretKey, ivSpec, aad, msg, chunk),
                    "chunk=" + chunk + ": AAD chunking diverged from one-shot");
        }

        // Random splits of the AAD.
        for (int trial = 0; trial < 5; trial++)
        {
            Assertions.assertArrayEquals(reference,
                    encryptWithRandomAADSplits(xform, secretKey, ivSpec, aad, msg, sr),
                    "random-split trial=" + trial + ": AAD chunking diverged from one-shot");
        }

        // Confirm the reference ciphertext decrypts (also through a
        // chunked-AAD decryptor) — guards against any AAD-side change
        // having silently produced a tag that doesn't actually verify.
        Cipher dec = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
        dec.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        for (int off = 0; off < aad.length; off += 17)
        {
            int len = Math.min(17, aad.length - off);
            dec.updateAAD(aad, off, len);
        }
        Assertions.assertArrayEquals(msg, dec.doFinal(reference),
                "chunked-AAD decrypt did not recover original plaintext");
    }

    private static byte[] encryptWithAADChunking(String xform, SecretKey key, IvParameterSpec ivSpec,
                                                 byte[] aad, byte[] msg, int chunk) throws Exception
    {
        Cipher enc = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        for (int off = 0; off < aad.length; off += chunk)
        {
            int len = Math.min(chunk, aad.length - off);
            enc.updateAAD(aad, off, len);
        }
        return enc.doFinal(msg);
    }

    private static byte[] encryptWithRandomAADSplits(String xform, SecretKey key, IvParameterSpec ivSpec,
                                                     byte[] aad, byte[] msg, SecureRandom sr) throws Exception
    {
        Cipher enc = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        int pos = 0;
        while (pos < aad.length)
        {
            int remaining = aad.length - pos;
            int chunk = 1 + sr.nextInt(Math.max(1, remaining));
            chunk = Math.min(chunk, remaining);
            enc.updateAAD(aad, pos, chunk);
            pos += chunk;
        }
        return enc.doFinal(msg);
    }

    /**
     * Reuse a single JSL GCM {@code Cipher} instance across several chunks, each
     * with its own nonce (the OpenPGP SEIPDv2 / RFC 9580 per-chunk pattern:
     * re-init → updateAAD → doFinal, repeated). Every chunk must agree byte-for-byte
     * with a fresh BouncyCastle GCM cipher on the same inputs, proving the re-init
     * path resets the AEAD state (no nonce/AAD/tag carry-over between chunks). This
     * is the JSL-side half of the OpenPGP GCM chunked-mode investigation in
     * docs/PGP_AEAD_CIPHER_GAP.md — it isolates whether the bc-jostle-libs "bad tag"
     * failure is a JSL GCM re-init bug (it is not) or lives in the consumer framing.
     */
    @Test
    public void aesGCM_reInitWithSuccessiveNonces_agreesWithBC() throws Exception
    {
        SecureRandom sr = seededRandom("aesGCM_reInitWithSuccessiveNonces_agreesWithBC");
        String xform = "AES/GCM/NoPadding";
        byte[] key = new byte[32];
        sr.nextBytes(key);
        SecretKey secretKey = new SecretKeySpec(key, "AES");
        byte[] baseIv = new byte[12];
        sr.nextBytes(baseIv);

        // One JSL cipher instance, re-initialised per chunk.
        Cipher jostleEnc = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);

        for (int chunk = 0; chunk < 6; chunk++)
        {
            // Per-chunk nonce: low byte of the base IV XOR chunk index.
            byte[] iv = Arrays.clone(baseIv);
            iv[iv.length - 1] ^= (byte) chunk;
            GCMParameterSpec spec = new GCMParameterSpec(128, iv);

            byte[] aad = new byte[sr.nextInt(40)];
            sr.nextBytes(aad);
            byte[] msg = new byte[1 + sr.nextInt(256)];
            sr.nextBytes(msg);

            jostleEnc.init(Cipher.ENCRYPT_MODE, secretKey, spec);
            jostleEnc.updateAAD(aad);
            byte[] jostleCT = jostleEnc.doFinal(msg);

            Cipher bcEnc = Cipher.getInstance(xform, BouncyCastleProvider.PROVIDER_NAME);
            bcEnc.init(Cipher.ENCRYPT_MODE, secretKey, spec);
            bcEnc.updateAAD(aad);
            byte[] bcCT = bcEnc.doFinal(msg);

            Assertions.assertArrayEquals(bcCT, jostleCT,
                    "chunk=" + chunk + ": re-init GCM ciphertext+tag diverged from BC");

            // And the reused instance must still decrypt correctly.
            jostleEnc.init(Cipher.DECRYPT_MODE, secretKey, spec);
            jostleEnc.updateAAD(aad);
            Assertions.assertArrayEquals(msg, jostleEnc.doFinal(jostleCT),
                    "chunk=" + chunk + ": re-init GCM roundtrip failed");
        }
    }


    // -----------------------------------------------------------------
    // AES-OCB (AEAD, RFC 7253) — agreement with BouncyCastle, tag-length
    // variation, AAD handling, tamper rejection. OCB shares the AEAD
    // code path with GCM (gated on is_aead_mode(mode_id) in C); these
    // tests pin the actual cross-impl agreement.
    // -----------------------------------------------------------------

    @Test
    public void aesOCB_agreesWithBC() throws Exception
    {
        SecureRandom sr = seededRandom("aesOCB_agreesWithBC");
        String xform = "AES/OCB/NoPadding";
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

            SecretKey secretKey = new SecretKeySpec(key, "AES");
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
                    "keySize=" + keySize + ": AES-OCB ciphertext+tag diverged");

            Cipher jostleDec = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
            jostleDec.init(Cipher.DECRYPT_MODE, secretKey, spec);
            jostleDec.updateAAD(aad);
            byte[] jostlePT = jostleDec.doFinal(jostleCT);
            Assertions.assertArrayEquals(msg, jostlePT, "keySize=" + keySize + ": AES-OCB roundtrip");
        }
    }

    /**
     * RFC 7253 permits OCB tags of 64, 96, or 128 bits. Some
     * implementations also support 8..128 in 8-bit steps; we test the
     * canonical three.
     */
    @Test
    public void aesOCB_tagLengthVariation_agreesWithBC() throws Exception
    {
        SecureRandom sr = seededRandom("aesOCB_tagLengthVariation_agreesWithBC");
        String xform = "AES/OCB/NoPadding";
        byte[] key = new byte[32];
        sr.nextBytes(key);
        byte[] iv = new byte[12];
        sr.nextBytes(iv);
        byte[] aad = new byte[sr.nextInt(64)];
        sr.nextBytes(aad);
        byte[] msg = new byte[1 + sr.nextInt(256)];
        sr.nextBytes(msg);

        for (int tagBits : new int[]{64, 96, 128})
        {
            SecretKey secretKey = new SecretKeySpec(key, "AES");
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
                    "tagBits=" + tagBits + ": AES-OCB ciphertext+tag diverged");

            Cipher jostleDec = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
            jostleDec.init(Cipher.DECRYPT_MODE, secretKey, spec);
            jostleDec.updateAAD(aad);
            byte[] jostlePT = jostleDec.doFinal(jostleCT);
            Assertions.assertArrayEquals(msg, jostlePT, "tagBits=" + tagBits + ": AES-OCB roundtrip");
        }
    }

    /**
     * RFC 7253: OCB nonce MUST be 1..15 bytes. The 16-byte boundary
     * (matching the AES block size) and the 0-byte boundary must both
     * be rejected; valid lengths in between must produce ciphertext
     * byte-equal with BouncyCastle's OCB implementation.
     */
    @Test
    public void aesOCB_nonceLengthBoundaries() throws Exception
    {
        SecureRandom sr = seededRandom("aesOCB_nonceLengthBoundaries");
        String xform = "AES/OCB/NoPadding";
        byte[] key = new byte[32];
        sr.nextBytes(key);
        SecretKey secretKey = new SecretKeySpec(key, "AES");
        byte[] aad = new byte[16];
        sr.nextBytes(aad);
        byte[] msg = new byte[64];
        sr.nextBytes(msg);

        // Every valid nonce length per RFC 7253 §3.1 (N_MIN = 1 byte,
        // N_MAX = 15 bytes). Each must agree with BC byte-for-byte AND
        // roundtrip via Jostle decrypt.
        for (int ivLen = 1; ivLen <= 15; ivLen++)
        {
            byte[] iv = new byte[ivLen];
            sr.nextBytes(iv);
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
                    "ivLen=" + ivLen + ": AES-OCB ciphertext diverged from BC");

            Cipher jostleDec = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
            jostleDec.init(Cipher.DECRYPT_MODE, secretKey, spec);
            jostleDec.updateAAD(aad);
            Assertions.assertArrayEquals(msg, jostleDec.doFinal(jostleCT),
                    "ivLen=" + ivLen + ": AES-OCB roundtrip failed");
        }

        // Invalid lengths: 0 and 16 must both be rejected. Use a
        // 16-byte IV via IvParameterSpec since GCMParameterSpec requires
        // >0 length; for the 0-length case, use IvParameterSpec(new byte[0]).
        for (int badLen : new int[]{0, 16, 17, 32})
        {
            byte[] badIv = new byte[badLen];
            sr.nextBytes(badIv);
            Cipher c = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
            try
            {
                if (badLen == 0)
                {
                    // GCMParameterSpec rejects 0-length tags too; pass via
                    // raw IvParameterSpec to bypass that and let our C-side
                    // OCB nonce check be the one that fires.
                    c.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(badIv));
                }
                else
                {
                    c.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(128, badIv));
                }
                Assertions.fail("AES-OCB must reject nonce length " + badLen);
            }
            catch (InvalidAlgorithmParameterException expected) { }
            catch (java.security.InvalidKeyException expected) { }
        }
    }

    @Test
    public void aesOCB_tamperedCiphertext_isRejected() throws Exception
    {
        SecureRandom sr = seededRandom("aesOCB_tamperedCiphertext_isRejected");
        String xform = "AES/OCB/NoPadding";
        byte[] key = new byte[32];
        sr.nextBytes(key);
        byte[] iv = new byte[12];
        sr.nextBytes(iv);
        byte[] aad = new byte[32];
        sr.nextBytes(aad);
        byte[] msg = new byte[64];
        sr.nextBytes(msg);

        SecretKey secretKey = new SecretKeySpec(key, "AES");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);

        Cipher enc = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        enc.updateAAD(aad);
        byte[] ct = enc.doFinal(msg);

        // Tamper ciphertext byte.
        byte[] tampered = ct.clone();
        tampered[0] ^= 0x01;
        Cipher dec = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
        dec.init(Cipher.DECRYPT_MODE, secretKey, spec);
        dec.updateAAD(aad);
        try
        {
            dec.doFinal(tampered);
            Assertions.fail("AES-OCB must reject tampered ciphertext");
        }
        catch (AEADBadTagException expected) { }

        // Tamper tag (last 16 bytes).
        byte[] tagFlip = ct.clone();
        tagFlip[tagFlip.length - 1] ^= 0xFF;
        dec = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
        dec.init(Cipher.DECRYPT_MODE, secretKey, spec);
        dec.updateAAD(aad);
        try
        {
            dec.doFinal(tagFlip);
            Assertions.fail("AES-OCB must reject tampered tag");
        }
        catch (AEADBadTagException expected) { }

        // Tamper AAD.
        byte[] tamperedAad = aad.clone();
        tamperedAad[0] ^= 0x01;
        dec = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
        dec.init(Cipher.DECRYPT_MODE, secretKey, spec);
        dec.updateAAD(tamperedAad);
        try
        {
            dec.doFinal(ct);
            Assertions.fail("AES-OCB must reject tampered AAD");
        }
        catch (AEADBadTagException expected) { }
    }

    /**
     * OCB initialised with a plain {@link IvParameterSpec} (no tag length
     * supplied) must default to a 128-bit tag and agree byte-for-byte with
     * BouncyCastle's OCB on the same path. This is the path that was broken:
     * OCB defaulted its tag length to 0 (only GCM defaulted to 16), leaving
     * OpenSSL's OCB cipher with no tag length and failing at GET_TAG with
     * {@code aes_ocb_get_ctx_params: invalid tag length}.
     */
    @Test
    public void aesOCB_ivParameterSpec_agreesWithBC() throws Exception
    {
        SecureRandom sr = seededRandom("aesOCB_ivParameterSpec_agreesWithBC");
        String xform = "AES/OCB/NoPadding";
        for (int trial = 0; trial < 10; trial++)
        {
            byte[] key = new byte[32];
            sr.nextBytes(key);
            // OCB accepts 1..15-byte nonces — vary the length per trial so the
            // default-tag path is exercised across the whole range, not just 12.
            byte[] iv = new byte[1 + sr.nextInt(15)];
            sr.nextBytes(iv);
            byte[] aad = new byte[sr.nextInt(48)];
            sr.nextBytes(aad);
            byte[] msg = new byte[1 + sr.nextInt(256)];
            sr.nextBytes(msg);

            SecretKey secretKey = new SecretKeySpec(key, "AES");
            IvParameterSpec spec = new IvParameterSpec(iv);

            Cipher bcEnc = Cipher.getInstance(xform, BouncyCastleProvider.PROVIDER_NAME);
            bcEnc.init(Cipher.ENCRYPT_MODE, secretKey, spec);
            bcEnc.updateAAD(aad);
            byte[] bcCT = bcEnc.doFinal(msg);

            Cipher jostleEnc = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
            jostleEnc.init(Cipher.ENCRYPT_MODE, secretKey, spec);
            jostleEnc.updateAAD(aad);
            byte[] jostleCT = jostleEnc.doFinal(msg);

            Assertions.assertArrayEquals(bcCT, jostleCT,
                    "trial=" + trial + ": AES-OCB (IvParameterSpec) ciphertext+tag diverged from BC");

            Cipher jostleDec = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
            jostleDec.init(Cipher.DECRYPT_MODE, secretKey, spec);
            jostleDec.updateAAD(aad);
            Assertions.assertArrayEquals(msg, jostleDec.doFinal(jostleCT),
                    "trial=" + trial + ": AES-OCB (IvParameterSpec) roundtrip failed");
        }
    }

    /**
     * OCB with no parameters at all: the SPI must auto-generate the nonce and
     * default the tag to 128 bits (the same contract GCM already honoured), then
     * round-trip through the parameters it exposes via {@code engineGetParameters}.
     * Proves the tag-default fix on the no-spec path without depending on BC's
     * default.
     */
    @Test
    public void aesOCB_noParams_roundTripsThroughExposedParameters() throws Exception
    {
        SecureRandom sr = seededRandom("aesOCB_noParams_roundTripsThroughExposedParameters");
        String xform = "AES/OCB/NoPadding";
        for (int trial = 0; trial < 10; trial++)
        {
            byte[] key = new byte[32];
            sr.nextBytes(key);
            byte[] aad = new byte[sr.nextInt(48)];
            sr.nextBytes(aad);
            byte[] msg = new byte[1 + sr.nextInt(256)];
            sr.nextBytes(msg);

            SecretKey secretKey = new SecretKeySpec(key, "AES");

            Cipher enc = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
            enc.init(Cipher.ENCRYPT_MODE, secretKey);
            enc.updateAAD(aad);
            byte[] ct = enc.doFinal(msg);

            // The SPI must have generated a nonce and exposed the AEAD parameters.
            java.security.AlgorithmParameters params = enc.getParameters();
            Assertions.assertNotNull(params, "trial=" + trial + ": OCB must expose generated parameters");

            Cipher dec = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
            dec.init(Cipher.DECRYPT_MODE, secretKey, params);
            dec.updateAAD(aad);
            Assertions.assertArrayEquals(msg, dec.doFinal(ct),
                    "trial=" + trial + ": AES-OCB no-params roundtrip failed");
        }
    }

    /**
     * BouncyCastle's {@code AEADParameterSpec} carries the AAD inside the spec
     * (not via {@code updateAAD}). Since it extends {@code IvParameterSpec}, the
     * SPI used to swallow it through the IvParameterSpec branch and silently drop
     * the AAD — computing a tag over no AAD, which then failed to decrypt against
     * a counterpart that did apply the AAD. This test pins that the AAD is now
     * honoured for both AEAD modes (GCM and OCB):
     * <ol>
     *   <li>JSL encrypt with {@code AEADParameterSpec(iv, 128, aad)} agrees
     *       byte-for-byte with BouncyCastle on the same spec — proving the AAD is
     *       folded into the tag identically;</li>
     *   <li>JSL decrypt via the same spec round-trips;</li>
     *   <li>decrypting the same ciphertext WITHOUT the AAD fails with
     *       {@code AEADBadTagException} — the regression guard proving the AAD
     *       actually participated in authentication (a dropped-AAD implementation
     *       would decrypt fine here).</li>
     * </ol>
     */
    @Test
    public void aesAEADParameterSpec_aadHonoured_agreesWithBC() throws Exception
    {
        SecureRandom sr = seededRandom("aesAEADParameterSpec_aadHonoured_agreesWithBC");
        for (String xform : new String[]{"AES/GCM/NoPadding", "AES/OCB/NoPadding"})
        {
            for (int trial = 0; trial < 10; trial++)
            {
                byte[] key = new byte[32];
                sr.nextBytes(key);
                byte[] iv = new byte[12];
                sr.nextBytes(iv);
                byte[] aad = new byte[1 + sr.nextInt(48)];   // non-empty so the no-AAD guard is meaningful
                sr.nextBytes(aad);
                byte[] msg = new byte[1 + sr.nextInt(256)];
                sr.nextBytes(msg);
                SecretKey secretKey = new SecretKeySpec(key, "AES");

                org.bouncycastle.jcajce.spec.AEADParameterSpec aeadSpec =
                        new org.bouncycastle.jcajce.spec.AEADParameterSpec(iv, 128, aad);

                Cipher bcEnc = Cipher.getInstance(xform, BouncyCastleProvider.PROVIDER_NAME);
                bcEnc.init(Cipher.ENCRYPT_MODE, secretKey, aeadSpec);
                byte[] bcCT = bcEnc.doFinal(msg);

                Cipher joEnc = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
                joEnc.init(Cipher.ENCRYPT_MODE, secretKey, aeadSpec);
                byte[] joCT = joEnc.doFinal(msg);

                Assertions.assertArrayEquals(bcCT, joCT,
                        xform + " trial=" + trial + ": AEADParameterSpec AAD not honoured (diverged from BC)");

                Cipher joDec = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
                joDec.init(Cipher.DECRYPT_MODE, secretKey, aeadSpec);
                Assertions.assertArrayEquals(msg, joDec.doFinal(joCT),
                        xform + " trial=" + trial + ": AEADParameterSpec roundtrip failed");

                // Regression guard: same nonce/tag but no AAD must fail.
                Cipher joDecNoAad = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
                joDecNoAad.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(128, iv));
                try
                {
                    joDecNoAad.doFinal(joCT);
                    Assertions.fail(xform + " trial=" + trial
                            + ": decrypt without the AAD must fail when AAD was authenticated");
                }
                catch (AEADBadTagException expected)
                {
                    // expected — the AAD was folded into the tag
                }
            }
        }
    }

    /**
     * The AEADParameterSpec's tag length must be honoured, not silently
     * replaced by the IvParameterSpec-branch default. At 128 bits the two are
     * indistinguishable (128 IS the default), so vary the tag across 96/112/128
     * and pin the ciphertext length ({@code msg + tagBits/8}) plus BC agreement
     * — an implementation that ignores {@code getMacSizeInBits()} fails the
     * length assert at 96/112.
     */
    @Test
    public void aesAEADParameterSpec_tagLengthHonoured_agreesWithBC() throws Exception
    {
        SecureRandom sr = seededRandom("aesAEADParameterSpec_tagLengthHonoured_agreesWithBC");
        for (String xform : new String[]{"AES/GCM/NoPadding", "AES/OCB/NoPadding"})
        {
            for (int tagBits : new int[]{96, 112, 128})
            {
                byte[] key = new byte[32];
                sr.nextBytes(key);
                byte[] iv = new byte[12];
                sr.nextBytes(iv);
                byte[] aad = new byte[1 + sr.nextInt(32)];
                sr.nextBytes(aad);
                byte[] msg = new byte[1 + sr.nextInt(128)];
                sr.nextBytes(msg);
                SecretKey secretKey = new SecretKeySpec(key, "AES");

                org.bouncycastle.jcajce.spec.AEADParameterSpec aeadSpec =
                        new org.bouncycastle.jcajce.spec.AEADParameterSpec(iv, tagBits, aad);

                Cipher joEnc = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
                joEnc.init(Cipher.ENCRYPT_MODE, secretKey, aeadSpec);
                byte[] joCT = joEnc.doFinal(msg);

                Assertions.assertEquals(msg.length + tagBits / 8, joCT.length,
                        xform + " tagBits=" + tagBits + ": ciphertext length shows the tag length was not honoured");

                Cipher bcEnc = Cipher.getInstance(xform, BouncyCastleProvider.PROVIDER_NAME);
                bcEnc.init(Cipher.ENCRYPT_MODE, secretKey, aeadSpec);
                Assertions.assertArrayEquals(bcEnc.doFinal(msg), joCT,
                        xform + " tagBits=" + tagBits + ": diverged from BC");

                Cipher joDec = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
                joDec.init(Cipher.DECRYPT_MODE, secretKey, aeadSpec);
                Assertions.assertArrayEquals(msg, joDec.doFinal(joCT),
                        xform + " tagBits=" + tagBits + ": roundtrip failed");
            }
        }
    }

    /**
     * The documented BC ordering — AAD carried in the {@code AEADParameterSpec}
     * PLUS a further {@code updateAAD} call before the payload — must
     * concatenate identically to BouncyCastle on all three AEAD modes
     * (GCM / OCB via {@code BlockCipherSpi}, CCM via its one-shot buffer).
     */
    @Test
    public void aesAEADParameterSpec_specAadThenUpdateAad_agreesWithBC() throws Exception
    {
        SecureRandom sr = seededRandom("aesAEADParameterSpec_specAadThenUpdateAad_agreesWithBC");
        for (String xform : new String[]{"AES/GCM/NoPadding", "AES/OCB/NoPadding", "AES/CCM/NoPadding"})
        {
            byte[] key = new byte[32];
            sr.nextBytes(key);
            byte[] iv = new byte[12];
            sr.nextBytes(iv);
            byte[] specAad = new byte[1 + sr.nextInt(24)];
            sr.nextBytes(specAad);
            byte[] extraAad = new byte[1 + sr.nextInt(24)];
            sr.nextBytes(extraAad);
            byte[] msg = new byte[1 + sr.nextInt(128)];
            sr.nextBytes(msg);
            SecretKey secretKey = new SecretKeySpec(key, "AES");

            org.bouncycastle.jcajce.spec.AEADParameterSpec aeadSpec =
                    new org.bouncycastle.jcajce.spec.AEADParameterSpec(iv, 128, specAad);

            Cipher bcEnc = Cipher.getInstance(xform, BouncyCastleProvider.PROVIDER_NAME);
            bcEnc.init(Cipher.ENCRYPT_MODE, secretKey, aeadSpec);
            bcEnc.updateAAD(extraAad);
            byte[] bcCT = bcEnc.doFinal(msg);

            Cipher joEnc = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
            joEnc.init(Cipher.ENCRYPT_MODE, secretKey, aeadSpec);
            joEnc.updateAAD(extraAad);
            byte[] joCT = joEnc.doFinal(msg);

            Assertions.assertArrayEquals(bcCT, joCT,
                    xform + ": spec-AAD + updateAAD concatenation diverged from BC");

            Cipher joDec = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
            joDec.init(Cipher.DECRYPT_MODE, secretKey, aeadSpec);
            joDec.updateAAD(extraAad);
            Assertions.assertArrayEquals(msg, joDec.doFinal(joCT),
                    xform + ": spec-AAD + updateAAD roundtrip failed");
        }
    }


    // -----------------------------------------------------------------
    // AES-CCM (AEAD, NIST SP 800-38C) — separate SPI path
    // (AESCCMCipherSpi) because CCM is one-shot at the OpenSSL layer:
    // total plaintext length must be set up-front, AAD must be a single
    // contiguous buffer. The SPI buffers Java-side; these tests verify
    // the end-to-end behaviour matches BouncyCastle.
    // -----------------------------------------------------------------

    @Test
    public void aesCCM_agreesWithBC() throws Exception
    {
        SecureRandom sr = seededRandom("aesCCM_agreesWithBC");
        String xform = "AES/CCM/NoPadding";
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

            SecretKey secretKey = new SecretKeySpec(key, "AES");
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
                    "keySize=" + keySize + ": AES-CCM ciphertext+tag diverged");

            Cipher jostleDec = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
            jostleDec.init(Cipher.DECRYPT_MODE, secretKey, spec);
            jostleDec.updateAAD(aad);
            byte[] jostlePT = jostleDec.doFinal(jostleCT);
            Assertions.assertArrayEquals(msg, jostlePT, "keySize=" + keySize + ": AES-CCM roundtrip");
        }
    }

    /**
     * CCM tag lengths per NIST SP 800-38C §6.1: {4, 6, 8, 10, 12, 14, 16}
     * bytes = {32, 48, 64, 80, 96, 112, 128} bits.
     */
    @Test
    public void aesCCM_tagLengthVariation_agreesWithBC() throws Exception
    {
        SecureRandom sr = seededRandom("aesCCM_tagLengthVariation_agreesWithBC");
        String xform = "AES/CCM/NoPadding";
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
            SecretKey secretKey = new SecretKeySpec(key, "AES");
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
                    "tagBits=" + tagBits + ": AES-CCM ciphertext+tag diverged");

            Cipher jostleDec = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
            jostleDec.init(Cipher.DECRYPT_MODE, secretKey, spec);
            jostleDec.updateAAD(aad);
            Assertions.assertArrayEquals(msg, jostleDec.doFinal(jostleCT),
                    "tagBits=" + tagBits + ": AES-CCM roundtrip");
        }
    }

    /**
     * CCM nonce length per NIST SP 800-38C §6.1: 7..13 bytes.
     */
    @Test
    public void aesCCM_nonceLengthBoundaries() throws Exception
    {
        SecureRandom sr = seededRandom("aesCCM_nonceLengthBoundaries");
        String xform = "AES/CCM/NoPadding";
        byte[] key = new byte[32];
        sr.nextBytes(key);
        SecretKey secretKey = new SecretKeySpec(key, "AES");
        byte[] aad = new byte[16];
        sr.nextBytes(aad);
        byte[] msg = new byte[64];
        sr.nextBytes(msg);

        for (int ivLen = 7; ivLen <= 13; ivLen++)
        {
            byte[] iv = new byte[ivLen];
            sr.nextBytes(iv);
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
                    "ivLen=" + ivLen + ": AES-CCM ciphertext diverged from BC");

            Cipher jostleDec = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
            jostleDec.init(Cipher.DECRYPT_MODE, secretKey, spec);
            jostleDec.updateAAD(aad);
            Assertions.assertArrayEquals(msg, jostleDec.doFinal(jostleCT),
                    "ivLen=" + ivLen + ": AES-CCM roundtrip failed");
        }

        // Out-of-range nonce: 6 and ≥14 must be rejected by Jostle.
        // CCMCipherSpi validates the nonce length at engineInit, so the
        // rejection is InvalidAlgorithmParameterException (the JCE-correct
        // type) — not a generic OpenSSLException/IllegalStateException
        // leaking up from the native layer.
        for (int badLen : new int[]{6, 14, 16, 32})
        {
            byte[] badIv = new byte[badLen];
            sr.nextBytes(badIv);
            try
            {
                Cipher c = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
                c.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(128, badIv));
                c.updateAAD(aad);
                c.doFinal(msg);
                Assertions.fail("AES-CCM must reject nonce length " + badLen);
            }
            catch (InvalidAlgorithmParameterException expected) { }
        }
    }

    /**
     * Tag, ciphertext, and AAD tampering must all be rejected with
     * AEADBadTagException.
     */
    @Test
    public void aesCCM_tamperedCiphertext_isRejected() throws Exception
    {
        SecureRandom sr = seededRandom("aesCCM_tamperedCiphertext_isRejected");
        String xform = "AES/CCM/NoPadding";
        byte[] key = new byte[32];
        sr.nextBytes(key);
        byte[] iv = new byte[12];
        sr.nextBytes(iv);
        byte[] aad = new byte[32];
        sr.nextBytes(aad);
        byte[] msg = new byte[64];
        sr.nextBytes(msg);

        SecretKey secretKey = new SecretKeySpec(key, "AES");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);

        Cipher enc = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        enc.updateAAD(aad);
        byte[] ct = enc.doFinal(msg);

        // Tamper CT.
        byte[] tampered = ct.clone();
        tampered[0] ^= 0x01;
        Cipher dec = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
        dec.init(Cipher.DECRYPT_MODE, secretKey, spec);
        dec.updateAAD(aad);
        try
        {
            dec.doFinal(tampered);
            Assertions.fail("AES-CCM must reject tampered ciphertext");
        }
        catch (AEADBadTagException expected) { }

        // Tamper tag (last 16 bytes).
        byte[] tagFlip = ct.clone();
        tagFlip[tagFlip.length - 1] ^= 0xFF;
        dec = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
        dec.init(Cipher.DECRYPT_MODE, secretKey, spec);
        dec.updateAAD(aad);
        try
        {
            dec.doFinal(tagFlip);
            Assertions.fail("AES-CCM must reject tampered tag");
        }
        catch (AEADBadTagException expected) { }

        // Tamper AAD.
        byte[] tamperedAad = aad.clone();
        tamperedAad[0] ^= 0x01;
        dec = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
        dec.init(Cipher.DECRYPT_MODE, secretKey, spec);
        dec.updateAAD(tamperedAad);
        try
        {
            dec.doFinal(ct);
            Assertions.fail("AES-CCM must reject tampered AAD");
        }
        catch (AEADBadTagException expected) { }
    }

    /**
     * Per CLAUDE.md "Tests must exercise the negative path", and per the
     * Option A design choice — CCM does NOT support incremental AAD.
     * A second updateAAD call MUST throw IllegalStateException with a
     * clear message about the underlying CCM constraint.
     */
    @Test
    public void aesCCM_incrementalAAD_throwsIllegalState() throws Exception
    {
        SecureRandom sr = seededRandom("aesCCM_incrementalAAD_throwsIllegalState");
        String xform = "AES/CCM/NoPadding";
        byte[] key = new byte[16];
        sr.nextBytes(key);
        byte[] iv = new byte[12];
        sr.nextBytes(iv);

        Cipher c = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(128, iv));
        c.updateAAD(new byte[]{0x01, 0x02, 0x03});
        try
        {
            c.updateAAD(new byte[]{0x04, 0x05});
            Assertions.fail("second updateAAD on CCM must throw");
        }
        catch (IllegalStateException expected)
        {
            Assertions.assertTrue(expected.getMessage().toLowerCase().contains("ccm"),
                    "exception message should mention CCM: " + expected.getMessage());
        }
    }

    // -----------------------------------------------------------------
    // CCM SPI-machinery coverage. CCMCipherSpi is cipher-agnostic (only
    // resolveCipherForKeyLen + the EVP name differ per family), so the
    // buffering / offset-write / reset / param-handling paths are
    // exercised thoroughly here for AES; ARIA and SM4 carry per-cipher
    // smoke tests of the same paths.
    // -----------------------------------------------------------------

    private static byte[] ccmEncryptChunked(String xform, SecretKey key, GCMParameterSpec spec,
                                            byte[] aad, byte[] msg, int chunk) throws Exception
    {
        Cipher c = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
        c.init(Cipher.ENCRYPT_MODE, key, spec);
        if (aad != null)
        {
            c.updateAAD(aad);
        }
        if (chunk <= 0)
        {
            // one-shot
            return c.doFinal(msg);
        }
        for (int off = 0; off < msg.length; off += chunk)
        {
            byte[] piece = c.update(msg, off, Math.min(chunk, msg.length - off));
            // CCM produces no incremental output.
            Assertions.assertEquals(0, piece == null ? 0 : piece.length,
                    "CCM update() must not produce incremental output");
        }
        return c.doFinal();
    }

    private static byte[] ccmEncryptRandomSplits(String xform, SecretKey key, GCMParameterSpec spec,
                                                 byte[] aad, byte[] msg, SecureRandom sr) throws Exception
    {
        Cipher c = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
        c.init(Cipher.ENCRYPT_MODE, key, spec);
        if (aad != null)
        {
            c.updateAAD(aad);
        }
        int pos = 0;
        while (pos < msg.length)
        {
            int remaining = msg.length - pos;
            int chunk = 1 + sr.nextInt(Math.max(1, remaining));
            chunk = Math.min(chunk, remaining);
            c.update(msg, pos, chunk);
            pos += chunk;
        }
        return c.doFinal();
    }

    private static byte[] ccmDecryptOneShot(String xform, SecretKey key, GCMParameterSpec spec,
                                            byte[] aad, byte[] ct) throws Exception
    {
        Cipher c = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
        c.init(Cipher.DECRYPT_MODE, key, spec);
        if (aad != null)
        {
            c.updateAAD(aad);
        }
        return c.doFinal(ct);
    }

    /**
     * HIGH gap: the whole point of the Java-side buffering is the
     * multi-update path. Drive the SAME (key, IV, AAD, plaintext)
     * through one-shot, byte-by-byte, adversarial AES-block-aligned
     * chunks, and random splits — every variation must produce a
     * byte-identical ciphertext (CCM is deterministic per key+nonce),
     * AND that ciphertext must agree with BC and round-trip.
     */
    @Test
    public void aesCCM_chunkingMatrix_byteIdentical() throws Exception
    {
        SecureRandom sr = seededRandom("aesCCM_chunkingMatrix_byteIdentical");
        String xform = "AES/CCM/NoPadding";
        byte[] key = new byte[32];
        sr.nextBytes(key);
        byte[] iv = new byte[12];
        sr.nextBytes(iv);
        byte[] aad = new byte[40];
        sr.nextBytes(aad);
        byte[] msg = new byte[200 + sr.nextInt(120)];
        sr.nextBytes(msg);
        SecretKey secretKey = new SecretKeySpec(key, "AES");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);

        byte[] reference = ccmEncryptChunked(xform, secretKey, spec, aad, msg, 0); // one-shot

        Assertions.assertArrayEquals(reference,
                ccmEncryptChunked(xform, secretKey, spec, aad, msg, 1),
                "byte-by-byte update diverged from one-shot");
        for (int chunk : new int[]{15, 16, 17, 31, 32, 33})
        {
            Assertions.assertArrayEquals(reference,
                    ccmEncryptChunked(xform, secretKey, spec, aad, msg, chunk),
                    "chunk=" + chunk + " diverged from one-shot");
        }
        for (int trial = 0; trial < 5; trial++)
        {
            Assertions.assertArrayEquals(reference,
                    ccmEncryptRandomSplits(xform, secretKey, spec, aad, msg, sr),
                    "random-split trial=" + trial + " diverged from one-shot");
        }

        // Agreement with BC + roundtrip.
        Cipher bc = Cipher.getInstance(xform, BouncyCastleProvider.PROVIDER_NAME);
        bc.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        bc.updateAAD(aad);
        Assertions.assertArrayEquals(bc.doFinal(msg), reference, "chunked ciphertext diverged from BC");
        Assertions.assertArrayEquals(msg, ccmDecryptOneShot(xform, secretKey, spec, aad, reference),
                "chunked-encrypt ciphertext failed to roundtrip");
    }

    /**
     * HIGH gap: 4-arg engineDoFinal(in, off, len, output, outOff) with
     * a non-zero outOff. Per CLAUDE.md "Verify offset-write contracts
     * via functional round-trip, not sentinel bytes":
     *   1. fill the output buffer with random bytes,
     *   2. save the prefix region,
     *   3. encrypt into the buffer at outOff,
     *   4. assert the prefix is byte-for-byte untouched,
     *   5. extract [outOff .. outOff+written] and confirm it decrypts
     *      back to the plaintext,
     *   6. extract a window starting at outOff-1 and confirm it does
     *      NOT authenticate (proves the write started at exactly outOff).
     */
    @Test
    public void aesCCM_offsetWrite_roundTripsWithoutClobberingPrefix() throws Exception
    {
        SecureRandom sr = seededRandom("aesCCM_offsetWrite_roundTripsWithoutClobberingPrefix");
        String xform = "AES/CCM/NoPadding";
        byte[] key = new byte[32];
        sr.nextBytes(key);
        byte[] iv = new byte[12];
        sr.nextBytes(iv);
        byte[] aad = new byte[24];
        sr.nextBytes(aad);
        byte[] msg = new byte[80];
        sr.nextBytes(msg);
        SecretKey secretKey = new SecretKeySpec(key, "AES");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);

        int prefix = 7;  // deliberately non-block-aligned
        int needed; // computed below
        // Determine output length via a sizing call.
        Cipher sizing = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
        sizing.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        needed = sizing.getOutputSize(msg.length);

        byte[] big = new byte[prefix + needed + 5];
        sr.nextBytes(big);
        byte[] expectedPrefix = new byte[prefix];
        System.arraycopy(big, 0, expectedPrefix, 0, prefix);

        Cipher enc = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        enc.updateAAD(aad);
        int written = enc.doFinal(msg, 0, msg.length, big, prefix);
        Assertions.assertTrue(written > 0, "expected ciphertext+tag written");

        // (4) prefix untouched.
        byte[] actualPrefix = new byte[prefix];
        System.arraycopy(big, 0, actualPrefix, 0, prefix);
        Assertions.assertArrayEquals(expectedPrefix, actualPrefix,
                "bytes before outOff must be untouched");

        // (5) functional roundtrip of the written window.
        byte[] ct = new byte[written];
        System.arraycopy(big, prefix, ct, 0, written);
        Assertions.assertArrayEquals(msg, ccmDecryptOneShot(xform, secretKey, spec, aad, ct),
                "ciphertext extracted at outOff failed to roundtrip");

        // (6) shifted window (outOff-1) must NOT authenticate — proves
        // the write began at exactly outOff, not one byte earlier.
        byte[] shifted = new byte[written];
        System.arraycopy(big, prefix - 1, shifted, 0, written);
        try
        {
            byte[] bad = ccmDecryptOneShot(xform, secretKey, spec, aad, shifted);
            Assertions.assertFalse(Arrays.areEqual(msg, bad),
                    "window shifted by one byte must not recover the plaintext");
        }
        catch (AEADBadTagException expected)
        {
            // Expected: the shifted window fails the tag check.
        }
    }

    /**
     * MED gap: the 4-arg engineDoFinal with a too-small output buffer
     * must throw ShortBufferException without producing output.
     */
    @Test
    public void aesCCM_offsetWrite_shortBufferRejected() throws Exception
    {
        SecureRandom sr = seededRandom("aesCCM_offsetWrite_shortBufferRejected");
        String xform = "AES/CCM/NoPadding";
        byte[] key = new byte[16];
        sr.nextBytes(key);
        byte[] iv = new byte[12];
        sr.nextBytes(iv);
        byte[] msg = new byte[48];
        sr.nextBytes(msg);
        SecretKey secretKey = new SecretKeySpec(key, "AES");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);

        Cipher enc = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        byte[] tooSmall = new byte[msg.length]; // missing room for the 16-byte tag
        try
        {
            enc.doFinal(msg, 0, msg.length, tooSmall, 0);
            Assertions.fail("expected ShortBufferException for under-sized output");
        }
        catch (ShortBufferException expected)
        {
            // expected
        }
    }

    /**
     * MED gap: SPI re-use. After a terminal doFinal the instance must
     * be usable again without re-init, AND a tamper-induced failure
     * must not poison the next clean operation (negative-then-positive).
     */
    @Test
    public void aesCCM_resetReuse_acrossOperations() throws Exception
    {
        SecureRandom sr = seededRandom("aesCCM_resetReuse_acrossOperations");
        String xform = "AES/CCM/NoPadding";
        byte[] key = new byte[32];
        sr.nextBytes(key);
        byte[] iv = new byte[12];
        sr.nextBytes(iv);
        SecretKey secretKey = new SecretKeySpec(key, "AES");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);

        // Two distinct encrypt operations on one instance.
        Cipher enc = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
        byte[] m1 = new byte[33];
        sr.nextBytes(m1);
        byte[] aad1 = new byte[8];
        sr.nextBytes(aad1);
        enc.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        enc.updateAAD(aad1);
        byte[] c1 = enc.doFinal(m1);
        Assertions.assertArrayEquals(m1, ccmDecryptOneShot(xform, secretKey, spec, aad1, c1));

        // Re-init with fresh nonce, drive again on the same instance.
        byte[] iv2 = new byte[12];
        sr.nextBytes(iv2);
        GCMParameterSpec spec2 = new GCMParameterSpec(128, iv2);
        byte[] m2 = new byte[64];
        sr.nextBytes(m2);
        enc.init(Cipher.ENCRYPT_MODE, secretKey, spec2);
        byte[] c2 = enc.doFinal(m2);
        Assertions.assertArrayEquals(m2, ccmDecryptOneShot(xform, secretKey, spec2, null, c2));

        // Negative-then-positive on a single decrypt instance.
        Cipher dec = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
        byte[] tampered = c2.clone();
        tampered[0] ^= 0x01;
        dec.init(Cipher.DECRYPT_MODE, secretKey, spec2);
        try
        {
            dec.doFinal(tampered);
            Assertions.fail("expected AEADBadTagException on tampered ciphertext");
        }
        catch (AEADBadTagException expected)
        {
            // expected
        }
        // Same instance must still work for a clean decrypt afterwards.
        dec.init(Cipher.DECRYPT_MODE, secretKey, spec2);
        Assertions.assertArrayEquals(m2, dec.doFinal(c2),
                "instance poisoned after a tamper-induced failure");
    }

    /**
     * Nonce-reuse guard (SunJCE-parity): after a successful ENCRYPT
     * doFinal, a second encryption on the same instance WITHOUT re-init
     * would reuse the nonce — catastrophic for CCM — and must be rejected
     * with IllegalStateException (from doFinal, update, and updateAAD).
     * Re-init with a fresh nonce clears the guard. Decrypt is exempt:
     * a second decrypt on one instance without re-init is allowed.
     */
    @Test
    public void aesCCM_encryptReuseWithoutReinit_rejected() throws Exception
    {
        SecureRandom sr = seededRandom("aesCCM_encryptReuseWithoutReinit_rejected");
        String xform = "AES/CCM/NoPadding";
        byte[] key = new byte[16];
        sr.nextBytes(key);
        byte[] iv = new byte[12];
        sr.nextBytes(iv);
        byte[] m1 = new byte[40];
        sr.nextBytes(m1);
        byte[] m2 = new byte[24];
        sr.nextBytes(m2);
        SecretKey secretKey = new SecretKeySpec(key, "AES");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);

        Cipher enc = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        enc.doFinal(m1); // first encrypt consumes the nonce

        // Second encrypt on the same instance WITHOUT re-init must throw.
        try
        {
            enc.doFinal(m2);
            Assertions.fail("CCM must reject a second encrypt without re-init (nonce reuse)");
        }
        catch (IllegalStateException expected)
        {
            Assertions.assertTrue(expected.getMessage().contains("re-initialise"),
                    "message should mention re-initialising: " + expected.getMessage());
        }
        // update / updateAAD must also be rejected after a terminal encrypt.
        try
        {
            enc.update(m2);
            Assertions.fail("CCM update after encrypt without re-init must throw");
        }
        catch (IllegalStateException expected) { }
        try
        {
            enc.updateAAD(new byte[4]);
            Assertions.fail("CCM updateAAD after encrypt without re-init must throw");
        }
        catch (IllegalStateException expected) { }

        // Re-init with a fresh nonce clears the guard — encryption works again.
        byte[] iv2 = new byte[12];
        sr.nextBytes(iv2);
        GCMParameterSpec spec2 = new GCMParameterSpec(128, iv2);
        enc.init(Cipher.ENCRYPT_MODE, secretKey, spec2);
        byte[] c2 = enc.doFinal(m2);
        Assertions.assertArrayEquals(m2, ccmDecryptOneShot(xform, secretKey, spec2, null, c2),
                "encryption after re-init should round-trip");

        // Decrypt is exempt: a second decrypt on one instance WITHOUT
        // re-init is allowed (no nonce-reuse risk on the decrypt side).
        Cipher dec = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
        dec.init(Cipher.DECRYPT_MODE, secretKey, spec2);
        Assertions.assertArrayEquals(m2, dec.doFinal(c2), "first decrypt");
        Assertions.assertArrayEquals(m2, dec.doFinal(c2),
                "second decrypt without re-init must be allowed");
    }

    /**
     * CCM transformation-form resolution. The canonical 3-token
     * "AES/CCM/NoPadding" resolves to the dedicated AESCCMCipherSpi
     * (round-trip is covered by aesCCM_agreesWithBC). The 2-token
     * "AES/CCM" is an INVALID JCE transformation format — javax.crypto.Cipher
     * requires 1 or 3 slash-separated tokens and rejects 2 at tokenisation,
     * so it throws NoSuchAlgorithmException BEFORE any provider/alias lookup.
     * It therefore never silently routes CCM through the generic
     * AESBlockCipherSpi; the only valid CCM transformation is the 3-token
     * form.
     */
    @Test
    public void aesCCM_twoTokenForm_isRejected() throws Exception
    {
        // Canonical 3-token form resolves to the dedicated CCM SPI.
        Assertions.assertNotNull(
                Cipher.getInstance("AES/CCM/NoPadding", JostleProvider.PROVIDER_NAME),
                "AES/CCM/NoPadding must resolve");

        // 2-token "AES/CCM" is an invalid transformation format — rejected
        // at tokenisation, never routed to the generic block-cipher SPI.
        try
        {
            Cipher.getInstance("AES/CCM", JostleProvider.PROVIDER_NAME);
            Assertions.fail("AES/CCM (2-token) must be rejected as an invalid transformation");
        }
        catch (NoSuchAlgorithmException expected)
        {
            // expected — JCE requires 1 or 3 transformation tokens.
        }
    }

    /**
     * Finding-9 residual: CCM must never route through the generic
     * streaming BlockCipherSpi. A 3-token transformation with a
     * non-NoPadding token (e.g. "AES/CCM/PKCS5Padding") IS a valid JCE
     * format, so without a guard JCE form-4 lookup falls through to the
     * generic AES SPI — OSSLMode has a CCM entry, so engineSetMode("CCM")
     * would otherwise succeed — yielding a broken CCM cipher on the
     * streaming path. The generic SPI must reject CCM (it is only valid via
     * the dedicated "AES/CCM/NoPadding" one-shot SPI).
     */
    @Test
    public void aesCCM_genericPathRejected() throws Exception
    {
        try
        {
            Cipher.getInstance("AES/CCM/PKCS5Padding", JostleProvider.PROVIDER_NAME);
            Assertions.fail("CCM must not route through the generic block-cipher SPI; " +
                    "only AES/CCM/NoPadding (dedicated SPI) is valid");
        }
        catch (NoSuchAlgorithmException expected)
        {
            // expected — the generic engineSetMode rejects CCM.
        }
    }

    /**
     * Regression (NF1): the offset engineDoFinal must NOT retain (and
     * re-buffer) its input when it rejects an under-sized output buffer.
     * Per the JCE contract a ShortBufferException is recoverable by
     * retrying with a larger buffer and the SAME input — if the SPI
     * buffered the input before throwing, the retry encrypts the plaintext
     * twice (doubled output / wrong ciphertext). The retry here must
     * encrypt the input exactly once and round-trip to the original msg.
     */
    @Test
    public void aesCCM_offsetDoFinal_shortBufferRetry_doesNotDoubleInput() throws Exception
    {
        SecureRandom sr = seededRandom("aesCCM_offsetDoFinal_shortBufferRetry_doesNotDoubleInput");
        byte[] key = new byte[16];
        sr.nextBytes(key);
        byte[] iv = new byte[12];
        sr.nextBytes(iv);
        byte[] aad = new byte[16];
        sr.nextBytes(aad);
        byte[] msg = new byte[48];
        sr.nextBytes(msg);
        SecretKey secretKey = new SecretKeySpec(key, "AES");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        final int tagBytes = 16;
        final int singleOutput = msg.length + tagBytes;

        Cipher enc = Cipher.getInstance("AES/CCM/NoPadding", JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        enc.updateAAD(aad);

        // 1. Under-sized output buffer → ShortBufferException (per JCE contract).
        try
        {
            enc.doFinal(msg, 0, msg.length, new byte[msg.length], 0);
            Assertions.fail("expected ShortBufferException for under-sized output");
        }
        catch (ShortBufferException expected)
        {
            // expected
        }

        // 2. Retry with the SAME input and a generous buffer (large enough
        //    even if the input were doubled). The SPI must have left no
        //    buffered input behind from the failed attempt.
        byte[] out = new byte[2 * msg.length + tagBytes + 16];
        int written = enc.doFinal(msg, 0, msg.length, out, 0);
        Assertions.assertEquals(singleOutput, written,
                "ShortBufferException retry must encrypt the input ONCE; a doubled " +
                "written count means the failed attempt's input was retained");

        // 3. Functional proof: the retry output decrypts to the original msg.
        byte[] ct = new byte[written];
        System.arraycopy(out, 0, ct, 0, written);
        Assertions.assertArrayEquals(msg,
                ccmDecryptOneShot("AES/CCM/NoPadding", secretKey, spec, aad, ct),
                "retry ciphertext must decrypt to the original plaintext");
    }

    /**
     * MED gap: CCM with zero-length plaintext — authenticate the AAD
     * only. Output is just the tag. Must agree with BC and round-trip.
     */
    @Test
    public void aesCCM_emptyPlaintext_agreesWithBC() throws Exception
    {
        SecureRandom sr = seededRandom("aesCCM_emptyPlaintext_agreesWithBC");
        String xform = "AES/CCM/NoPadding";
        byte[] key = new byte[16];
        sr.nextBytes(key);
        byte[] iv = new byte[12];
        sr.nextBytes(iv);
        byte[] aad = new byte[40];
        sr.nextBytes(aad);
        SecretKey secretKey = new SecretKeySpec(key, "AES");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);

        Cipher bc = Cipher.getInstance(xform, BouncyCastleProvider.PROVIDER_NAME);
        bc.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        bc.updateAAD(aad);
        byte[] bcCt = bc.doFinal(new byte[0]);

        Cipher jo = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
        jo.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        jo.updateAAD(aad);
        byte[] joCt = jo.doFinal(new byte[0]);

        Assertions.assertArrayEquals(bcCt, joCt, "empty-plaintext CCM tag diverged from BC");
        Assertions.assertEquals(16, joCt.length, "empty-plaintext output should be the 16-byte tag");

        // Decrypt (tag-only) must succeed and produce empty plaintext.
        byte[] pt = ccmDecryptOneShot(xform, secretKey, spec, aad, joCt);
        Assertions.assertEquals(0, pt.length, "empty-plaintext decrypt should yield zero bytes");
    }

    /**
     * MED gap: the engineUpdateAAD(ByteBuffer) overload — exercises
     * both the array-backed and direct (non-array-backed) branches.
     */
    @Test
    public void aesCCM_byteBufferAAD_agreesWithBC() throws Exception
    {
        SecureRandom sr = seededRandom("aesCCM_byteBufferAAD_agreesWithBC");
        String xform = "AES/CCM/NoPadding";
        byte[] key = new byte[16];
        sr.nextBytes(key);
        byte[] iv = new byte[12];
        sr.nextBytes(iv);
        byte[] aad = new byte[40];
        sr.nextBytes(aad);
        byte[] msg = new byte[64];
        sr.nextBytes(msg);
        SecretKey secretKey = new SecretKeySpec(key, "AES");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);

        Cipher bc = Cipher.getInstance(xform, BouncyCastleProvider.PROVIDER_NAME);
        bc.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        bc.updateAAD(aad);
        byte[] bcCt = bc.doFinal(msg);

        // Array-backed ByteBuffer.
        Cipher joHeap = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
        joHeap.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        joHeap.updateAAD(ByteBuffer.wrap(aad));
        Assertions.assertArrayEquals(bcCt, joHeap.doFinal(msg), "array-backed ByteBuffer AAD diverged");

        // Direct (non-array-backed) ByteBuffer.
        ByteBuffer direct = ByteBuffer.allocateDirect(aad.length);
        direct.put(aad);
        direct.flip();
        Cipher joDirect = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
        joDirect.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        joDirect.updateAAD(direct);
        Assertions.assertArrayEquals(bcCt, joDirect.doFinal(msg), "direct ByteBuffer AAD diverged");
    }

    /**
     * LOW gap: init without parameters must be rejected — CCM needs a
     * nonce + tag length.
     */
    @Test
    public void aesCCM_initWithoutParams_rejected() throws Exception
    {
        byte[] key = new byte[16];
        new SecureRandom().nextBytes(key);
        Cipher c = Cipher.getInstance("AES/CCM/NoPadding", JostleProvider.PROVIDER_NAME);
        try
        {
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
            Assertions.fail("CCM init without GCMParameterSpec must be rejected");
        }
        catch (InvalidKeyException expected)
        {
            // expected — no nonce/tag supplied; the no-params engineInit
            // overload throws InvalidKeyException (its only checked type).
        }
    }

    /**
     * CCM accepts an IvParameterSpec (nonce only). Because the spec
     * carries no tag length, the SPI must default to a 64-bit (8-byte)
     * tag — matching BouncyCastle's CCM IV-only default — for the output
     * to agree byte-for-byte with BC.
     */
    @Test
    public void aesCCM_ivParameterSpec_agreesWithBC() throws Exception
    {
        SecureRandom sr = seededRandom("aesCCM_ivParameterSpec_agreesWithBC");
        String xform = "AES/CCM/NoPadding";
        byte[] key = new byte[16]; sr.nextBytes(key);
        byte[] iv = new byte[12]; sr.nextBytes(iv);
        byte[] aad = new byte[sr.nextInt(48)]; sr.nextBytes(aad);
        byte[] msg = new byte[1 + sr.nextInt(256)]; sr.nextBytes(msg);

        SecretKey secretKey = new SecretKeySpec(key, "AES");
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
                "AES-CCM IvParameterSpec diverged from BC (default tag length mismatch?)");
        // 64-bit default tag => ciphertext is plaintext + 8 bytes.
        Assertions.assertEquals(msg.length + 8, joCt.length, "expected 8-byte default CCM tag");

        // Decrypt must also accept IvParameterSpec.
        Cipher joDec = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
        joDec.init(Cipher.DECRYPT_MODE, secretKey, spec);
        joDec.updateAAD(aad);
        Assertions.assertArrayEquals(msg, joDec.doFinal(joCt), "AES-CCM IvParameterSpec roundtrip failed");
    }

    /**
     * CCM must honour a BouncyCastle {@code AEADParameterSpec}'s tag length AND
     * associated data, not silently treat it as a plain {@code IvParameterSpec}
     * (which it extends) and drop the AAD. Mirrors the GCM/OCB
     * {@code aesAEADParameterSpec_aadHonoured_agreesWithBC} test for the separate
     * CCM SPI: byte-for-byte agreement with BC on the spec-carried-AAD path, a
     * decrypt round-trip, and a guard that decrypting without the AAD fails.
     */
    @Test
    public void aesCCM_aeadParameterSpec_aadHonoured_agreesWithBC() throws Exception
    {
        SecureRandom sr = seededRandom("aesCCM_aeadParameterSpec_aadHonoured_agreesWithBC");
        String xform = "AES/CCM/NoPadding";
        for (int trial = 0; trial < 10; trial++)
        {
            byte[] key = new byte[32];
            sr.nextBytes(key);
            byte[] nonce = new byte[7 + sr.nextInt(7)];   // RFC 3610 / CCM: 7..13 bytes
            sr.nextBytes(nonce);
            byte[] aad = new byte[1 + sr.nextInt(48)];    // non-empty so the no-AAD guard is meaningful
            sr.nextBytes(aad);
            byte[] msg = new byte[1 + sr.nextInt(256)];
            sr.nextBytes(msg);
            SecretKey secretKey = new SecretKeySpec(key, "AES");

            org.bouncycastle.jcajce.spec.AEADParameterSpec aeadSpec =
                    new org.bouncycastle.jcajce.spec.AEADParameterSpec(nonce, 128, aad);

            Cipher bcEnc = Cipher.getInstance(xform, BouncyCastleProvider.PROVIDER_NAME);
            bcEnc.init(Cipher.ENCRYPT_MODE, secretKey, aeadSpec);
            byte[] bcCt = bcEnc.doFinal(msg);

            Cipher joEnc = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
            joEnc.init(Cipher.ENCRYPT_MODE, secretKey, aeadSpec);
            byte[] joCt = joEnc.doFinal(msg);

            Assertions.assertArrayEquals(bcCt, joCt,
                    "trial=" + trial + ": CCM AEADParameterSpec AAD not honoured (diverged from BC)");

            Cipher joDec = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
            joDec.init(Cipher.DECRYPT_MODE, secretKey, aeadSpec);
            Assertions.assertArrayEquals(msg, joDec.doFinal(joCt),
                    "trial=" + trial + ": CCM AEADParameterSpec roundtrip failed");

            // Regression guard: same nonce/tag but no AAD must fail.
            Cipher joDecNoAad = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
            joDecNoAad.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(128, nonce));
            try
            {
                joDecNoAad.doFinal(joCt);
                Assertions.fail("trial=" + trial
                        + ": CCM decrypt without the AAD must fail when AAD was authenticated");
            }
            catch (AEADBadTagException expected)
            {
                // expected — the AAD was folded into the tag
            }
        }
    }

    /**
     * LOW gap: init via AlgorithmParameters (rather than the spec
     * directly) must resolve to the GCMParameterSpec and work.
     */
    @Test
    public void aesCCM_initWithAlgorithmParameters_works() throws Exception
    {
        SecureRandom sr = seededRandom("aesCCM_initWithAlgorithmParameters_works");
        String xform = "AES/CCM/NoPadding";
        byte[] key = new byte[16];
        sr.nextBytes(key);
        byte[] iv = new byte[12];
        sr.nextBytes(iv);
        byte[] aad = new byte[16];
        sr.nextBytes(aad);
        byte[] msg = new byte[48];
        sr.nextBytes(msg);
        SecretKey secretKey = new SecretKeySpec(key, "AES");

        // Build AlgorithmParameters carrying a GCMParameterSpec. Use BC's
        // CCM AlgorithmParameters so the encoding is interoperable.
        AlgorithmParameters ap = AlgorithmParameters.getInstance("CCM", BouncyCastleProvider.PROVIDER_NAME);
        ap.init(new GCMParameterSpec(128, iv));

        Cipher jo = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
        jo.init(Cipher.ENCRYPT_MODE, secretKey, ap, sr);
        jo.updateAAD(aad);
        byte[] joCt = jo.doFinal(msg);

        Cipher bc = Cipher.getInstance(xform, BouncyCastleProvider.PROVIDER_NAME);
        bc.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(128, iv));
        bc.updateAAD(aad);
        Assertions.assertArrayEquals(bc.doFinal(msg), joCt,
                "init via AlgorithmParameters diverged from spec-based init");
    }

    /**
     * Key-length boundary: the valid AES key sizes {16,24,32} must be
     * accepted (exercising AES-128/192/256-CCM), and each length one byte
     * to either side of a valid size — plus 1 and a value well above the
     * max — must be rejected with InvalidKeyException. (0 is not probed:
     * SecretKeySpec itself rejects an empty key with IllegalArgumentException
     * before init is reached.)
     */
    @Test
    public void aesCCM_wrongKeyLength_rejected() throws Exception
    {
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        // Valid sizes accepted.
        for (int len : new int[]{16, 24, 32})
        {
            Cipher c = Cipher.getInstance("AES/CCM/NoPadding", JostleProvider.PROVIDER_NAME);
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[len], "AES"),
                    new GCMParameterSpec(128, iv));
        }
        // boundary±1 around 16/24/32, plus 1 and well-above-max.
        for (int badLen : new int[]{1, 15, 17, 23, 25, 31, 33, 64})
        {
            Cipher c = Cipher.getInstance("AES/CCM/NoPadding", JostleProvider.PROVIDER_NAME);
            try
            {
                c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[badLen], "AES"),
                        new GCMParameterSpec(128, iv));
                Assertions.fail("AES-CCM must reject key length " + badLen);
            }
            catch (InvalidKeyException expected)
            {
                // expected
            }
        }
    }

    /**
     * CCM supports only ENCRYPT/DECRYPT. Initialising for WRAP_MODE must
     * be rejected with a clean IllegalStateException("invalid operation
     * mode") — mapped by CCMCipherNI.handleErrors — not the generic
     * "unexpected error code" message baseErrorHandler would emit for an
     * unmapped JO_INVALID_OP_MODE.
     */
    @Test
    public void aesCCM_wrapMode_rejected() throws Exception
    {
        byte[] key = new byte[16];
        new SecureRandom().nextBytes(key);
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        for (int opMode : new int[]{Cipher.WRAP_MODE, Cipher.UNWRAP_MODE})
        {
            Cipher c = Cipher.getInstance("AES/CCM/NoPadding", JostleProvider.PROVIDER_NAME);
            try
            {
                c.init(opMode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
                Assertions.fail("CCM must reject opMode " + opMode);
            }
            catch (IllegalStateException expected)
            {
                Assertions.assertEquals("invalid operation mode", expected.getMessage());
            }
        }
    }

    /**
     * Tag lengths that are multiples of 8 bits but NOT in the CCM valid
     * set {32,48,64,80,96,112,128} must be rejected at engineInit with
     * InvalidAlgorithmParameterException (not leak a native
     * JO_INVALID_TAG_LEN up as a generic IllegalStateException).
     */
    @Test
    public void aesCCM_invalidTagLength_rejected() throws Exception
    {
        byte[] key = new byte[16];
        new SecureRandom().nextBytes(key);
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        SecretKey secretKey = new SecretKeySpec(key, "AES");
        // 16=2 bytes (<min), 40=5 bytes (odd), 144=18 bytes (>max).
        for (int badTagBits : new int[]{16, 40, 144})
        {
            Cipher c = Cipher.getInstance("AES/CCM/NoPadding", JostleProvider.PROVIDER_NAME);
            try
            {
                c.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(badTagBits, iv));
                Assertions.fail("AES-CCM must reject tag length " + badTagBits + " bits");
            }
            catch (InvalidAlgorithmParameterException expected) { }
        }
    }

    /**
     * Boundary check for CCMCipherSpi's tag-length validation: every
     * valid CCM tag length must init (and yield a tag of that exact
     * size), and the multiple-of-8 value immediately on each side of a
     * valid length must be rejected — so a logic slip that admitted an
     * out-of-set length would be caught. Also confirms the
     * {@code (tagBits & 7)} gate rejects non-multiples of 8.
     */
    @Test
    public void aesCCM_tagLength_boundaryRejection() throws Exception
    {
        byte[] key = new byte[16];
        new SecureRandom().nextBytes(key);
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        SecretKey secretKey = new SecretKeySpec(key, "AES");

        // Every valid tag length (bits) must init; an empty-plaintext
        // encrypt is exactly the tag, so its length confirms tagBits/8.
        for (int tagBits : new int[]{32, 48, 64, 80, 96, 112, 128})
        {
            Cipher c = Cipher.getInstance("AES/CCM/NoPadding", JostleProvider.PROVIDER_NAME);
            c.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(tagBits, iv));
            Assertions.assertEquals(tagBits / 8, c.doFinal(new byte[0]).length,
                    "tagBits=" + tagBits + " produced the wrong tag size");
        }

        // The multiple-of-8 value on each side of every valid length must
        // be rejected: 24 (below 32) and 136 (above 128) bracket the set;
        // 40/56/72/88/104/120 are the odd-byte gaps between the valid
        // even-byte lengths. Together these are both neighbours of every
        // valid value.
        for (int badTagBits : new int[]{24, 40, 56, 72, 88, 104, 120, 136})
        {
            assertCcmTagRejected(secretKey, iv, badTagBits);
        }

        // Non-multiples of 8 must be rejected by the (tagBits & 7) gate.
        for (int badTagBits : new int[]{33, 60, 100, 127})
        {
            assertCcmTagRejected(secretKey, iv, badTagBits);
        }
    }

    private static void assertCcmTagRejected(SecretKey key, byte[] iv, int tagBits) throws Exception
    {
        Cipher c = Cipher.getInstance("AES/CCM/NoPadding", JostleProvider.PROVIDER_NAME);
        try
        {
            c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(tagBits, iv));
            Assertions.fail("AES-CCM must reject tag length " + tagBits + " bits");
        }
        catch (InvalidAlgorithmParameterException expected) { }
    }

    /**
     * LOW gap: engineGetIV must return the nonce supplied at init.
     */
    @Test
    public void aesCCM_getIV_returnsNonce() throws Exception
    {
        SecureRandom sr = seededRandom("aesCCM_getIV_returnsNonce");
        byte[] key = new byte[16];
        sr.nextBytes(key);
        byte[] iv = new byte[12];
        sr.nextBytes(iv);
        Cipher c = Cipher.getInstance("AES/CCM/NoPadding", JostleProvider.PROVIDER_NAME);
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
        Assertions.assertArrayEquals(iv, c.getIV(), "getIV must return the configured nonce");
    }

    /**
     * LOW gap: explicit reverse direction — encrypt with Jostle,
     * decrypt with BouncyCastle — to confirm interoperability isn't
     * only implied by byte-equal ciphertext.
     */
    @Test
    public void aesCCM_encryptJostle_decryptBC() throws Exception
    {
        SecureRandom sr = seededRandom("aesCCM_encryptJostle_decryptBC");
        String xform = "AES/CCM/NoPadding";
        for (int keySize : new int[]{16, 24, 32})
        {
            byte[] key = new byte[keySize];
            sr.nextBytes(key);
            byte[] iv = new byte[12];
            sr.nextBytes(iv);
            byte[] aad = new byte[sr.nextInt(48)];
            sr.nextBytes(aad);
            byte[] msg = new byte[1 + sr.nextInt(200)];
            sr.nextBytes(msg);
            SecretKey secretKey = new SecretKeySpec(key, "AES");
            GCMParameterSpec spec = new GCMParameterSpec(128, iv);

            Cipher jo = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
            jo.init(Cipher.ENCRYPT_MODE, secretKey, spec);
            jo.updateAAD(aad);
            byte[] joCt = jo.doFinal(msg);

            Cipher bc = Cipher.getInstance(xform, BouncyCastleProvider.PROVIDER_NAME);
            bc.init(Cipher.DECRYPT_MODE, secretKey, spec);
            bc.updateAAD(aad);
            Assertions.assertArrayEquals(msg, bc.doFinal(joCt),
                    "keySize=" + keySize + ": BC failed to decrypt Jostle ciphertext");
        }
    }


    /**
     * AES-CTR accepts IVs in the range [block_size/2, block_size] —
     * i.e. 8..16 bytes for AES. Every valid length must agree with BC
     * byte-for-byte; lengths outside the range must be rejected by both.
     */
    @Test
    public void aesCtr_nonceLengthBoundaries() throws Exception
    {
        SecureRandom sr = seededRandom("aesCtr_nonceLengthBoundaries");
        String xform = "AES/CTR/NoPadding";
        byte[] key = new byte[32];
        sr.nextBytes(key);
        SecretKey secretKey = new SecretKeySpec(key, "AES");
        byte[] msg = new byte[64];
        sr.nextBytes(msg);

        // Every valid nonce length.
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
                    "ivLen=" + ivLen + ": AES-CTR ciphertext diverged from BC");

            Cipher jostleDec = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
            jostleDec.init(Cipher.DECRYPT_MODE, secretKey, spec);
            Assertions.assertArrayEquals(msg, jostleDec.doFinal(jostleCT),
                    "ivLen=" + ivLen + ": AES-CTR roundtrip failed");
        }

        // Invalid lengths: both sides must reject.
        for (int badLen : new int[]{0, 1, 7, 17, 32})
        {
            byte[] iv = new byte[badLen];
            sr.nextBytes(iv);
            Cipher c = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
            try
            {
                c.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
                Assertions.fail("AES-CTR must reject IV length " + badLen);
            }
            catch (InvalidAlgorithmParameterException expected) { }
        }
    }

}
