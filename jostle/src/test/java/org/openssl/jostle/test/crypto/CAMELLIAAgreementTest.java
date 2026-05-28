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
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.encoders.Hex;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.security.Security;

/**
 * Test agreement between BC Java and Jostle.
 * Official vector tests elsewhere
 */
public class CAMELLIAAgreementTest
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


                SecretKey secretKey = new SecretKeySpec(key, "CAMELLIA");

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

                        SecretKey secretKey = new SecretKeySpec(key, "CAMELLIA");

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

                        SecretKey secretKey = new SecretKeySpec(key, "CAMELLIA");

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


            SecretKey secretKey = new SecretKeySpec(key, "CAMELLIA");

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

        try {
            Cipher cipher = Cipher.getInstance("CAMELLIA/ECB/NoPadding",JostleProvider.PROVIDER_NAME);
            cipher.init(Cipher.ENCRYPT_MODE, wrongSpec);
            Assertions.fail("Should have thrown an exception");
        } catch (InvalidKeyException ikes) {
            Assertions.assertEquals("unsupported key algorithm AES",ikes.getMessage());
        }

        try {
            Cipher cipher = Cipher.getInstance("CAMELLIA/CBC/NoPadding",JostleProvider.PROVIDER_NAME);
            cipher.init(Cipher.ENCRYPT_MODE, wrongSpec, new IvParameterSpec(new byte[16]));
            Assertions.fail("Should have thrown an exception");
        } catch (InvalidKeyException ikes) {
            Assertions.assertEquals("unsupported key algorithm AES",ikes.getMessage());
        }

        try {
            Cipher cipher = Cipher.getInstance("CAMELLIA/CBC/NoPadding",JostleProvider.PROVIDER_NAME);
            DummyParams params = new DummyParams();
            params.init(new byte[16]);
            cipher.init(Cipher.ENCRYPT_MODE, wrongSpec, params);
            Assertions.fail("Should have thrown an exception");
        } catch (InvalidKeyException ikes) {
            Assertions.assertEquals("unsupported key algorithm AES",ikes.getMessage());
        }

        // Correct spec
        Cipher cipher = Cipher.getInstance("CAMELLIA/ECB/NoPadding", JostleProvider.PROVIDER_NAME);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[16], "CAMELLIA"));

        cipher = Cipher.getInstance("CAMELLIA/CBC/NoPadding", JostleProvider.PROVIDER_NAME);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[16], "CAMELLIA"), new IvParameterSpec(new byte[16]));

        cipher = Cipher.getInstance("CAMELLIA/CBC/NoPadding", JostleProvider.PROVIDER_NAME);
        DummyParams params = new DummyParams();
        params.init(new byte[16]);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[16], "CAMELLIA"), params);

    }

    @Test
    public void testCamellia() throws Exception
    {
        SecureRandom sr = seededRandom("testCamellia");


        //
        // The doFinal that returns a byte[]
        //


        exercise_simpleDoFinal("CAMELLIA/ECB/NoPadding", new int[]{16, 24, 32}, 5 * 16, 16, -1, sr);
        exercise_simpleDoFinal("CAMELLIA/ECB/PKCS7Padding", new int[]{16, 24, 32}, (5 * 16) + 1, 1, -1, sr);

        exercise_simpleDoFinal("CAMELLIA/CBC/NoPadding", new int[]{16, 24, 32}, 5 * 16, 16, 16, sr);
        exercise_simpleDoFinal("CAMELLIA/CBC/PKCS7Padding", new int[]{16, 24, 32}, (5 * 16) + 1, 1, 16, sr);
        exercise_simpleDoFinal("CAMELLIA/CBC/PKCS5Padding", new int[]{16, 24, 32}, (5 * 16) + 1, 1, 16, sr);
        exercise_simpleDoFinal("CAMELLIA/CFB128/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 16, sr);
        exercise_simpleDoFinal("CAMELLIA/CFB8/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 16, sr);
        exercise_simpleDoFinal("CAMELLIA/OFB/NoPadding", new int[]{16, 24, 32}, 5 * 16, 1, 16, sr);

        exercise_simpleDoFinal("CAMELLIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 8, sr);
        exercise_simpleDoFinal("CAMELLIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 9, sr);
        exercise_simpleDoFinal("CAMELLIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 10, sr);
        exercise_simpleDoFinal("CAMELLIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 11, sr);
        exercise_simpleDoFinal("CAMELLIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 12, sr);
        exercise_simpleDoFinal("CAMELLIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 13, sr);
        exercise_simpleDoFinal("CAMELLIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 14, sr);
        exercise_simpleDoFinal("CAMELLIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 15, sr);
        exercise_simpleDoFinal("CAMELLIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 16, sr);


        //
        // Complex doFinal, that takes input and output arrays.
        //


        exercise_complexDoFinal("CAMELLIA/ECB/NoPadding", new int[]{16, 24, 32}, 5 * 16, 16, -1, sr);
        exercise_complexDoFinal("CAMELLIA/ECB/PKCS7Padding", new int[]{16, 24, 32}, (5 * 16) + 1, 1, -1, sr);

        exercise_complexDoFinal("CAMELLIA/CBC/NoPadding", new int[]{16, 24, 32}, 5 * 16, 16, 16, sr);
        exercise_complexDoFinal("CAMELLIA/CBC/PKCS7Padding", new int[]{16, 24, 32}, (5 * 16) + 1, 1, 16, sr);
        exercise_complexDoFinal("CAMELLIA/CBC/PKCS5Padding", new int[]{16, 24, 32}, (5 * 16) + 1, 1, 16, sr);
        exercise_complexDoFinal("CAMELLIA/CFB128/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 16, sr);
        exercise_complexDoFinal("CAMELLIA/CFB8/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 16, sr);
        exercise_complexDoFinal("CAMELLIA/OFB/NoPadding", new int[]{16, 24, 32}, 5 * 16, 1, 16, sr);

        exercise_complexDoFinal("CAMELLIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 8, sr);
        exercise_complexDoFinal("CAMELLIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 9, sr);
        exercise_complexDoFinal("CAMELLIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 10, sr);
        exercise_complexDoFinal("CAMELLIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 11, sr);
        exercise_complexDoFinal("CAMELLIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 12, sr);
        exercise_complexDoFinal("CAMELLIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 13, sr);
        exercise_complexDoFinal("CAMELLIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 14, sr);
        exercise_complexDoFinal("CAMELLIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 15, sr);
        exercise_complexDoFinal("CAMELLIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 16, sr);


        //
        // Spread message between update and doFinal calls.
        //
        exercise_complexUpdateDoFinal("CAMELLIA/ECB/NoPadding", new int[]{16, 24, 32}, 5 * 16, 16, -1, sr);
        exercise_complexUpdateDoFinal("CAMELLIA/ECB/PKCS7Padding", new int[]{16, 24, 32}, (5 * 16) + 1, 1, -1, sr);

        exercise_complexUpdateDoFinal("CAMELLIA/CBC/NoPadding", new int[]{16, 24, 32}, 5 * 16, 16, 16, sr);
        exercise_complexUpdateDoFinal("CAMELLIA/CBC/PKCS7Padding", new int[]{16, 24, 32}, (5 * 16) + 1, 1, 16, sr);
        exercise_complexUpdateDoFinal("CAMELLIA/CBC/PKCS5Padding", new int[]{16, 24, 32}, (5 * 16) + 1, 1, 16, sr);
        exercise_complexUpdateDoFinal("CAMELLIA/CFB128/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 16, sr);
        exercise_complexUpdateDoFinal("CAMELLIA/CFB8/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 16, sr);
        exercise_complexUpdateDoFinal("CAMELLIA/OFB/NoPadding", new int[]{16, 24, 32}, 5 * 16, 1, 16, sr);

        exercise_complexUpdateDoFinal("CAMELLIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 8, sr);
        exercise_complexUpdateDoFinal("CAMELLIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 9, sr);
        exercise_complexUpdateDoFinal("CAMELLIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 10, sr);
        exercise_complexUpdateDoFinal("CAMELLIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 11, sr);
        exercise_complexUpdateDoFinal("CAMELLIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 12, sr);
        exercise_complexUpdateDoFinal("CAMELLIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 13, sr);
        exercise_complexUpdateDoFinal("CAMELLIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 14, sr);
        exercise_complexUpdateDoFinal("CAMELLIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 15, sr);
        exercise_complexUpdateDoFinal("CAMELLIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 16, sr);


        //
        // Where input and output array is the same.
        //

        exercise_complexDoFinalSameArray("CAMELLIA/ECB/NoPadding", new int[]{16, 24, 32}, 16 * 17, 16, -1, sr);
        exercise_complexDoFinalSameArray("CAMELLIA/ECB/PKCS7Padding", new int[]{16, 24, 32}, (5 * 16) + 1, 1, -1, sr);

        exercise_complexDoFinalSameArray("CAMELLIA/CBC/NoPadding", new int[]{16, 24, 32}, 16 * 17, 16, 16, sr);
        exercise_complexDoFinalSameArray("CAMELLIA/CBC/PKCS7Padding", new int[]{16, 24, 32}, (5 * 16) + 1, 1, 16, sr);
        exercise_complexDoFinalSameArray("CAMELLIA/CBC/PKCS5Padding", new int[]{16, 24, 32}, (5 * 16) + 1, 1, 16, sr);
        exercise_complexDoFinalSameArray("CAMELLIA/CFB128/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 16, sr);
        exercise_complexDoFinalSameArray("CAMELLIA/CFB8/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 16, sr);
        exercise_complexDoFinalSameArray("CAMELLIA/OFB/NoPadding", new int[]{16, 24, 32}, 5 * 16, 1, 16, sr);

        exercise_complexDoFinalSameArray("CAMELLIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 8, sr);
        exercise_complexDoFinalSameArray("CAMELLIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 9, sr);
        exercise_complexDoFinalSameArray("CAMELLIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 10, sr);
        exercise_complexDoFinalSameArray("CAMELLIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 11, sr);
        exercise_complexDoFinalSameArray("CAMELLIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 12, sr);
        exercise_complexDoFinalSameArray("CAMELLIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 13, sr);
        exercise_complexDoFinalSameArray("CAMELLIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 14, sr);
        exercise_complexDoFinalSameArray("CAMELLIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 15, sr);
        exercise_complexDoFinalSameArray("CAMELLIA/CTR/NoPadding", new int[]{16, 24, 32}, 5 * 16 + 1, 1, 16, sr);


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
        // CAMELLIA is a 128-bit block cipher. Use CBC/NoPadding so the
        // decrypt path produces wrong-but-non-throwing plaintext.
        byte[] key = new byte[16];
        sr.nextBytes(key);
        byte[] iv = new byte[16];
        sr.nextBytes(iv);
        byte[] msg = new byte[3 * 16];
        sr.nextBytes(msg);

        Cipher enc = Cipher.getInstance("CAMELLIA/CBC/NoPadding", JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "CAMELLIA"), new IvParameterSpec(iv));
        byte[] ct = enc.doFinal(msg);

        byte[] tampered = ct.clone();
        tampered[16] ^= (byte) 0x01;

        Cipher dec = Cipher.getInstance("CAMELLIA/CBC/NoPadding", JostleProvider.PROVIDER_NAME);
        dec.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "CAMELLIA"), new IvParameterSpec(iv));
        byte[] decoded = dec.doFinal(tampered);

        Assertions.assertFalse(Arrays.areEqual(msg, decoded),
                "tampered ciphertext must not decrypt to the original plaintext");
    }

    @Test
    public void testTamperedPadding_rejectsAtDoFinal() throws Exception
    {
        SecureRandom sr = seededRandom("testTamperedPadding_rejectsAtDoFinal");
        byte[] key = new byte[16];
        sr.nextBytes(key);
        byte[] iv = new byte[16];
        sr.nextBytes(iv);

        boolean sawBadPadding = false;
        for (int trial = 0; trial < 20; trial++)
        {
            byte[] msg = new byte[37];
            sr.nextBytes(msg);

            Cipher enc = Cipher.getInstance("CAMELLIA/CBC/PKCS7Padding", JostleProvider.PROVIDER_NAME);
            enc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "CAMELLIA"), new IvParameterSpec(iv));
            byte[] ct = enc.doFinal(msg);

            byte[] tampered = ct.clone();
            tampered[tampered.length - 1] ^= (byte) 0xFF;

            Cipher dec = Cipher.getInstance("CAMELLIA/CBC/PKCS7Padding", JostleProvider.PROVIDER_NAME);
            dec.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "CAMELLIA"), new IvParameterSpec(iv));
            try
            {
                byte[] out = dec.doFinal(tampered);
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

        Cipher enc = Cipher.getInstance("CAMELLIA/CBC/NoPadding", JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(k1, "CAMELLIA"), new IvParameterSpec(iv));
        byte[] ct = enc.doFinal(msg);

        Cipher dec = Cipher.getInstance("CAMELLIA/CBC/NoPadding", JostleProvider.PROVIDER_NAME);
        dec.init(Cipher.DECRYPT_MODE, new SecretKeySpec(k2, "CAMELLIA"), new IvParameterSpec(iv));
        byte[] decoded = dec.doFinal(ct);

        Assertions.assertFalse(Arrays.areEqual(msg, decoded),
                "decrypting with the wrong key must not yield the original plaintext");
    }


    /**
     * CAMELLIA-CTR accepts IVs in the range [block_size/2, block_size] —
     * i.e. 8..16 bytes for the 128-bit CAMELLIA block size. Every valid
     * length must agree with BC byte-for-byte; lengths outside the range
     * must be rejected by both.
     */
    @Test
    public void camelliaCtr_nonceLengthBoundaries() throws Exception
    {
        SecureRandom sr = seededRandom("camelliaCtr_nonceLengthBoundaries");
        String xform = "CAMELLIA/CTR/NoPadding";
        byte[] key = new byte[32];
        sr.nextBytes(key);
        SecretKey secretKey = new SecretKeySpec(key, "CAMELLIA");
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
                    "ivLen=" + ivLen + ": CAMELLIA-CTR ciphertext diverged from BC");

            Cipher jostleDec = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
            jostleDec.init(Cipher.DECRYPT_MODE, secretKey, spec);
            Assertions.assertArrayEquals(msg, jostleDec.doFinal(jostleCT),
                    "ivLen=" + ivLen + ": CAMELLIA-CTR roundtrip failed");
        }

        for (int badLen : new int[]{0, 1, 7, 17, 32})
        {
            byte[] iv = new byte[badLen];
            sr.nextBytes(iv);
            Cipher c = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
            try
            {
                c.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
                Assertions.fail("CAMELLIA-CTR must reject IV length " + badLen);
            }
            catch (InvalidAlgorithmParameterException expected) { }
        }
    }

}
