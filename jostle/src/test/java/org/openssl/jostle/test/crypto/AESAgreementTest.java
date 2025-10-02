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
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
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

        exercise_simpleDoFinal("AES/ECB/NoPadding", new int[]{16, 24, 32}, 17 * 16, 16, -1);
        exercise_simpleDoFinal("AES/ECB/PKCS7Padding", new int[]{16, 24, 32}, (17 * 16) + 1, 1, -1);

        exercise_simpleDoFinal("AES/CBC/NoPadding", new int[]{16, 24, 32}, 17 * 16, 16, 16);
        exercise_simpleDoFinal("AES/CBC/PKCS7Padding", new int[]{16, 24, 32}, (17 * 16) + 1, 1, 16);
        exercise_simpleDoFinal("AES/CFB128/NoPadding", new int[]{16, 24, 32}, 17 * 16 + 1, 1, 16);
        exercise_simpleDoFinal("AES/CFB8/NoPadding", new int[]{16, 24, 32}, 17 * 16 + 1, 1, 16);
        exercise_simpleDoFinal("AES/OFB/NoPadding", new int[]{16, 24, 32}, 17 * 16, 1, 16);

        exercise_simpleDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 17 * 16 + 1, 1, 8);
        exercise_simpleDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 17 * 16 + 1, 1, 9);
        exercise_simpleDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 17 * 16 + 1, 1, 10);
        exercise_simpleDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 17 * 16 + 1, 1, 11);
        exercise_simpleDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 17 * 16 + 1, 1, 12);
        exercise_simpleDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 17 * 16 + 1, 1, 13);
        exercise_simpleDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 17 * 16 + 1, 1, 14);
        exercise_simpleDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 17 * 16 + 1, 1, 15);
        exercise_simpleDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 17 * 16 + 1, 1, 16);


        //
        // Complex doFinal, that takes input and output arrays.
        //


        exercise_complexDoFinal("AES/ECB/NoPadding", new int[]{16, 24, 32}, 17 * 16, 16, -1);
        exercise_complexDoFinal("AES/ECB/PKCS7Padding", new int[]{16, 24, 32}, (17 * 16) + 1, 1, -1);

        exercise_complexDoFinal("AES/CBC/NoPadding", new int[]{16, 24, 32}, 17 * 16, 16, 16);
        exercise_complexDoFinal("AES/CBC/PKCS7Padding", new int[]{16, 24, 32}, (17 * 16) + 1, 1, 16);
        exercise_complexDoFinal("AES/CFB128/NoPadding", new int[]{16, 24, 32}, 17 * 16 + 1, 1, 16);
        exercise_complexDoFinal("AES/CFB8/NoPadding", new int[]{16, 24, 32}, 17 * 16 + 1, 1, 16);
        exercise_complexDoFinal("AES/OFB/NoPadding", new int[]{16, 24, 32}, 17 * 16, 1, 16);

        exercise_complexDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 17 * 16 + 1, 1, 8);
        exercise_complexDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 17 * 16 + 1, 1, 9);
        exercise_complexDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 17 * 16 + 1, 1, 10);
        exercise_complexDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 17 * 16 + 1, 1, 11);
        exercise_complexDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 17 * 16 + 1, 1, 12);
        exercise_complexDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 17 * 16 + 1, 1, 13);
        exercise_complexDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 17 * 16 + 1, 1, 14);
        exercise_complexDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 17 * 16 + 1, 1, 15);
        exercise_complexDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 17 * 16 + 1, 1, 16);


        //
        // Spread message between update and doFinal calls.
        //
        exercise_complexUpdateDoFinal("AES/ECB/NoPadding", new int[]{16, 24, 32}, 17 * 16, 16, -1);
        exercise_complexUpdateDoFinal("AES/ECB/PKCS7Padding", new int[]{16, 24, 32}, (17 * 16) + 1, 1, -1);

        exercise_complexUpdateDoFinal("AES/CBC/NoPadding", new int[]{16, 24, 32}, 17 * 16, 16, 16);
        exercise_complexUpdateDoFinal("AES/CBC/PKCS7Padding", new int[]{16, 24, 32}, (17 * 16) + 1, 1, 16);
        exercise_complexUpdateDoFinal("AES/CFB128/NoPadding", new int[]{16, 24, 32}, 17 * 16 + 1, 1, 16);
        exercise_complexUpdateDoFinal("AES/CFB8/NoPadding", new int[]{16, 24, 32}, 17 * 16 + 1, 1, 16);
        exercise_complexUpdateDoFinal("AES/OFB/NoPadding", new int[]{16, 24, 32}, 17 * 16, 1, 16);

        exercise_complexUpdateDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 17 * 16 + 1, 1, 8);
        exercise_complexUpdateDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 17 * 16 + 1, 1, 9);
        exercise_complexUpdateDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 17 * 16 + 1, 1, 10);
        exercise_complexUpdateDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 17 * 16 + 1, 1, 11);
        exercise_complexUpdateDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 17 * 16 + 1, 1, 12);
        exercise_complexUpdateDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 17 * 16 + 1, 1, 13);
        exercise_complexUpdateDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 17 * 16 + 1, 1, 14);
        exercise_complexUpdateDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 17 * 16 + 1, 1, 15);
        exercise_complexUpdateDoFinal("AES/CTR/NoPadding", new int[]{16, 24, 32}, 17 * 16 + 1, 1, 16);


        //
        // Where input and output array is the same.
        //

        exercise_complexDoFinalSameArray("AES/ECB/NoPadding", new int[]{16, 24, 32}, 16 * 17, 16, -1);
        exercise_complexDoFinalSameArray("AES/ECB/PKCS7Padding", new int[]{16, 24, 32}, (17 * 16) + 1, 1, -1);

        exercise_complexDoFinalSameArray("AES/CBC/NoPadding", new int[]{16, 24, 32}, 17 * 16, 16, 16);
        exercise_complexDoFinalSameArray("AES/CBC/PKCS7Padding", new int[]{16, 24, 32}, (17 * 16) + 1, 1, 16);
        exercise_complexDoFinalSameArray("AES/CFB128/NoPadding", new int[]{16, 24, 32}, 17 * 16 + 1, 1, 16);
        exercise_complexDoFinalSameArray("AES/CFB8/NoPadding", new int[]{16, 24, 32}, 17 * 16 + 1, 1, 16);
        exercise_complexDoFinalSameArray("AES/OFB/NoPadding", new int[]{16, 24, 32}, 17 * 16, 1, 16);

        exercise_complexDoFinalSameArray("AES/CTR/NoPadding", new int[]{16, 24, 32}, 17 * 16 + 1, 1, 8);
        exercise_complexDoFinalSameArray("AES/CTR/NoPadding", new int[]{16, 24, 32}, 17 * 16 + 1, 1, 9);
        exercise_complexDoFinalSameArray("AES/CTR/NoPadding", new int[]{16, 24, 32}, 17 * 16 + 1, 1, 10);
        exercise_complexDoFinalSameArray("AES/CTR/NoPadding", new int[]{16, 24, 32}, 17 * 16 + 1, 1, 11);
        exercise_complexDoFinalSameArray("AES/CTR/NoPadding", new int[]{16, 24, 32}, 17 * 16 + 1, 1, 12);
        exercise_complexDoFinalSameArray("AES/CTR/NoPadding", new int[]{16, 24, 32}, 17 * 16 + 1, 1, 13);
        exercise_complexDoFinalSameArray("AES/CTR/NoPadding", new int[]{16, 24, 32}, 17 * 16 + 1, 1, 14);
        exercise_complexDoFinalSameArray("AES/CTR/NoPadding", new int[]{16, 24, 32}, 17 * 16 + 1, 1, 15);
        exercise_complexDoFinalSameArray("AES/CTR/NoPadding", new int[]{16, 24, 32}, 17 * 16 + 1, 1, 16);


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

            for (int mlen = 0; mlen < 1 + 17 * 16; )
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


}
