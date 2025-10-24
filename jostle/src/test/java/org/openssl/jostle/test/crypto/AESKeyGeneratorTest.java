package org.openssl.jostle.test.crypto;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;

public class AESKeyGeneratorTest
{
    static SecureRandom secRand = new SecureRandom();

    @BeforeAll
    static void before()
    {

        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }


    @Test
    public void testInitFails_notSupported() throws Exception
    {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES", JostleProvider.PROVIDER_NAME);
        try
        {
            keyGen.init(new AlgorithmParameterSpec()
            {
            }, secRand);
            Assertions.fail("Should have thrown an exception");
        } catch (UnsupportedOperationException ose)
        {
            Assertions.assertEquals("not implemented, use keySize, random", ose.getMessage());
        }

    }


    @Test
    public void testGenFails_invalidKeySize() throws Exception
    {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES", JostleProvider.PROVIDER_NAME);
        for (int size : new int[]{0, 127, 129, 191, 193, 255, 257})
            try
            {
                keyGen.init(size, new SecureRandom());
                Assertions.fail("Should have thrown an exception");
            } catch (IllegalArgumentException ila)
            {
                Assertions.assertEquals("key size must be 128, 192 or 256", ila.getMessage());
            }

    }

    @Test
    public void testGenFails_fixedKeySize() throws Exception
    {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES128", JostleProvider.PROVIDER_NAME);
        try
        {
            keyGen.init(192, secRand);
            Assertions.fail("Should have thrown an exception");
        } catch (IllegalArgumentException iae)
        {
            Assertions.assertEquals("key size must be 128", iae.getMessage());
        }

        keyGen = KeyGenerator.getInstance("AES192", JostleProvider.PROVIDER_NAME);
        try
        {
            keyGen.init(256, secRand);
            Assertions.fail("Should have thrown an exception");
        } catch (IllegalArgumentException iae)
        {
            Assertions.assertEquals("key size must be 192", iae.getMessage());
        }

        keyGen = KeyGenerator.getInstance("AES256", JostleProvider.PROVIDER_NAME);
        try
        {
            keyGen.init(128, secRand);
            Assertions.fail("Should have thrown an exception");
        } catch (IllegalArgumentException iae)
        {
            Assertions.assertEquals("key size must be 256", iae.getMessage());
        }
    }


    @Test
    public void testGen_default256() throws Exception
    {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES", JostleProvider.PROVIDER_NAME);
        byte[] keyBytes = keyGen.generateKey().getEncoded();
        Assertions.assertEquals(256, keyBytes.length << 3);
        Assertions.assertFalse(Arrays.areAllZeroes(keyBytes, 0, keyBytes.length));
    }


    @Test
    public void testGen_validKeySizes() throws Exception
    {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES", JostleProvider.PROVIDER_NAME);
        for (int size : new int[]{128, 192, 256})
        {
            keyGen.init(size, new SecureRandom());
            byte[] keyBytes = keyGen.generateKey().getEncoded();
            Assertions.assertEquals(size, keyBytes.length << 3);
            Assertions.assertFalse(Arrays.areAllZeroes(keyBytes, 0, keyBytes.length));
        }
    }


    @Test
    public void testGen_basicUse() throws Exception
    {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES", JostleProvider.PROVIDER_NAME);
        SecretKey key = keyGen.generateKey();

        Cipher cipher = Cipher.getInstance("AES", JostleProvider.PROVIDER_NAME);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] msg = new byte[32];
        secRand.nextBytes(msg);

        byte[] ct = cipher.doFinal(msg);

        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] pt = cipher.doFinal(ct);

        Assertions.assertArrayEquals(msg, pt);
    }

    @Test
    public void testDestroy() throws Exception
    {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES", JostleProvider.PROVIDER_NAME);
        SecretKey key = keyGen.generateKey();
        key.destroy();
        Assertions.assertTrue(key.isDestroyed());
        try
        {
            key.getEncoded();
            Assertions.fail("Should have thrown an exception");
        } catch (IllegalStateException ise)
        {
            Assertions.assertEquals("key has been destroyed", ise.getMessage());
        }
    }

}
