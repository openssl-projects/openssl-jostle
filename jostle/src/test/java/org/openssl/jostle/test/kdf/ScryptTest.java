package org.openssl.jostle.test.kdf;

import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.spec.ScryptKeySpec;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import java.security.SecureRandom;
import java.security.Security;

public class ScryptTest
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

    private static byte[] random(int length)
    {
        byte[] bytes = new byte[length];
        secRand.nextBytes(bytes);
        return bytes;
    }


    @Test
    public void testBCAgreement() throws Exception
    {
        // "SCRYPT"


        //
        // Parameter values in this test were just chosen without regard to
        // real world viability, please do not cut and paste this into anything important.
        //


        char[] passphrase = new String(random(8)).toCharArray();
        byte[] salt = random(16);
        SecretKeyFactory kfJostle = SecretKeyFactory.getInstance("SCRYPT", JostleProvider.PROVIDER_NAME);
        SecretKeyFactory kfBc = SecretKeyFactory.getInstance("SCRYPT", BouncyCastleProvider.PROVIDER_NAME);

        SecretKey joKey = kfJostle.generateSecret(new ScryptKeySpec(passphrase, salt, 2, 1, 1, 512));
        SecretKey bcKey = kfBc.generateSecret(new org.bouncycastle.jcajce.spec.ScryptKeySpec(passphrase, salt, 2, 1, 1, 512));

        Assertions.assertArrayEquals(joKey.getEncoded(), bcKey.getEncoded(), "SCRYPT");

    }



}
