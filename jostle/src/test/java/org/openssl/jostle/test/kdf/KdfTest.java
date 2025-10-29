package org.openssl.jostle.test.kdf;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.SecureRandom;
import java.security.Security;

public class KdfTest
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
        // "PBKDF2"
        for (String prf : new String[]{
                "PBKDF2",
                "PBKDF2WITHHMACSHA1",
                "PBKDF2WITHHMACSHA224",
                "PBKDF2WITHHMACSHA256",
                "PBKDF2WITHHMACSHA384",
                "PBKDF2WITHHMACSHA512",
//                "PBKDF2WITHHMACSHA512-224",
//                "PBKDF2WITHHMACSHA512-256", // Put back on next BC release 1.83+
                "PBKDF2WITHHMACSHA3-224",
                "PBKDF2WITHHMACSHA3-256",
                "PBKDF2WITHHMACSHA3-384",
                "PBKDF2WITHHMACSHA3-512",
                "PBKDF2WITHHMACSM3",


        })
        {

            char[] passphrase = new String(random(8)).toCharArray();
            byte[] salt = random(16);
            SecretKeyFactory kfJostle = SecretKeyFactory.getInstance(prf, JostleProvider.PROVIDER_NAME);
            SecretKeyFactory kfBc = SecretKeyFactory.getInstance(prf, BouncyCastleProvider.PROVIDER_NAME);

            SecretKey joKey = kfJostle.generateSecret(new PBEKeySpec(passphrase, salt, 100,256));
            SecretKey bcKey = kfBc.generateSecret(new PBEKeySpec(passphrase, salt, 100,256));

            Assertions.assertArrayEquals(joKey.getEncoded(), bcKey.getEncoded(), prf);
        }
    }


}
