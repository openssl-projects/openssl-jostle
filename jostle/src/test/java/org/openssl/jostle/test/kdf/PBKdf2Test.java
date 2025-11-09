package org.openssl.jostle.test.kdf;

import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.digests.*;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.util.Strings;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.SecureRandom;
import java.security.Security;

public class PBKdf2Test
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
//                "PBKDF2WITHHMACSHA512-224", Put back on next BC release 1.83+
//                "PBKDF2WITHHMACSHA512-256", both tested in testBCAgreementLowLevel
                "PBKDF2WITHHMACSHA3-224",
                "PBKDF2WITHHMACSHA3-256",
                "PBKDF2WITHHMACSHA3-384",
                "PBKDF2WITHHMACSHA3-512",
                "PBKDF2WITHHMACSM3",
        })
        {

            //
            // Parameter values in this test were just chosen without regard to
            // real world viability, please do not cut and paste this into anything important.
            //

            char[] passphrase = new String(random(8)).toCharArray();
            byte[] salt = random(16);
            SecretKeyFactory kfJostle = SecretKeyFactory.getInstance(prf, JostleProvider.PROVIDER_NAME);
            SecretKeyFactory kfBc = SecretKeyFactory.getInstance(prf, BouncyCastleProvider.PROVIDER_NAME);

            SecretKey joKey = kfJostle.generateSecret(new PBEKeySpec(passphrase, salt, 100, 256));
            SecretKey bcKey = kfBc.generateSecret(new PBEKeySpec(passphrase, salt, 100, 256));

            Assertions.assertArrayEquals(joKey.getEncoded(), bcKey.getEncoded(), prf);
        }
    }

    @Test
    public void testBCAgreementLowLevel() throws Exception
    {
        //
        // We need to use the low level api to get some of the variations on the BC side
        //
        char[] passphrase = new String(random(8)).toCharArray();
        byte[] salt = random(16);
        byte[] passphraseAsBytes = Strings.toUTF8ByteArray(passphrase);


        { // BLAKE2B-512
            PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator(new Blake2bDigest(512));
            generator.init(passphraseAsBytes, salt, 100);
            KeyParameter llBC = (KeyParameter) generator.generateDerivedParameters(256);

            SecretKeyFactory kfJostle = SecretKeyFactory.getInstance("PBKDF2WITHHMACBLAKE2B-512", JostleProvider.PROVIDER_NAME);
            SecretKey sk = kfJostle.generateSecret(new PBEKeySpec(passphrase, salt, 100, 256));
            Assertions.assertArrayEquals(llBC.getKey(), sk.getEncoded());
        }

        { // BLAKE2S-256
            PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator(new Blake2sDigest(256));
            generator.init(passphraseAsBytes, salt, 100);
            KeyParameter llBC = (KeyParameter) generator.generateDerivedParameters(256);

            SecretKeyFactory kfJostle = SecretKeyFactory.getInstance("PBKDF2WITHHMACBLAKE2S-256", JostleProvider.PROVIDER_NAME);
            SecretKey sk = kfJostle.generateSecret(new PBEKeySpec(passphrase, salt, 100, 256));
            Assertions.assertArrayEquals(llBC.getKey(), sk.getEncoded());
        }


        { // MD5
            PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator(new MD5Digest());
            generator.init(passphraseAsBytes, salt, 100);
            KeyParameter llBC = (KeyParameter) generator.generateDerivedParameters(256);

            SecretKeyFactory kfJostle = SecretKeyFactory.getInstance("PBKDF2WITHHMACMD5", JostleProvider.PROVIDER_NAME);
            SecretKey sk = kfJostle.generateSecret(new PBEKeySpec(passphrase, salt, 100, 256));
            Assertions.assertArrayEquals(llBC.getKey(), sk.getEncoded());
        }


        { // MD5-SHA1
            PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator(new MD5SHA1Digest());
            generator.init(passphraseAsBytes, salt, 100);
            KeyParameter llBC = (KeyParameter) generator.generateDerivedParameters(256);

            SecretKeyFactory kfJostle = SecretKeyFactory.getInstance("PBKDF2WITHHMACMD5-SHA1", JostleProvider.PROVIDER_NAME);
            SecretKey sk = kfJostle.generateSecret(new PBEKeySpec(passphrase, salt, 100, 256));

            Assertions.assertArrayEquals(llBC.getKey(), sk.getEncoded());
        }

        { // SHA512-224
            PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator(new SHA512tDigest(224));
            generator.init(passphraseAsBytes, salt, 100);
            KeyParameter llBC = (KeyParameter) generator.generateDerivedParameters(256);

            SecretKeyFactory kfJostle = SecretKeyFactory.getInstance("PBKDF2WITHHMACSHA512-224", JostleProvider.PROVIDER_NAME);
            SecretKey sk = kfJostle.generateSecret(new PBEKeySpec(passphrase, salt, 100, 256));

            Assertions.assertArrayEquals(llBC.getKey(), sk.getEncoded());
        }

        { // SHA512-256
            PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator(new SHA512tDigest(256));
            generator.init(passphraseAsBytes, salt, 100);
            KeyParameter llBC = (KeyParameter) generator.generateDerivedParameters(256);

            SecretKeyFactory kfJostle = SecretKeyFactory.getInstance("PBKDF2WITHHMACSHA512-256", JostleProvider.PROVIDER_NAME);
            SecretKey sk = kfJostle.generateSecret(new PBEKeySpec(passphrase, salt, 100, 256));

            Assertions.assertArrayEquals(llBC.getKey(), sk.getEncoded());
        }


        { // RIPEMD-160
            PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator(new RIPEMD160Digest());
            generator.init(passphraseAsBytes, salt, 100);
            KeyParameter llBC = (KeyParameter) generator.generateDerivedParameters(256);

            SecretKeyFactory kfJostle = SecretKeyFactory.getInstance("PBKDF2WITHHMACRIPEMD160", JostleProvider.PROVIDER_NAME);
            SecretKey sk = kfJostle.generateSecret(new PBEKeySpec(passphrase, salt, 100, 256));
            Assertions.assertArrayEquals(llBC.getKey(), sk.getEncoded());
        }

    }


    private static class MD5SHA1Digest implements ExtendedDigest
    {
        // blast from the past!

        private MD5Digest md5;
        private SHA1Digest sha1;

        public MD5SHA1Digest()
        {
            md5 = new MD5Digest();
            sha1 = new SHA1Digest();
        }


        @Override
        public String getAlgorithmName()
        {
            return "MD5-SHA1";
        }

        @Override
        public int getDigestSize()
        {
            return 20 + 16;
        }

        @Override
        public void update(byte in)
        {
            md5.update(in);
            sha1.update(in);
        }

        @Override
        public void update(byte[] in, int inOff, int len)
        {
            md5.update(in, inOff, len);
            sha1.update(in, inOff, len);
        }

        @Override
        public int doFinal(byte[] out, int outOff)
        {
            md5.doFinal(out, outOff);
            sha1.doFinal(out, outOff + md5.getDigestSize());
            return 20 + 16;
        }

        @Override
        public void reset()
        {
            md5.reset();
            sha1.reset();
        }

        @Override
        public int getByteLength()
        {
            return 64;
        }
    }
}
