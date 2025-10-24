package org.openssl.jostle.jcajce.provider;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

class AESKeyGenerator extends KeyGeneratorSpi
{

    private SecureRandom random;
    private AlgorithmParameterSpec params;
    private int keySize;
    private int fixedKeySize = 0;

    AESKeyGenerator()
    {
        random = new SecureRandom();
        keySize = 256;
    }

    AESKeyGenerator(int fixedSize)
    {
        this.fixedKeySize = fixedSize;
        this.keySize = fixedSize;
    }


    @Override
    protected void engineInit(SecureRandom random)
    {
        this.random = random;
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException
    {
        throw new UnsupportedOperationException("not implemented, use keySize, random");
    }

    @Override
    protected void engineInit(int keysize, SecureRandom random)
    {

        switch (keysize)
        {
            case 128:
            case 192:
            case 256:
                break;
            default:
                throw new IllegalArgumentException("key size must be 128, 192 or 256");
        }

        if (random == null)
        {
            throw new IllegalArgumentException("random is null");
        }

        if (fixedKeySize > 0 && keysize != fixedKeySize)
        {
            throw new IllegalArgumentException("key size must be " + fixedKeySize);
        }


        this.random = random;
        this.keySize = keysize;

    }

    @Override
    protected SecretKey engineGenerateKey()
    {

        assert keySize == 128 || keySize == 192 || keySize == 256;

        byte[] keyBytes = new byte[keySize >> 3];
        random.nextBytes(keyBytes);
        return new ProvSecretKeySpec(keyBytes, "AES");
    }


    static class AESSecretKey extends SecretKeySpec {

        public AESSecretKey(byte[] key, String algorithm)
        {
            super(key, algorithm);
        }

        public AESSecretKey(byte[] key, int offset, int len, String algorithm)
        {
            super(key, offset, len, algorithm);
        }

        @Override
        public void destroy() throws DestroyFailedException
        {

            super.destroy();
        }
    }
}
