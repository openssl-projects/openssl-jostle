package org.openssl.jostle.jcajce.provider.kdf;

import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.util.DigestUtil;
import org.openssl.jostle.util.Strings;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactorySpi;
import javax.crypto.interfaces.PBEKey;
import javax.crypto.spec.PBEKeySpec;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

public class PBESecretKeyFactory extends SecretKeyFactorySpi
{

    private final String forcedDigestAlgorithm;

    public PBESecretKeyFactory(String forcedDigestAlgorithm)
    {
        this.forcedDigestAlgorithm = DigestUtil.getCanonicalDigestName(forcedDigestAlgorithm);
    }

    public PBESecretKeyFactory()
    {
        this.forcedDigestAlgorithm = null;
    }


    @Override
    protected SecretKey engineGenerateSecret(KeySpec keySpec) throws InvalidKeySpecException
    {
        if (keySpec instanceof PBEKeySpec)
        {
            PBEKeySpec spec = (PBEKeySpec) keySpec;

            byte[] rawKey = new byte[spec.getKeyLength() >> 3];

            String algo = null;
            if (spec instanceof PBKDF2KeySpec)
            {
                algo = ((PBKDF2KeySpec) spec).getPrf();
            }

            if (algo == null)
            {
                algo = forcedDigestAlgorithm;
            }

            if (forcedDigestAlgorithm != null && !forcedDigestAlgorithm.equals(algo))
            {
                throw new InvalidKeySpecException("PRF in spec " + algo + " does not match forced prf " + forcedDigestAlgorithm);
            }

            if (algo == null)
            {
                algo = DigestUtil.getCanonicalDigestName("SHA-1");
            }

            NISelector.KdfNI.handleErrorCodes(NISelector.KdfNI.pbkdf2(
                    Strings.toUTF8ByteArray(spec.getPassword()),
                    spec.getSalt(),
                    spec.getIterationCount(),
                    algo, rawKey, 0, rawKey.length));


            String name = "PBKDF2WithHmac" + algo + "andUTF8";

            return new JOPBEKey(name, spec.getPassword(), spec.getSalt(), spec.getIterationCount(), rawKey);

        }
        
        throw new InvalidKeySpecException("unsupported KeySpec " + keySpec.getClass().getName());
    }

    @Override
    protected KeySpec engineGetKeySpec(SecretKey key, Class<?> keySpec) throws InvalidKeySpecException
    {
        throw new UnsupportedOperationException("not implemented");
    }

    @Override
    protected SecretKey engineTranslateKey(SecretKey key) throws InvalidKeyException
    {
        if (key == null)
        {
            throw new InvalidKeyException("key parameter is null");
        }

        if (key instanceof PBEKey)
        {
            PBEKey pbeKey = (PBEKey) key;
            return new JOPBEKey(key.getAlgorithm(), pbeKey.getPassword(), pbeKey.getSalt(), pbeKey.getIterationCount(), pbeKey.getEncoded());
        }

        throw new InvalidKeyException("unsupported key type: " + key.getClass());

    }
}
