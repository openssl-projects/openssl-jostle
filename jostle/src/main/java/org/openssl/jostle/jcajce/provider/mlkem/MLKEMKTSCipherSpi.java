/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.mlkem;

import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.jcajce.interfaces.OSSLKey;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.rand.DefaultRandSource;
import org.openssl.jostle.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import java.lang.reflect.Method;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

/**
 * ML-KEM KTS (key-transport) Cipher for the CMS KEMRecipientInfo path (RFC 9629),
 * driven by BouncyCastle's {@code JceCMSKEMKeyWrapper}/{@code JceCMSKEMKeyUnwrapper}:
 * <pre>
 *   Cipher.getInstance(&lt;ml-kem-oid&gt;).init(WRAP_MODE, pubKey, KTSParameterSpec); wrap(cek)
 *   Cipher.getInstance(&lt;ml-kem-oid&gt;).init(UNWRAP_MODE, privKey, KTSParameterSpec); unwrap(enc, name, SECRET_KEY)
 * </pre>
 * <p>
 * Wrap performs ML-KEM encapsulate &rarr; KDF3 &rarr; AES key-wrap and returns
 * {@code encapsulation ‖ wrappedKey}; unwrap is the inverse, splitting at the
 * fixed encapsulation length for the key's parameter set.
 * <p>
 * The {@link AlgorithmParameterSpec} BC supplies is its
 * {@code org.bouncycastle.jcajce.spec.KTSParameterSpec}. To keep this provider
 * free of any compile-time BouncyCastle dependency the spec is read reflectively
 * ({@code getKeyAlgorithmName}/{@code getKeySize}/{@code getOtherInfo}/{@code getKdfAlgorithm}).
 */
public class MLKEMKTSCipherSpi
    extends CipherSpi
{
    // FIPS 203 fixed shared-secret size (bytes).
    private static final int SHARED_SECRET_LEN = 32;
    // X9.44 / NIST concatenation KDF (KDF3) OID — the only KDF used by CMS here.
    private static final String ID_KDF_KDF3 = "1.3.133.16.840.9.44.1.2";

    private int opmode;
    private PKEYKeySpec keySpec;
    private SecureRandom random;

    // KTSParameterSpec contents (read reflectively in engineInit).
    private int kekBits;
    private byte[] otherInfo;
    private String digestName;   // null => no KDF, use the shared secret directly

    @Override
    protected void engineSetMode(String mode)
        throws NoSuchAlgorithmException
    {
        // KTS via Cipher.getInstance(oid) carries no mode; ignore.
    }

    @Override
    protected void engineSetPadding(String padding)
        throws NoSuchPaddingException
    {
        // No padding concept for a KTS cipher; ignore.
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random)
        throws InvalidKeyException
    {
        throw new InvalidKeyException("ML-KEM KTS cipher requires a KTSParameterSpec");
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
        throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        if (opmode != Cipher.WRAP_MODE && opmode != Cipher.UNWRAP_MODE)
        {
            throw new InvalidAlgorithmParameterException("ML-KEM KTS cipher only supports WRAP_MODE/UNWRAP_MODE");
        }
        if (!(key instanceof OSSLKey))
        {
            throw new InvalidKeyException("not a JSL ML-KEM key: " + (key == null ? "null" : key.getClass().getName()));
        }
        if (opmode == Cipher.WRAP_MODE && !(key instanceof PublicKey))
        {
            throw new InvalidKeyException("WRAP_MODE requires an ML-KEM public key");
        }
        if (opmode == Cipher.UNWRAP_MODE && !(key instanceof PrivateKey))
        {
            throw new InvalidKeyException("UNWRAP_MODE requires an ML-KEM private key");
        }

        PKEYKeySpec spec = ((OSSLKey) key).getSpec();
        switch (spec.getType())
        {
        case ML_KEM_512:
        case ML_KEM_768:
        case ML_KEM_1024:
            break;
        default:
            throw new InvalidKeyException("not an ML-KEM key: " + spec.getType().getAlgorithmName());
        }

        readKtsSpec(params);

        this.opmode = opmode;
        this.keySpec = spec;
        this.random = random;
    }

    @Override
    protected void engineInit(int opmode, Key key, java.security.AlgorithmParameters params, SecureRandom random)
        throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        throw new InvalidAlgorithmParameterException("ML-KEM KTS cipher requires a KTSParameterSpec");
    }

    @Override
    protected byte[] engineWrap(Key key)
        throws javax.crypto.IllegalBlockSizeException, InvalidKeyException
    {
        if (opmode != Cipher.WRAP_MODE)
        {
            throw new IllegalStateException("cipher not initialised for wrapping");
        }

        int encLen = encapsulationLength(keySpec.getType());
        byte[] secret = new byte[SHARED_SECRET_LEN];
        byte[] encapsulation = new byte[encLen];

        SecureRandom rng = (random != null) ? random : CryptoServicesRegistrar.getSecureRandom();
        int written = NISelector.SpecNI.encap(keySpec.getReference(), null,
            secret, 0, secret.length, encapsulation, 0, encapsulation.length, DefaultRandSource.wrap(rng));
        if (written != encLen)
        {
            throw new InvalidKeyException("unexpected ML-KEM encapsulation length: " + written);
        }

        try
        {
            byte[] kek = deriveKek(secret);
            try
            {
                Cipher aesKw;
                try
                {
                    aesKw = aesKeyWrap(Cipher.WRAP_MODE, kek);
                }
                catch (NoSuchAlgorithmException | NoSuchPaddingException
                    | java.security.NoSuchProviderException | InvalidAlgorithmParameterException e)
                {
                    throw new InvalidKeyException("unable to create AES key-wrap cipher: " + e.getMessage(), e);
                }
                byte[] wrapped = aesKw.wrap(key);
                return Arrays.concatenate(encapsulation, wrapped);
            }
            finally
            {
                Arrays.fill(kek, (byte) 0);
            }
        }
        finally
        {
            Arrays.fill(secret, (byte) 0);
        }
    }

    @Override
    protected Key engineUnwrap(byte[] wrappedKey, String wrappedKeyAlgorithm, int wrappedKeyType)
        throws InvalidKeyException, NoSuchAlgorithmException
    {
        if (opmode != Cipher.UNWRAP_MODE)
        {
            throw new IllegalStateException("cipher not initialised for unwrapping");
        }

        int encLen = encapsulationLength(keySpec.getType());
        if (wrappedKey.length < encLen)
        {
            throw new InvalidKeyException("input shorter than ML-KEM encapsulation");
        }
        byte[] encapsulation = Arrays.copyOfRange(wrappedKey, 0, encLen);
        byte[] wrapped = Arrays.copyOfRange(wrappedKey, encLen, wrappedKey.length);

        byte[] secret = new byte[SHARED_SECRET_LEN];
        int written = NISelector.SpecNI.decap(keySpec.getReference(), null,
            encapsulation, 0, encapsulation.length, secret, 0, secret.length);
        if (written != SHARED_SECRET_LEN)
        {
            throw new InvalidKeyException("unexpected ML-KEM shared-secret length: " + written);
        }

        try
        {
            byte[] kek = deriveKek(secret);
            try
            {
                Cipher aesKw = aesKeyWrap(Cipher.UNWRAP_MODE, kek);
                return aesKw.unwrap(wrapped, wrappedKeyAlgorithm, wrappedKeyType);
            }
            catch (InvalidAlgorithmParameterException | NoSuchPaddingException | java.security.NoSuchProviderException e)
            {
                throw new InvalidKeyException("unable to unwrap key: " + e.getMessage(), e);
            }
            finally
            {
                Arrays.fill(kek, (byte) 0);
            }
        }
        finally
        {
            Arrays.fill(secret, (byte) 0);
        }
    }

    // --- KEK derivation -----------------------------------------------------

    private byte[] deriveKek(byte[] sharedSecret)
        throws InvalidKeyException
    {
        int kekBytes = (kekBits + 7) / 8;
        if (digestName == null)
        {
            // withNoKdf(): use the shared secret directly.
            if (sharedSecret.length < kekBytes)
            {
                throw new InvalidKeyException("shared secret too short for " + kekBits + "-bit KEK without a KDF");
            }
            return Arrays.copyOfRange(sharedSecret, 0, kekBytes);
        }
        try
        {
            return kdf3(digestName, sharedSecret, otherInfo, kekBytes);
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new InvalidKeyException("KDF digest unavailable: " + e.getMessage(), e);
        }
    }

    /**
     * X9.44 KDF3 (NIST concatenation KDF): {@code K = Hash(counter32 ‖ Z ‖ otherInfo)}
     * concatenated over counter = 1, 2, ... until {@code outLen} bytes are produced.
     */
    private static byte[] kdf3(String digestName, byte[] z, byte[] otherInfo, int outLen)
        throws NoSuchAlgorithmException
    {
        MessageDigest md = MessageDigest.getInstance(digestName);
        byte[] out = new byte[outLen];
        byte[] counter = new byte[4];
        int pos = 0;
        int i = 1;
        while (pos < outLen)
        {
            counter[0] = (byte) (i >>> 24);
            counter[1] = (byte) (i >>> 16);
            counter[2] = (byte) (i >>> 8);
            counter[3] = (byte) i;
            md.update(counter);
            md.update(z);
            if (otherInfo != null && otherInfo.length != 0)
            {
                md.update(otherInfo);
            }
            byte[] block = md.digest();
            int n = Math.min(block.length, outLen - pos);
            System.arraycopy(block, 0, out, pos, n);
            pos += n;
            i++;
        }
        return out;
    }

    private Cipher aesKeyWrap(int mode, byte[] kek)
        throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
        java.security.NoSuchProviderException, InvalidAlgorithmParameterException
    {
        String oid;
        switch (kek.length)
        {
        case 16: oid = "2.16.840.1.101.3.4.1.5";  break;   // id-aes128-wrap
        case 24: oid = "2.16.840.1.101.3.4.1.25"; break;   // id-aes192-wrap
        case 32: oid = "2.16.840.1.101.3.4.1.45"; break;   // id-aes256-wrap
        default: throw new InvalidKeyException("unsupported AES-KW KEK size: " + kek.length);
        }
        Cipher c = Cipher.getInstance(oid, JostleProvider.PROVIDER_NAME);
        c.init(mode, new SecretKeySpec(kek, "AES"));
        return c;
    }

    // --- KTSParameterSpec via reflection (no compile-time BC dependency) -----

    private void readKtsSpec(AlgorithmParameterSpec params)
        throws InvalidAlgorithmParameterException
    {
        if (params == null)
        {
            throw new InvalidAlgorithmParameterException("a KTSParameterSpec is required");
        }
        try
        {
            Class<?> c = params.getClass();
            this.kekBits = (Integer) method(c, "getKeySize").invoke(params);
            this.otherInfo = (byte[]) method(c, "getOtherInfo").invoke(params);
            Object kdfAlgId = method(c, "getKdfAlgorithm").invoke(params);
            this.digestName = (kdfAlgId == null) ? null : resolveKdfDigest(kdfAlgId);
        }
        catch (InvalidAlgorithmParameterException e)
        {
            throw e;
        }
        catch (NoSuchMethodException e)
        {
            throw new InvalidAlgorithmParameterException("unsupported parameter spec " + params.getClass().getName(), e);
        }
        catch (ReflectiveOperationException e)
        {
            throw new InvalidAlgorithmParameterException("unable to read KTSParameterSpec: " + e.getMessage(), e);
        }
        if (kekBits <= 0)
        {
            throw new InvalidAlgorithmParameterException("invalid KEK size: " + kekBits);
        }
    }

    private static Method method(Class<?> c, String name)
        throws NoSuchMethodException
    {
        Method m = c.getMethod(name);
        m.setAccessible(true);
        return m;
    }

    /**
     * Reflectively DER-encode the KDF {@code AlgorithmIdentifier} and extract its
     * structure {@code SEQUENCE { kdfOID, SEQUENCE { digestOID } }}, mapping the
     * digest OID to a JDK {@link MessageDigest} name. Only KDF3 is supported.
     */
    private static String resolveKdfDigest(Object kdfAlgId)
        throws InvalidAlgorithmParameterException
    {
        byte[] der;
        try
        {
            der = (byte[]) kdfAlgId.getClass().getMethod("getEncoded").invoke(kdfAlgId);
        }
        catch (ReflectiveOperationException e)
        {
            throw new InvalidAlgorithmParameterException("unable to read KDF algorithm: " + e.getMessage(), e);
        }

        try
        {
            int[] pos = {0};
            readSequenceHeader(der, pos);          // AlgorithmIdentifier
            String kdfOid = readOid(der, pos);     // KDF OID
            if (!ID_KDF_KDF3.equals(kdfOid))
            {
                throw new InvalidAlgorithmParameterException("unsupported KDF (only X9.44 KDF3 supported): " + kdfOid);
            }
            readSequenceHeader(der, pos);          // digest AlgorithmIdentifier
            String digestOid = readOid(der, pos);
            String name = digestNameForOid(digestOid);
            if (name == null)
            {
                throw new InvalidAlgorithmParameterException("unsupported KDF digest: " + digestOid);
            }
            return name;
        }
        catch (RuntimeException e)
        {
            throw new InvalidAlgorithmParameterException("malformed KDF AlgorithmIdentifier", e);
        }
    }

    private static String digestNameForOid(String oid)
    {
        if ("2.16.840.1.101.3.4.2.1".equals(oid))
        {
            return "SHA-256";
        }
        if ("2.16.840.1.101.3.4.2.2".equals(oid))
        {
            return "SHA-384";
        }
        if ("2.16.840.1.101.3.4.2.3".equals(oid))
        {
            return "SHA-512";
        }
        if ("2.16.840.1.101.3.4.2.4".equals(oid))
        {
            return "SHA-224";
        }
        if ("1.3.14.3.2.26".equals(oid))
        {
            return "SHA-1";
        }
        return null;
    }

    private static int encapsulationLength(OSSLKeyType type)
    {
        switch (type)
        {
        case ML_KEM_512:  return 768;
        case ML_KEM_768:  return 1088;
        case ML_KEM_1024: return 1568;
        default: throw new IllegalStateException("not an ML-KEM key: " + type.getAlgorithmName());
        }
    }

    // --- minimal DER helpers (single-byte tags) ------------------------------

    private static void readSequenceHeader(byte[] data, int[] pos)
    {
        if (pos[0] >= data.length || (data[pos[0]++] & 0xFF) != 0x30)
        {
            throw new IllegalArgumentException("expected SEQUENCE");
        }
        readLength(data, pos);
    }

    private static String readOid(byte[] data, int[] pos)
    {
        if (pos[0] >= data.length || (data[pos[0]++] & 0xFF) != 0x06)
        {
            throw new IllegalArgumentException("expected OBJECT IDENTIFIER");
        }
        int len = readLength(data, pos);
        int off = pos[0];
        if (len <= 0 || off + len > data.length)
        {
            throw new IllegalArgumentException("invalid OID");
        }
        pos[0] += len;
        StringBuilder sb = new StringBuilder();
        long value = 0;
        boolean first = true;
        for (int i = 0; i < len; i++)
        {
            int b = data[off + i] & 0xFF;
            value = (value << 7) | (b & 0x7F);
            if ((b & 0x80) == 0)
            {
                if (first)
                {
                    long arc = value / 40 > 2 ? 2 : value / 40;
                    sb.append(arc).append('.').append(value - arc * 40);
                    first = false;
                }
                else
                {
                    sb.append('.').append(value);
                }
                value = 0;
            }
        }
        return sb.toString();
    }

    private static int readLength(byte[] data, int[] pos)
    {
        if (pos[0] >= data.length)
        {
            throw new IllegalArgumentException("truncated length");
        }
        int b = data[pos[0]++] & 0xFF;
        if ((b & 0x80) == 0)
        {
            return b;
        }
        int count = b & 0x7F;
        if (count == 0 || count > 4)
        {
            throw new IllegalArgumentException("unsupported length");
        }
        int len = 0;
        for (int i = 0; i < count; i++)
        {
            if (pos[0] >= data.length)
            {
                throw new IllegalArgumentException("truncated length");
            }
            len = (len << 8) | (data[pos[0]++] & 0xFF);
        }
        if (len < 0)
        {
            throw new IllegalArgumentException("length out of range");
        }
        return len;
    }

    // --- unused streaming entry points --------------------------------------

    @Override
    protected int engineGetBlockSize()
    {
        return 0;
    }

    @Override
    protected int engineGetOutputSize(int inputLen)
    {
        return inputLen;
    }

    @Override
    protected byte[] engineGetIV()
    {
        return null;
    }

    @Override
    protected java.security.AlgorithmParameters engineGetParameters()
    {
        return null;
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen)
    {
        throw new IllegalStateException("ML-KEM KTS cipher only supports wrap/unwrap");
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
        throws ShortBufferException
    {
        throw new IllegalStateException("ML-KEM KTS cipher only supports wrap/unwrap");
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
    {
        throw new IllegalStateException("ML-KEM KTS cipher only supports wrap/unwrap");
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
        throws ShortBufferException
    {
        throw new IllegalStateException("ML-KEM KTS cipher only supports wrap/unwrap");
    }
}
