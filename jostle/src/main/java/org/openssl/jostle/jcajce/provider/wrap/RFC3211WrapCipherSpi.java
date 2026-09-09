package org.openssl.jostle.jcajce.provider.wrap;

import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

/**
 * RFC 3211 password-based key wrap, for CMS PasswordRecipientInfo.
 * <p>
 * Not an SP 800-38F wrap and not reachable through OpenSSL, so this is Java
 * over our own CBC cipher. Registered in JSL only (Megan, 2026-09-09).
 */
public class RFC3211WrapCipherSpi
    extends CipherSpi
{
    /** count(1) + complement of the first three CEK bytes. RFC 3211 2.3.1. */
    private static final int HEADER_LEN = 4;

    private final String baseCipher;
    private final int blockSize;
    private final int[] validKekLengths;
    private final Provider providerInstance;

    private int opmode = -1;
    private byte[] kekBytes;
    private byte[] iv;
    private SecureRandom random;

    public RFC3211WrapCipherSpi(String baseCipher, int blockSize, int[] validKekLengths,
                                Provider providerInstance)
    {
        this.baseCipher = baseCipher;
        this.blockSize = blockSize;
        this.validKekLengths = Arrays.clone(validKekLengths);
        this.providerInstance = providerInstance;
    }

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException
    {
        throw new NoSuchAlgorithmException("can't support mode " + mode);
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException
    {
        throw new NoSuchPaddingException("padding not supported: " + padding);
    }

    @Override
    protected int engineGetBlockSize()
    {
        return blockSize;
    }

    @Override
    protected int engineGetKeySize(Key key)
    {
        byte[] enc = key.getEncoded();
        return enc == null ? 0 : enc.length * 8;
    }

    @Override
    protected int engineGetOutputSize(int inputLen)
    {
        return wrappedLength(inputLen);
    }

    @Override
    protected byte[] engineGetIV()
    {
        return Arrays.clone(iv);
    }

    @Override
    protected AlgorithmParameters engineGetParameters()
    {
        if (iv == null)
        {
            return null;
        }
        try
        {
            AlgorithmParameters p = providerInstance == null
                    ? AlgorithmParameters.getInstance(baseCipher)
                    : AlgorithmParameters.getInstance(baseCipher, providerInstance);
            p.init(new IvParameterSpec(iv));
            return p;
        }
        catch (GeneralSecurityException e)
        {
            return null;
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException
    {
        try
        {
            engineInit(opmode, key, (AlgorithmParameterSpec) null, random);
        }
        catch (InvalidAlgorithmParameterException e)
        {
            // Only reachable for UNWRAP, which needs the sender's IV.
            throw new InvalidKeyException(e.getMessage());
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        if (opmode != Cipher.WRAP_MODE && opmode != Cipher.UNWRAP_MODE)
        {
            throw new java.security.InvalidParameterException(
                    "RFC 3211 key wrap supports WRAP_MODE and UNWRAP_MODE only");
        }
        if (key == null)
        {
            throw new InvalidKeyException("key is null");
        }

        // D3: bcpkix names the KEK after the wrap ("AESRFC3211Wrap"), so the
        // algorithm name is not usable. Take the bytes, check the length here,
        // and give the inner cipher a key named after the base cipher.
        byte[] enc = key.getEncoded();
        if (enc == null)
        {
            throw new InvalidKeyException("key has no encoding");
        }
        if (!isValidKekLength(enc.length))
        {
            throw new InvalidKeyException(baseCipher + " KEK must be "
                    + describeValidLengths() + " bytes, got " + enc.length);
        }

        // The provider's convention: a cached instance from the registrar, never
        // a fresh SecureRandom per operation. Resolved once here and used for
        // both the generated IV and the wrap padding.
        SecureRandom resolved = random != null ? random : CryptoServicesRegistrar.getSecureRandom();

        byte[] newIv;
        if (params == null)
        {
            if (opmode == Cipher.UNWRAP_MODE)
            {
                throw new InvalidAlgorithmParameterException(
                        "an IvParameterSpec is required to unwrap");
            }
            newIv = new byte[blockSize];
            resolved.nextBytes(newIv);
        }
        else if (params instanceof IvParameterSpec)
        {
            newIv = ((IvParameterSpec) params).getIV();
            // Diverges from BouncyCastle, deliberately: BC accepts any length
            // here and raises an unchecked IllegalArgumentException later, at
            // wrap. InvalidAlgorithmParameterException at init is what
            // Cipher.init declares for a parameter the cipher cannot use.
            if (newIv == null || newIv.length != blockSize)
            {
                throw new InvalidAlgorithmParameterException(
                        "IV must be " + blockSize + " bytes for " + baseCipher);
            }
        }
        else
        {
            throw new InvalidAlgorithmParameterException(
                    "expected an IvParameterSpec, got " + params.getClass().getName());
        }

        this.opmode = opmode;
        this.kekBytes = enc;
        this.iv = newIv;
        this.random = resolved;
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        AlgorithmParameterSpec spec = null;
        if (params != null)
        {
            try
            {
                spec = params.getParameterSpec(IvParameterSpec.class);
            }
            catch (java.security.spec.InvalidParameterSpecException e)
            {
                throw new InvalidAlgorithmParameterException("cannot read an IV from " + params);
            }
        }
        engineInit(opmode, key, spec, random);
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen)
    {
        throw new IllegalStateException("RFC 3211 key wrap does not support update");
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws ShortBufferException
    {
        throw new IllegalStateException("RFC 3211 key wrap does not support update");
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
    {
        throw new IllegalStateException("RFC 3211 key wrap supports wrap and unwrap only");
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws ShortBufferException
    {
        throw new IllegalStateException("RFC 3211 key wrap supports wrap and unwrap only");
    }

    @Override
    protected byte[] engineWrap(Key key) throws javax.crypto.IllegalBlockSizeException, InvalidKeyException
    {
        if (opmode != Cipher.WRAP_MODE)
        {
            throw new IllegalStateException("not initialised for wrapping");
        }
        byte[] cek = key.getEncoded();
        if (cek == null)
        {
            throw new InvalidKeyException("key has no encoding");
        }
        if (cek.length < 1 || cek.length > 255)
        {
            // The count is one byte (2.3.1), so it cannot describe more.
            throw new javax.crypto.IllegalBlockSizeException(
                    "CEK must be 1..255 bytes, got " + cek.length);
        }

        byte[] block = new byte[wrappedLength(cek.length)];
        try
        {
            block[0] = (byte) cek.length;
            System.arraycopy(cek, 0, block, HEADER_LEN, cek.length);

            int padOff = HEADER_LEN + cek.length;
            if (padOff < block.length)
            {
                byte[] pad = new byte[block.length - padOff];
                random.nextBytes(pad);
                System.arraycopy(pad, 0, block, padOff, pad.length);
            }

            // The check bytes complement block[4..6] AFTER padding, not the
            // CEK — so for a CEK under three bytes they cover padding. Taking
            // them from the CEK instead round-trips against itself and fails
            // against every other implementation.
            block[1] = (byte) ~block[HEADER_LEN];
            block[2] = (byte) ~block[HEADER_LEN + 1];
            block[3] = (byte) ~block[HEADER_LEN + 2];

            // 2.3.1: encrypt, then encrypt the RESULT again without resetting
            // the IV. One Cipher, so the chaining value carried into the
            // second pass is the last ciphertext block of the first.
            Cipher c = cbc(Cipher.ENCRYPT_MODE, iv);
            byte[] first = c.update(block);
            try
            {
                return c.doFinal(first);
            }
            finally
            {
                Arrays.clear(first);
            }
        }
        catch (GeneralSecurityException e)
        {
            throw new javax.crypto.IllegalBlockSizeException(e.getMessage());
        }
        finally
        {
            Arrays.clear(block);
            Arrays.clear(cek);
        }
    }

    @Override
    protected Key engineUnwrap(byte[] wrappedKey, String wrappedKeyAlgorithm, int wrappedKeyType)
            throws InvalidKeyException
    {
        if (opmode != Cipher.UNWRAP_MODE)
        {
            throw new IllegalStateException("not initialised for unwrapping");
        }
        if (wrappedKey == null)
        {
            throw new InvalidKeyException("wrapped key is null");
        }
        // A structurally impossible length. Reported apart from the two
        // KEK-validity failures below because it leaks nothing: the caller
        // supplied the length and can already see it.
        if (wrappedKey.length < 2 * blockSize || (wrappedKey.length % blockSize) != 0)
        {
            throw new InvalidKeyException("input too short");
        }

        byte[] intermediate = null;
        byte[] plain = null;
        try
        {
            int n = wrappedKey.length;
            // 2.3.2 step 1: the n-1'th ciphertext block is the IV for the n'th.
            byte[] lastIv = new byte[blockSize];
            System.arraycopy(wrappedKey, n - 2 * blockSize, lastIv, 0, blockSize);
            byte[] lastBlock = cbc(Cipher.DECRYPT_MODE, lastIv)
                    .doFinal(wrappedKey, n - blockSize, blockSize);

            // Step 2: the decrypted n'th block is the IV for blocks 1..n-1.
            byte[] head = cbc(Cipher.DECRYPT_MODE, lastBlock)
                    .doFinal(wrappedKey, 0, n - blockSize);

            intermediate = new byte[n];
            System.arraycopy(head, 0, intermediate, 0, head.length);
            System.arraycopy(lastBlock, 0, intermediate, head.length, lastBlock.length);
            Arrays.clear(head);
            Arrays.clear(lastBlock);

            // Step 3: strip the inner layer under the original IV.
            plain = cbc(Cipher.DECRYPT_MODE, iv).doFinal(intermediate);

            int cekLen = plain[0] & 0xff;
            // 2.3.2 1a and 1b are ONE answer: both mean the KEK was invalid,
            // and separating them is an oracle. All three are compared and
            // accumulated before deciding, so the number of matching bytes
            // cannot be timed either.
            int diff = cekLen < 1 || cekLen > plain.length - HEADER_LEN ? 1 : 0;
            for (int i = 0; i < 3; i++)
            {
                diff |= ((~plain[1 + i]) & 0xff) ^ (plain[HEADER_LEN + i] & 0xff);
            }
            if (diff != 0)
            {
                throw new InvalidKeyException("wrapped key corrupted");
            }

            byte[] cek = new byte[cekLen];
            System.arraycopy(plain, HEADER_LEN, cek, 0, cekLen);
            try
            {
                // D4: the caller's algorithm string, untouched. bcpkix passes
                // the content-encryption OID, so this is often an OID.
                return new SecretKeySpec(cek, wrappedKeyAlgorithm);
            }
            finally
            {
                Arrays.clear(cek);
            }
        }
        catch (GeneralSecurityException e)
        {
            throw new InvalidKeyException("wrapped key corrupted");
        }
        finally
        {
            Arrays.clear(intermediate);
            Arrays.clear(plain);
        }
    }

    private Cipher cbc(int mode, byte[] withIv) throws GeneralSecurityException
    {
        Cipher c = providerInstance == null
                ? Cipher.getInstance(baseCipher + "/CBC/NoPadding")
                : Cipher.getInstance(baseCipher + "/CBC/NoPadding", providerInstance);
        c.init(mode, new SecretKeySpec(kekBytes, baseCipher), new IvParameterSpec(withIv));
        return c;
    }

    /** 4-byte header + CEK, up to a multiple of the block and at least two blocks. */
    private int wrappedLength(int cekLen)
    {
        int n = HEADER_LEN + cekLen;
        if ((n % blockSize) != 0)
        {
            n += blockSize - (n % blockSize);
        }
        return Math.max(n, 2 * blockSize);
    }

    private boolean isValidKekLength(int len)
    {
        for (int valid : validKekLengths)
        {
            if (valid == len)
            {
                return true;
            }
        }
        return false;
    }

    private String describeValidLengths()
    {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < validKekLengths.length; i++)
        {
            if (i > 0)
            {
                sb.append(i == validKekLengths.length - 1 ? " or " : ", ");
            }
            sb.append(validKekLengths[i]);
        }
        return sb.toString();
    }

}
