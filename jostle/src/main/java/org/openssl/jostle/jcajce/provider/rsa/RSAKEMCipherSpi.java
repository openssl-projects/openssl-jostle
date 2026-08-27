/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.rsa;

import org.openssl.jostle.jcajce.interfaces.OSSLKey;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.rand.DefaultRandSource;
import org.openssl.jostle.rand.RandSource;
import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.asn1.oids.NISTObjectIdentifiers;

import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import java.lang.reflect.Method;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAKey;
import java.security.spec.AlgorithmParameterSpec;

/**
 * RSA-KEM key transport (ISO 18033-2 / RFC 9690), registered as
 * {@code RSA-KTS-KEM-KWS} and under the two OIDs BouncyCastle uses, for the CMS
 * KEMRecipientInfo path:
 * <pre>
 *   Cipher.getInstance("RSA-KTS-KEM-KWS").init(WRAP_MODE, pubKey, KTSParameterSpec); wrap(cek)
 *   Cipher.getInstance("RSA-KTS-KEM-KWS").init(UNWRAP_MODE, privKey, KTSParameterSpec); unwrap(...)
 * </pre>
 *
 * <p>Wrap performs RSASVE encapsulate &rarr; KDF3 &rarr; AES key-wrap and returns
 * {@code encapsulation ‖ wrappedKey}; unwrap is the inverse, splitting at the
 * modulus length. This is the {@link org.openssl.jostle.jcajce.provider.mlkem.MLKEMKTSCipherSpi}
 * shape with three differences, all forced by RSA rather than chosen:
 *
 * <ol>
 *   <li>the KEM operation must be named explicitly - see {@link #KEM_OP};</li>
 *   <li>the encapsulation and the shared secret are both one MODULUS length,
 *       which varies per key, where ML-KEM's are fixed per parameter set;</li>
 *   <li>the key is an ordinary RSA key, so any RSA keypair works - there is no
 *       KEM-specific key type to check.</li>
 * </ol>
 *
 * <p><b>Interoperability with BouncyCastle.</b> BC's {@code RSAKEMCipherSpi}
 * derives its KEK from {@code r} zero-padded to the modulus length; OpenSSL's
 * RSASVE returns exactly that (measured on mainline and both FIPS modules,
 * {@code fips-c-review/probes/rsakem_probe.c}), so the two agree given the same
 * KDF and wrap parameters. The {@code KTSParameterSpec} is read reflectively so
 * this provider keeps no compile-time BouncyCastle dependency.
 */
public class RSAKEMCipherSpi
    extends CipherSpi
{
    /**
     * The OpenSSL KEM operation name, hard-coded. SECURITY/INTEROP-CRITICAL -
     * do not remove this in favour of OpenSSL's default.
     *
     * <p>This is the "hard-code security-critical OpenSSL parameters" rule
     * (native-code.md) in its strongest form: the pin is not defensive against
     * a future default changing, it is REQUIRED TODAY on the CMVP-validated
     * 3.1.2 module. Measured on all four supported environments
     * ({@code fips-c-review/probes/rsakem_probe.c}): mainline and the 3.5.7
     * module default to RSASVE and work without it, while 3.1.2 refuses
     * {@code EVP_PKEY_encapsulate}'s size query outright - and refuses it
     * MUTELY, with an empty error queue. A build tested only against mainline
     * would look correct and fail on the validated module.
     *
     * <p>{@code "RSAKEM"} is not a valid operation name on any of them.
     */
    private static final String KEM_OP = "RSASVE";

    /** X9.44 / NIST concatenation KDF (KDF3) OID - BC's default for KTS. */
    private static final String ID_KDF_KDF3 = "1.3.133.16.840.9.44.1.2";

    /**
     * Upper bound on the requested KEK size, checked at init: {@code kekBits + 7}
     * overflows int near {@code Integer.MAX_VALUE} (a negative byte count would
     * throw NegativeArraySizeException inside the KDF), and an unbounded value
     * would drive an unbounded allocation. Matches MLKEMKTSCipherSpi.
     */
    private static final int MAX_KEK_BITS = 4096;

    // Bound to one interface library. The factory translates a foreign key into
    // THIS provider's lib ctx; specNI is what a Jostle key's own spec is checked
    // against, so a private key from the other provider is rejected rather than
    // driven through the wrong library.
    private final RSAKeyFactorySpi keyFactory;
    private final SpecNI specNI;


    /**
     * The provider this SPI belongs to, sourced from construction. The same
     * class serves JSL and JSLFIPS, so a constant names the wrong one for half
     * its instances - which is exactly what it did: the KDF digest resolved
     * against the JCA provider list (normally SUN) and the AES key wrap was
     * pinned to "JSL", so a JSLFIPS wrap hashed and key-wrapped outside the
     * module with nothing failing. See MT-5.
     */
    private final String providerName;

    public RSAKEMCipherSpi()
    {
        this(new RSAKeyFactorySpi(), NISelector.SpecNI, JostleProvider.PROVIDER_NAME);
    }

    public RSAKEMCipherSpi(RSAKeyFactorySpi keyFactory, SpecNI specNI, String providerName)
    {
        this.keyFactory = keyFactory;
        this.specNI = specNI;
        this.providerName = providerName;
    }

    /**
     * Resolve the KDF digest from THIS SPI's own provider.
     *
     * <p>A bare {@code MessageDigest.getInstance(name)} resolves against the
     * JCA provider list in order - normally SUN - so a JSLFIPS wrap derived
     * its KEK outside the FIPS module. No behavioural test can see that:
     * SHA-256 is SHA-256 whoever computes it, which is why the guard for this
     * is a source-level lint rather than a unit test.
     *
     * <p>Failure is LOUD under both providers. With the name sourced from
     * construction, "my own provider does not serve my digest" is a broken
     * build, and a silent fall-through to another provider is the shape that
     * hid the original defect.
     */
    private static MessageDigest digestFromOwnProvider(String providerName, String name)
            throws NoSuchAlgorithmException
    {
        try
        {
            return MessageDigest.getInstance(name, providerName);
        }
        catch (java.security.NoSuchProviderException e)
        {
            throw new NoSuchAlgorithmException(
                    "provider " + providerName + " is not installed, so the " + name
                            + " KDF digest cannot be computed by it", e);
        }
    }

    private int opmode;
    private PKEYKeySpec keySpec;
    private RandSource randSource;

    /**
     * Modulus length in bytes, captured at init. Both the encapsulation and the
     * shared secret are exactly this long (probe-measured on every supported
     * environment), and both native calls below cross-check what they wrote
     * against it - so a provider that ever disagreed would be caught rather
     * than silently producing a short buffer.
     */
    private int modLen;

    // KTSParameterSpec contents (read reflectively in engineInit).
    private int kekBits;
    private byte[] otherInfo;
    private String digestName;   // null => no KDF, use the shared secret directly

    @Override
    protected void engineSetMode(String mode)
        throws NoSuchAlgorithmException
    {
        // KTS via Cipher.getInstance(name/oid) carries no mode; ignore.
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
        throw new InvalidKeyException("RSA-KTS-KEM-KWS requires a KTSParameterSpec");
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
        throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        if (opmode != Cipher.WRAP_MODE && opmode != Cipher.UNWRAP_MODE)
        {
            throw new InvalidAlgorithmParameterException("RSA-KTS-KEM-KWS only supports WRAP_MODE/UNWRAP_MODE");
        }
        if (!(key instanceof OSSLKey))
        {
            // Foreign RSA key (e.g. from a parsed certificate, which is what the
            // CMS KEMRecipientInfo path hands us) - translate to a JSL key via
            // the KeyFactory; only non-RSA / untranslatable keys are rejected.
            if (key == null)
            {
                throw new InvalidKeyException("not an RSA key: null");
            }
            try
            {
                key = keyFactory.engineTranslateKey(key);
            }
            catch (InvalidKeyException e)
            {
                throw new InvalidKeyException("not an RSA key: " + key.getClass().getName(), e);
            }
        }
        if (opmode == Cipher.WRAP_MODE && !(key instanceof PublicKey))
        {
            throw new InvalidKeyException("WRAP_MODE requires an RSA public key");
        }
        if (opmode == Cipher.UNWRAP_MODE && !(key instanceof PrivateKey))
        {
            throw new InvalidKeyException("UNWRAP_MODE requires an RSA private key");
        }
        if (!(key instanceof RSAKey))
        {
            throw new InvalidKeyException("not an RSA key: " + key.getClass().getName());
        }

        PKEYKeySpec spec = ((OSSLKey) key).getSpec();
        // Provider isolation, private side only: a key is bound to the interface
        // library - and OSSL_LIB_CTX - that created it, so a JSL private key must
        // not be unwrapped through the JSLFIPS NI or vice versa. PUBLIC keys
        // (WRAP_MODE) deliberately cross freely; see java-spi.md
        // "JSL <-> JSLFIPS key sharing".
        // Additive: library check live now, instance check inert until Phase 2
        // (substituting would drop the interim — learned on RSA).
        if (opmode == Cipher.UNWRAP_MODE
                && (spec.getSpecNI() != specNI
                        || !spec.usableBy(keyFactory.ownProviderInstance())))
        {
            throw new InvalidKeyException(
                    "private key was created by a different Jostle provider; encode it with getEncoded() and decode it through this provider's KeyFactory");
        }
        // MT-14, WRAP (public) side: instance-only, no library half. Public
        // keys deliberately cross LIBRARIES; what they must not do is cross
        // provider INSTANCES, because the EVP_PKEY stays with its creating
        // provider and the operation would be served there. Inert until
        // Phase 2 binds.
        if (opmode == Cipher.WRAP_MODE && !spec.usableBy(keyFactory.ownProviderInstance()))
        {
            throw new InvalidKeyException(
                    "public key was created by a different Jostle provider instance; encode it "
                            + "with getEncoded() and decode it through this provider's KeyFactory");
        }
        if (spec.getType() != OSSLKeyType.RSA)
        {
            // An RSASSA-PSS key carries its own type and a parameter-restricted
            // AlgorithmIdentifier; it is not a key-transport key.
            throw new InvalidKeyException("not an RSA key: " + spec.getType().getAlgorithmName());
        }

        java.math.BigInteger modulus = ((RSAKey) key).getModulus();
        if (modulus == null || modulus.signum() <= 0)
        {
            throw new InvalidKeyException("RSA key has no usable modulus");
        }
        int bytes = (modulus.bitLength() + 7) / 8;

        readKtsSpec(params);

        // RSASVE draws the ephemeral value from RAND on the wrap side; the
        // unwrap side binds a source too, because the decap NI is type-agnostic
        // and any RAND consumed inside OpenSSL (blinding, for instance) must
        // resolve to fresh Java entropy rather than a stale thread-local.
        RandSource resolvedRandSource = DefaultRandSource.replaceWith(null, random);

        // Assign state only after all validation has passed, so a rejected init
        // leaves the SPI "not initialised" rather than half-configured.
        this.opmode = opmode;
        this.keySpec = spec;
        this.modLen = bytes;
        this.randSource = resolvedRandSource;
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
        throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        throw new InvalidAlgorithmParameterException("RSA-KTS-KEM-KWS requires a KTSParameterSpec");
    }

    @Override
    protected byte[] engineWrap(Key key)
        throws javax.crypto.IllegalBlockSizeException, InvalidKeyException
    {
        if (opmode != Cipher.WRAP_MODE)
        {
            throw new IllegalStateException("cipher not initialised for wrapping");
        }

        byte[] secret = new byte[modLen];
        byte[] encapsulation = new byte[modLen];

        // synchronized(this) keeps keySpec (a field-held PKEYKeySpec) reachable
        // across the native encapsulate call; nothing after the block touches
        // keySpec. See java-spi.md "Native references must outlive every
        // JNI/FFI call".
        synchronized (this)
        {
            try
            {
                int written = keySpec.getSpecNI().encap(keySpec.getReference(), KEM_OP,
                    secret, 0, secret.length, encapsulation, 0, encapsulation.length, randSource);
                if (written != modLen)
                {
                    throw new InvalidKeyException("unexpected RSA-KEM encapsulation length: " + written);
                }
            }
            catch (OpenSSLException e)
            {
                // A native encapsulation failure surfaces as an unchecked
                // OpenSSLException; the JCE wrap contract requires a typed
                // exception, so map it rather than let it escape.
                throw new InvalidKeyException("RSA-KEM encapsulation failed: " + e.getMessage(), e);
            }
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
                Arrays.clear(kek);
            }
        }
        finally
        {
            Arrays.clear(secret);
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
        if (wrappedKey == null)
        {
            throw new InvalidKeyException("wrapped key is null");
        }
        if (wrappedKey.length < modLen)
        {
            throw new InvalidKeyException("input shorter than RSA-KEM encapsulation");
        }

        byte[] secret = new byte[modLen];
        byte[] wrapped = Arrays.copyOfRange(wrappedKey, modLen, wrappedKey.length);

        // synchronized(this): see the note in engineWrap.
        synchronized (this)
        {
            try
            {
                byte[] encapsulation = Arrays.copyOfRange(wrappedKey, 0, modLen);
                int written = keySpec.getSpecNI().decap(keySpec.getReference(), KEM_OP,
                    encapsulation, 0, encapsulation.length, secret, 0, secret.length, randSource);
                if (written != modLen)
                {
                    throw new InvalidKeyException("unexpected RSA-KEM shared-secret length: " + written);
                }
            }
            catch (OpenSSLException e)
            {
                // The JCE unwrap contract requires InvalidKeyException on all
                // unwrap failures - never BadPaddingException, which would be a
                // Bleichenbacher-style oracle. Map rather than let the unchecked
                // exception escape.
                throw new InvalidKeyException("unable to unwrap key: " + e.getMessage(), e);
            }
        }

        try
        {
            byte[] kek = deriveKek(secret);
            try
            {
                Cipher aesKw = aesKeyWrap(Cipher.UNWRAP_MODE, kek);
                return aesKw.unwrap(wrapped, wrappedKeyAlgorithm, wrappedKeyType);
            }
            catch (InvalidAlgorithmParameterException | NoSuchPaddingException
                | java.security.NoSuchProviderException | OpenSSLException e)
            {
                // An AES-KW integrity failure (tampered encapsulation or wrapped
                // key) surfaces from OpenSSL as an unchecked OpenSSLException;
                // the JCE unwrap contract requires InvalidKeyException.
                throw new InvalidKeyException("unable to unwrap key: " + e.getMessage(), e);
            }
            finally
            {
                Arrays.clear(kek);
            }
        }
        finally
        {
            Arrays.clear(secret);
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
            return kdf3(providerName, digestName, sharedSecret, otherInfo, kekBytes);
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new InvalidKeyException("KDF digest unavailable: " + e.getMessage(), e);
        }
    }

    /**
     * X9.44 KDF3 (NIST concatenation KDF): {@code K = Hash(counter32 ‖ Z ‖ otherInfo)}
     * concatenated over counter = 1, 2, ... until {@code outLen} bytes are produced.
     *
     * <p>Byte-for-byte BouncyCastle's {@code ConcatenationKDFGenerator}, which is
     * what makes the two providers' RSA-KEM interoperate.
     */
    private static byte[] kdf3(String providerName, String digestName, byte[] z, byte[] otherInfo, int outLen)
        throws NoSuchAlgorithmException
    {
        MessageDigest md = digestFromOwnProvider(providerName, digestName);
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
            // block is KEK-derivation material — scrub each iteration.
            Arrays.fill(block, (byte) 0);
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
        case 16: oid = NISTObjectIdentifiers.id_aes128_wrap.getId(); break;   // id-aes128-wrap
        case 24: oid = NISTObjectIdentifiers.id_aes192_wrap.getId(); break;   // id-aes192-wrap
        case 32: oid = NISTObjectIdentifiers.id_aes256_wrap.getId(); break;   // id-aes256-wrap
        default: throw new InvalidKeyException("unsupported AES-KW KEK size: " + kek.length);
        }
        Cipher c = Cipher.getInstance(oid, providerName);
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
        if (kekBits <= 0 || kekBits > MAX_KEK_BITS)
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
     * Resolve the digest name from the spec's KDF AlgorithmIdentifier. Only KDF3
     * is supported, matching the ML-KEM KTS cipher and BC's default; anything
     * else is refused by name so the caller learns what IS supported rather than
     * getting a wrong KEK.
     */
    private static String resolveKdfDigest(Object kdfAlgId)
        throws InvalidAlgorithmParameterException
    {
        try
        {
            Object alg = method(kdfAlgId.getClass(), "getAlgorithm").invoke(kdfAlgId);
            String kdfOid = String.valueOf(alg);
            if (!ID_KDF_KDF3.equals(kdfOid))
            {
                throw new InvalidAlgorithmParameterException(
                        "unsupported KDF " + kdfOid + "; RSA-KTS-KEM-KWS supports KDF3 (" + ID_KDF_KDF3 + ")");
            }
            Object digParams = method(kdfAlgId.getClass(), "getParameters").invoke(kdfAlgId);
            if (digParams == null)
            {
                throw new InvalidAlgorithmParameterException("KDF3 requires a digest AlgorithmIdentifier");
            }
            Object digAlg = method(digParams.getClass(), "getAlgorithm").invoke(digParams);
            return digestNameForOid(String.valueOf(digAlg));
        }
        catch (InvalidAlgorithmParameterException e)
        {
            throw e;
        }
        catch (ReflectiveOperationException e)
        {
            throw new InvalidAlgorithmParameterException("unable to read KDF algorithm: " + e.getMessage(), e);
        }
    }

    private static String digestNameForOid(String oid)
        throws InvalidAlgorithmParameterException
    {
        if (NISTObjectIdentifiers.id_sha256.getId().equals(oid))
        {
            return "SHA-256";
        }
        if (NISTObjectIdentifiers.id_sha384.getId().equals(oid))
        {
            return "SHA-384";
        }
        if (NISTObjectIdentifiers.id_sha512.getId().equals(oid))
        {
            return "SHA-512";
        }
        throw new InvalidAlgorithmParameterException("unsupported KDF digest " + oid
                + "; RSA-KTS-KEM-KWS supports SHA-256, SHA-384 and SHA-512");
    }

    // --- unsupported CipherSpi surface --------------------------------------

    @Override
    protected int engineGetBlockSize()
    {
        return 0;
    }

    @Override
    protected int engineGetOutputSize(int inputLen)
    {
        return -1;
    }

    @Override
    protected byte[] engineGetIV()
    {
        return null;
    }

    @Override
    protected AlgorithmParameters engineGetParameters()
    {
        return null;
    }

    @Override
    protected int engineGetKeySize(Key key)
    {
        if (key instanceof RSAKey)
        {
            return ((RSAKey) key).getModulus().bitLength();
        }
        throw new IllegalArgumentException("not an RSA key");
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen)
    {
        throw new IllegalStateException("not supported in a wrapping mode");
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
        throws ShortBufferException
    {
        throw new IllegalStateException("not supported in a wrapping mode");
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
    {
        throw new IllegalStateException("not supported in a wrapping mode");
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
        throws ShortBufferException
    {
        throw new IllegalStateException("not supported in a wrapping mode");
    }
}
