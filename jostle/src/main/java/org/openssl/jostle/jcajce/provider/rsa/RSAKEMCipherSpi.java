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
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.provider.kts.KtsKdf;
import org.openssl.jostle.jcajce.provider.kts.KtsWrap;
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
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
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
     * ({@code fips-c-review/probes/rsakem_probe.c}): mainline and the 3.5.8
     * module default to RSASVE and work without it, while 3.1.2 refuses
     * {@code EVP_PKEY_encapsulate}'s size query outright - and refuses it
     * MUTELY, with an empty error queue. A build tested only against mainline
     * would look correct and fail on the validated module.
     *
     * <p>{@code "RSAKEM"} is not a valid operation name on any of them.
     */
    private static final String KEM_OP = "RSASVE";


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


    public RSAKEMCipherSpi()
    {
        this(new RSAKeyFactorySpi(), NISelector.SpecNI);
    }

    public RSAKEMCipherSpi(RSAKeyFactorySpi keyFactory, SpecNI specNI)
    {
        this.keyFactory = keyFactory;
        this.specNI = specNI;
    }

    /**
     * The provider INSTANCE this SPI belongs to, and the single identity
     * channel for everything it resolves out of JCA - the KDF digest and the
     * AES key wrap.
     *
     * <p>MT-5 pinned both by NAME, sourced from construction, which fixed the
     * original defect: the digest had resolved against the JCA provider list
     * (normally SUN) and the key wrap was hard-pinned to "JSL", so a JSLFIPS
     * wrap hashed and key-wrapped outside the module with nothing failing.
     *
     * <p>A name is still not identity. {@code removeProvider} +
     * {@code addProvider} swaps which instance a name resolves to, and
     * {@code getInstance(alg, Provider)} never required registration at all -
     * so both leave the inner lookups landing in a DIFFERENT instance from the
     * one this SPI belongs to. That is not only a boundary concern here: the
     * inner AES key wrap performs the WHOLE unwrap, {@code wrappedKeyType}
     * included, so the key it reconstructs is bound to that other instance and
     * this provider then refuses it (MT-14). MT-16 converts the pin to the
     * instance.
     *
     * <p>Read from the key factory rather than carried as a second field: the
     * factory is already bound to the provider that built this SPI, and a
     * separate identity channel could disagree with it.
     *
     * @return the provider instance, or {@code null} when this SPI was
     *         constructed outside any provider.
     */
    private Provider ownProvider()
    {
        return keyFactory.ownProviderInstance();
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
    /** RFC 3394 (KW) or RFC 5649 (KWP), from the spec's key-algorithm name. */
    private KtsWrap.Kind wrapKind = KtsWrap.Kind.KW;
    private byte[] otherInfo;
    private String digestName;   // null => no KDF, use the shared secret directly
    private KtsKdf.Kind kdfKind; // which family digestName belongs to; null with digestName

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
        // Provider isolation, UNWRAP (private) side. Two independent checks,
        // and the library one is not redundant: instance-equal implies
        // library-equal for anything a provider made, but two hand-wired SPIs
        // are both unbound, and only the library check catches a private key
        // crossing between them. See testing.md "JSL <-> JSLFIPS key sharing".
        if (opmode == Cipher.UNWRAP_MODE
                && (spec.getSpecNI() != specNI
                        || !spec.usableBy(keyFactory.ownProviderInstance())))
        {
            throw new InvalidKeyException(
                    "private key was created by a different Jostle provider instance; encode it with getEncoded() and decode it through this provider's KeyFactory");
        }
        // MT-14, WRAP (public) side: instance-only, no library half. The
        // EVP_PKEY stays with its creating provider and the operation is
        // served THERE, so accepting a foreign public key object would
        // encapsulate outside this provider while reporting success. The
        // library half is left off deliberately - it would refuse the unbound
        // direct-SPI case that public keys have no reason to be denied.
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
                catch (NoSuchAlgorithmException | NoSuchPaddingException e)
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

        //
        // Resolve the inner key-wrap Cipher BEFORE the decapsulation. Ordering
        // is load-bearing, not tidiness: resolved afterwards, the exception
        // TYPE would report whether the decapsulation succeeded, because an
        // instance that cannot serve the key wrap answers
        // NoSuchAlgorithmException for a well-formed encapsulation and
        // InvalidKeyException for a malformed one. That is an oracle, and it
        // is the same rule MT-10 applied to the KeyFactory in the ordinary
        // unwrap paths.
        //
        // Only the init needs the KEK, so it stays below; the OID depends on
        // the KEK LENGTH, which is fixed at init.
        //
        final Cipher aesKw;
        try
        {
            aesKw = resolveAesKeyWrap(kekByteLength());
        }
        catch (NoSuchPaddingException e)
        {
            throw new InvalidKeyException("unable to create AES key-wrap cipher: " + e.getMessage(), e);
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
                aesKw.init(Cipher.UNWRAP_MODE, new SecretKeySpec(kek, "AES"));
                return aesKw.unwrap(wrapped, wrappedKeyAlgorithm, wrappedKeyType);
            }
            catch (OpenSSLException e)
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
            return KtsKdf.derive(ownProvider(), kdfKind, digestName, sharedSecret, otherInfo, kekBytes);
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new InvalidKeyException("KDF digest unavailable: " + e.getMessage(), e);
        }
    }

    /**
     * The KEK length in bytes. Fixed at init from the KTSParameterSpec, which
     * is what lets the key-wrap Cipher be resolved before any ciphertext is
     * touched.
     */
    private int kekByteLength()
    {
        return (kekBits + 7) / 8;
    }

    private Cipher aesKeyWrap(int mode, byte[] kek)
        throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException
    {
        Cipher c = resolveAesKeyWrap(kek.length);
        c.init(mode, new SecretKeySpec(kek, "AES"));
        return c;
    }

    /**
     * The key-wrap Cipher for a KEK of {@code kekLen} bytes, resolved from
     * this SPI's own provider INSTANCE but NOT yet keyed.
     *
     * <p>Separate from {@link #aesKeyWrap} so the unwrap path can resolve
     * before it decapsulates; see the note at that call site.
     */
    private Cipher resolveAesKeyWrap(int kekLen)
        throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException
    {
        // id-aesNNN-wrap for KW, id-aesNNN-wrap-pad for KWP.
        String oid = KtsWrap.oidFor(wrapKind, kekLen);
        Provider ownProvider = ownProvider();
        if (ownProvider == null)
        {
            throw new NoSuchAlgorithmException(
                    "this cipher was constructed outside any provider, so the AES key wrap "
                            + oid + " cannot be performed by it; obtain the Cipher from a "
                            + "Jostle provider rather than constructing the SPI directly");
        }
        Cipher c;
        try
        {
            c = Cipher.getInstance(oid, ownProvider);
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new NoSuchAlgorithmException(
                    "provider " + ownProvider.getName() + " does not serve the AES key wrap "
                            + oid + ", so the key cannot be wrapped by it", e);
        }
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
            // The name selects RFC 3394 vs RFC 5649; refused here so an
            // unsupported one cannot reach a key operation.
            String keyAlgorithmName = (String) method(c, "getKeyAlgorithmName").invoke(params);
            KtsWrap.Kind kind = KtsWrap.kindForName(keyAlgorithmName);
            if (kind == null)
            {
                throw new InvalidAlgorithmParameterException(
                        KtsWrap.unsupportedNameMessage(keyAlgorithmName));
            }
            this.wrapKind = kind;
            this.otherInfo = (byte[]) method(c, "getOtherInfo").invoke(params);
            Object kdfAlgId = method(c, "getKdfAlgorithm").invoke(params);
            if (kdfAlgId == null)
            {
                this.kdfKind = null;
                this.digestName = null;
            }
            else
            {
                resolveKdf(kdfAlgId);
            }
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
    private void resolveKdf(Object kdfAlgId)
        throws InvalidAlgorithmParameterException
    {
        try
        {
            Object alg = method(kdfAlgId.getClass(), "getAlgorithm").invoke(kdfAlgId);
            String kdfOid = String.valueOf(alg);
            KtsKdf.Kind kind = KtsKdf.kindForOid(kdfOid);
            if (kind == null)
            {
                throw new InvalidAlgorithmParameterException(KtsKdf.unsupportedKdfMessage(kdfOid));
            }
            // Branch on the OID BEFORE reading parameters: HKDF names its digest
            // in the OID and RFC 8619 requires the parameters be absent, while
            // KDF2/KDF3 carry a digest AlgorithmIdentifier there.
            Object digParams = method(kdfAlgId.getClass(), "getParameters").invoke(kdfAlgId);
            if (KtsKdf.Kind.HKDF == kind)
            {
                if (digParams != null)
                {
                    throw new InvalidAlgorithmParameterException(KtsKdf.hkdfParametersForbiddenMessage());
                }
                this.kdfKind = kind;
                this.digestName = KtsKdf.hkdfDigestForOid(kdfOid);
                return;
            }
            if (digParams == null)
            {
                throw new InvalidAlgorithmParameterException(KtsKdf.digestParameterRequiredMessage());
            }
            Object digAlg = method(digParams.getClass(), "getAlgorithm").invoke(digParams);
            this.kdfKind = kind;
            this.digestName = digestNameForOid(String.valueOf(digAlg));
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
