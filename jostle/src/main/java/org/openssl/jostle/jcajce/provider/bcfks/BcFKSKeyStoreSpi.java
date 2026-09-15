/*
 *
 *   Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *   Licensed under the Apache License 2.0 (the "License"). You may not use
 *   this file except in compliance with the License.  You can obtain a copy
 *   in the file LICENSE in the source distribution or at
 *   https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */
package org.openssl.jostle.jcajce.provider.bcfks;

import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.provider.kdf.BytePasswordKdf;
import org.openssl.jostle.jcajce.provider.kdf.KdfNI;
import org.openssl.jostle.jcajce.provider.kdf.MemoryHardKdfNI;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.Properties;
import org.openssl.jostle.util.asn1.ASN1Encoder;
import org.openssl.jostle.util.asn1.Asn1Ni;
import org.openssl.jostle.util.asn1.Der;
import org.openssl.jostle.util.asn1.oids.MiscObjectIdentifiers;
import org.openssl.jostle.util.asn1.oids.NISTObjectIdentifiers;
import org.openssl.jostle.util.asn1.oids.OIWObjectIdentifiers;
import org.openssl.jostle.util.asn1.oids.PKCSObjectIdentifiers;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.NoSuchElementException;

/**
 * BCFKS keystore, read and write: a standalone Jostle implementation of the
 * file format BouncyCastle defines (r1rv86,
 * {@code prov/.../keystore/bcfks/BcFKSKeyStoreSpi.java}), over {@link
 * BcFKSFormat} and this provider's own registered services. No BouncyCastle
 * type appears anywhere in this class; interop with BC is file-level only.
 *
 * <p><b>Per-entry passwords.</b> {@code engineGetKey(alias, password)}
 * derives the entry's decryption key with THAT password under {@code
 * PRIVATE_KEY_ENCRYPTION} / {@code SECRET_KEY_ENCRYPTION}; only {@code
 * engineLoad}'s store-wide MAC check and (when the store is encrypted) the
 * store decrypt use the password passed to {@code load} under {@code
 * INTEGRITY_CHECK} / {@code STORE_ENCRYPTION}. A real BCFKS file's entries
 * commonly carry passwords different from the store password (measured:
 * BCFKSStoreTest's kwpKeyStore fixture), so entries are kept as raw, encrypted
 * {@link BcFKSFormat.ObjectData} until the caller asks for one by name and
 * password -- never decoded at load time.
 *
 * <p><b>Write defaults.</b> Every write derives with PBKDF2-HMAC-SHA512, a
 * fresh 64-byte salt, and {@link #storeIterationCount()} iterations (BC's own
 * defaults). Entry and store data both encrypt under AES-256-CCM with a
 * 128-bit (16-octet) tag -- BC's own writer, given no explicit parameters,
 * takes whatever its underlying Cipher defaults to and every BC-written
 * fixture in this tree carries a 64-bit (8-octet) tag instead; both lengths
 * load in both implementations, and 16 octets is the stronger of the two, so
 * that is what this class writes. The store's integrity MAC is HMAC-SHA512
 * with a 64-byte key. {@code engineStore} always writes the store encrypted
 * -- BCFKS has no plaintext-store writer path, matching BC.
 */
public class BcFKSKeyStoreSpi
    extends KeyStoreSpi
{
    private final Provider providerInstance;
    private final KdfNI kdfNI;
    private final MemoryHardKdfNI memoryHardKdfNI;
    private final Asn1Ni asn1NI;
    private final SpecNI specNI;

    private final Map<String, BcFKSFormat.ObjectData> entries = new LinkedHashMap<String, BcFKSFormat.ObjectData>();
    private Date creationDate;
    private Date lastModifiedDate;

    /** Base-provider convenience constructor: base NIs throughout, scrypt served. */
    public BcFKSKeyStoreSpi(Provider providerInstance)
    {
        this(providerInstance, NISelector.KdfNI, NISelector.MemoryHardKdfNI, NISelector.Asn1NI, NISelector.SpecNI);
    }

    /**
     * Every SPI takes its NI by constructor: this class serves both
     * providers, so a hard-coded {@code NISelector.X} read would weld it to
     * the base interface library. {@code ProvFIPSBCFKS} passes the FIPS
     * bindings. {@code memoryHardKdfNI} is {@code null} under FIPS -- the
     * module has no scrypt -- which gives a typed refusal before any
     * derivation runs (see {@link #deriveKey}) rather than reaching into the
     * base library.
     */
    public BcFKSKeyStoreSpi(Provider providerInstance, KdfNI kdfNI, MemoryHardKdfNI memoryHardKdfNI,
                             Asn1Ni asn1NI, SpecNI specNI)
    {
        this.providerInstance = providerInstance;
        this.kdfNI = kdfNI;
        this.memoryHardKdfNI = memoryHardKdfNI;
        this.asn1NI = asn1NI;
        this.specNI = specNI;
    }

    // ---- Caps, measured against BcFKSKeyStoreSpi.java (r1rv86) -------------
    // validateIterationCount :977-991, validateScryptParams :924-947,
    // validateKeyLength :959-975. Every cap is enforced BEFORE the (CPU/memory
    // intensive) derivation runs, on an input that has not yet been
    // MAC-verified.

    private static final int MAX_SCRYPT_BLOCK_SIZE = 1024;
    private static final int MAX_KEY_LENGTH = 1024;

    static final String MAX_IT_COUNT_PROPERTY = "org.openssl.jostle.bcfks.max_it_count";
    static final long DEFAULT_MAX_IT_COUNT = 5_000_000L;
    static final String MAX_SCRYPT_MEMORY_PROPERTY = "org.openssl.jostle.bcfks.max_scrypt_memory";
    static final long DEFAULT_MAX_SCRYPT_MEMORY = 1L << 30;

    private static long maxIterationCount()
    {
        try
        {
            long configured = Properties.asInteger(MAX_IT_COUNT_PROPERTY, (int) DEFAULT_MAX_IT_COUNT);
            return configured < 1 ? DEFAULT_MAX_IT_COUNT : configured;
        }
        catch (NumberFormatException e)
        {
            // Fail-open toward the default rather than refusing every load on
            // an operator typo, same trade-off as Der.usableOr.
            return DEFAULT_MAX_IT_COUNT;
        }
    }

    private static long maxScryptMemory()
    {
        // Properties.asInteger only carries an int; 1 GiB fits, and a
        // property override up to Integer.MAX_VALUE (~2 GiB) is enough range
        // for this bound.
        try
        {
            long configured = Properties.asInteger(MAX_SCRYPT_MEMORY_PROPERTY, (int) DEFAULT_MAX_SCRYPT_MEMORY);
            return configured < 1 ? DEFAULT_MAX_SCRYPT_MEMORY : configured;
        }
        catch (NumberFormatException e)
        {
            return DEFAULT_MAX_SCRYPT_MEMORY;
        }
    }

    // ---- Write-side caps and defaults, measured against BcFKSKeyStoreSpi.java
    // (r1rv86 :116, :1669-1687). BC's own default PBKDF2 iteration count for
    // everything it writes (the MAC key, the store-encryption key, every entry
    // key) -- 50 * 1024 = 51,200 -- clamped, like the read-side cap, against a
    // property rather than left fixed.

    static final String STORE_IT_COUNT_PROPERTY = "org.openssl.jostle.bcfks.store_it_count";
    static final int DEFAULT_STORE_IT_COUNT = 50 * 1024;

    private static final int PBKDF2_SALT_BYTES = 64;
    private static final int ENTRY_KEY_BYTES = 32;
    private static final int MAC_KEY_BYTES = 64;
    private static final int CCM_NONCE_BYTES = 12;
    // 16-octet tag; BC's own writer emits 8 by default (measured from its
    // fixtures), either loads in both implementations.
    private static final int CCM_ICV_BYTES = 16;

    /**
     * The iteration count to write with -- {@link #DEFAULT_STORE_IT_COUNT}
     * unless {@link #STORE_IT_COUNT_PROPERTY} names a usable value, clamped to
     * {@code 1..}{@link #maxIterationCount()} so an operator cannot configure
     * a store that its own read-side cap then refuses to open.
     */
    static int storeIterationCount()
    {
        try
        {
            int configured = Properties.asInteger(STORE_IT_COUNT_PROPERTY, DEFAULT_STORE_IT_COUNT);
            if (configured < 1 || configured > maxIterationCount())
            {
                return DEFAULT_STORE_IT_COUNT;
            }
            return configured;
        }
        catch (NumberFormatException e)
        {
            return DEFAULT_STORE_IT_COUNT;
        }
    }

    private static int validateIterationCount(int iterationCount) throws IOException
    {
        if (iterationCount < 0)
        {
            throw new IOException("BCFKS KeyStore: invalid iteration count");
        }
        long max = maxIterationCount();
        if (iterationCount > max)
        {
            throw new IOException("BCFKS KeyStore: iteration count (" + iterationCount + ") greater than " + max);
        }
        return iterationCount;
    }

    private static int validateKeyLength(int keyLength) throws IOException
    {
        if (keyLength <= 0)
        {
            throw new IOException("BCFKS KeyStore: invalid keyLength");
        }
        if (keyLength > MAX_KEY_LENGTH)
        {
            throw new IOException("BCFKS KeyStore: keyLength (" + keyLength + ") greater than " + MAX_KEY_LENGTH);
        }
        return keyLength;
    }

    private static void validateScryptParams(long costParameter, int blockSize, int parallelizationParameter)
        throws IOException
    {
        if (costParameter <= 0 || blockSize <= 0 || parallelizationParameter <= 0)
        {
            throw new IOException("BCFKS KeyStore: invalid scrypt parameters");
        }
        if (blockSize > MAX_SCRYPT_BLOCK_SIZE)
        {
            throw new IOException("BCFKS KeyStore: scrypt block size (" + blockSize
                    + ") greater than " + MAX_SCRYPT_BLOCK_SIZE);
        }
        long maxMemory = maxScryptMemory();
        if (costParameter > maxMemory / (128L * blockSize))
        {
            throw new IOException("BCFKS KeyStore: scrypt cost parameters require more than "
                    + maxMemory + " bytes");
        }
    }

    // ---- Key derivation ------------------------------------------------

    /**
     * BCFKS scrypt derivations use a parallelization parameter equal to the
     * block size; the encoded {@code parallelizationParameter} is read and
     * bounded but the block size governs derivation.
     */
    byte[] deriveKey(Der.AlgorithmIdentifier pbkdAlgorithm, String purpose, char[] password,
                      Integer defaultKeyLength)
        throws IOException
    {
        byte[] derivationPassword = BytePasswordKdf.derivationPassword(password, purpose);
        try
        {
            if (MiscObjectIdentifiers.id_scrypt.getId().equals(pbkdAlgorithm.oid))
            {
                if (memoryHardKdfNI == null)
                {
                    throw new IOException("BCFKS store uses scrypt, which this provider does not serve");
                }
                Der.ScryptParams params = new Der.Reader(pbkdAlgorithm.parameters).readScryptParams("scrypt-params");
                int parallelizationParameter = params.parallelizationParameter;
                validateScryptParams(params.costParameter, params.blockSize, parallelizationParameter);
                int keyLength = params.keyLength != null
                        ? validateKeyLength(params.keyLength.intValue())
                        : requireDefault(defaultKeyLength, "scrypt-params");
                if (params.costParameter > Integer.MAX_VALUE)
                {
                    throw new IOException("BCFKS KeyStore: scrypt cost parameter out of range");
                }
                byte[] out = new byte[keyLength];
                BytePasswordKdf.scrypt(memoryHardKdfNI, derivationPassword, params.salt,
                        (int) params.costParameter, params.blockSize, params.blockSize, out, 0, out.length);
                return out;
            }
            if (PKCSObjectIdentifiers.id_PBKDF2.getId().equals(pbkdAlgorithm.oid))
            {
                Der.Pbkdf2Params params = new Der.Reader(pbkdAlgorithm.parameters).readPbkdf2Params("PBKDF2-params");
                int iterationCount = validateIterationCount(params.iterationCount);
                int keyLength = params.keyLength != null
                        ? validateKeyLength(params.keyLength.intValue())
                        : requireDefault(defaultKeyLength, "PBKDF2-params");
                String prfOid = params.prf != null ? params.prf.oid : PKCSObjectIdentifiers.id_hmacWithSHA1.getId();
                String digest = digestForHmacOid(prfOid);
                byte[] out = new byte[keyLength];
                BytePasswordKdf.pbkdf2(kdfNI, derivationPassword, params.salt, iterationCount,
                        digest, out, 0, out.length);
                return out;
            }
            throw new IOException("BCFKS KeyStore: unrecognized MAC PBKD: " + pbkdAlgorithm.oid);
        }
        finally
        {
            Arrays.clear(derivationPassword);
        }
    }

    private static int requireDefault(Integer defaultKeyLength, String what) throws IOException
    {
        if (defaultKeyLength == null)
        {
            throw new IOException("BCFKS KeyStore: no keyLength found in " + what);
        }
        return defaultKeyLength.intValue();
    }

    /** PRF / MAC HMAC OIDs this reader recognises, to our own digest-name convention. */
    private static String digestForHmacOid(String oid) throws IOException
    {
        if (PKCSObjectIdentifiers.id_hmacWithSHA1.getId().equals(oid))
        {
            return "SHA-1";
        }
        if (PKCSObjectIdentifiers.id_hmacWithSHA224.getId().equals(oid))
        {
            return "SHA2-224";
        }
        if (PKCSObjectIdentifiers.id_hmacWithSHA256.getId().equals(oid))
        {
            return "SHA2-256";
        }
        if (PKCSObjectIdentifiers.id_hmacWithSHA384.getId().equals(oid))
        {
            return "SHA2-384";
        }
        if (PKCSObjectIdentifiers.id_hmacWithSHA512.getId().equals(oid))
        {
            return "SHA2-512";
        }
        if (PKCSObjectIdentifiers.id_hmacWithSHA512_224.getId().equals(oid))
        {
            return "SHA2-512/224";
        }
        if (PKCSObjectIdentifiers.id_hmacWithSHA512_256.getId().equals(oid))
        {
            return "SHA2-512/256";
        }
        if (NISTObjectIdentifiers.id_hmacWithSHA3_224.getId().equals(oid))
        {
            return "SHA3-224";
        }
        if (NISTObjectIdentifiers.id_hmacWithSHA3_256.getId().equals(oid))
        {
            return "SHA3-256";
        }
        if (NISTObjectIdentifiers.id_hmacWithSHA3_384.getId().equals(oid))
        {
            return "SHA3-384";
        }
        if (NISTObjectIdentifiers.id_hmacWithSHA3_512.getId().equals(oid))
        {
            return "SHA3-512";
        }
        throw new IOException("BCFKS KeyStore: unrecognized MAC PBKD PRF: " + oid);
    }

    // ---- MAC verification ------------------------------------------------

    private byte[] computeMac(Der.AlgorithmIdentifier macAlgorithm, byte[] key, byte[] content) throws IOException
    {
        requireProvider("verify the store's MAC");
        try
        {
            Mac mac = Mac.getInstance(macAlgorithm.oid, providerInstance);
            mac.init(new SecretKeySpec(key, macAlgorithm.oid));
            return mac.doFinal(content);
        }
        catch (NoSuchAlgorithmException | InvalidKeyException e)
        {
            throw new IOException("BCFKS KeyStore: cannot set up MAC calculation: " + e.getMessage(), e);
        }
    }

    /**
     * Every service this class resolves goes through its OWN provider
     * instance, never JCA search order (the no-foreign-provider-delegation
     * rule) -- an unbound instance (direct construction) refuses typed rather
     * than silently falling through to whichever provider the registry
     * resolves first, normally SUN.
     */
    private void requireProvider(String what) throws IOException
    {
        if (providerInstance == null)
        {
            throw new IOException("this keystore was constructed outside any provider, so it cannot "
                    + what + "; obtain the KeyStore from a Jostle provider rather than constructing "
                    + "the SPI directly");
        }
    }

    // ---- Decryption (PBES2: PBKDF2/scrypt + AES-CCM/AES-256-KWP) -----------

    private byte[] decrypt(Der.AlgorithmIdentifier encryptionAlgorithm, String purpose, char[] password,
                            byte[] ciphertext)
        throws IOException
    {
        if (!PKCSObjectIdentifiers.id_PBES2.getId().equals(encryptionAlgorithm.oid))
        {
            throw new IOException("BCFKS KeyStore: unrecognized encryption algorithm: " + encryptionAlgorithm.oid);
        }
        Der.Pbes2Params pbes2 = new Der.Reader(encryptionAlgorithm.parameters).readPbes2Params("PBES2-params");
        // 32: BC's own default (decryptData :1554) when the PBES2 KDF params
        // omit keyLength. The MAC derivation keeps null -- BC passes -1 there,
        // no default, the wire keyLength is required.
        byte[] key = deriveKey(pbes2.keyDerivationFunc, purpose, password, 32);
        try
        {
            String encOid = pbes2.encryptionScheme.oid;
            requireProvider("decrypt an entry");
            Cipher cipher = Cipher.getInstance(encOid, providerInstance);
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            if (NISTObjectIdentifiers.id_aes256_CCM.getId().equals(encOid))
            {
                Der.CcmParameters ccm = new Der.Reader(pbes2.encryptionScheme.parameters)
                        .readCcmParameters("CCMParameters");
                cipher.init(Cipher.DECRYPT_MODE, keySpec, new GCMParameterSpec(ccm.icvBytes * 8, ccm.nonce));
            }
            else if (NISTObjectIdentifiers.id_aes256_wrap_pad.getId().equals(encOid))
            {
                cipher.init(Cipher.DECRYPT_MODE, keySpec);
            }
            else
            {
                throw new IOException("BCFKS KeyStore: unrecognized encryption scheme: " + encOid);
            }
            return cipher.doFinal(ciphertext);
        }
        catch (NoSuchAlgorithmException | InvalidKeyException | InvalidAlgorithmParameterException
                | javax.crypto.NoSuchPaddingException | javax.crypto.IllegalBlockSizeException
                | javax.crypto.BadPaddingException e)
        {
            throw new IOException("BCFKS KeyStore: unable to decrypt: " + e.getMessage(), e);
        }
        finally
        {
            Arrays.clear(key);
        }
    }

    // ---- Encryption (PBES2: PBKDF2-HMAC-SHA512 + AES-256-CCM) --------------

    /**
     * This provider's own {@code SecureRandom} service, resolved through the
     * owning provider instance -- the no-foreign-provider-delegation rule
     * applies to randomness the same as it does to Cipher/Mac/KeyFactory.
     */
    private SecureRandom secureRandom() throws NoSuchAlgorithmException
    {
        return SecureRandom.getInstance("DEFAULT", providerInstance);
    }

    /**
     * A fresh PBKDF2-HMAC-SHA512 {@code AlgorithmIdentifier}: a random
     * {@value #PBKDF2_SALT_BYTES}-byte salt from this provider's own
     * SecureRandom, {@link #storeIterationCount()} iterations, and an
     * explicit {@code keyLength}. Built by encoding the TLV and reading it
     * straight back through {@link Der.Reader#readAlgorithmIdentifier} -- the
     * structure {@link #deriveKey} derives from is then byte-identical to
     * what gets embedded in the file, by construction rather than by
     * agreement between two separate encodings.
     */
    private Der.AlgorithmIdentifier freshPbkdf2AlgorithmIdentifier(int keyLength)
        throws NoSuchAlgorithmException, IOException
    {
        byte[] salt = new byte[PBKDF2_SALT_BYTES];
        secureRandom().nextBytes(salt);
        byte[] prfTlv = Der.algorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA512.getId(), Der.nullValue());
        byte[] paramsTlv = Der.pbkdf2Params(salt, storeIterationCount(), keyLength, prfTlv);
        byte[] fullTlv = Der.algorithmIdentifier(PKCSObjectIdentifiers.id_PBKDF2.getId(), paramsTlv);
        return new Der.Reader(fullTlv).readAlgorithmIdentifier("PBKDF2-params");
    }

    /**
     * Encrypts {@code plaintext} under a fresh PBES2/PBKDF2-HMAC-SHA512/AES-256-CCM
     * key, and returns the complete {@code SEQUENCE { AlgorithmIdentifier,
     * OCTET STRING }} wrapper -- the shape shared by {@code
     * EncryptedObjectStoreData}, {@code EncryptedPrivateKeyInfo} and {@code
     * EncryptedSecretKeyData}, so this one method serves all three write
     * sites. {@code purpose} is one of {@code BytePasswordKdf.PURPOSE_*}.
     *
     * <p>Package-visible so a test can build a valid, standalone type-3/4
     * (PROTECTED_PRIVATE_KEY / PROTECTED_SECRET_KEY) entry payload the same
     * way this class does, for driving BC's own byte[]-form {@code
     * setKeyEntry} -- matching {@link #deriveKey}'s precedent.
     */
    byte[] encryptEntry(byte[] plaintext, String purpose, char[] password)
        throws GeneralSecurityException, IOException
    {
        Der.AlgorithmIdentifier pbkdf2AlgId = freshPbkdf2AlgorithmIdentifier(ENTRY_KEY_BYTES);
        byte[] key = deriveKey(pbkdf2AlgId, purpose, password, ENTRY_KEY_BYTES);
        try
        {
            byte[] nonce = new byte[CCM_NONCE_BYTES];
            secureRandom().nextBytes(nonce);

            requireProvider("encrypt an entry");
            Cipher cipher = Cipher.getInstance(NISTObjectIdentifiers.id_aes256_CCM.getId(), providerInstance);
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(CCM_ICV_BYTES * 8, nonce));
            byte[] ciphertext = cipher.doFinal(plaintext);

            byte[] pbkdf2FullTlv = Der.algorithmIdentifier(pbkdf2AlgId.oid, pbkdf2AlgId.parameters);
            byte[] ccmAlgIdTlv = Der.algorithmIdentifier(NISTObjectIdentifiers.id_aes256_CCM.getId(),
                    Der.ccmParameters(nonce, CCM_ICV_BYTES));
            byte[] pbes2ParamsTlv = Der.pbes2Params(pbkdf2FullTlv, ccmAlgIdTlv);
            byte[] pbes2AlgIdTlv = Der.algorithmIdentifier(PKCSObjectIdentifiers.id_PBES2.getId(), pbes2ParamsTlv);
            return Der.encryptedPrivateKeyInfo(pbes2AlgIdTlv, ciphertext);
        }
        finally
        {
            Arrays.clear(key);
        }
    }

    // ---- Secret-key algorithm OID vocabulary --------------------------------
    // BC's own write side (BcFKSKeyStoreSpi.java :124-156) uses an equivalent
    // hand-written table: JCA has no generic "name a symmetric algorithm from
    // its raw OID" mechanism the way KeyFactory OID aliases give us for
    // asymmetric keys. Scoped to what the read-path fixtures here actually
    // carry (AES, DESede) plus HMAC/KMAC, whose OIDs are already in the oids
    // package; Camellia/SEED/ARIA are not exercised by any fixture in this
    // tree and are left for whoever adds one.

    static String secretKeyAlgorithmName(String oid) throws IOException
    {
        if (NISTObjectIdentifiers.aes.getId().equals(oid))
        {
            return "AES";
        }
        if (OIWObjectIdentifiers.desEDE.getId().equals(oid))
        {
            return "DESede";
        }
        if (NISTObjectIdentifiers.id_Kmac128.getId().equals(oid))
        {
            return "KMAC128";
        }
        if (NISTObjectIdentifiers.id_Kmac256.getId().equals(oid))
        {
            return "KMAC256";
        }
        String hmacName = hmacSecretKeyName(oid);
        if (hmacName != null)
        {
            return hmacName;
        }
        throw new IOException("BCFKS KeyStore: unrecognized secret key algorithm: " + oid);
    }

    /**
     * The JCA {@code SecretKeySpec} algorithm name for an HMAC key OID, or
     * {@code null} if not one of the HMAC OIDs this reader recognises.
     * Written out explicitly, not derived from {@link #digestForHmacOid}'s
     * digest-name spelling: JCA keeps the hyphen for the SHA3 family
     * ("HmacSHA3-224") and a derived transform stripped it.
     */
    private static String hmacSecretKeyName(String oid)
    {
        if (PKCSObjectIdentifiers.id_hmacWithSHA1.getId().equals(oid))
        {
            return "HmacSHA1";
        }
        if (PKCSObjectIdentifiers.id_hmacWithSHA224.getId().equals(oid))
        {
            return "HmacSHA224";
        }
        if (PKCSObjectIdentifiers.id_hmacWithSHA256.getId().equals(oid))
        {
            return "HmacSHA256";
        }
        if (PKCSObjectIdentifiers.id_hmacWithSHA384.getId().equals(oid))
        {
            return "HmacSHA384";
        }
        if (PKCSObjectIdentifiers.id_hmacWithSHA512.getId().equals(oid))
        {
            return "HmacSHA512";
        }
        if (PKCSObjectIdentifiers.id_hmacWithSHA512_224.getId().equals(oid))
        {
            return "HmacSHA512/224";
        }
        if (PKCSObjectIdentifiers.id_hmacWithSHA512_256.getId().equals(oid))
        {
            return "HmacSHA512/256";
        }
        if (NISTObjectIdentifiers.id_hmacWithSHA3_224.getId().equals(oid))
        {
            return "HmacSHA3-224";
        }
        if (NISTObjectIdentifiers.id_hmacWithSHA3_256.getId().equals(oid))
        {
            return "HmacSHA3-256";
        }
        if (NISTObjectIdentifiers.id_hmacWithSHA3_384.getId().equals(oid))
        {
            return "HmacSHA3-384";
        }
        if (NISTObjectIdentifiers.id_hmacWithSHA3_512.getId().equals(oid))
        {
            return "HmacSHA3-512";
        }
        return null;
    }

    /**
     * Inverse of {@link #secretKeyAlgorithmName}: the wire OID for a JCA
     * secret key algorithm name, measured against BC's own {@code oidMap}
     * (BcFKSKeyStoreSpi.java, r1rv86 :124-156) restricted to the same 15
     * names {@link #secretKeyAlgorithmName} recognises on read.
     */
    static String secretKeyAlgorithmOid(String jcaAlgorithm) throws KeyStoreException
    {
        String upper = jcaAlgorithm.toUpperCase(Locale.ROOT);
        if (upper.contains("AES"))
        {
            return NISTObjectIdentifiers.aes.getId();
        }
        if ("DESEDE".equals(upper) || "TRIPLEDES".equals(upper) || "TDEA".equals(upper))
        {
            return OIWObjectIdentifiers.desEDE.getId();
        }
        if ("KMAC128".equals(upper))
        {
            return NISTObjectIdentifiers.id_Kmac128.getId();
        }
        if ("KMAC256".equals(upper))
        {
            return NISTObjectIdentifiers.id_Kmac256.getId();
        }
        String hmacOid = hmacOidForName(upper);
        if (hmacOid != null)
        {
            return hmacOid;
        }
        throw new KeyStoreException("BCFKS KeyStore: unrecognized secret key algorithm for storage: " + jcaAlgorithm);
    }

    private static String hmacOidForName(String upper)
    {
        if ("HMACSHA1".equals(upper))
        {
            return PKCSObjectIdentifiers.id_hmacWithSHA1.getId();
        }
        if ("HMACSHA224".equals(upper))
        {
            return PKCSObjectIdentifiers.id_hmacWithSHA224.getId();
        }
        if ("HMACSHA256".equals(upper))
        {
            return PKCSObjectIdentifiers.id_hmacWithSHA256.getId();
        }
        if ("HMACSHA384".equals(upper))
        {
            return PKCSObjectIdentifiers.id_hmacWithSHA384.getId();
        }
        if ("HMACSHA512".equals(upper))
        {
            return PKCSObjectIdentifiers.id_hmacWithSHA512.getId();
        }
        if ("HMACSHA512/224".equals(upper))
        {
            return PKCSObjectIdentifiers.id_hmacWithSHA512_224.getId();
        }
        if ("HMACSHA512/256".equals(upper))
        {
            return PKCSObjectIdentifiers.id_hmacWithSHA512_256.getId();
        }
        if ("HMACSHA3-224".equals(upper))
        {
            return NISTObjectIdentifiers.id_hmacWithSHA3_224.getId();
        }
        if ("HMACSHA3-256".equals(upper))
        {
            return NISTObjectIdentifiers.id_hmacWithSHA3_256.getId();
        }
        if ("HMACSHA3-384".equals(upper))
        {
            return NISTObjectIdentifiers.id_hmacWithSHA3_384.getId();
        }
        if ("HMACSHA3-512".equals(upper))
        {
            return NISTObjectIdentifiers.id_hmacWithSHA3_512.getId();
        }
        return null;
    }

    // ---- engineLoad ------------------------------------------------------

    @Override
    public void engineLoad(InputStream stream, char[] password)
        throws IOException, NoSuchAlgorithmException, CertificateException
    {
        entries.clear();
        creationDate = null;
        lastModifiedDate = null;

        if (stream == null)
        {
            creationDate = lastModifiedDate = new Date();
            return;
        }

        byte[] whole = BcFKSFormat.readWholeStore(stream);

        BcFKSFormat.ObjectStore store;
        BcFKSFormat.ObjectStoreData storeData;
        try
        {
            store = BcFKSFormat.parseObjectStore(whole);

            if (store.integrityCheck.pbkdMac == null)
            {
                throw new IOException("BCFKS signature integrity checks are not implemented");
            }
            BcFKSFormat.PbkdMac pbkdMac = store.integrityCheck.pbkdMac;
            byte[] macKey = deriveKey(pbkdMac.pbkdAlgorithm, BytePasswordKdf.PURPOSE_INTEGRITY_CHECK,
                    password, null);
            byte[] actualMac;
            try
            {
                actualMac = computeMac(pbkdMac.macAlgorithm, macKey, store.storeDataRaw);
            }
            finally
            {
                Arrays.clear(macKey);
            }
            if (!MessageDigest.isEqual(actualMac, pbkdMac.mac))
            {
                throw new IOException("BCFKS KeyStore corrupted: MAC calculation failed");
            }

            byte[] storeDataBytes;
            if (store.encrypted)
            {
                BcFKSFormat.EncryptedObjectStoreData enc =
                        BcFKSFormat.parseEncryptedObjectStoreData(store.storeDataRaw);
                storeDataBytes = decrypt(enc.encryptionAlgorithm, BytePasswordKdf.PURPOSE_STORE_ENCRYPTION,
                        password, enc.encryptedContent);
            }
            else
            {
                storeDataBytes = store.storeDataRaw;
            }

            storeData = BcFKSFormat.parseObjectStoreData(storeDataBytes);
        }
        catch (IOException e)
        {
            // Failed load resets to empty, matching BcFKSKeyStoreSpi's own
            // contract (checkInvalidLoadForPassword, r1rv86).
            entries.clear();
            creationDate = lastModifiedDate = null;
            throw e;
        }

        creationDate = storeData.creationDate;
        lastModifiedDate = storeData.lastModifiedDate;
        for (BcFKSFormat.ObjectData entry : storeData.entries)
        {
            entries.put(entry.identifier, entry);
        }
    }

    // ---- Entry decode ------------------------------------------------------

    private PrivateKey decodePrivateKey(byte[] pkcs8) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        PKEYKeySpec spec = ASN1Encoder.fromPrivateKeyInfo(asn1NI, specNI, pkcs8, 0, pkcs8.length);
        String algorithm = keyFactoryAlgorithm(spec.getType());
        if (providerInstance == null)
        {
            throw new NoSuchAlgorithmException("this keystore was constructed outside any provider, so "
                    + "it cannot rebuild a private key; obtain the KeyStore from a Jostle provider "
                    + "rather than constructing the SPI directly");
        }
        // Provider-instance overload: it cannot throw NoSuchProviderException
        // (that is only the provider-NAME overload's contract).
        KeyFactory kf = KeyFactory.getInstance(algorithm, providerInstance);
        return kf.generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
    }

    private static String keyFactoryAlgorithm(OSSLKeyType type)
    {
        switch (type)
        {
        case Ed25519ctx:
        case Ed25519ph:
            return "ED25519";
        case ED448ph:
            return "ED448";
        default:
            return type.getTypeName();
        }
    }

    private Certificate decodeCertificate(byte[] der) throws CertificateException
    {
        if (providerInstance == null)
        {
            throw new CertificateException("this keystore was constructed outside any provider, so it "
                    + "cannot rebuild a certificate; obtain the KeyStore from a Jostle provider rather "
                    + "than constructing the SPI directly");
        }
        CertificateFactory cf = CertificateFactory.getInstance("X.509", providerInstance);
        return cf.generateCertificate(new ByteArrayInputStream(der));
    }

    /** Decrypts and decodes a PRIVATE_KEY entry, returning the key and its certificate chain. */
    private Object[] decodePrivateKeyEntry(BcFKSFormat.ObjectData entry, char[] password) throws Exception
    {
        BcFKSFormat.EncryptedPrivateKeyData encData = BcFKSFormat.parseEncryptedPrivateKeyData(entry.data);
        byte[] pkcs8 = decrypt(encData.encryptedPrivateKeyInfo.encryptionAlgorithm,
                BytePasswordKdf.PURPOSE_PRIVATE_KEY_ENCRYPTION, password, encData.encryptedPrivateKeyInfo.encryptedData);
        PrivateKey key;
        try
        {
            key = decodePrivateKey(pkcs8);
        }
        finally
        {
            Arrays.clear(pkcs8);
        }
        Certificate[] chain = new Certificate[encData.certificateChain.length];
        for (int i = 0; i < chain.length; i++)
        {
            chain[i] = decodeCertificate(encData.certificateChain[i]);
        }
        return new Object[]{key, chain};
    }

    private javax.crypto.SecretKey decodeSecretKeyEntry(BcFKSFormat.ObjectData entry, char[] password)
        throws Exception
    {
        Der.EncryptedPrivateKeyInfo encData = BcFKSFormat.parseEncryptedSecretKeyData(entry.data);
        byte[] secretKeyDataBytes = decrypt(encData.encryptionAlgorithm,
                BytePasswordKdf.PURPOSE_SECRET_KEY_ENCRYPTION, password, encData.encryptedData);
        try
        {
            BcFKSFormat.SecretKeyData keyData = BcFKSFormat.parseSecretKeyData(secretKeyDataBytes);
            String algorithm = secretKeyAlgorithmName(keyData.keyAlgorithmOid);
            return new SecretKeySpec(keyData.keyBytes, algorithm);
        }
        finally
        {
            Arrays.clear(secretKeyDataBytes);
        }
    }

    // ---- Entry-type classification ------------------------------------------
    // BC treats PROTECTED_PRIVATE_KEY (3) exactly as PRIVATE_KEY (1) and
    // PROTECTED_SECRET_KEY (4) exactly as SECRET_KEY (2) in engineGetKey,
    // engineGetCertificateChain and engineIsKeyEntry (measured: the same
    // EncryptedPrivateKeyData / EncryptedSecretKeyData decode either way) --
    // "PROTECTED" names who chose the encryption parameters, not a different
    // wire shape.

    static boolean isPrivateKeyEntryType(int type)
    {
        return type == BcFKSFormat.ObjectData.TYPE_PRIVATE_KEY
                || type == BcFKSFormat.ObjectData.TYPE_PROTECTED_PRIVATE_KEY;
    }

    static boolean isSecretKeyEntryType(int type)
    {
        return type == BcFKSFormat.ObjectData.TYPE_SECRET_KEY
                || type == BcFKSFormat.ObjectData.TYPE_PROTECTED_SECRET_KEY;
    }

    // ---- KeyStoreSpi surface -----------------------------------------------

    @Override
    public Key engineGetKey(String alias, char[] password) throws NoSuchAlgorithmException, UnrecoverableKeyException
    {
        BcFKSFormat.ObjectData entry = entries.get(alias);
        if (entry == null)
        {
            return null;
        }
        if (entry.type == BcFKSFormat.ObjectData.TYPE_CERTIFICATE)
        {
            // JCA contract: getKey on a certificate entry answers null. BC
            // throws UnrecoverableKeyException here instead -- a recorded
            // divergence, not replicated.
            return null;
        }
        if (!isPrivateKeyEntryType(entry.type) && !isSecretKeyEntryType(entry.type))
        {
            // Type 5 (PBKDF_KEY) is not implemented yet; anything else is
            // unrecognised. BC's own type and wording for both cases.
            throw new UnrecoverableKeyException(
                    "BCFKS KeyStore unable to recover key (" + alias + "): type not recognized");
        }
        try
        {
            if (isPrivateKeyEntryType(entry.type))
            {
                Object[] result = decodePrivateKeyEntry(entry, password);
                return (PrivateKey) result[0];
            }
            return decodeSecretKeyEntry(entry, password);
        }
        catch (Exception e)
        {
            UnrecoverableKeyException uke = new UnrecoverableKeyException(
                    "BCFKS KeyStore unable to recover key (" + alias + "): " + e.getMessage());
            uke.initCause(e);
            throw uke;
        }
    }

    @Override
    public Certificate[] engineGetCertificateChain(String alias)
    {
        BcFKSFormat.ObjectData entry = entries.get(alias);
        if (entry == null || !isPrivateKeyEntryType(entry.type))
        {
            return null;
        }
        try
        {
            BcFKSFormat.EncryptedPrivateKeyData encData = BcFKSFormat.parseEncryptedPrivateKeyData(entry.data);
            Certificate[] chain =
                    new Certificate[encData.certificateChain.length];
            for (int i = 0; i < chain.length; i++)
            {
                chain[i] = decodeCertificate(encData.certificateChain[i]);
            }
            return chain;
        }
        catch (Exception e)
        {
            return null;
        }
    }

    @Override
    public Certificate engineGetCertificate(String alias)
    {
        BcFKSFormat.ObjectData entry = entries.get(alias);
        if (entry == null || entry.type != BcFKSFormat.ObjectData.TYPE_CERTIFICATE)
        {
            return null;
        }
        try
        {
            return decodeCertificate(entry.data);
        }
        catch (CertificateException e)
        {
            return null;
        }
    }

    @Override
    public Date engineGetCreationDate(String alias)
    {
        // BC returns the ENTRY's lastModifiedDate here, not the store's
        // creation date (BcFKSKeyStoreSpi.engineGetCreationDate, r1rv86: "we
        // return last modified as it represents date current state of entry
        // was created").
        BcFKSFormat.ObjectData entry = entries.get(alias);
        return entry != null ? entry.lastModifiedDate : null;
    }

    /** The existing entry's own creation date, or {@code fallback} for a fresh alias. */
    private Date existingCreationDate(String alias, Date fallback)
    {
        BcFKSFormat.ObjectData existing = entries.get(alias);
        return existing != null ? existing.creationDate : fallback;
    }

    private static byte[][] encodeCertificateChain(Certificate[] chain) throws CertificateEncodingException
    {
        byte[][] tlvs = new byte[chain.length][];
        for (int i = 0; i < chain.length; i++)
        {
            tlvs[i] = chain[i].getEncoded();
        }
        return tlvs;
    }

    @Override
    public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain)
        throws KeyStoreException
    {
        if (providerInstance == null)
        {
            throw new KeyStoreException("this keystore was constructed outside any provider, so it cannot "
                    + "store a key; obtain the KeyStore from a Jostle provider rather than constructing "
                    + "the SPI directly");
        }

        Date now = new Date();
        Date created = existingCreationDate(alias, now);

        if (key instanceof PrivateKey)
        {
            if (chain == null)
            {
                throw new KeyStoreException("BCFKS KeyStore requires a certificate chain for private key storage.");
            }
            byte[] encodedKey = key.getEncoded();
            try
            {
                byte[] encryptedInfoTlv = encryptEntry(encodedKey, BytePasswordKdf.PURPOSE_PRIVATE_KEY_ENCRYPTION,
                        password);
                byte[][] certTlvs = encodeCertificateChain(chain);
                byte[] data = BcFKSFormat.writeEncryptedPrivateKeyData(encryptedInfoTlv, certTlvs);
                entries.put(alias, new BcFKSFormat.ObjectData(BcFKSFormat.ObjectData.TYPE_PRIVATE_KEY, alias,
                        created, now, data, null));
            }
            catch (Exception e)
            {
                throw new KeyStoreException("BCFKS KeyStore exception storing private key: " + e.getMessage(), e);
            }
            finally
            {
                Arrays.clear(encodedKey);
            }
        }
        else if (key instanceof SecretKey)
        {
            if (chain != null)
            {
                throw new KeyStoreException("BCFKS KeyStore cannot store certificate chain with secret key.");
            }
            byte[] encodedKey = key.getEncoded();
            try
            {
                String oid = secretKeyAlgorithmOid(key.getAlgorithm());
                byte[] secretKeyDataBytes = BcFKSFormat.writeSecretKeyData(oid, encodedKey);
                byte[] data = encryptEntry(secretKeyDataBytes, BytePasswordKdf.PURPOSE_SECRET_KEY_ENCRYPTION,
                        password);
                entries.put(alias, new BcFKSFormat.ObjectData(BcFKSFormat.ObjectData.TYPE_SECRET_KEY, alias,
                        created, now, data, null));
            }
            catch (KeyStoreException e)
            {
                throw e;
            }
            catch (Exception e)
            {
                throw new KeyStoreException("BCFKS KeyStore exception storing secret key: " + e.getMessage(), e);
            }
            finally
            {
                Arrays.clear(encodedKey);
            }
        }
        else
        {
            throw new KeyStoreException("BCFKS KeyStore unable to recognize key.");
        }

        lastModifiedDate = now;
    }

    /**
     * The caller supplies already-encrypted bytes. With a chain, they must be
     * a well-formed {@code EncryptedPrivateKeyInfo} -- validated, then stored
     * VERBATIM as type 3 (PROTECTED_PRIVATE_KEY), never re-derived. Without
     * one, the bytes are opaque and stored as type 4 (PROTECTED_SECRET_KEY)
     * exactly as given, matching BC's own {@code engineSetKeyEntry(byte[])}.
     */
    @Override
    public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain)
        throws KeyStoreException
    {
        Date now = new Date();
        Date created = existingCreationDate(alias, now);

        if (chain != null)
        {
            try
            {
                new Der.Reader(key).readEncryptedPrivateKeyInfo("EncryptedPrivateKeyInfo");
            }
            catch (IOException e)
            {
                throw new KeyStoreException(
                        "BCFKS KeyStore private key encoding must be an EncryptedPrivateKeyInfo: "
                                + e.getMessage(), e);
            }
            try
            {
                byte[][] certTlvs = encodeCertificateChain(chain);
                byte[] data = BcFKSFormat.writeEncryptedPrivateKeyData(key, certTlvs);
                entries.put(alias, new BcFKSFormat.ObjectData(BcFKSFormat.ObjectData.TYPE_PROTECTED_PRIVATE_KEY,
                        alias, created, now, data, null));
            }
            catch (CertificateEncodingException e)
            {
                throw new KeyStoreException(
                        "BCFKS KeyStore exception storing protected private key: " + e.getMessage(), e);
            }
        }
        else
        {
            // Opaque and stored verbatim (matching BC), but as our OWN copy
            // -- a caller mutating its buffer afterwards must not change the
            // entry.
            entries.put(alias, new BcFKSFormat.ObjectData(BcFKSFormat.ObjectData.TYPE_PROTECTED_SECRET_KEY,
                    alias, created, now, Arrays.clone(key), null));
        }

        lastModifiedDate = now;
    }

    @Override
    public void engineSetCertificateEntry(String alias, Certificate cert)
        throws KeyStoreException
    {
        BcFKSFormat.ObjectData entry = entries.get(alias);
        Date now = new Date();
        Date created = now;

        if (entry != null)
        {
            if (entry.type != BcFKSFormat.ObjectData.TYPE_CERTIFICATE)
            {
                throw new KeyStoreException("BCFKS KeyStore already has a key entry with alias " + alias);
            }
            created = entry.creationDate;
        }

        try
        {
            entries.put(alias, new BcFKSFormat.ObjectData(BcFKSFormat.ObjectData.TYPE_CERTIFICATE, alias,
                    created, now, cert.getEncoded(), null));
        }
        catch (CertificateEncodingException e)
        {
            throw new KeyStoreException("BCFKS KeyStore unable to handle certificate: " + e.getMessage(), e);
        }

        lastModifiedDate = now;
    }

    @Override
    public void engineDeleteEntry(String alias) throws KeyStoreException
    {
        if (entries.remove(alias) != null)
        {
            lastModifiedDate = new Date();
        }
    }

    @Override
    public Enumeration<String> engineAliases()
    {
        final java.util.Iterator<String> it = new ArrayList<String>(entries.keySet()).iterator();
        return new Enumeration<String>()
        {
            @Override
            public boolean hasMoreElements()
            {
                return it.hasNext();
            }

            @Override
            public String nextElement()
            {
                if (!it.hasNext())
                {
                    throw new NoSuchElementException();
                }
                return it.next();
            }
        };
    }

    @Override
    public boolean engineContainsAlias(String alias)
    {
        return entries.containsKey(alias);
    }

    @Override
    public int engineSize()
    {
        return entries.size();
    }

    @Override
    public boolean engineIsKeyEntry(String alias)
    {
        BcFKSFormat.ObjectData entry = entries.get(alias);
        return entry != null && (isPrivateKeyEntryType(entry.type) || isSecretKeyEntryType(entry.type));
    }

    @Override
    public boolean engineIsCertificateEntry(String alias)
    {
        BcFKSFormat.ObjectData entry = entries.get(alias);
        return entry != null && entry.type == BcFKSFormat.ObjectData.TYPE_CERTIFICATE;
    }

    @Override
    public String engineGetCertificateAlias(Certificate cert)
    {
        try
        {
            byte[] encoded = cert.getEncoded();
            for (Map.Entry<String, BcFKSFormat.ObjectData> e : entries.entrySet())
            {
                if (e.getValue().type == BcFKSFormat.ObjectData.TYPE_CERTIFICATE
                        && Arrays.areEqual(encoded, e.getValue().data))
                {
                    return e.getKey();
                }
            }
        }
        catch (CertificateException ignored)
        {
            // Falls through to null, matching every other provider's contract
            // for an encoding failure at this entry point.
        }
        return null;
    }

    /**
     * Always writes the store encrypted, matching BC -- BCFKS has no
     * plaintext-store writer path. The whole-store PBES2/AES-256-CCM
     * encryption and the integrity MAC each get their own fresh salt.
     */
    @Override
    public void engineStore(OutputStream stream, char[] password)
        throws IOException, NoSuchAlgorithmException, CertificateException
    {
        if (creationDate == null)
        {
            throw new IOException("KeyStore not initialized");
        }
        if (providerInstance == null)
        {
            throw new IOException("this keystore was constructed outside any provider, so it cannot "
                    + "store; obtain the KeyStore from a Jostle provider rather than constructing the "
                    + "SPI directly");
        }

        byte[][] entryTlvs = new byte[entries.size()][];
        int i = 0;
        for (BcFKSFormat.ObjectData entry : entries.values())
        {
            entryTlvs[i++] = BcFKSFormat.writeObjectData(entry.type, entry.identifier, entry.creationDate,
                    entry.lastModifiedDate, entry.data, entry.comment);
        }

        byte[] hmacAlgorithmTlv = Der.algorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA512.getId(),
                Der.nullValue());
        Der.AlgorithmIdentifier hmacAlgorithmId = new Der.Reader(hmacAlgorithmTlv).readAlgorithmIdentifier("macAlgorithm");
        byte[] storeDataDer = BcFKSFormat.writeObjectStoreData(hmacAlgorithmTlv, creationDate, lastModifiedDate,
                entryTlvs, null);

        byte[] encryptedStoreDataTlv;
        try
        {
            encryptedStoreDataTlv = encryptEntry(storeDataDer, BytePasswordKdf.PURPOSE_STORE_ENCRYPTION, password);
        }
        catch (GeneralSecurityException e)
        {
            throw new IOException("BCFKS KeyStore: unable to encrypt store: " + e.getMessage(), e);
        }

        Der.AlgorithmIdentifier macPbkdAlgId = freshPbkdf2AlgorithmIdentifier(MAC_KEY_BYTES);
        byte[] macKey = deriveKey(macPbkdAlgId, BytePasswordKdf.PURPOSE_INTEGRITY_CHECK, password, MAC_KEY_BYTES);
        byte[] mac;
        try
        {
            mac = computeMac(hmacAlgorithmId, macKey, encryptedStoreDataTlv);
        }
        finally
        {
            Arrays.clear(macKey);
        }

        byte[] macPbkdFullTlv = Der.algorithmIdentifier(macPbkdAlgId.oid, macPbkdAlgId.parameters);
        byte[] integrityCheckTlv = BcFKSFormat.writePbkdMacIntegrityCheck(hmacAlgorithmTlv, macPbkdFullTlv, mac);

        stream.write(BcFKSFormat.writeObjectStore(encryptedStoreDataTlv, integrityCheckTlv));
        stream.flush();
    }
}
