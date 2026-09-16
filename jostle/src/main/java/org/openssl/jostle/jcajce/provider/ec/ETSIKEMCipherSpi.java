/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.ec;

import org.openssl.jostle.jcajce.provider.binding.ProviderBinding;
import org.openssl.jostle.jcajce.provider.kdf.KeyAgreementKDF;
import org.openssl.jostle.jcajce.provider.wrap.UnwrappedKeys;
import org.openssl.jostle.jcajce.spec.IESKEMParameterSpec;
import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.asn1.Der;

import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import org.openssl.jostle.util.asn1.oids.X9ObjectIdentifiers;

/**
 * The IEEE 1609.2 (ITS) integrated-encryption KEM, registered as
 * {@code Cipher.ETSIKEMwithSHA256} — the name BouncyCastle's
 * {@code JceETSIKeyWrapper} and {@code JcaETSIDataDecryptor} resolve by string.
 *
 * <p><b>The claim is interop with BouncyCastle, not conformance with IEEE
 * 1609.2.</b> Every construction detail below was measured from BouncyCastle at
 * tag {@code r1rv86} ({@code IESKEMCipher}, and {@code KEMwithSHA256}'s
 * parameters at :462-468) rather than read from the standard, whose clause
 * 5.3.5.1 is not in the standards library. A later reading of that clause may
 * contradict a choice here; BouncyCastle is the authority until it does.
 *
 * <p>Wrap, in order:
 * <ol>
 *   <li>an ephemeral EC key pair on the recipient's curve;</li>
 *   <li>raw ECDH against the recipient's public key;</li>
 *   <li>{@code KDF2(secret, recipientInfo)} — ISO 18033-2 KDF2, which is the
 *       X9.63 KDF construction, sized {@code keyLen + 32};</li>
 *   <li>the wrapped key XORed with the first {@code keyLen} bytes;</li>
 *   <li>HMAC-SHA-256 over that ciphertext, keyed with the TRAILING 32 bytes and
 *       truncated to 16;</li>
 *   <li>{@code ephemeralPublicKey ‖ enc ‖ mac[0..16]}.</li>
 * </ol>
 *
 * <p>Three places this is easy to get silently wrong, all pinned by tests: the
 * KDF output length depends on the wrapped key's length and the MAC key is the
 * TAIL rather than the head (the two coincide only at a 16-byte key); the MAC
 * covers the ciphertext, not the plaintext; and the truncation to 16 bytes
 * happens after the fact rather than through a MAC-length parameter.
 *
 * <p><b>Cofactor.</b> BouncyCastle agrees with {@code ECDHCRawAgreement} —
 * cofactor ECDH. Jostle exposes plain ECDH only, and the two coincide exactly
 * when the curve's cofactor is 1, which holds for the two curves the ITS
 * wrapper emits ({@code secp256r1} and {@code brainpoolP256r1}). A curve with
 * any other cofactor is REFUSED at init rather than served by an agreement that
 * would silently diverge.
 */
public class ETSIKEMCipherSpi extends CipherSpi
{
    /**
     * BouncyCastle's {@code IESKEMCipher$KEMwithSHA256}: a 32-byte MAC key
     * drawn from the KDF output, and a MAC truncated to 16 bytes.
     */
    private static final int MAC_KEY_LENGTH = 32;
    private static final int MAC_LENGTH = 16;

    /** id-ecPublicKey, the SubjectPublicKeyInfo algorithm for an EC point. */
    private static final String ID_EC_PUBLIC_KEY = X9ObjectIdentifiers.id_ecPublicKey.getId();

    private final ECServiceNI ecServiceNI;
    private final ECKeyFactorySpi keyFactory;
    /** One fact, one field — see {@link ProviderBinding}. */
    private final ProviderBinding binding;
    private final String digest;
    private final String macAlgorithm;

    private int opmode = -1;
    private ECPublicKey wrapKey;
    private ECPrivateKey unwrapKey;
    private ECParameterSpec params;
    private byte[] recipientInfo;
    private boolean usePointCompression;
    private SecureRandom random;

    public ETSIKEMCipherSpi(ECServiceNI ecServiceNI, ECKeyFactorySpi keyFactory,
                            String digest, String macAlgorithm, String providerName)
    {
        this.ecServiceNI = ecServiceNI;
        this.keyFactory = keyFactory;
        this.digest = digest;
        this.macAlgorithm = macAlgorithm;
        this.binding = ProviderBinding.ofName(providerName);
    }

    public ETSIKEMCipherSpi(ECServiceNI ecServiceNI, ECKeyFactorySpi keyFactory,
                            String digest, String macAlgorithm,
                            java.security.Provider providerInstance)
    {
        this.ecServiceNI = ecServiceNI;
        this.keyFactory = keyFactory;
        this.digest = digest;
        this.macAlgorithm = macAlgorithm;
        this.binding = ProviderBinding.of(providerInstance);
    }

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException
    {
        if (mode != null && !mode.isEmpty() && !"NONE".equalsIgnoreCase(mode))
        {
            throw new NoSuchAlgorithmException("ETSI KEM does not support mode " + mode);
        }
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException
    {
        if (padding != null && !padding.isEmpty() && !"NOPADDING".equalsIgnoreCase(padding))
        {
            throw new NoSuchPaddingException("ETSI KEM does not support padding " + padding);
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
            // The spec is mandatory, so the no-spec overload can only fail. The
            // JCE contract for this overload permits InvalidKeyException only.
            throw new InvalidKeyException(e.getMessage(), e);
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        if (params == null)
        {
            engineInit(opmode, key, (AlgorithmParameterSpec) null, random);
            return;
        }
        throw new InvalidAlgorithmParameterException(
                "ETSI KEM takes an IESKEMParameterSpec, which has no AlgorithmParameters encoding");
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec spec, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        if (opmode != Cipher.WRAP_MODE && opmode != Cipher.UNWRAP_MODE)
        {
            throw new InvalidAlgorithmParameterException(
                    "ETSI KEM only supports WRAP_MODE/UNWRAP_MODE");
        }

        byte[] newRecipientInfo = readRecipientInfo(spec);
        boolean newCompression = readPointCompression(spec);

        ECPublicKey newWrapKey = null;
        ECPrivateKey newUnwrapKey = null;
        ECParameterSpec newParams;

        if (opmode == Cipher.WRAP_MODE)
        {
            if (!(key instanceof PublicKey))
            {
                throw new InvalidKeyException("WRAP_MODE requires the recipient's EC public key");
            }
            // Import enforces provider-instance isolation in both halves.
            newWrapKey = ECKeyImport.importPublic(keyFactory, key,
                    "expected an ECPublicKey from the Jostle provider");
            newParams = newWrapKey.getParams();
        }
        else
        {
            if (!(key instanceof PrivateKey))
            {
                throw new InvalidKeyException("UNWRAP_MODE requires the recipient's EC private key");
            }
            newUnwrapKey = ECKeyImport.importPrivate(keyFactory, key,
                    "expected an ECPrivateKey from the Jostle provider");
            newParams = newUnwrapKey.getParams();
        }

        requireCofactorOne(newParams);

        this.opmode = opmode;
        this.wrapKey = newWrapKey;
        this.unwrapKey = newUnwrapKey;
        this.params = newParams;
        this.recipientInfo = newRecipientInfo;
        this.usePointCompression = newCompression;
        this.random = random;
    }

    /**
     * Plain ECDH equals cofactor ECDH only at h = 1, and BouncyCastle's KEM
     * agrees with the cofactor form. Anything else would derive a different
     * secret without failing, so it is refused here.
     */
    private void requireCofactorOne(ECParameterSpec spec) throws InvalidKeyException
    {
        if (spec == null || spec.getCofactor() != 1)
        {
            throw new InvalidKeyException(
                    "ETSI KEM requires a curve of cofactor 1; this key's curve has cofactor "
                            + (spec == null ? "unknown" : Integer.toString(spec.getCofactor()))
                            + ", where Jostle's plain ECDH would diverge from the cofactor "
                            + "agreement BouncyCastle uses");
        }
    }

    /**
     * Accepts Jostle's {@link IESKEMParameterSpec} and null, as
     * {@link KeyAgreementKDF#extractUkm} does for the UKM specs.
     *
     * <p>BouncyCastle casts the spec unchecked and so raises
     * {@code ClassCastException} on a foreign type, and accepts null and fails
     * later. Both breach the {@code engineInit} contract, so this is one of the
     * places JCE-canonical behaviour wins over parity — both halves pinned in
     * {@code ETSIKEMAgreementTest.aForeignOrAbsentSpecIsRefusedTyped}, which
     * measures BouncyCastle's live.
     */
    private static byte[] readRecipientInfo(AlgorithmParameterSpec spec)
            throws InvalidAlgorithmParameterException
    {
        if (spec == null)
        {
            throw new InvalidAlgorithmParameterException(
                    "ETSI KEM requires an IESKEMParameterSpec carrying the recipient info");
        }
        if (spec instanceof IESKEMParameterSpec)
        {
            return ((IESKEMParameterSpec) spec).getRecipientInfo();
        }
        throw new InvalidAlgorithmParameterException(
                "expected an " + IESKEMParameterSpec.class.getName() + ", got " + spec.getClass().getName());
    }

    /**
     * Called only after {@link #readRecipientInfo} has already refused any
     * spec that is neither null nor an {@link IESKEMParameterSpec}, so a
     * non-Jostle spec can never reach here.
     */
    private static boolean readPointCompression(AlgorithmParameterSpec spec)
    {
        if (spec instanceof IESKEMParameterSpec)
        {
            return ((IESKEMParameterSpec) spec).hasUsePointCompression();
        }
        return false;
    }

    @Override
    protected byte[] engineWrap(Key key) throws IllegalBlockSizeException, InvalidKeyException
    {
        if (opmode != Cipher.WRAP_MODE)
        {
            throw new IllegalStateException("cipher not initialised for wrapping");
        }
        byte[] keyBytes = key == null ? null : key.getEncoded();
        if (keyBytes == null)
        {
            throw new InvalidKeyException("cannot wrap key, null encoding");
        }
        byte[] zz = null;
        byte[] kdfOut = null;
        try
        {
            KeyPair ephemeral = generateEphemeral();
            byte[] point = encodePoint((ECPublicKey) ephemeral.getPublic(), usePointCompression);

            zz = agree(ephemeral.getPrivate(), wrapKey);
            kdfOut = kdf(zz, keyBytes.length + MAC_KEY_LENGTH);

            byte[] enc = new byte[keyBytes.length + MAC_LENGTH];
            for (int i = 0; i != keyBytes.length; i++)
            {
                enc[i] = (byte) (keyBytes[i] ^ kdfOut[i]);
            }
            byte[] mac = mac(kdfOut, keyBytes.length, enc, keyBytes.length);
            System.arraycopy(mac, 0, enc, keyBytes.length, MAC_LENGTH);
            Arrays.clear(mac);

            byte[] out = new byte[point.length + enc.length];
            System.arraycopy(point, 0, out, 0, point.length);
            System.arraycopy(enc, 0, out, point.length, enc.length);
            return out;
        }
        catch (InvalidKeyException e)
        {
            throw e;
        }
        catch (GeneralSecurityException e)
        {
            throw new InvalidKeyException("ETSI KEM wrap failed: " + e.getMessage(), e);
        }
        finally
        {
            Arrays.clear(keyBytes);
            Arrays.clear(zz);
            Arrays.clear(kdfOut);
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

        // Resolve the KeyFactory BEFORE any derivation, so an unserved
        // algorithm cannot be distinguished from a failed MAC by exception
        // type — see the engineUnwrap rule in java-spi.md.
        KeyFactory targetFactory = null;
        if (wrappedKeyType == Cipher.PUBLIC_KEY || wrappedKeyType == Cipher.PRIVATE_KEY)
        {
            targetFactory = UnwrappedKeys.keyFactory(
                    keyFactory.ownProviderInstance(), wrappedKeyAlgorithm);
        }

        int fieldBytes = fieldSizeBytes(params);
        // Length-check BEFORE indexing: the point form is read from byte 0, so
        // an empty or short input would otherwise leave the boundary as an
        // ArrayIndexOutOfBoundsException instead of a typed refusal. The
        // smallest conceivable input is a compressed point plus a MAC.
        if (wrappedKey.length < 1 + fieldBytes + MAC_LENGTH)
        {
            throw new InvalidKeyException(
                    "ETSI KEM input is shorter than an ephemeral point plus a MAC");
        }
        int pointLen = wrappedKey[0] == 0x04 ? 1 + 2 * fieldBytes : 1 + fieldBytes;
        int keyLen = wrappedKey.length - (pointLen + MAC_LENGTH);
        if (keyLen < 0)
        {
            // Reachable only for the uncompressed form, whose point is longer
            // than the minimum checked above.
            throw new InvalidKeyException(
                    "ETSI KEM input is shorter than an ephemeral point plus a MAC");
        }

        byte[] zz = null;
        byte[] kdfOut = null;
        byte[] plain = null;
        try
        {
            PublicKey ephemeral = decodePoint(wrappedKey, pointLen);
            zz = agree(unwrapKey, ephemeral);
            kdfOut = kdf(zz, keyLen + MAC_KEY_LENGTH);

            byte[] mac = mac(kdfOut, keyLen, wrappedKey, pointLen, keyLen);
            boolean ok = Arrays.constantTimeAreEqual(
                    MAC_LENGTH, mac, 0, wrappedKey, wrappedKey.length - MAC_LENGTH);
            Arrays.clear(mac);
            if (!ok)
            {
                // BouncyCastle raises BadPaddingException("mac field") here and
                // its BaseCipherSpi.engineUnwrap converts it to
                // InvalidKeyException, so this is both BC's type at the Cipher
                // surface and the type the unwrap rule requires.
                throw new InvalidKeyException("unable to unwrap: mac field");
            }

            plain = new byte[keyLen];
            for (int i = 0; i != keyLen; i++)
            {
                plain[i] = (byte) (wrappedKey[pointLen + i] ^ kdfOut[i]);
            }
            return buildKey(plain, wrappedKeyAlgorithm, wrappedKeyType, targetFactory);
        }
        catch (InvalidKeyException e)
        {
            throw e;
        }
        catch (GeneralSecurityException e)
        {
            throw new InvalidKeyException("ETSI KEM unwrap failed: " + e.getMessage(), e);
        }
        finally
        {
            Arrays.clear(zz);
            Arrays.clear(kdfOut);
            Arrays.clear(plain);
        }
    }

    private Key buildKey(byte[] encoded, String algorithm, int type, KeyFactory targetFactory)
            throws InvalidKeyException
    {
        if (type == Cipher.SECRET_KEY)
        {
            // No native residency and no provider to bind to, so a secret key
            // stays an unbound SecretKeySpec — the line MT-14 drew.
            return new SecretKeySpec(encoded, algorithm);
        }
        try
        {
            if (type == Cipher.PUBLIC_KEY)
            {
                return targetFactory.generatePublic(new X509EncodedKeySpec(encoded));
            }
            if (type == Cipher.PRIVATE_KEY)
            {
                return targetFactory.generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(encoded));
            }
        }
        catch (InvalidKeySpecException e)
        {
            throw new InvalidKeyException("unable to decode the unwrapped key", e);
        }
        throw new InvalidKeyException("unknown wrapped key type " + type);
    }

    /**
     * The ephemeral pair is generated through a directly-constructed
     * {@link ECKeyPairGenerator} carrying the KeyFactory's own NI and provider
     * instance, so the pair binds exactly where the recipient key is checked
     * against — a JCA lookup by name would bind to whatever that name resolves
     * to, which the import check then refuses in the unbound case.
     */
    private KeyPair generateEphemeral() throws InvalidAlgorithmParameterException
    {
        KeyPairGenerator generator = new ECKeyPairGenerator(
                ecServiceNI, keyFactory.ownSpecNI(), keyFactory.ownAsn1Ni(),
                keyFactory.ownProviderInstance());
        if (random != null)
        {
            generator.initialize(params, random);
        }
        else
        {
            generator.initialize(params);
        }
        return generator.generateKeyPair();
    }

    /**
     * Raw ECDH through a directly-constructed {@link ECDHKeyAgreementSpi} on
     * this SPI's own NI, rather than a JCA lookup: the agreement must run on
     * the same interface library the keys were made in, and construction is the
     * only way to say so without relying on a registration.
     */
    private byte[] agree(Key local, Key peer) throws InvalidKeyException
    {
        ECDHKeyAgreementSpi agreement = new ECDHKeyAgreementSpi(ecServiceNI, keyFactory);
        agreement.engineInit(local, random);
        agreement.engineDoPhase(peer, true);
        return agreement.engineGenerateSecret();
    }

    /**
     * ISO 18033-2 KDF2 over the agreed secret with the recipient info as shared
     * info. KDF2 and the ANSI X9.63 KDF are the same recurrence — counter from
     * 1, {@code H(Z ‖ counter ‖ sharedInfo)} — so {@code x963} serves both;
     * BouncyCastle reaches it as {@code KDF2BytesGenerator}.
     */
    private byte[] kdf(byte[] zz, int outLen) throws NoSuchAlgorithmException
    {
        return KeyAgreementKDF.x963(binding.instance(), binding.name(), digest, zz, outLen, recipientInfo);
    }

    private byte[] mac(byte[] kdfOut, int macKeyOff, byte[] data, int dataLen)
            throws GeneralSecurityException
    {
        return mac(kdfOut, macKeyOff, data, 0, dataLen);
    }

    /** HMAC over {@code data}, keyed with the KDF output's TRAILING bytes. */
    private byte[] mac(byte[] kdfOut, int macKeyOff, byte[] data, int dataOff, int dataLen)
            throws GeneralSecurityException
    {
        byte[] macKey = Arrays.copyOfRange(kdfOut, macKeyOff, kdfOut.length);
        try
        {
            Mac hmac = binding.instance() != null
                    ? Mac.getInstance(macAlgorithm, binding.instance())
                    : Mac.getInstance(macAlgorithm, binding.name());
            hmac.init(new SecretKeySpec(macKey, macAlgorithm));
            hmac.update(data, dataOff, dataLen);
            return hmac.doFinal();
        }
        finally
        {
            Arrays.clear(macKey);
        }
    }

    /**
     * Rebuild the ephemeral public key by assembling a SubjectPublicKeyInfo
     * around the raw point and decoding it through this provider's KeyFactory,
     * so OpenSSL performs any point decompression — there is no EC arithmetic
     * on the Java side.
     */
    private PublicKey decodePoint(byte[] wrapped, int pointLen) throws InvalidKeyException
    {
        String curveName = ECComponents.findCurveName(ecServiceNI, params);
        String curveOid = curveName == null ? null : ECComponents.curveOid(ecServiceNI, curveName);
        if (curveOid == null)
        {
            throw new InvalidKeyException(
                    "ETSI KEM requires a named curve with an OID; this key's curve has none");
        }
        byte[] point = Arrays.copyOfRange(wrapped, 0, pointLen);
        byte[] bitString = new byte[point.length + 1];
        System.arraycopy(point, 0, bitString, 1, point.length);

        byte[] spki = Der.sequence(
                Der.sequence(Der.objectIdentifier(ID_EC_PUBLIC_KEY), Der.objectIdentifier(curveOid)),
                Der.tlv(0x03, bitString));
        try
        {
            return (PublicKey) keyFactory.engineGeneratePublic(new X509EncodedKeySpec(spki));
        }
        catch (InvalidKeySpecException e)
        {
            throw new InvalidKeyException("ETSI KEM: unusable ephemeral public point", e);
        }
    }

    private static int fieldSizeBytes(ECParameterSpec spec)
    {
        return (spec.getCurve().getField().getFieldSize() + 7) / 8;
    }

    private static byte[] encodePoint(ECPublicKey key, boolean compressed)
    {
        ECPoint w = key.getW();
        int fieldBytes = fieldSizeBytes(key.getParams());
        byte[] x = unsignedFixed(w.getAffineX(), fieldBytes);
        if (compressed)
        {
            byte[] out = new byte[1 + fieldBytes];
            out[0] = (byte) (w.getAffineY().testBit(0) ? 0x03 : 0x02);
            System.arraycopy(x, 0, out, 1, fieldBytes);
            return out;
        }
        byte[] y = unsignedFixed(w.getAffineY(), fieldBytes);
        byte[] out = new byte[1 + 2 * fieldBytes];
        out[0] = 0x04;
        System.arraycopy(x, 0, out, 1, fieldBytes);
        System.arraycopy(y, 0, out, 1 + fieldBytes, fieldBytes);
        return out;
    }

    /** Big-endian unsigned magnitude, left-padded to exactly {@code len}. */
    private static byte[] unsignedFixed(BigInteger v, int len)
    {
        byte[] raw = v.toByteArray();
        byte[] out = new byte[len];
        if (raw.length <= len)
        {
            System.arraycopy(raw, 0, out, len - raw.length, raw.length);
        }
        else
        {
            // toByteArray() prefixes a sign octet when the top bit is set.
            System.arraycopy(raw, raw.length - len, out, 0, len);
        }
        return out;
    }

    @Override
    protected int engineGetBlockSize()
    {
        return 0;
    }

    @Override
    protected int engineGetKeySize(Key key) throws InvalidKeyException
    {
        if (!(key instanceof java.security.interfaces.ECKey))
        {
            throw new InvalidKeyException("not an EC key: " + key.getClass().getName());
        }
        return ((java.security.interfaces.ECKey) key).getParams().getOrder().bitLength();
    }

    @Override
    protected int engineGetOutputSize(int inputLen)
    {
        if (params == null)
        {
            return 0;
        }
        int fieldBytes = fieldSizeBytes(params);
        int pointLen = usePointCompression ? 1 + fieldBytes : 1 + 2 * fieldBytes;
        return pointLen + inputLen + MAC_LENGTH;
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
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen)
    {
        throw new IllegalStateException("not supported in a wrapping mode");
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
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
