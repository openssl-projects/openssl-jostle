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

package org.openssl.jostle.jcajce.provider.xec;

import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.asn1.ASN1Encoder;
import org.openssl.jostle.util.asn1.Asn1Ni;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.math.BigInteger;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPrivateKeySpec;
import java.security.spec.XECPublicKeySpec;
import org.openssl.jostle.util.asn1.Der;

/**
 * KeyFactorySpi for X25519 / X448. Supports the encoded key-spec forms:
 * <ol>
 *   <li>{@link X509EncodedKeySpec} for public keys — decoded via the
 *       generic {@link ASN1Encoder} (OpenSSL auto-detects the X25519 / X448
 *       type from the SubjectPublicKeyInfo algorithm OID);</li>
 *   <li>{@link PKCS8EncodedKeySpec} for private keys — same path.</li>
 * </ol>
 *
 * <p><b>Java 11+ override.</b> Adds the raw-component spec forms
 * {@link XECPublicKeySpec} and {@link XECPrivateKeySpec}, which exist from
 * Java 11 and which the baseline therefore cannot reference. Before this,
 * jostle's X25519/X448 keys could not be built from the JDK's own specs at all
 * while BouncyCastle accepted them, so the gap was one-sided and ours.
 *
 * <p>The specs carry a coordinate and a scalar, not RFC 8410 encodings, so this
 * override builds the encoding and delegates to the existing decode path. No
 * new native entry point is involved: RFC 8410 sections 4 and 7 give these keys
 * a fixed layout with no algorithm parameters, so the encoding can be
 * constructed with {@link Der} directly.
 */
public class XECKeyFactorySpi extends KeyFactorySpi
{
    // Instance fields, not NISelector statics (NISelector for JSL,
    // FIPSNISelector for JSLFIPS).
    private final SpecNI specNI;
    private final Asn1Ni asn1NI;


    /**
     * The provider INSTANCE this SPI belongs to, or null when constructed
     * outside any provider. MT-14; see {@code PKEYKeySpec.usableBy}.
     */
    private final java.security.Provider providerInstance;

    public XECKeyFactorySpi()
    {
        this(NISelector.SpecNI, NISelector.Asn1NI);
    }

    public XECKeyFactorySpi(SpecNI specNI, Asn1Ni asn1NI)
    {
        this(specNI, asn1NI, null);
    }

    public XECKeyFactorySpi(SpecNI specNI, Asn1Ni asn1NI, java.security.Provider providerInstance)
    {
        this.providerInstance = providerInstance;
        this.specNI = specNI;
        this.asn1NI = asn1NI;
    }

    /**
     * The NI backend this factory allocates keys in - used by the import
     * helpers to reject keys created by the other Jostle provider.
     */
    java.security.Provider ownProviderInstance()
    {
        return providerInstance;
    }

    SpecNI ownSpecNI()
    {
        return specNI;
    }

    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException
    {
        if (keySpec instanceof XECPublicKeySpec)
        {
            XECPublicKeySpec jdk = (XECPublicKeySpec) keySpec;
            OSSLKeyType type = xecType(jdk.getParams());
            BigInteger u = jdk.getU();
            if (u == null)
            {
                throw new InvalidKeySpecException("XECPublicKeySpec has no u-coordinate");
            }
            // Non-canonical u is REDUCED, not refused. RFC 7748 section 5:
            // "Implementations MUST accept non-canonical values and process
            // them as if they had been reduced modulo the field prime."
            byte[] raw = XECMontgomery.uToLittleEndian(type, u);
            // RFC 8410 section 4: the raw key IS the BIT STRING content, with
            // no algorithm parameters. The leading 0x00 is the unused-bits
            // octet a BIT STRING requires.
            byte[] spki = Der.sequence(
                    Der.sequence(Der.objectIdentifier(curveOid(type))),
                    Der.tlv(0x03, prepend((byte) 0x00, raw)));
            return engineGeneratePublic(new X509EncodedKeySpec(spki));
        }
        if (keySpec instanceof X509EncodedKeySpec)
        {
            byte[] encoded = ((X509EncodedKeySpec) keySpec).getEncoded();
            try
            {
                PKEYKeySpec spec = ASN1Encoder.fromSubjectPublicKeyInfo(asn1NI, specNI, encoded, 0, encoded.length, providerInstance);
                requireXEC(spec);
                return new JOXECPublicKey(asn1NI, spec);
            }
            catch (RuntimeException e)
            {
                // Malformed encoding surfaces from the decoder as OpenSSLException
                // / IllegalArgumentException; the KeyFactory contract requires
                // InvalidKeySpecException (RSAKeyFactorySpi precedent).
                throw new InvalidKeySpecException("unable to decode XDH public key", e);
            }
        }
        throw new InvalidKeySpecException(
                "unsupported key spec: " + keySpec + ". Use X509EncodedKeySpec.");
    }

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException
    {
        if (keySpec instanceof XECPrivateKeySpec)
        {
            XECPrivateKeySpec jdk = (XECPrivateKeySpec) keySpec;
            OSSLKeyType type = xecType(jdk.getParams());
            byte[] scalar = jdk.getScalar();
            int want = XECMontgomery.rawLength(type);
            if (scalar == null || scalar.length != want)
            {
                throw new InvalidKeySpecException("XECPrivateKeySpec scalar must be "
                        + want + " octets for " + type.getAlgorithmName() + ", got "
                        + (scalar == null ? "null" : String.valueOf(scalar.length)));
            }
            // EVERY intermediate below carries the scalar in the clear, not
            // just the final encoding: Der.octetString allocates a new array
            // each time, so the inner CurvePrivateKey and the privateKey
            // OCTET STRING that wraps it are two more copies. All are held in
            // locals and cleared together; clearing only p8 would leave two.
            //
            // `scalar` is ours to clear too — XECPrivateKeySpec.getScalar()
            // returns a clone, so the caller's array is untouched.
            byte[] inner = null;
            byte[] wrapped = null;
            byte[] p8 = null;
            try
            {
                // RFC 8410 section 7: CurvePrivateKey ::= OCTET STRING, nested
                // inside the PrivateKeyInfo privateKey OCTET STRING. version 0.
                inner = Der.octetString(scalar);
                wrapped = Der.octetString(inner);
                p8 = Der.sequence(
                        Der.integer(0),
                        Der.sequence(Der.objectIdentifier(curveOid(type))),
                        wrapped);
                return engineGeneratePrivate(new PKCS8EncodedKeySpec(p8));
            }
            finally
            {
                org.openssl.jostle.util.Arrays.clear(scalar);
                org.openssl.jostle.util.Arrays.clear(inner);
                org.openssl.jostle.util.Arrays.clear(wrapped);
                org.openssl.jostle.util.Arrays.clear(p8);
            }
        }
        if (keySpec instanceof PKCS8EncodedKeySpec)
        {
            // getEncoded() returns a fresh copy carrying the private key bytes —
            // scrub it once the native key is built (Ed/RSA precedent).
            byte[] encoded = ((PKCS8EncodedKeySpec) keySpec).getEncoded();
            try
            {
                PKEYKeySpec spec = ASN1Encoder.fromPrivateKeyInfo(asn1NI, specNI, encoded, 0, encoded.length, providerInstance);
                requireXEC(spec);
                return new JOXECPrivateKey(asn1NI, spec);
            }
            catch (RuntimeException e)
            {
                throw new InvalidKeySpecException("unable to decode XDH private key", e);
            }
            finally
            {
                Arrays.clear(encoded);
            }
        }
        throw new InvalidKeySpecException(
                "unsupported key spec: " + keySpec + ". Use PKCS8EncodedKeySpec.");
    }

    @Override
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec) throws InvalidKeySpecException
    {
        if (key instanceof JOXECPublicKey)
        {
            if (X509EncodedKeySpec.class.isAssignableFrom(keySpec))
            {
                return keySpec.cast(new X509EncodedKeySpec(((JOXECPublicKey) key).getEncoded()));
            }
            throw new InvalidKeySpecException("unsupported key spec for XDH public key: " + keySpec);
        }
        if (key instanceof JOXECPrivateKey)
        {
            if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec))
            {
                return keySpec.cast(new PKCS8EncodedKeySpec(((JOXECPrivateKey) key).getEncoded()));
            }
            throw new InvalidKeySpecException("unsupported key spec for XDH private key: " + keySpec);
        }
        throw new InvalidKeySpecException(
                "unrecognised key type: " + (key == null ? "null" : key.getClass().getName()));
    }

    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException
    {
        if (key instanceof JOXECPublicKey || key instanceof JOXECPrivateKey)
        {
            org.openssl.jostle.jcajce.spec.PKEYKeySpec s =
                    ((org.openssl.jostle.jcajce.interfaces.OSSLKey) key).getSpec();
            // INSTANCE check only, deliberately — no library half here.
            // translateKey never had one, and for anything a provider made the
            // instance check subsumes it: same instance implies same library.
            // The only case it would add is two hand-wired, unbound SPIs on
            // different libraries, and translateKey's answer there is to
            // re-decode rather than refuse.
            if (!s.usableBy(providerInstance))
            {
                throw new java.security.InvalidKeyException(
                        "key was created by a different Jostle provider instance; encode it "
                                + "with getEncoded() and decode it through this provider's "
                                + "KeyFactory");
            }
            return key;
        }
        if (key == null)
        {
            throw new InvalidKeyException("key is null");
        }
        // Foreign XDH key — re-encode and decode through us so we own the EVP_PKEY.
        byte[] encoded = null;
        try
        {
            encoded = key.getEncoded();
            if (encoded == null)
            {
                throw new InvalidKeyException("foreign key has no encoded form");
            }
            if (key instanceof PrivateKey)
            {
                return engineGeneratePrivate(new PKCS8EncodedKeySpec(encoded));
            }
            return engineGeneratePublic(new X509EncodedKeySpec(encoded));
        }
        catch (InvalidKeySpecException e)
        {
            throw new InvalidKeyException(e.getMessage(), e);
        }
        catch (RuntimeException e)
        {
            // A hostile/broken foreign key can throw from getEncoded();
            // surface the typed exception the translate contract requires.
            throw new InvalidKeyException("unable to translate key", e);
        }
        finally
        {
            // The local copy may carry private material — scrub it
            // (engineGeneratePrivate scrubbed only its own inner clone).
            Arrays.clear(encoded);
        }
    }

    private static void requireXEC(PKEYKeySpec spec) throws InvalidKeySpecException
    {
        if (spec.getType() != OSSLKeyType.X25519 && spec.getType() != OSSLKeyType.X448)
        {
            throw new InvalidKeySpecException(
                    "expected an XDH key but got " + spec.getType().getAlgorithmName());
        }
    }

    /** RFC 8410 section 3 curve OIDs. */
    private static String curveOid(OSSLKeyType type)
    {
        return XECMontgomery.isX448(type) ? "1.3.101.111" : "1.3.101.110";
    }

    /** Map the JDK's {@link NamedParameterSpec} to jostle's key type. */
    private OSSLKeyType xecType(java.security.spec.AlgorithmParameterSpec params)
            throws InvalidKeySpecException
    {
        String n = params instanceof NamedParameterSpec
                ? ((NamedParameterSpec) params).getName() : null;
        OSSLKeyType type;
        if (NamedParameterSpec.X25519.getName().equalsIgnoreCase(n))
        {
            type = OSSLKeyType.X25519;
        }
        else if (NamedParameterSpec.X448.getName().equalsIgnoreCase(n))
        {
            type = OSSLKeyType.X448;
        }
        else
        {
            throw new InvalidKeySpecException("unsupported XDH parameter spec: " + n);
        }
        // No fixedType check here: unlike EdKeyFactorySpi, the XEC factory is
        // not constructed per-algorithm — one instance serves X25519 and X448
        // and the type comes from the spec. Verified: the baseline has no
        // fixedType field.
        return type;
    }

    private static byte[] prepend(byte b, byte[] rest)
    {
        byte[] out = new byte[rest.length + 1];
        out[0] = b;
        System.arraycopy(rest, 0, out, 1, rest.length);
        return out;
    }
}
