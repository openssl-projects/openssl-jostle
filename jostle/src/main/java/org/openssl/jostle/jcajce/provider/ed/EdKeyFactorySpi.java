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

package org.openssl.jostle.jcajce.provider.ed;

import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.spec.*;
import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.asn1.ASN1Encoder;
import org.openssl.jostle.util.asn1.Asn1Ni;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class EdKeyFactorySpi extends KeyFactorySpi
{
    // Instance fields, not NISelector statics (NISelector for JSL,
    // FIPSNISelector for JSLFIPS). A KeyFactory welded to the base statics
    // could never serve JSLFIPS — it would hand FIPS callers keys made by the
    // base interface library and its OSSL_LIB_CTX.
    private final EDServiceNI edServiceNI;
    private final SpecNI specNI;
    private final Asn1Ni asn1NI;

    private final OSSLKeyType fixedType;

    private static final Map<EdDSAParameterSpec, OSSLKeyType> typeMap = Collections.unmodifiableMap(new HashMap<EdDSAParameterSpec, OSSLKeyType>()
    {
        {
            put(EdDSAParameterSpec.ED25519, OSSLKeyType.ED25519);
            put(EdDSAParameterSpec.ED448, OSSLKeyType.ED448);
        }
    });

    public EdKeyFactorySpi(OSSLKeyType fixedType)
    {
        this(NISelector.EDServiceNI, NISelector.SpecNI, NISelector.Asn1NI, fixedType);
    }


    /**
     * The provider INSTANCE this SPI belongs to, or null when constructed
     * outside any provider. MT-14; see {@code PKEYKeySpec.usableBy}.
     */
    private final java.security.Provider providerInstance;

    public EdKeyFactorySpi()
    {
        this(NISelector.EDServiceNI, NISelector.SpecNI, NISelector.Asn1NI, OSSLKeyType.NONE);
    }

    public EdKeyFactorySpi(EDServiceNI edServiceNI, SpecNI specNI, Asn1Ni asn1NI, OSSLKeyType fixedType)
    {
        this(edServiceNI, specNI, asn1NI, fixedType, null);
    }

    public EdKeyFactorySpi(EDServiceNI edServiceNI, SpecNI specNI, Asn1Ni asn1NI, OSSLKeyType fixedType, java.security.Provider providerInstance)
    {
        this.providerInstance = providerInstance;
        assert fixedType != null;
        this.edServiceNI = edServiceNI;
        this.specNI = specNI;
        this.asn1NI = asn1NI;
        this.fixedType = fixedType;
    }

    /**
     * The SpecNI this factory's keys are bound to — the identity used to tell
     * a JSL key from a JSLFIPS one in {@link #importPrivateKey}.
     */
    SpecNI ownSpecNI()
    {
        return specNI;
    }


    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException
    {
        if (keySpec instanceof X509EncodedKeySpec)
        {
            byte[] encoded = ((X509EncodedKeySpec) keySpec).getEncoded();
            PKEYKeySpec pkeySpec;
            try
            {
                pkeySpec = ASN1Encoder.fromSubjectPublicKeyInfo(asn1NI, specNI, encoded, 0, encoded.length, providerInstance);
            }
            catch (RuntimeException e)
            {
                // Malformed encoding surfaces as OpenSSLException / IllegalArgumentException;
                // the KeyFactory contract requires InvalidKeySpecException.
                throw new InvalidKeySpecException("unable to decode Ed public key", e);
            }
            if (fixedType != OSSLKeyType.NONE && fixedType != pkeySpec.getType())
            {
                throw new InvalidKeySpecException("expected " + fixedType.getAlgorithmName() + " but got " + pkeySpec.getType().getAlgorithmName());
            }

            switch (pkeySpec.getType())
            {
                case ED25519:
                case ED448:
                    break;
                default:
                    throw new InvalidKeySpecException("expected ED key but got " + pkeySpec.getType());
            }

            return new JOEdPublicKey(edServiceNI, asn1NI, pkeySpec);
        }
        else
        {
            if (keySpec instanceof EdDSAPublicKeySpec)
            {
                EdDSAPublicKeySpec pubSpec = (EdDSAPublicKeySpec) keySpec;

                OSSLKeyType osslKeyType = typeMap.get(pubSpec.getParameterSpec());

                if (fixedType != OSSLKeyType.NONE && osslKeyType != fixedType)
                {
                    throw new InvalidKeySpecException("Invalid KeySpec: " + keySpec);
                }

                byte[] encoded = ((EdDSAPublicKeySpec) keySpec).getPublicData();
                try
                {
                    PKEYKeySpec pkeySpec = new PKEYKeySpec(specNI, specNI.allocate(), osslKeyType, providerInstance);

                    edServiceNI.decode_publicKey(
                            pkeySpec.getReference(), osslKeyType.getKsType(), encoded, 0, encoded.length);
                    return new JOEdPublicKey(edServiceNI, asn1NI, pkeySpec);
                }
                catch (RuntimeException e)
                {
                    // A native rejection (wrong-length key, unknown parameter
                    // spec) surfaces as OpenSSLException / IllegalArgumentException;
                    // the KeyFactory contract requires InvalidKeySpecException,
                    // matching the X.509 branch above.
                    throw new InvalidKeySpecException("unable to decode Ed public key", e);
                }
            }
        }
        throw new InvalidKeySpecException("Invalid KeySpec: " + keySpec);
    }

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException
    {
        if (keySpec instanceof PKCS8EncodedKeySpec)
        {

            // PKCS8EncodedKeySpec.getEncoded() returns a fresh copy carrying
            // the private scalar — scrub it once the native key is built.
            byte[] encoded = ((PKCS8EncodedKeySpec) keySpec).getEncoded();

            try
            {
                PKEYKeySpec pkeySpec = ASN1Encoder.fromPrivateKeyInfo(asn1NI, specNI, encoded, 0, encoded.length, providerInstance);

                if (fixedType != OSSLKeyType.NONE && fixedType != pkeySpec.getType())
                {
                    throw new InvalidKeySpecException("expected " + fixedType.getAlgorithmName() + " but got " + pkeySpec.getType());
                }

                switch (pkeySpec.getType())
                {
                    case ED25519:
                    case ED448:
                        break;
                    default:
                        throw new InvalidKeySpecException("expected ED key but got " + pkeySpec.getType());
                }

                return new JOEdPrivateKey(edServiceNI, asn1NI, pkeySpec);
            }
            catch (RuntimeException e)
            {
                throw new InvalidKeySpecException("unable to decode Ed private key", e);
            }
            finally
            {
                Arrays.clear(encoded);
            }
        }
        else
        {
            if (keySpec instanceof EdDSAPrivateKeySpec)
            {
                EdDSAPrivateKeySpec spec = (EdDSAPrivateKeySpec) keySpec;
                OSSLKeyType osslKeyType = typeMap.get(spec.getParameterSpec());

                if (fixedType != OSSLKeyType.NONE && osslKeyType != fixedType)
                {
                    throw new InvalidKeySpecException("Invalid KeySpec: " + keySpec);
                }

                // getPrivateData() returns Arrays.clone(...) — a fresh copy of
                // the raw scalar — so scrubbing it can't corrupt the caller's spec.
                byte[] encoded = spec.getPrivateData();

                try
                {
                    PKEYKeySpec pkeySpec = new PKEYKeySpec(specNI, specNI.allocate(), osslKeyType, providerInstance);
                    edServiceNI.decode_privateKey(
                            pkeySpec.getReference(), osslKeyType.getKsType(),
                            encoded, 0, encoded.length);
                    return new JOEdPrivateKey(edServiceNI, asn1NI, pkeySpec);
                }
                catch (RuntimeException e)
                {
                    // A native rejection (wrong-length key, unknown parameter
                    // spec) surfaces as OpenSSLException / IllegalArgumentException;
                    // the KeyFactory contract requires InvalidKeySpecException,
                    // matching the PKCS#8 branch above.
                    throw new InvalidKeySpecException("unable to decode Ed private key", e);
                }
                finally
                {
                    Arrays.clear(encoded);
                }
            }
        }

        throw new InvalidKeySpecException("Invalid KeySpec: " + keySpec);
    }

    @Override
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec) throws InvalidKeySpecException
    {
        if (key instanceof JOEdPrivateKey)
        {
            if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec))
            {
                return keySpec.cast(new PKCS8EncodedKeySpec(key.getEncoded()));
            }
            else
            {
                if (EdDSAPrivateKeySpec.class.isAssignableFrom(keySpec))
                {
                    JOEdPrivateKey mKey = (JOEdPrivateKey) key;
                    return keySpec.cast(new EdDSAPrivateKeySpec(
                            mKey.getParameterSpec(),
                            mKey.getRawScalar(),
                            mKey.getRawPublic()));
                }
            }
        }
        else if (key instanceof JOEdPublicKey)
        {
            if (X509EncodedKeySpec.class.isAssignableFrom(keySpec))
            {
                return keySpec.cast(new X509EncodedKeySpec(key.getEncoded()));
            }
            else
            {
                if (EdDSAPublicKeySpec.class.isAssignableFrom(keySpec))
                {
                    JOEdPublicKey mKey = (JOEdPublicKey) key;
                    return keySpec.cast(new EdDSAPublicKeySpec(
                            mKey.getParameterSpec(), mKey.getRawPublic())
                    );
                }
            }
        }

        throw new InvalidKeySpecException("Invalid KeySpec: " + keySpec);

    }

    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException
    {
        if (key instanceof JOEdPublicKey || key instanceof JOEdPrivateKey)
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
        if (key instanceof PublicKey)
        {
            return importPublicKey((PublicKey) key);
        }
        if (key instanceof PrivateKey)
        {
            return importPrivateKey((PrivateKey) key);
        }
        throw new InvalidKeyException("Invalid Key: " + key);
    }

    /**
     * Adopt an EdDSA public key produced by another provider (SunEC's
     * {@code EdECPublicKey}, BouncyCastle's EdDSA key, etc.) as a
     * Jostle-native {@link JOEdPublicKey} by re-decoding its X.509
     * SubjectPublicKeyInfo. Jostle keys are returned unchanged. This is
     * what lets {@code Signature.getInstance("Ed25519","JSL").initVerify(k)}
     * accept a foreign-decoded public key — the case BouncyCastle's TLS
     * layer hits when a peer certificate's key was decoded by a different
     * provider (GH issue: JCA/TLS gap #5).
     */
    JOEdPublicKey importPublicKey(PublicKey key) throws InvalidKeyException
    {
        if (key == null)
        {
            throw new InvalidKeyException("public key is null");
        }
        if (key instanceof JOEdPublicKey)
        {
            // MT-14: instance-checked. An older comment here claimed OpenSSL
            // imported the public components into this lib ctx; measurement
            // disproved it (xprovider_key_probe.c) — the key keeps its
            // creating provider and the operation is served THERE, so
            // accepting the object executed outside this provider.
            JOEdPublicKey joPub = (JOEdPublicKey) key;
            if (!joPub.getSpec().usableBy(providerInstance))
            {
                throw new InvalidKeyException(
                        "public key was created by a different Jostle provider instance; "
                                + "encode it with getEncoded() and decode it through this "
                                + "provider's KeyFactory");
            }
            return joPub;
        }
        byte[] encoded = key.getEncoded();
        if (encoded == null)
        {
            throw new InvalidKeyException(
                    "cannot import EdDSA public key: no X.509 encoding available from "
                            + key.getClass().getName());
        }
        try
        {
            PKEYKeySpec pkeySpec = ASN1Encoder.fromSubjectPublicKeyInfo(asn1NI, specNI, encoded, 0, encoded.length, providerInstance);
            switch (pkeySpec.getType())
            {
                case ED25519:
                case ED448:
                    return new JOEdPublicKey(edServiceNI, asn1NI, pkeySpec);
                default:
                    throw new InvalidKeyException(
                            "not an EdDSA public key: " + pkeySpec.getType());
            }
        }
        catch (InvalidKeyException e)
        {
            throw e;
        }
        catch (RuntimeException e)
        {
            throw new InvalidKeyException(
                    "unable to import EdDSA public key from its encoding", e);
        }
    }

    /**
     * Counterpart of {@link #importPublicKey(PublicKey)} for private
     * keys: re-decodes a foreign EdDSA private key's PKCS#8
     * PrivateKeyInfo into a Jostle-native {@link JOEdPrivateKey}. A Jostle key
     * made by THIS provider is returned unchanged; one made by the other
     * Jostle provider is refused — see below.
     */
    JOEdPrivateKey importPrivateKey(PrivateKey key) throws InvalidKeyException
    {
        if (key == null)
        {
            throw new InvalidKeyException("private key is null");
        }
        if (key instanceof JOEdPrivateKey)
        {
            JOEdPrivateKey joKey = (JOEdPrivateKey) key;
            // Both halves; the library one has teeth only in the unbound
            // direct-SPI realm.
            if (joKey.getSpec().getSpecNI() != specNI
                    || !joKey.getSpec().usableBy(providerInstance))
            {
                // Keys are bound to the interface library (and OSSL_LIB_CTX)
                // that created them; JSL and JSLFIPS keys must not cross
                // implicitly. The sanctioned crossing is the one the message
                // names, and it is what a caller has to do anyway.
                throw new InvalidKeyException(
                        "private key was created by a different Jostle provider instance; encode it with getEncoded() and decode it through this provider's KeyFactory");
            }
            return joKey;
        }
        byte[] encoded = key.getEncoded();
        if (encoded == null)
        {
            throw new InvalidKeyException(
                    "cannot import EdDSA private key: no PKCS#8 encoding available from "
                            + key.getClass().getName());
        }
        try
        {
            PKEYKeySpec pkeySpec = ASN1Encoder.fromPrivateKeyInfo(asn1NI, specNI, encoded, 0, encoded.length, providerInstance);
            switch (pkeySpec.getType())
            {
                case ED25519:
                case ED448:
                    return new JOEdPrivateKey(edServiceNI, asn1NI, pkeySpec);
                default:
                    throw new InvalidKeyException(
                            "not an EdDSA private key: " + pkeySpec.getType());
            }
        }
        catch (InvalidKeyException e)
        {
            throw e;
        }
        catch (RuntimeException e)
        {
            throw new InvalidKeyException(
                    "unable to import EdDSA private key from its encoding", e);
        }
        finally
        {
            // The PKCS#8 encoding carries the private scalar — scrub our copy
            // once the native key has been built. getEncoded() returned a
            // fresh array (non-null, checked above), so this can't corrupt the
            // caller's key. Arrays.fill is not null-safe, but encoded != null.
            Arrays.clear(encoded);
        }
    }

    // Unused since MT-17 rekeyed creatorMap: the registrations construct
    // the parent with a key-type argument, so these name nothing. Retained
    // pending the API-removal decision.
    public static class ED25519 extends EdKeyFactorySpi
    {
        public ED25519()
        {
            super(OSSLKeyType.ED25519);
        }
    }

    public static class ED448 extends EdKeyFactorySpi
    {
        public ED448()
        {
            super(OSSLKeyType.ED448);
        }
    }

}
