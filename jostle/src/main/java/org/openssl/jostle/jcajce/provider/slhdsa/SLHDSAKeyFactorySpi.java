/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.slhdsa;

import org.openssl.jostle.jcajce.interfaces.SLHDSAPrivateKey;
import org.openssl.jostle.jcajce.interfaces.SLHDSAPublicKey;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.spec.*;
import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.asn1.ASN1Encoder;
import org.openssl.jostle.util.asn1.Asn1Ni;
import org.openssl.jostle.util.asn1.KeyInfoCanonicalizer;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class SLHDSAKeyFactorySpi extends KeyFactorySpi
{

    private final OSSLKeyType fixedType;

    private static final Map<SLHDSAParameterSpec, OSSLKeyType> typeMap;

    static
    {
        typeMap = Collections.unmodifiableMap(new HashMap<SLHDSAParameterSpec, OSSLKeyType>()
        {
            {
                SLHDSAParameterSpec.getParameterSpecs().forEach(it ->
                {
                    put(it, it.getKeyType());
                });
            }
        });

    }


    // Instance fields, not NISelector statics (NISelector for JSL,
    // FIPSNISelector for JSLFIPS).
    private final SLHDSAServiceNI slhdsaServiceNI;
    private final SpecNI specNI;
    private final Asn1Ni asn1NI;

    public SLHDSAKeyFactorySpi(OSSLKeyType keyType)
    {
        this(NISelector.SLHDSAServiceNI, NISelector.SpecNI, NISelector.Asn1NI, keyType);
    }

    public SLHDSAKeyFactorySpi()
    {
        this(NISelector.SLHDSAServiceNI, NISelector.SpecNI, NISelector.Asn1NI, OSSLKeyType.NONE);
    }

    public SLHDSAKeyFactorySpi(SLHDSAServiceNI slhdsaServiceNI, SpecNI specNI, Asn1Ni asn1NI)
    {
        this(slhdsaServiceNI, specNI, asn1NI, OSSLKeyType.NONE);
    }

    public SLHDSAKeyFactorySpi(SLHDSAServiceNI slhdsaServiceNI, SpecNI specNI, Asn1Ni asn1NI,
                               OSSLKeyType keyType)
    {
        this(slhdsaServiceNI, specNI, asn1NI, keyType, null);
    }

    /**
     * The provider INSTANCE this SPI belongs to, or null when constructed
     * outside any provider. MT-14; see {@code PKEYKeySpec.usableBy}.
     */
    private final java.security.Provider providerInstance;

    public SLHDSAKeyFactorySpi(SLHDSAServiceNI slhdsaServiceNI, SpecNI specNI, Asn1Ni asn1NI,
                               OSSLKeyType keyType, java.security.Provider providerInstance)
    {
        this.slhdsaServiceNI = slhdsaServiceNI;
        this.specNI = specNI;
        this.asn1NI = asn1NI;
        this.fixedType = keyType;
        this.providerInstance = providerInstance;
        assert keyType != null;
    }

    /**
     * The SpecNI this factory's keys are bound to - used by the key-import
     * helpers to reject a key made by the other Jostle provider.
     */
    SpecNI ownSpecNI()
    {
        return specNI;
    }

    /** The provider instance this factory belongs to; null when unbound. */
    java.security.Provider ownProviderInstance()
    {
        return providerInstance;
    }

    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException
    {
        if (keySpec instanceof X509EncodedKeySpec)
        {
            byte[] encoded = KeyInfoCanonicalizer.subjectPublicKeyInfo(((X509EncodedKeySpec) keySpec).getEncoded());

            try
            {
                PKEYKeySpec pkeySpec = ASN1Encoder.fromSubjectPublicKeyInfo(asn1NI, specNI, encoded, 0, encoded.length, providerInstance);

                if (fixedType != OSSLKeyType.NONE && fixedType != pkeySpec.getType())
                {
                    throw new InvalidKeySpecException("expected " + fixedType.getAlgorithmName() + " but got " + pkeySpec.getType().getAlgorithmName());
                }

                if (SLHDSAParameterSpec.getSpecForOSSLType(pkeySpec.getType()) == null)
                {
                    throw new InvalidKeySpecException("expected SLH-DSA key but got " + pkeySpec.getType());
                }

                return new JOSLHDSAPublicKey(slhdsaServiceNI, pkeySpec);
            }
            catch (RuntimeException e)
            {
                // Malformed encoding surfaces from the decoder as OpenSSLException
                // / IllegalArgumentException; the KeyFactory contract requires
                // InvalidKeySpecException (RSAKeyFactorySpi precedent).
                throw new InvalidKeySpecException("unable to decode SLH-DSA public key", e);
            }
        }
        else
        {
            if (keySpec instanceof SLHDSAPublicKeySpec)
            {
                SLHDSAPublicKeySpec pubSpec = (SLHDSAPublicKeySpec) keySpec;

                OSSLKeyType osslKeyType = typeMap.get(pubSpec.getParameterSpec());

                if (osslKeyType == null)
                {
                    // A spec built with a null / unrecognised parameter set
                    // would otherwise NPE at osslKeyType.getKsType().
                    throw new InvalidKeySpecException("unknown SLH-DSA parameter set: " + pubSpec.getParameterSpec());
                }

                if (fixedType != OSSLKeyType.NONE && osslKeyType != fixedType)
                {
                    throw new InvalidKeySpecException("Invalid KeySpec: " + keySpec);
                }

                byte[] encoded = pubSpec.getPublicData();
                try
                {
                    PKEYKeySpec pkeySpec = new PKEYKeySpec(specNI, specNI.allocate(), osslKeyType, providerInstance);
                    slhdsaServiceNI.decode_publicKey(
                            pkeySpec.getReference(), osslKeyType.getKsType(), encoded, 0, encoded.length);
                    return new JOSLHDSAPublicKey(slhdsaServiceNI, pkeySpec);
                }
                catch (RuntimeException e)
                {
                    // A wrong-length / malformed raw encoding surfaces from the
                    // decoder as IllegalArgumentException / OpenSSLException; the
                    // KeyFactory contract requires InvalidKeySpecException (matches
                    // the X509 wrapper above).
                    throw new InvalidKeySpecException("unable to decode SLH-DSA public key", e);
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

            byte[] pkcs8 = ((PKCS8EncodedKeySpec) keySpec).getEncoded();
            byte[] encoded = KeyInfoCanonicalizer.privateKeyInfo(pkcs8);

            try
            {
                PKEYKeySpec pkeySpec = ASN1Encoder.fromPrivateKeyInfo(asn1NI, specNI, encoded, 0, encoded.length, providerInstance);

                if (fixedType != OSSLKeyType.NONE && fixedType != pkeySpec.getType())
                {
                    throw new InvalidKeySpecException("expected " + fixedType.getAlgorithmName() + " but got " + pkeySpec.getType().getAlgorithmName());
                }

                if (SLHDSAParameterSpec.getSpecForOSSLType(pkeySpec.getType()) == null)
                {
                    throw new InvalidKeySpecException("expected SLH-DSA key but got " + pkeySpec.getType());
                }

                return new JOSLHDSAPrivateKey(slhdsaServiceNI, pkeySpec);
            }
            catch (RuntimeException e)
            {
                throw new InvalidKeySpecException("unable to decode SLH-DSA private key", e);
            }
            finally
            {
                // The PKCS#8 blob and any canonicalized copy carry the raw private
                // key — scrub both, on failure paths too (MLKEM/Ed/RSA precedent).
                Arrays.clear(pkcs8);
                if (encoded != null && encoded != pkcs8)
                {
                    Arrays.clear(encoded);
                }
            }
        }
        else
        {
            if (keySpec instanceof SLHDSAPrivateKeySpec)
            {
                SLHDSAPrivateKeySpec spec = (SLHDSAPrivateKeySpec) keySpec;
                OSSLKeyType osslKeyType = typeMap.get(spec.getParameterSpec());

                if (osslKeyType == null)
                {
                    // A spec built with a null / unrecognised parameter set
                    // would otherwise NPE at osslKeyType.getKsType().
                    throw new InvalidKeySpecException("unknown SLH-DSA parameter set: " + spec.getParameterSpec());
                }

                if (fixedType != OSSLKeyType.NONE && osslKeyType != fixedType)
                {
                    throw new InvalidKeySpecException("Invalid KeySpec: " + keySpec);
                }

                byte[] encoded = spec.getPrivateData();
                try
                {
                    PKEYKeySpec pkeySpec = new PKEYKeySpec(specNI, specNI.allocate(), osslKeyType, providerInstance);
                    slhdsaServiceNI.decode_privateKey(
                            pkeySpec.getReference(), osslKeyType.getKsType(),
                            encoded, 0, encoded.length);
                    return new JOSLHDSAPrivateKey(slhdsaServiceNI, pkeySpec);
                }
                catch (RuntimeException e)
                {
                    // A wrong-length / malformed raw encoding surfaces from the
                    // decoder as IllegalArgumentException / OpenSSLException; the
                    // KeyFactory contract requires InvalidKeySpecException (matches
                    // the PKCS#8 wrapper above).
                    throw new InvalidKeySpecException("unable to decode SLH-DSA private key", e);
                }
                finally
                {
                    // Transient raw private encoding cloned from the spec.
                    Arrays.clear(encoded);
                }
            }
        }

        throw new InvalidKeySpecException("Invalid KeySpec: " + keySpec);
    }

    @Override
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec) throws InvalidKeySpecException
    {
        if (key instanceof JOSLHDSAPrivateKey)
        {
            if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec))
            {
                return keySpec.cast(new PKCS8EncodedKeySpec(key.getEncoded()));
            }
            else
            {
                if (SLHDSAPrivateKeySpec.class.isAssignableFrom(keySpec))
                {
                    JOSLHDSAPrivateKey mKey = (JOSLHDSAPrivateKey) key;
                    return keySpec.cast(new SLHDSAPrivateKeySpec(mKey.getParameterSpec(), mKey.getDirectEncoding()));
                }
            }
            throw new InvalidKeySpecException("Invalid KeySpec: " + keySpec);
        }
        else
        {
            if (key instanceof JOSLHDSAPublicKey)
            {
                if (X509EncodedKeySpec.class.isAssignableFrom(keySpec))
                {
                    return keySpec.cast(new X509EncodedKeySpec(key.getEncoded()));
                }
                else
                {
                    if (SLHDSAPublicKeySpec.class.isAssignableFrom(keySpec))
                    {
                        JOSLHDSAPublicKey mKey = (JOSLHDSAPublicKey) key;
                        return keySpec.cast(new SLHDSAPublicKeySpec(mKey.getParameterSpec(), mKey.getPublicData()));
                    }
                }
                throw new InvalidKeySpecException("Invalid KeySpec: " + keySpec);
            }
        }
        throw new InvalidKeySpecException("Invalid Key: " + key);
    }

    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException
    {
        if (key instanceof SLHDSAPrivateKey || key instanceof SLHDSAPublicKey)
        {
            org.openssl.jostle.jcajce.spec.PKEYKeySpec s =
                    ((org.openssl.jostle.jcajce.interfaces.OSSLKey) key).getSpec();
            // INSTANCE check only, deliberately — no library half here.
            //
            // translateKey had NO pre-existing check (that was the twelfth
            // acceptance shape). Adding the library half would therefore not
            // be "additive": it would be a NEW Phase-1 restriction, refusing
            // cross-library public keys at this one surface while initVerify,
            // encrypt and the import helpers still accept them until Phase 2.
            // Phase 1's contract is "checks in place, behaviour unchanged", and
            // a window where translateKey refuses what initVerify accepts is a
            // bug report waiting to happen for no benefit — the object route
            // leaks everywhere else regardless until the flip.
            //
            // Inert now (all specs unbound => usableBy true), live the moment
            // Phase 2 binds, at which point it subsumes a library check anyway.
            if (!s.usableBy(providerInstance))
            {
                throw new InvalidKeyException(
                        "key was created by a different Jostle provider instance; encode it "
                                + "with getEncoded() and decode it through this provider's "
                                + "KeyFactory");
            }
            return key;
        }
        throw new InvalidKeyException("Invalid Key: " + key);
    }


}
