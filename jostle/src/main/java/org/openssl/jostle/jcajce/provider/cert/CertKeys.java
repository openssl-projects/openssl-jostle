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

package org.openssl.jostle.jcajce.provider.cert;

import org.openssl.jostle.util.asn1.oids.X9ObjectIdentifiers;
import org.openssl.jostle.jcajce.provider.binding.ProviderBinding;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

/**
 * Rebuilds a certificate's public key through the owning provider's own
 * KeyFactory.
 *
 * <p>Through the provider INSTANCE, never a name and never JCA search order:
 * a key from another instance is refused on first use by the isolation check,
 * so a factory that reached for JCA order would hand back keys its own
 * provider rejects. {@code KSServiceSPI.generatePrivateKey} is the same shape
 * on the keystore side.
 *
 * <p>The round trip through {@code X509EncodedKeySpec} does NOT normalise the
 * algorithm identifier away: {@code RSAKeyFactorySpi} captures the source
 * AlgorithmIdentifier and {@code JORSAPublicKey.getEncoded()} re-emits it, so
 * an {@code id-RSASSA-PSS} key keeps its OID and parameters. Measured over the
 * corpus plus the PSS fixture: the re-encoded key is byte-equal to the
 * certificate's SubjectPublicKeyInfo on 405 of 407 files. The two exceptions
 * are the inherited-parameter DSA certificates handled below.
 */
final class CertKeys
{
    /** RFC 3279 §2.3.2: DSA with the parameters omitted inherits the issuer's. */
    private static final String DSA_OID = X9ObjectIdentifiers.id_dsa.getId();

    private CertKeys()
    {
    }

    /**
     * @param provider the factory's own provider instance
     * @param spkiAlgOid the SubjectPublicKeyInfo algorithm OID, or null when
     *                   the certificate did not yield one — treated as UNKNOWN,
     *                   never as served
     * @param spki       the encoded SubjectPublicKeyInfo
     */
    static PublicKey publicKeyOf(ProviderBinding binding, String spkiAlgOid, byte[] spki,
                                 boolean parametersInherited)
    {
        // Distinct texts for three distinct causes, so a caller can tell them
        // apart and a test can pin each one.
        if (parametersInherited)
        {
            throw new ProviderException(
                    "DSA public key inherits its parameters from the issuer (RFC 3279 2.3.2);"
                            + " this provider cannot build it from the certificate alone");
        }
        if (spkiAlgOid == null)
        {
            // An absent slot reads as UNKNOWN, never as served.
            throw new ProviderException(
                    "certificate public key algorithm could not be identified");
        }
        try
        {
            // Resolved BY OID against the provider itself. Every KeyFactory
            // this provider serves is registered under its SPKI OID alias --
            // measured, all 17 that reach a certificate resolve -- so asking
            // the provider IS the coverage. A hand-written OID-to-name table
            // was the first shape and was deleted: it is pure transcription,
            // it silently lacked the ML-DSA, ML-KEM and SLH-DSA rows, and the
            // three tests that caught that are the argument against ever
            // writing it again.
            //
            // The INSTANCE when there is one; the NAME only when the factory
            // was built without an instance, which is all the name-only
            // constructor ever had.
            KeyFactory kf = (binding.instance() != null)
                    ? KeyFactory.getInstance(spkiAlgOid, binding.instance())
                    : KeyFactory.getInstance(spkiAlgOid, binding.name());
            return kf.generatePublic(new X509EncodedKeySpec(spki));
        }
        catch (NoSuchProviderException e)
        {
            throw new ProviderException(
                    "no provider named " + binding.name() + " to rebuild the certificate"
                            + " public key through", e);
        }
        catch (NoSuchAlgorithmException e)
        {
            // The OID is in the table but this provider does not register the
            // factory — the FIPS module that does not serve the algorithm.
            throw new ProviderException(
                    "provider " + binding.name() + " serves no KeyFactory for certificate"
                            + " public key algorithm " + spkiAlgOid, e);
        }
        catch (InvalidKeySpecException e)
        {
            // TWO causes reach here and no input separates them: the
            // SubjectPublicKeyInfo really is malformed, or it is well-formed
            // and this provider's KeyFactory refuses the key — a curve the
            // FIPS module does not serve is the live example, and there the
            // earlier "malformed" wording named the wrong cause outright. The
            // message therefore states both rather than asserting one.
            throw new ProviderException(
                    "provider " + binding.name() + " could not rebuild the certificate public"
                            + " key (algorithm " + spkiAlgOid + "): the SubjectPublicKeyInfo is"
                            + " malformed, or this provider refuses the key", e);
        }
    }

    /**
     * A {@link java.security.Signature} from the same provider the key came
     * from, by INSTANCE where there is one.
     */
    static java.security.Signature signatureFor(ProviderBinding binding, String algorithm)
        throws NoSuchAlgorithmException
    {
        try
        {
            return (binding.instance() != null)
                    ? java.security.Signature.getInstance(algorithm, binding.instance())
                    : java.security.Signature.getInstance(algorithm, binding.name());
        }
        catch (NoSuchProviderException e)
        {
            throw new ProviderException(
                    "no provider named " + binding.name() + " to verify through", e);
        }
    }

    /**
     * Whether this SubjectPublicKeyInfo is a DSA key whose parameters are
     * absent, and therefore inherited from the issuer.
     *
     * <p>Detected from the encoding rather than from the failure, so the
     * refusal names the cause instead of reporting a generic decode error —
     * OpenSSL's {@code X509_PUBKEY_get0} cannot load these at all, which is
     * the same root cause as the certification-path divergence already pinned
     * in {@code PkitsDivergenceTest}.
     */
    static boolean hasInheritedDsaParameters(String spkiAlgOid, byte[] spki)
    {
        if (!DSA_OID.equals(spkiAlgOid) || spki == null)
        {
            return false;
        }
        // SubjectPublicKeyInfo ::= SEQUENCE { AlgorithmIdentifier, BIT STRING }
        // AlgorithmIdentifier ::= SEQUENCE { OBJECT IDENTIFIER, ANY OPTIONAL }
        // Inherited parameters means that OPTIONAL is absent, so the inner
        // SEQUENCE holds exactly the OID and nothing else.
        try
        {
            int[] p = {0};
            expect(spki, p, 0x30);
            readLength(spki, p);
            expect(spki, p, 0x30);
            int algLen = readLength(spki, p);
            int algEnd = p[0] + algLen;
            expect(spki, p, 0x06);
            int oidLen = readLength(spki, p);
            p[0] += oidLen;
            return p[0] == algEnd;
        }
        catch (RuntimeException malformed)
        {
            return false;
        }
    }

    private static void expect(byte[] b, int[] p, int tag)
    {
        if (p[0] >= b.length || (b[p[0]] & 0xFF) != tag)
        {
            throw new IllegalArgumentException("unexpected tag");
        }
        p[0]++;
    }

    private static int readLength(byte[] b, int[] p)
    {
        int l = b[p[0]++] & 0xFF;
        if ((l & 0x80) == 0)
        {
            return l;
        }
        int n = l & 0x7F;
        if (n == 0 || n > 4)
        {
            throw new IllegalArgumentException("unsupported length");
        }
        int len = 0;
        for (int i = 0; i < n; i++)
        {
            len = (len << 8) | (b[p[0]++] & 0xFF);
        }
        if (len < 0)
        {
            throw new IllegalArgumentException("length out of range");
        }
        return len;
    }
}
