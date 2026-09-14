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

import org.openssl.jostle.util.asn1.Der;
import org.openssl.jostle.util.asn1.oids.NISTObjectIdentifiers;
import org.openssl.jostle.util.asn1.oids.OIWObjectIdentifiers;
import org.openssl.jostle.util.asn1.oids.PKCSObjectIdentifiers;

import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * RFC 4055 {@code RSASSA-PSS-params}, encoded and decoded in house.
 *
 * <pre>
 *   RSASSA-PSS-params ::= SEQUENCE {
 *     hashAlgorithm      [0] HashAlgorithm    DEFAULT sha1Identifier,
 *     maskGenAlgorithm   [1] MaskGenAlgorithm DEFAULT mgf1SHA1Identifier,
 *     saltLength         [2] INTEGER          DEFAULT 20,
 *     trailerField       [3] INTEGER          DEFAULT 1 }
 * </pre>
 *
 * <p>Encoding OMITS every field at its DEFAULT — RFC 4055 makes that a MUST for
 * signature generation on all three of hashAlgorithm, maskGenAlgorithm and
 * trailerField. Decoding accepts them present or absent, also a MUST, so a
 * re-encode NORMALISES rather than preserving bytes. Measured: SunRsaSign and
 * BouncyCastle 1.86 produce identical DER for every spec tried, and both
 * normalise an all-DEFAULTs-present input to the two-byte empty SEQUENCE.
 *
 * <p>Two deliberate divergences, each pinned in both halves by
 * {@code RSAPSSAlgorithmParametersTest}:
 *
 * <ol>
 *   <li><b>trailerField other than 1 is refused</b>, on the spec side and on
 *       the wire. RFC 4055 says the value MUST be 1 and that other trailer
 *       fields are not supported. Both references encode a 2 from a spec, and
 *       BouncyCastle also accepts one off the wire; accepting it here would
 *       emit parameters {@link RSAPSSSignatureSpi} itself refuses.</li>
 *   <li><b>Trailing bytes after the SEQUENCE are refused</b>, matching
 *       BouncyCastle and the project rule that a decoder checks consumed
 *       length. SunRsaSign accepts them.</li>
 * </ol>
 *
 * <p>The digest name in a {@code PSSParameterSpec} is provider-scoped and the
 * two reference domains are disjoint for the truncated SHA-512s: SunRsaSign
 * takes {@code SHA-512/256} and refuses {@code SHA512(256)}, BouncyCastle the
 * exact reverse. Both spellings are accepted on the way in; the JCA standard
 * name is what comes back out.
 */
public class RSAPSSAlgorithmParameters
    extends AlgorithmParametersSpi
{
    private static final int TAG_HASH = 0xA0;
    private static final int TAG_MGF = 0xA1;
    private static final int TAG_SALT = 0xA2;
    private static final int TAG_TRAILER = 0xA3;
    private static final int TAG_NULL = 0x05;

    private static final String DEFAULT_DIGEST = "SHA-1";
    private static final int DEFAULT_SALT_LENGTH = 20;
    private static final int TRAILER_FIELD = 1;

    /**
     * Salt length is a caller-supplied length that reaches the native layer,
     * so it carries a stated bound. No digest we serve exceeds 64 bytes and a
     * salt longer than the modulus cannot sign, so this is far above anything
     * usable and only excludes absurd values.
     */
    private static final int MAX_SALT_LENGTH = 1024;

    /** Whole-blob ceiling: the structure is a handful of OIDs and two integers. */
    private static final int MAX_ENCODED_BYTES = 512;

    /** Canonical JCA digest name to its OID. Insertion order is arc order. */
    private static final Map<String, String> DIGEST_TO_OID;
    /** OID back to the canonical JCA name. */
    private static final Map<String, String> OID_TO_DIGEST;
    /** Accepted spelling, upper-cased, to the canonical JCA name. */
    private static final Map<String, String> ALIASES;

    static
    {
        Map<String, String> toOid = new LinkedHashMap<String, String>();
        toOid.put("SHA-1", OIWObjectIdentifiers.idSHA1.getId());
        toOid.put("SHA-224", NISTObjectIdentifiers.id_sha224.getId());
        toOid.put("SHA-256", NISTObjectIdentifiers.id_sha256.getId());
        toOid.put("SHA-384", NISTObjectIdentifiers.id_sha384.getId());
        toOid.put("SHA-512", NISTObjectIdentifiers.id_sha512.getId());
        toOid.put("SHA-512/224", NISTObjectIdentifiers.id_sha512_224.getId());
        toOid.put("SHA-512/256", NISTObjectIdentifiers.id_sha512_256.getId());
        toOid.put("SHA3-224", NISTObjectIdentifiers.id_sha3_224.getId());
        toOid.put("SHA3-256", NISTObjectIdentifiers.id_sha3_256.getId());
        toOid.put("SHA3-384", NISTObjectIdentifiers.id_sha3_384.getId());
        toOid.put("SHA3-512", NISTObjectIdentifiers.id_sha3_512.getId());
        DIGEST_TO_OID = Collections.unmodifiableMap(toOid);

        Map<String, String> fromOid = new LinkedHashMap<String, String>();
        for (Map.Entry<String, String> e : toOid.entrySet())
        {
            fromOid.put(e.getValue(), e.getKey());
        }
        OID_TO_DIGEST = Collections.unmodifiableMap(fromOid);

        Map<String, String> aliases = new LinkedHashMap<String, String>();
        for (String canonical : toOid.keySet())
        {
            aliases.put(canonical.toUpperCase(java.util.Locale.ROOT), canonical);
        }
        aliases.put("SHA1", "SHA-1");
        aliases.put("SHA224", "SHA-224");
        aliases.put("SHA256", "SHA-256");
        aliases.put("SHA384", "SHA-384");
        aliases.put("SHA512", "SHA-512");
        // BouncyCastle's spelling of the truncated SHA-512s.
        aliases.put("SHA512(224)", "SHA-512/224");
        aliases.put("SHA512(256)", "SHA-512/256");
        ALIASES = Collections.unmodifiableMap(aliases);
    }

    private String digest;
    private String mgfDigest;
    private int saltLength;

    @Override
    protected void engineInit(AlgorithmParameterSpec paramSpec)
        throws InvalidParameterSpecException
    {
        if (!(paramSpec instanceof PSSParameterSpec))
        {
            throw new InvalidParameterSpecException(
                    "RSASSA-PSS parameters require a PSSParameterSpec, got "
                            + (paramSpec == null ? "null" : paramSpec.getClass().getName()));
        }

        PSSParameterSpec pss = (PSSParameterSpec) paramSpec;

        String hash = canonicalOrNull(pss.getDigestAlgorithm());
        if (hash == null)
        {
            throw new InvalidParameterSpecException(
                    "unsupported PSS digest: " + pss.getDigestAlgorithm());
        }

        String mgf = pss.getMGFAlgorithm();
        if (mgf != null && !"MGF1".equalsIgnoreCase(mgf))
        {
            throw new InvalidParameterSpecException("only MGF1 is supported (got " + mgf + ")");
        }

        String mgfHash;
        AlgorithmParameterSpec mgfParams = pss.getMGFParameters();
        if (mgfParams == null)
        {
            mgfHash = hash;
        }
        else if (mgfParams instanceof MGF1ParameterSpec)
        {
            mgfHash = canonicalOrNull(((MGF1ParameterSpec) mgfParams).getDigestAlgorithm());
            if (mgfHash == null)
            {
                throw new InvalidParameterSpecException("unsupported MGF1 digest: "
                        + ((MGF1ParameterSpec) mgfParams).getDigestAlgorithm());
            }
        }
        else
        {
            throw new InvalidParameterSpecException(
                    "unsupported MGF parameters: " + mgfParams.getClass().getName());
        }

        int salt = pss.getSaltLength();
        if (salt < 0 || salt > MAX_SALT_LENGTH)
        {
            throw new InvalidParameterSpecException(
                    "PSS salt length out of range [0, " + MAX_SALT_LENGTH + "]: " + salt);
        }

        int trailer = pss.getTrailerField();
        if (trailer != TRAILER_FIELD)
        {
            // RFC 4055: the value MUST be 1. Both references encode other
            // values; RSAPSSSignatureSpi refuses them, so emitting one would
            // produce parameters this provider cannot sign under.
            throw new InvalidParameterSpecException(
                    "trailer field must be " + TRAILER_FIELD + " (got " + trailer + ")");
        }

        this.digest = hash;
        this.mgfDigest = mgfHash;
        this.saltLength = salt;
    }

    @Override
    protected void engineInit(byte[] params)
        throws IOException
    {
        if (params == null)
        {
            throw new IOException("null RSASSA-PSS parameters");
        }
        if (params.length > MAX_ENCODED_BYTES)
        {
            throw new IOException("RSASSA-PSS parameters longer than "
                    + MAX_ENCODED_BYTES + " bytes (" + params.length + ")");
        }

        Der.Reader outer = new Der.Reader(params);
        Der.Reader seq = outer.readTLV(Der.SEQUENCE, "RSASSA-PSS-params SEQUENCE");
        outer.requireEnd("trailing bytes after RSASSA-PSS-params");

        String hash = DEFAULT_DIGEST;
        String mgfHash = DEFAULT_DIGEST;
        int salt = DEFAULT_SALT_LENGTH;
        int trailer = TRAILER_FIELD;

        if (seq.peekTag() == TAG_HASH)
        {
            hash = readDigestAlgorithm(seq.readTLV(TAG_HASH, "hashAlgorithm [0]"), "hashAlgorithm");
        }
        if (seq.peekTag() == TAG_MGF)
        {
            Der.Reader mgfOuter = seq.readTLV(TAG_MGF, "maskGenAlgorithm [1]");
            Der.Reader mgfAlg = mgfOuter.readTLV(Der.SEQUENCE, "MaskGenAlgorithm SEQUENCE");
            mgfOuter.requireEnd("trailing bytes in maskGenAlgorithm [1]");
            String mgfOid = mgfAlg.readObjectIdentifier("maskGenAlgorithm OID");
            if (!PKCSObjectIdentifiers.id_mgf1.getId().equals(mgfOid))
            {
                throw new IOException("only MGF1 is supported (got " + mgfOid + ")");
            }
            mgfHash = readDigestAlgorithm(mgfAlg, "MGF1 hash");
            mgfAlg.requireEnd("trailing bytes in MaskGenAlgorithm");
        }
        if (seq.peekTag() == TAG_SALT)
        {
            Der.Reader saltOuter = seq.readTLV(TAG_SALT, "saltLength [2]");
            salt = saltOuter.readSmallInteger("saltLength INTEGER");
            saltOuter.requireEnd("trailing bytes in saltLength [2]");
        }
        if (seq.peekTag() == TAG_TRAILER)
        {
            Der.Reader trailerOuter = seq.readTLV(TAG_TRAILER, "trailerField [3]");
            trailer = trailerOuter.readSmallInteger("trailerField INTEGER");
            trailerOuter.requireEnd("trailing bytes in trailerField [3]");
        }
        seq.requireEnd("trailing bytes inside RSASSA-PSS-params");

        if (salt < 0 || salt > MAX_SALT_LENGTH)
        {
            throw new IOException("PSS salt length out of range [0, " + MAX_SALT_LENGTH + "]: " + salt);
        }
        if (trailer != TRAILER_FIELD)
        {
            throw new IOException("unsupported trailerField value " + trailer);
        }

        this.digest = hash;
        this.mgfDigest = mgfHash;
        this.saltLength = salt;
    }

    /**
     * Read a {@code HashAlgorithm} — an AlgorithmIdentifier whose parameters
     * are absent or NULL — and return the canonical JCA digest name.
     */
    private static String readDigestAlgorithm(Der.Reader outer, String what)
        throws IOException
    {
        Der.Reader alg = outer.readTLV(Der.SEQUENCE, what + " AlgorithmIdentifier");
        outer.requireEnd("trailing bytes in " + what);
        String oid = alg.readObjectIdentifier(what + " OID");
        if (!alg.atEnd())
        {
            // Absent parameters and an explicit NULL both mean the same thing
            // here; anything else is a structure we did not write.
            alg.readTLV(TAG_NULL, what + " NULL parameters");
            alg.requireEnd("trailing bytes after " + what + " parameters");
        }
        String name = OID_TO_DIGEST.get(oid);
        if (name == null)
        {
            throw new IOException("unsupported " + what + ": " + oid);
        }
        return name;
    }

    @Override
    protected void engineInit(byte[] params, String format)
        throws IOException
    {
        if (format == null || "ASN.1".equalsIgnoreCase(format) || "DER".equalsIgnoreCase(format))
        {
            engineInit(params);
            return;
        }
        throw new IOException("unsupported RSASSA-PSS parameters format: " + format);
    }

    @Override
    @SuppressWarnings("unchecked")
    protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> paramSpec)
        throws InvalidParameterSpecException
    {
        requireInitialised();
        if (paramSpec == null)
        {
            throw new InvalidParameterSpecException("null parameter spec class");
        }
        if (paramSpec.isAssignableFrom(PSSParameterSpec.class))
        {
            return (T) new PSSParameterSpec(digest, "MGF1",
                    new MGF1ParameterSpec(mgfDigest), saltLength, TRAILER_FIELD);
        }
        throw new InvalidParameterSpecException("unsupported parameter spec: " + paramSpec.getName());
    }

    @Override
    protected byte[] engineGetEncoded()
        throws IOException
    {
        if (digest == null)
        {
            throw new IOException("RSASSA-PSS parameters not initialised");
        }
        byte[] hashPart = DEFAULT_DIGEST.equals(digest)
                ? null
                : Der.tlv(TAG_HASH, digestAlgorithm(digest));
        byte[] mgfPart = DEFAULT_DIGEST.equals(mgfDigest)
                ? null
                : Der.tlv(TAG_MGF, Der.sequence(
                        Der.objectIdentifier(PKCSObjectIdentifiers.id_mgf1.getId()),
                        digestAlgorithm(mgfDigest)));
        byte[] saltPart = saltLength == DEFAULT_SALT_LENGTH
                ? null
                : Der.tlv(TAG_SALT, Der.integer(saltLength));
        // trailerField is always 1 here, which is the DEFAULT, so it is never
        // emitted.
        return Der.sequence(nonNull(hashPart, mgfPart, saltPart));
    }

    private static byte[] digestAlgorithm(String jcaName)
        throws IOException
    {
        String oid = DIGEST_TO_OID.get(jcaName);
        if (oid == null)
        {
            throw new IOException("unsupported digest: " + jcaName);
        }
        // The explicit NULL is what both references emit; an absent-parameters
        // form would decode the same and encode differently.
        return Der.sequence(Der.objectIdentifier(oid), Der.tlv(TAG_NULL, new byte[0]));
    }

    private static byte[][] nonNull(byte[]... items)
    {
        int n = 0;
        for (byte[] item : items)
        {
            if (item != null)
            {
                n++;
            }
        }
        byte[][] out = new byte[n][];
        int i = 0;
        for (byte[] item : items)
        {
            if (item != null)
            {
                out[i++] = item;
            }
        }
        return out;
    }

    @Override
    protected byte[] engineGetEncoded(String format)
        throws IOException
    {
        if (format == null || "ASN.1".equalsIgnoreCase(format) || "DER".equalsIgnoreCase(format))
        {
            return engineGetEncoded();
        }
        throw new IOException("unsupported RSASSA-PSS parameters format: " + format);
    }

    @Override
    protected String engineToString()
    {
        if (digest == null)
        {
            return "RSASSA-PSS parameters (uninitialised)";
        }
        return "RSASSA-PSS[hash=" + digest + ", MGF1=" + mgfDigest
                + ", saltLength=" + saltLength + ", trailerField=" + TRAILER_FIELD + "]";
    }

    private void requireInitialised()
        throws InvalidParameterSpecException
    {
        if (digest == null)
        {
            throw new InvalidParameterSpecException("RSASSA-PSS parameters not initialised");
        }
    }

    /** The canonical JCA name for an accepted spelling, or null. */
    private static String canonicalOrNull(String name)
    {
        if (name == null || name.isEmpty())
        {
            return null;
        }
        return ALIASES.get(name.toUpperCase(java.util.Locale.ROOT));
    }

    /**
     * The effective parameters an SPI reports when the caller supplied none.
     * Package-private: {@link RSAPSSSignatureSpi} builds its
     * {@code engineGetParameters} answer through this.
     */
    static PSSParameterSpec specFor(String digest, String mgfDigest, int saltLength)
    {
        return new PSSParameterSpec(digest, "MGF1",
                new MGF1ParameterSpec(mgfDigest), saltLength, TRAILER_FIELD);
    }
}
