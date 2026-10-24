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
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * The digest spellings the RSA PSS and OAEP surfaces accept, the canonical JCA name each maps to, and that name's
 * OID. The map only normalises spellings: whether the loaded library serves a digest is asked of the library.
 */
final class RSADigestNames
{
    private static final int TAG_NULL = 0x05;

    /** Canonical JCA digest name to its OID. */
    private static final Map<String, String> DIGEST_TO_OID;
    /** OID back to the canonical JCA name. */
    private static final Map<String, String> OID_TO_DIGEST;
    /** Accepted spelling, upper-cased, to the canonical JCA name. */
    private static final Map<String, String> ALIASES;

    static
    {
        Map<String, String> toOid = new LinkedHashMap<String, String>();
        toOid.put("MD5", PKCSObjectIdentifiers.md5.getId());
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
            aliases.put(canonical.toUpperCase(Locale.ROOT), canonical);
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

    private RSADigestNames()
    {
    }

    /** The canonical JCA name for an accepted spelling, or null. */
    static String canonicalDigestName(String name)
    {
        if (name == null || name.isEmpty())
        {
            return null;
        }
        return ALIASES.get(name.toUpperCase(Locale.ROOT));
    }

    /**
     * A {@code HashAlgorithm} AlgorithmIdentifier for a canonical name, with the explicit NULL parameters both
     * references emit.
     */
    static byte[] hashAlgorithmIdentifier(String jcaName)
        throws IOException
    {
        String oid = DIGEST_TO_OID.get(jcaName);
        if (oid == null)
        {
            throw new IOException("unsupported digest: " + jcaName);
        }
        return Der.sequence(Der.objectIdentifier(oid), Der.tlv(TAG_NULL, new byte[0]));
    }

    /**
     * Reads a {@code HashAlgorithm} AlgorithmIdentifier, whose parameters are absent or NULL, from the explicit tag
     * wrapping it, and returns the canonical JCA name.
     */
    static String readHashAlgorithm(Der.Reader outer, String what)
        throws IOException
    {
        Der.Reader alg = outer.readTLV(Der.SEQUENCE, what + " AlgorithmIdentifier");
        outer.requireEnd("trailing bytes in " + what);
        return readHashAlgorithmBody(alg, what);
    }

    /** As {@link #readHashAlgorithm}, over the AlgorithmIdentifier's contents. */
    static String readHashAlgorithmBody(Der.Reader alg, String what)
        throws IOException
    {
        String oid = alg.readObjectIdentifier(what + " OID");
        if (!alg.atEnd())
        {
            // Absent parameters and an explicit NULL both mean the same thing here.
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
}
