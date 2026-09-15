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

import org.openssl.jostle.util.asn1.oids.EdECObjectIdentifiers;
import org.openssl.jostle.util.asn1.oids.NISTObjectIdentifiers;
import org.openssl.jostle.util.asn1.oids.PKCSObjectIdentifiers;
import org.openssl.jostle.util.asn1.oids.X9ObjectIdentifiers;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Signature algorithm OID to the name {@code getSigAlgName()} reports.
 *
 * <p>These are JCA NAMES, which OpenSSL does not own, so they are a table
 * rather than a query — the same exemption the project applies to algorithm
 * names and OID strings generally.
 *
 * <p><b>The spellings are the JDK's</b>, which is both the ruling and what
 * this provider already shipped while it delegated, so no caller sees a
 * change. Measured, BouncyCastle differs on 401 of 405 corpus certificates —
 * {@code SHA256WITHRSA} against {@code SHA256withRSA} — and differs in more
 * than case on PSS, where it reports {@code SHA256withRSAandMGF1} where the
 * JDK reports {@code RSASSA-PSS}. Both are pinned as directional divergences.
 *
 * <p>An OID with no entry reports the OID itself, which is what the JDK does.
 */
final class SigAlgNames
{
    private static final Map<String, String> NAMES;

    static
    {
        Map<String, String> m = new HashMap<String, String>();
        // RFC 8017 PKCS#1
        m.put(PKCSObjectIdentifiers.sha1WithRSAEncryption.getId(), "SHA1withRSA");
        m.put(PKCSObjectIdentifiers.sha256WithRSAEncryption.getId(), "SHA256withRSA");
        m.put(PKCSObjectIdentifiers.sha384WithRSAEncryption.getId(), "SHA384withRSA");
        m.put(PKCSObjectIdentifiers.sha512WithRSAEncryption.getId(), "SHA512withRSA");
        m.put(PKCSObjectIdentifiers.sha224WithRSAEncryption.getId(), "SHA224withRSA");
        m.put(PKCSObjectIdentifiers.id_RSASSA_PSS.getId(), "RSASSA-PSS");
        // RFC 5758 / FIPS 186 DSA and ECDSA
        m.put(X9ObjectIdentifiers.id_dsa_with_sha1.getId(), "SHA1withDSA");
        m.put(NISTObjectIdentifiers.dsa_with_sha224.getId(), "SHA224withDSA");
        m.put(NISTObjectIdentifiers.dsa_with_sha256.getId(), "SHA256withDSA");
        m.put(X9ObjectIdentifiers.ecdsa_with_SHA1.getId(), "SHA1withECDSA");
        m.put(X9ObjectIdentifiers.ecdsa_with_SHA224.getId(), "SHA224withECDSA");
        m.put(X9ObjectIdentifiers.ecdsa_with_SHA256.getId(), "SHA256withECDSA");
        m.put(X9ObjectIdentifiers.ecdsa_with_SHA384.getId(), "SHA384withECDSA");
        m.put(X9ObjectIdentifiers.ecdsa_with_SHA512.getId(), "SHA512withECDSA");
        // RFC 8410
        m.put(EdECObjectIdentifiers.id_Ed25519.getId(), "Ed25519");
        m.put(EdECObjectIdentifiers.id_Ed448.getId(), "Ed448");

        // ---- arm (a): the JDK registers this OID, so its EXACT spelling,
        // case included. Eighteen rows, each verified against whichever JDK
        // provider aliases the OID.
        m.put(PKCSObjectIdentifiers.md5WithRSAEncryption.getId(), "MD5withRSA");
        m.put(NISTObjectIdentifiers.dsa_with_sha384.getId(), "SHA384withDSA");
        m.put(NISTObjectIdentifiers.dsa_with_sha512.getId(), "SHA512withDSA");
        m.put(NISTObjectIdentifiers.id_dsa_with_sha3_224.getId(), "SHA3-224withDSA");
        m.put(NISTObjectIdentifiers.id_dsa_with_sha3_256.getId(), "SHA3-256withDSA");
        m.put(NISTObjectIdentifiers.id_dsa_with_sha3_384.getId(), "SHA3-384withDSA");
        m.put(NISTObjectIdentifiers.id_dsa_with_sha3_512.getId(), "SHA3-512withDSA");
        m.put(NISTObjectIdentifiers.id_ecdsa_with_sha3_224.getId(), "SHA3-224withECDSA");
        m.put(NISTObjectIdentifiers.id_ecdsa_with_sha3_256.getId(), "SHA3-256withECDSA");
        m.put(NISTObjectIdentifiers.id_ecdsa_with_sha3_384.getId(), "SHA3-384withECDSA");
        m.put(NISTObjectIdentifiers.id_ecdsa_with_sha3_512.getId(), "SHA3-512withECDSA");
        m.put(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_224.getId(), "SHA3-224withRSA");
        m.put(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_256.getId(), "SHA3-256withRSA");
        m.put(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_384.getId(), "SHA3-384withRSA");
        m.put(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_512.getId(), "SHA3-512withRSA");
        m.put(NISTObjectIdentifiers.id_ml_dsa_44.getId(), "ML-DSA-44");
        m.put(NISTObjectIdentifiers.id_ml_dsa_65.getId(), "ML-DSA-65");
        m.put(NISTObjectIdentifiers.id_ml_dsa_87.getId(), "ML-DSA-87");

        // ---- arm (b): the truncated SHA-512s, where the JDK's names and ours
        // are a DIFFERENT naming domain (BouncyCastle takes SHA512(224),
        // OpenSSL takes SHA-512/224 and each refuses the other). Our own
        // spelling, per that recorded divergence.
        m.put(PKCSObjectIdentifiers.sha512_224WithRSAEncryption.getId(), "SHA512(224)WITHRSA");
        m.put(PKCSObjectIdentifiers.sha512_256WithRSAEncryption.getId(), "SHA512(256)WITHRSA");

        // ---- arm (c): no JDK provider registers these OIDs, so there is no
        // oracle. Our own PRIMARY Signature service name, which guarantees
        // getSigAlgName() always returns something
        // Signature.getInstance(name, thisProvider) accepts.
        m.put(NISTObjectIdentifiers.id_slh_dsa_sha2_128s.getId(), "SLH-DSA-SHA2-128S");
        m.put(NISTObjectIdentifiers.id_slh_dsa_sha2_128f.getId(), "SLH-DSA-SHA2-128F");
        m.put(NISTObjectIdentifiers.id_slh_dsa_sha2_192s.getId(), "SLH-DSA-SHA2-192S");
        m.put(NISTObjectIdentifiers.id_slh_dsa_sha2_192f.getId(), "SLH-DSA-SHA2-192F");
        m.put(NISTObjectIdentifiers.id_slh_dsa_sha2_256s.getId(), "SLH-DSA-SHA2-256S");
        m.put(NISTObjectIdentifiers.id_slh_dsa_sha2_256f.getId(), "SLH-DSA-SHA2-256F");
        m.put(NISTObjectIdentifiers.id_slh_dsa_shake_128s.getId(), "SLH-DSA-SHAKE-128S");
        m.put(NISTObjectIdentifiers.id_slh_dsa_shake_128f.getId(), "SLH-DSA-SHAKE-128F");
        m.put(NISTObjectIdentifiers.id_slh_dsa_shake_192s.getId(), "SLH-DSA-SHAKE-192S");
        m.put(NISTObjectIdentifiers.id_slh_dsa_shake_192f.getId(), "SLH-DSA-SHAKE-192F");
        m.put(NISTObjectIdentifiers.id_slh_dsa_shake_256s.getId(), "SLH-DSA-SHAKE-256S");
        m.put(NISTObjectIdentifiers.id_slh_dsa_shake_256f.getId(), "SLH-DSA-SHAKE-256F");

        NAMES = Collections.unmodifiableMap(m);
    }

    private SigAlgNames()
    {
    }

    /**
     * @param params the encoded signature parameters, or null. Unused today —
     *               {@code RSASSA-PSS} reports one name whatever its
     *               parameters say, as the JDK does — and present because a
     *               name that depended on them would otherwise be added by
     *               changing this signature everywhere.
     */
    static String nameFor(String oid, byte[] params)
    {
        if (oid == null)
        {
            return null;
        }
        String name = NAMES.get(oid);
        return name != null ? name : oid;
    }
}
