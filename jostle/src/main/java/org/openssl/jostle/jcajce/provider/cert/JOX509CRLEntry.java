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

import org.openssl.jostle.jcajce.provider.CertificateParseException;
import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.asn1.Der;
import org.openssl.jostle.util.asn1.oids.X509ObjectIdentifiers;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CRLException;
import java.security.cert.CRLReason;
import java.security.cert.X509CRLEntry;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * One revoked entry, decoded from the DER the native layer handed back.
 *
 * <pre>
 * revokedCertificate ::= SEQUENCE {
 *     userCertificate     CertificateSerialNumber,
 *     revocationDate      Time,
 *     crlEntryExtensions  Extensions OPTIONAL }
 * </pre>
 * (RFC 5280 §5.1). The revocation date comes from OpenSSL rather than from
 * this parse — {@code Time} is a CHOICE of UTCTime and GeneralizedTime with
 * two-digit-year rules, and re-implementing that in Java would be a second
 * source of truth for a value the native side already has.
 */
class JOX509CRLEntry
    extends X509CRLEntry
{
    private final byte[] encoded;
    private final BigInteger serialNumber;
    private final Date revocationDate;
    private final Map<String, byte[]> extensionValues;
    private final Set<String> criticalOids;
    private final Set<String> nonCriticalOids;

    /**
     * The issuer this entry's certificate was issued by, already resolved by
     * {@link JOX509CRL} under RFC 5280 §5.3.3, or null when it is the CRL's
     * own issuer.
     */
    private final X500Principal certificateIssuer;

    JOX509CRLEntry(byte[] entryDer, long revocationSeconds, X500Principal certificateIssuer)
    {
        this.encoded = entryDer;
        this.revocationDate = new Date(revocationSeconds * 1000L);
        this.certificateIssuer = certificateIssuer;

        try
        {
            Der.Reader entry = new Der.Reader(entryDer).readTLV(Der.SEQUENCE, "revokedCertificate");
            // Two's complement from the INTEGER's own content octets, NOT
            // Der.Reader.readInteger, which refuses a negative value. A CRL
            // entry's userCertificate serial may legitimately be negative —
            // SUN reads NegativeSerialNumberCACRL's single entry as -1, and
            // PKITS carries that file to test exactly this. Same reason the
            // certificate's serial is read from its TLV rather than through
            // OpenSSL's magnitude-plus-flag BIGNUM.
            byte[] serialOctets = entry.readTLV(Der.INTEGER, "userCertificate").remaining();
            if (serialOctets.length == 0)
            {
                throw new CertificateParseException("userCertificate INTEGER is empty");
            }
            this.serialNumber = new BigInteger(serialOctets);
            // revocationDate: consumed and discarded, its value coming from
            // OpenSSL. peekTag because Time is a CHOICE.
            entry.readTLV(entry.peekTag(), "revocationDate");

            if (entry.atEnd())
            {
                this.extensionValues = null;
                this.criticalOids = null;
                this.nonCriticalOids = null;
            }
            else
            {
                Map<String, byte[]> values = new LinkedHashMap<String, byte[]>();
                Set<String> crit = new TreeSet<String>();
                Set<String> nonCrit = new TreeSet<String>();
                Der.Reader exts = entry.readTLV(Der.SEQUENCE, "crlEntryExtensions");
                while (!exts.atEnd())
                {
                    Der.Reader ext = exts.readTLV(Der.SEQUENCE, "Extension");
                    String oid = ext.readObjectIdentifier("extnID");
                    boolean critical = false;
                    if (ext.peekTag() == 0x01)
                    {
                        // critical BOOLEAN DEFAULT FALSE. The length is checked
                        // because the contents are indexed: a zero-length
                        // BOOLEAN made this remaining()[0] and threw
                        // ArrayIndexOutOfBoundsException, an unchecked throw
                        // out of generateCRL. X.690 8.2 gives a BOOLEAN exactly
                        // one content octet.
                        byte[] flag = ext.readTLV(0x01, "critical").remaining();
                        if (flag.length != 1)
                        {
                            throw new CertificateParseException(
                                    "CRL entry extension " + oid + " has a critical BOOLEAN of "
                                            + flag.length + " octets; X.690 requires exactly one");
                        }
                        critical = flag[0] != 0;
                    }
                    byte[] value = ext.readTLV(Der.OCTET_STRING, "extnValue").remaining();
                    // Wrapped as getExtensionValue's contract requires: the
                    // OCTET STRING, not its contents.
                    byte[] wrapped = Der.tlv(Der.OCTET_STRING, value);

                    // Same uniqueness rule the native side applies to
                    // certificate and CRL extensions: a repeated OID is
                    // refused, not silently resolved to one of them.
                    if (values.put(oid, wrapped) != null)
                    {
                        throw new CertificateParseException(
                                "CRL entry extension " + oid + " occurs more than once");
                    }
                    if (critical)
                    {
                        crit.add(oid);
                    }
                    else
                    {
                        nonCrit.add(oid);
                    }
                }
                this.extensionValues = values;
                this.criticalOids = Collections.unmodifiableSet(crit);
                this.nonCriticalOids = Collections.unmodifiableSet(nonCrit);
            }
        }
        catch (IOException e)
        {
            throw new CertificateParseException("unable to decode a CRL entry", e);
        }
        catch (CertificateParseException e)
        {
            // Already the typed refusal; re-wrapping would bury its message.
            throw e;
        }
        catch (RuntimeException e)
        {
            // The DER walk indexes and slices, so a malformed entry could reach
            // an unchecked throw that is not an IOException, and that would
            // escape generateCRL, whose contract is CRLException.
            //
            // UNREACHABLE BY CONSTRUCTION today, and deliberately kept: this
            // walk only ever sees OpenSSL's OWN re-encoding of an entry
            // (x509.c's i2d_X509_REVOKED), so the bytes have already survived
            // d2i and been normalised to DER. It has NO test for that reason —
            // an input contrived to break the walk is refused by d2i first, so
            // a cell would go green on JO_CRL_DECODE_FAILED and prove nothing
            // about this arm. Defence in depth against a future caller that
            // feeds this class DER from somewhere else.
            throw new CertificateParseException("malformed CRL entry", e);
        }
    }

    /**
     * The revocation reason, from this entry's own cRLReasons extension.
     *
     * <p>OVERRIDDEN because the inherited default is a SECOND PARSER: the base
     * class re-parses {@code getEncoded()} through
     * {@code sun.security.x509.X509CRLEntryImpl}, so without this the reason
     * would be read by the JDK while every other field on this object is read
     * by OpenSSL.
     *
     * <p>{@code cRLReason ::= ENUMERATED}, RFC 5280 5.3.1. An absent extension
     * is null, per the method's contract; a value outside the enum is null
     * rather than a guess, because the JDK's {@code CRLReason} has no room for
     * one and inventing a mapping would be worse than admitting ignorance.
     */
    @Override
    public CRLReason getRevocationReason()
    {
        byte[] wrapped = rawExtension(X509ObjectIdentifiers.id_ce_cRLReasons.getId());
        if (wrapped == null)
        {
            return null;
        }
        try
        {
            // rawExtension hands back the WRAPPING OCTET STRING, so unwrap it
            // and then read the ENUMERATED inside.
            byte[] inner = new Der.Reader(wrapped)
                    .readTLV(Der.OCTET_STRING, "cRLReasons extnValue").remaining();
            byte[] content = new Der.Reader(inner).readTLV(0x0A, "cRLReason").remaining();
            if (content.length != 1)
            {
                // A multi-octet reason is not one this enum can name.
                return null;
            }
            int code = content[0] & 0xFF;
            CRLReason[] all = CRLReason.values();
            return code < all.length ? all[code] : null;
        }
        catch (IOException e)
        {
            throw new CertificateParseException("unable to decode the CRL entry reason code", e);
        }
    }

    /**
     * The raw extension value as {@code getExtensionValue} reports it —
     * the WRAPPING OCTET STRING included, not its contents. The caller
     * unwraps; {@link JOX509CRL}'s certificateIssuer read is the one that does.
     */
    byte[] rawExtension(String oid)
    {
        if (extensionValues == null)
        {
            return null;
        }
        return extensionValues.get(oid);
    }

    public byte[] getEncoded()
        throws CRLException
    {
        return Arrays.clone(encoded);
    }

    public BigInteger getSerialNumber()
    {
        return serialNumber;
    }

    /**
     * {@inheritDoc}
     *
     * <p>Null when the entry's issuer is the CRL's own, which is the contract:
     * "If the certificate issuer is also the CRL issuer, this method returns
     * null." {@link JOX509CRL} resolves the running issuer under RFC 5280
     * §5.3.3 and passes the ANSWER in, so this accessor holds no logic.
     *
     * <p>Measured divergence: BouncyCastle returns the issuer even when it
     * equals the CRL issuer, which the sentence above forbids.
     */
    public X500Principal getCertificateIssuer()
    {
        return certificateIssuer;
    }

    public Date getRevocationDate()
    {
        return new Date(revocationDate.getTime());
    }

    public boolean hasExtensions()
    {
        return extensionValues != null;
    }

    public Set<String> getCriticalExtensionOIDs()
    {
        return criticalOids;
    }

    public Set<String> getNonCriticalExtensionOIDs()
    {
        return nonCriticalOids;
    }

    public byte[] getExtensionValue(String oid)
    {
        if (extensionValues == null || oid == null)
        {
            return null;
        }
        return Arrays.clone(extensionValues.get(oid));
    }

    public boolean hasUnsupportedCriticalExtension()
    {
        if (criticalOids == null)
        {
            return false;
        }
        for (String oid : criticalOids)
        {
            if (!SupportedExtensions.isSupportedOnCrlEntry(oid))
            {
                return true;
            }
        }
        return false;
    }

    public String toString()
    {
        return "X.509 CRL entry serial " + serialNumber + " revoked " + revocationDate;
    }
}
