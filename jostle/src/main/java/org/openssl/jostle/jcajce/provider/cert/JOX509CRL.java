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

import org.openssl.jostle.util.asn1.oids.X509ObjectIdentifiers;
import org.openssl.jostle.jcajce.provider.CertificateParseException;
import org.openssl.jostle.jcajce.provider.binding.ProviderBinding;
import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.asn1.Der;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * An X.509 CRL parsed by OpenSSL, built the same way as
 * {@link JOX509Certificate}: every field copied out at construction, no native
 * handle retained, the encoding COMPOSED rather than taken from
 * {@code i2d_X509_CRL}.
 */
class JOX509CRL
    extends X509CRL
{
    /** RFC 5280 §5.3.3 certificateIssuer. */
    private static final String CERTIFICATE_ISSUER_OID = X509ObjectIdentifiers.id_ce_certificateIssuer.getId();

    private final ProviderBinding binding;
    private final byte[] encoded;
    private final byte[] tbs;
    private final X500Principal issuer;
    private final byte[] signature;
    private final String sigAlgOid;
    private final byte[] sigAlgParams;
    private final int version;
    private final Date thisUpdate;
    private final Date nextUpdate;

    private final Map<String, byte[]> extensionValues;
    private final Set<String> criticalOids;
    private final Set<String> nonCriticalOids;

    /** Null when the CRL has no entries, per the X509CRL contract. */
    private final Set<X509CRLEntry> entries;
    /**
     * Keyed on (EFFECTIVE ISSUER, serial), never serial alone. An indirect CRL
     * may legitimately carry one serial under two issuers (RFC 5280 5.3.3),
     * and a serial-only index silently keeps whichever came last. Measured
     * against an indirect CRL carrying serial 4242 under both the CRL issuer
     * and another CA: SUN and BouncyCastle both answer
     * getRevokedCertificate(serial) with the entry under the CRL's OWN issuer,
     * while a serial-only index answered with the other one.
     */
    private final Map<IssuerSerial, JOX509CRLEntry> byIssuerSerial;

    JOX509CRL(ProviderBinding binding, byte[] blob, int[] sizes, int[] info,
              byte[] extBlob, int[] extOidSizes, int[] extValSizes, int[] extCritical,
              byte[] entryBlob, int[] entrySizes, int[] entryDates)
    {
        this.binding = binding;

        int[] off = new int[1];
        this.encoded = slice(blob, off, sizes[X509NI.CRL_SLOT_ENCODED]);
        this.tbs = slice(blob, off, sizes[X509NI.CRL_SLOT_TBS]);
        byte[] issuerDer = slice(blob, off, sizes[X509NI.CRL_SLOT_ISSUER]);
        this.signature = slice(blob, off, sizes[X509NI.CRL_SLOT_SIGNATURE]);
        this.sigAlgOid = ascii(slice(blob, off, sizes[X509NI.CRL_SLOT_SIGALG_OID]));
        byte[] params = slice(blob, off, sizes[X509NI.CRL_SLOT_SIGALG_PARAMS]);

        this.sigAlgParams = params.length == 0 ? null : params;
        this.issuer = new X500Principal(issuerDer);
        this.version = info[X509NI.CRL_INFO_VERSION];
        this.thisUpdate = new Date(seconds(info, X509NI.CRL_INFO_THIS_UPDATE_HI) * 1000L);
        this.nextUpdate = (info[X509NI.CRL_INFO_HAS_NEXT_UPDATE] == 1)
                ? new Date(seconds(info, X509NI.CRL_INFO_NEXT_UPDATE_HI) * 1000L)
                : null;

        int extCount = info[X509NI.CRL_INFO_EXT_COUNT];
        if (extCount == 0)
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
            int oidOff = 0;
            int valOff = 0;
            for (int i = 0; i < extCount; i++)
            {
                valOff += extOidSizes[i];
            }
            for (int i = 0; i < extCount; i++)
            {
                String oid = ascii(java.util.Arrays.copyOfRange(extBlob, oidOff, oidOff + extOidSizes[i]));
                oidOff += extOidSizes[i];
                values.put(oid, java.util.Arrays.copyOfRange(extBlob, valOff, valOff + extValSizes[i]));
                valOff += extValSizes[i];
                if (extCritical[i] == 1)
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

        int entryCount = info[X509NI.CRL_INFO_ENTRY_COUNT];
        if (entryCount == 0)
        {
            // Null, not an empty set. Measured: SUN and BouncyCastle both
            // return null from getRevokedCertificates for a CRL with no
            // entries, and X509CRL's contract says so.
            this.entries = null;
            this.byIssuerSerial = Collections.emptyMap();
        }
        else
        {
            Set<X509CRLEntry> set = new LinkedHashSet<X509CRLEntry>(entryCount);
            Map<IssuerSerial, JOX509CRLEntry> index =
                    new LinkedHashMap<IssuerSerial, JOX509CRLEntry>(entryCount);

            /*
             * RFC 5280 §5.3.3: a certificateIssuer extension applies to its
             * entry AND to every following entry until the next one appears;
             * entries before the first take the CRL's own issuer. So the
             * issuer is carried FORWARD while the list is built — it cannot be
             * derived from an entry in isolation.
             */
            X500Principal running = issuer;
            int entryOff = 0;
            for (int i = 0; i < entryCount; i++)
            {
                byte[] der = java.util.Arrays.copyOfRange(entryBlob, entryOff, entryOff + entrySizes[i]);
                entryOff += entrySizes[i];

                // Built once with the CRL issuer to read its own extension,
                // then rebuilt with the resolved issuer. Cheap, and it keeps
                // the resolution in ONE place rather than inside the entry.
                JOX509CRLEntry probe = new JOX509CRLEntry(der, 0L, null);
                byte[] ci = probe.rawExtension(CERTIFICATE_ISSUER_OID);
                if (ci != null)
                {
                    X500Principal named = directoryName(ci);
                    if (named != null)
                    {
                        running = named;
                    }
                }

                long secs = ((long) entryDates[2 * i] << 32) | (entryDates[2 * i + 1] & 0xFFFFFFFFL);
                // Null when the effective issuer IS the CRL issuer, which is
                // the contract's sentence, compared canonically rather than as
                // rendered text.
                X500Principal effective = issuer.equals(running) ? null : running;

                JOX509CRLEntry entry = new JOX509CRLEntry(der, secs, effective);
                set.add(entry);
                // FIRST wins on an exact (issuer, serial) repeat. UNMEASURED
                // against the references, which is why it is stated rather
                // than relied on; the case this index exists for is the same
                // serial under DIFFERENT issuers, where both keys are distinct.
                IssuerSerial key = new IssuerSerial(running, entry.getSerialNumber());
                if (!index.containsKey(key))
                {
                    index.put(key, entry);
                }
            }
            this.entries = Collections.unmodifiableSet(set);
            this.byIssuerSerial = Collections.unmodifiableMap(index);
        }
    }

    /** (effective issuer, serial) — an entry's identity on an indirect CRL. */
    private static final class IssuerSerial
    {
        private final X500Principal issuer;
        private final BigInteger serial;

        IssuerSerial(X500Principal issuer, BigInteger serial)
        {
            this.issuer = issuer;
            this.serial = serial;
        }

        @Override
        public boolean equals(Object other)
        {
            if (!(other instanceof IssuerSerial))
            {
                return false;
            }
            IssuerSerial o = (IssuerSerial) other;
            return serial.equals(o.serial) && issuer.equals(o.issuer);
        }

        @Override
        public int hashCode()
        {
            return serial.hashCode() * 31 + issuer.hashCode();
        }
    }

    /**
     * The first directoryName out of a certificateIssuer extension value.
     *
     * <p>{@code certificateIssuer ::= GeneralNames} (RFC 5280 §5.3.3), and the
     * form that names an X.500 issuer is the {@code [4] directoryName} choice.
     * Anything else is not an issuer this can compare against the CRL's, so it
     * is ignored rather than guessed at.
     */
    private static X500Principal directoryName(byte[] extensionValue)
    {
        try
        {
            Der.Reader outer = new Der.Reader(extensionValue);
            byte[] inner = outer.readTLV(Der.OCTET_STRING, "certificateIssuer").remaining();
            Der.Reader names = new Der.Reader(inner).readTLV(Der.SEQUENCE, "GeneralNames");
            while (!names.atEnd())
            {
                int tag = names.peekTag();
                byte[] body = names.readTLV(tag, "GeneralName").remaining();
                if ((tag & 0x1F) == 4)
                {
                    return new X500Principal(body);
                }
            }
            return null;
        }
        catch (IOException | RuntimeException e)
        {
            return null;
        }
    }

    private static long seconds(int[] info, int hiIndex)
    {
        return ((long) info[hiIndex] << 32) | (info[hiIndex + 1] & 0xFFFFFFFFL);
    }

    private static byte[] slice(byte[] blob, int[] off, int len)
    {
        byte[] out = java.util.Arrays.copyOfRange(blob, off[0], off[0] + len);
        off[0] += len;
        return out;
    }

    private static String ascii(byte[] b)
    {
        if (b.length == 0)
        {
            return null;
        }
        try
        {
            return new String(b, "US-ASCII");
        }
        catch (java.io.UnsupportedEncodingException e)
        {
            throw new IllegalStateException("US-ASCII is required of every JVM", e);
        }
    }

    public byte[] getEncoded()
        throws CRLException
    {
        return Arrays.clone(encoded);
    }

    public byte[] getTBSCertList()
        throws CRLException
    {
        return Arrays.clone(tbs);
    }

    public int getVersion()
    {
        return version;
    }

    public Principal getIssuerDN()
    {
        return new JcaDistinguishedName(issuer);
    }

    public X500Principal getIssuerX500Principal()
    {
        return issuer;
    }

    public Date getThisUpdate()
    {
        return new Date(thisUpdate.getTime());
    }

    public Date getNextUpdate()
    {
        return nextUpdate == null ? null : new Date(nextUpdate.getTime());
    }

    /**
     * {@inheritDoc}
     *
     * <p>Looked up under the CRL's OWN issuer, which is what the references do:
     * this overload names no issuer, so the only one it can mean is the CRL's.
     * An entry that an indirect CRL attributes to another CA is reachable
     * through the {@link #getRevokedCertificate(X509Certificate)} overload,
     * which does name one.
     */
    public X509CRLEntry getRevokedCertificate(BigInteger serialNumber)
    {
        return serialNumber == null ? null : byIssuerSerial.get(new IssuerSerial(issuer, serialNumber));
    }

    /**
     * {@inheritDoc}
     *
     * <p>Serial AND issuer, per the contract: on an indirect CRL the entry's
     * EFFECTIVE issuer under RFC 5280 §5.3.3 is what must match, not the CRL's.
     */
    public X509CRLEntry getRevokedCertificate(X509Certificate certificate)
    {
        if (certificate == null)
        {
            return null;
        }
        // Straight to the (issuer, serial) key: the certificate names its own
        // issuer, so there is nothing to search and nothing to re-check. The
        // earlier form looked up on serial alone and then compared issuers,
        // which returned null whenever a same-serial entry under a DIFFERENT
        // issuer had displaced this one in the index.
        return byIssuerSerial.get(
                new IssuerSerial(certificate.getIssuerX500Principal(), certificate.getSerialNumber()));
    }

    public Set<? extends X509CRLEntry> getRevokedCertificates()
    {
        return entries;
    }

    public boolean isRevoked(Certificate certificate)
    {
        if (!(certificate instanceof X509Certificate))
        {
            return false;
        }
        return getRevokedCertificate((X509Certificate) certificate) != null;
    }

    public byte[] getSignature()
    {
        return Arrays.clone(signature);
    }

    public String getSigAlgOID()
    {
        return sigAlgOid;
    }

    public String getSigAlgName()
    {
        return SigAlgNames.nameFor(sigAlgOid, sigAlgParams);
    }

    public byte[] getSigAlgParams()
    {
        return Arrays.clone(sigAlgParams);
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
            if (!SupportedExtensions.isSupportedOnCrl(oid))
            {
                return true;
            }
        }
        return false;
    }

    public void verify(PublicKey key)
        throws CRLException, NoSuchAlgorithmException, InvalidKeyException,
               NoSuchProviderException, SignatureException
    {
        doVerify(key, CertKeys.signatureFor(binding, getSigAlgName()));
    }

    public void verify(PublicKey key, String sigProvider)
        throws CRLException, NoSuchAlgorithmException, InvalidKeyException,
               NoSuchProviderException, SignatureException
    {
        // A null provider resolves through the provider this CRL BELONGS TO,
        // never through JCA search order. "The default provider" for an object
        // this provider built is this provider: reaching for the installed
        // list would verify a JSLFIPS CRL outside the module, and nothing
        // behavioural could see it.
        doVerify(key, (sigProvider == null)
                ? CertKeys.signatureFor(binding, getSigAlgName())
                : Signature.getInstance(getSigAlgName(), sigProvider));
    }

    public void verify(PublicKey key, Provider sigProvider)
        throws CRLException, NoSuchAlgorithmException, InvalidKeyException, SignatureException
    {
        // A null provider resolves through the provider this CRL BELONGS TO,
        // never through JCA search order. "The default provider" for an object
        // this provider built is this provider: reaching for the installed
        // list would verify a JSLFIPS CRL outside the module, and nothing
        // behavioural could see it.
        doVerify(key, (sigProvider == null)
                ? CertKeys.signatureFor(binding, getSigAlgName())
                : Signature.getInstance(getSigAlgName(), sigProvider));
    }

    private void doVerify(PublicKey key, Signature verifier)
        throws CRLException, NoSuchAlgorithmException, InvalidKeyException, SignatureException
    {
        if (sigAlgParams != null)
        {
            try
            {
                AlgorithmParameters params =
                        AlgorithmParameters.getInstance(getSigAlgName(), verifier.getProvider());
                params.init(sigAlgParams);
                verifier.setParameter(params.getParameterSpec(AlgorithmParameterSpec.class));
            }
            catch (NoSuchAlgorithmException | IOException | InvalidParameterSpecException
                   | InvalidAlgorithmParameterException e)
            {
                throw new CRLException(
                        "unable to apply the CRL's signature parameters for " + getSigAlgName(), e);
            }
        }
        verifier.initVerify(key);
        verifier.update(tbs);
        if (!verifier.verify(signature))
        {
            throw new SignatureException("CRL signature did not verify");
        }
    }

    public String toString()
    {
        return "X.509 CRL issued by [" + issuer.getName() + "] on " + thisUpdate;
    }
}
