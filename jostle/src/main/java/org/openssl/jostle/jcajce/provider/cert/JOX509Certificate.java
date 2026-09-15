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
import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.asn1.Der;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import org.openssl.jostle.jcajce.provider.binding.ProviderBinding;

import java.security.Principal;
import java.security.Provider;
import java.security.ProviderException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * An X.509 certificate parsed by OpenSSL.
 *
 * <p>Every fixed field is decoded ONCE at construction, from a single native
 * call, into final Java fields. Only {@link #getPublicKey()} needs the live
 * {@code X509*} afterwards — a certificate whose key algorithm the provider's
 * lib ctx does not serve must still parse and answer every structural accessor
 * (measured on the 3.1.2 FIPS module with an Ed25519 certificate), so the key
 * cannot be built eagerly. That shape also keeps the reachability-fence
 * surface down to the one method that needs it.
 *
 * <p><b>Non-DER input is accepted and NORMALISED.</b> {@link #getEncoded()}
 * returns the composed DER, not the bytes supplied, so two byte-distinct
 * encodings of one certificate produce objects that are {@code equals}, share
 * a {@code hashCode} and both verify. A relying party fingerprinting the bytes
 * it received and one comparing certificate objects will therefore disagree
 * about whether they hold the same certificate. That is BouncyCastle's
 * behaviour and it is deliberate here.
 */
class JOX509Certificate
    extends X509Certificate
{
    private final ProviderBinding binding;
    private final byte[] spki;
    private final boolean inheritedDsaParameters;

    private final byte[] encoded;
    private final byte[] tbs;
    private final BigInteger serialNumber;
    private final X500Principal issuer;
    private final X500Principal subject;
    private final byte[] signature;
    private final String sigAlgOid;
    private final byte[] sigAlgParams;
    private final String spkiAlgOid;
    private final boolean[] issuerUniqueId;
    private final boolean[] subjectUniqueId;
    private final int version;
    private final Date notBefore;
    private final Date notAfter;
    private final int basicConstraints;
    private final boolean[] keyUsage;

    /** Null when the certificate carries NO extensions at all; see below. */
    private final Map<String, byte[]> extensionValues;
    private final Set<String> criticalOids;
    private final Set<String> nonCriticalOids;

    JOX509Certificate(ProviderBinding binding, byte[] blob, int[] sizes, int[] info,
                      byte[] extBlob, int[] extOidSizes, int[] extValSizes, int[] extCritical)
    {
        this.binding = binding;

        int[] off = new int[1];
        this.encoded = slice(blob, off, sizes[X509NI.SLOT_ENCODED]);
        this.tbs = slice(blob, off, sizes[X509NI.SLOT_TBS]);
        byte[] serialTlv = slice(blob, off, sizes[X509NI.SLOT_SERIAL]);
        byte[] issuerDer = slice(blob, off, sizes[X509NI.SLOT_ISSUER]);
        byte[] subjectDer = slice(blob, off, sizes[X509NI.SLOT_SUBJECT]);
        this.signature = slice(blob, off, sizes[X509NI.SLOT_SIGNATURE]);
        this.sigAlgOid = ascii(slice(blob, off, sizes[X509NI.SLOT_SIGALG_OID]));
        byte[] params = slice(blob, off, sizes[X509NI.SLOT_SIGALG_PARAMS]);
        byte[] iuid = slice(blob, off, sizes[X509NI.SLOT_ISSUER_UID]);
        byte[] suid = slice(blob, off, sizes[X509NI.SLOT_SUBJECT_UID]);
        this.spki = slice(blob, off, sizes[X509NI.SLOT_SPKI]);
        this.spkiAlgOid = ascii(slice(blob, off, sizes[X509NI.SLOT_SPKI_ALG_OID]));
        this.inheritedDsaParameters = CertKeys.hasInheritedDsaParameters(spkiAlgOid, spki);

        // An ABSENT parameter and an explicit ASN.1 NULL both report null,
        // which is SUN's reading; BouncyCastle returns the encoded NULL. The
        // divergence is pinned rather than reconciled.
        this.sigAlgParams = params.length == 0 ? null : params;

        this.serialNumber = decodeSerial(serialTlv);
        this.issuer = new X500Principal(issuerDer);
        this.subject = new X500Principal(subjectDer);

        this.version = info[X509NI.INFO_VERSION];
        this.notBefore = new Date(seconds(info, X509NI.INFO_NOT_BEFORE_HI) * 1000L);
        this.notAfter = new Date(seconds(info, X509NI.INFO_NOT_AFTER_HI) * 1000L);
        this.basicConstraints = info[X509NI.INFO_BASIC_CONSTRAINTS];
        this.keyUsage = bits(info[X509NI.INFO_KEY_USAGE_BITS], info[X509NI.INFO_KEY_USAGE_VALUE]);
        this.issuerUniqueId = bitString(iuid, info[X509NI.INFO_ISSUER_UID_BITS]);
        this.subjectUniqueId = bitString(suid, info[X509NI.INFO_SUBJECT_UID_BITS]);

        int extCount = info[X509NI.INFO_EXT_COUNT];
        if (extCount == 0)
        {
            // NO extensions at all. The contract distinguishes this from
            // "extensions present, none critical": X509Extension's javadoc
            // says getCriticalExtensionOIDs returns an empty Set when none are
            // marked critical but NULL when there are no extensions present at
            // all. Measured: SUN and BouncyCastle both return null here.
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
                byte[] value = java.util.Arrays.copyOfRange(extBlob, valOff, valOff + extValSizes[i]);
                valOff += extValSizes[i];
                // A repeated OID cannot reach here: a duplicated extension is
                // refused in the native layer, as SUN and BouncyCastle refuse
                // it at parse. So putting unconditionally cannot lose one.
                values.put(oid, value);
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
            // Empty Sets, not null: extensions ARE present, just none in this
            // class. The other branch above is the null case.
            this.criticalOids = Collections.unmodifiableSet(crit);
            this.nonCriticalOids = Collections.unmodifiableSet(nonCrit);
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
        catch (UnsupportedEncodingException e)
        {
            throw new IllegalStateException("US-ASCII is required of every JVM", e);
        }
    }

    /**
     * The serialNumber from its whole INTEGER TLV, read as two's complement.
     *
     * <p>Not {@code ASN1_INTEGER_to_BN}: OpenSSL stores a magnitude plus a sign
     * flag, so a negative serial loses its sign on the way out, and the PKITS
     * corpus carries one deliberately.
     */
    private static BigInteger decodeSerial(byte[] tlv)
    {
        if (tlv.length < 2 || (tlv[0] & 0xFF) != 0x02)
        {
            throw new CertificateParseException("serialNumber is not an INTEGER");
        }
        int i = 1;
        int len = tlv[i++] & 0xFF;
        if ((len & 0x80) != 0)
        {
            int n = len & 0x7F;
            len = 0;
            for (int k = 0; k < n; k++)
            {
                len = (len << 8) | (tlv[i++] & 0xFF);
            }
        }
        if (len <= 0 || i + len != tlv.length)
        {
            throw new CertificateParseException("serialNumber INTEGER length is wrong");
        }
        return new BigInteger(java.util.Arrays.copyOfRange(tlv, i, i + len));
    }

    /** A BIT STRING's bits as a boolean[] whose LENGTH is the declared count. */
    private static boolean[] bitString(byte[] data, int bitCount)
    {
        if (data.length == 0 || bitCount <= 0)
        {
            return null;
        }
        boolean[] out = new boolean[bitCount];
        for (int i = 0; i < bitCount; i++)
        {
            out[i] = ((data[i / 8] >> (7 - (i % 8))) & 1) != 0;
        }
        return out;
    }

    /**
     * The nine KeyUsage bits RFC 5280 §4.2.1.3 defines, digitalSignature
     * through decipherOnly.
     */
    private static final int KEY_USAGE_DEFINED_BITS = 9;

    /**
     * keyUsage, which crosses as a bit count plus the bits packed MSB-first.
     *
     * <p>The array is padded to at least {@link #KEY_USAGE_DEFINED_BITS}, and
     * NOT truncated when the certificate declares more. That is the contract,
     * verbatim: "The array will contain a value for each KeyUsage defined
     * above. If the KeyUsage list encoded in the certificate is longer than
     * the above list, it will not be truncated."
     *
     * <p>Returning the declared bit count instead is caller-visible breakage
     * rather than a cosmetic difference — every PKITS certificate declares
     * four bits, so {@code getKeyUsage()[5]}, the keyCertSign a path builder
     * reads, threw ArrayIndexOutOfBounds where the JDK answers false. Found by
     * sweeping our own accessors against the JDK's over the corpus.
     */
    private static boolean[] bits(int bitCount, int value)
    {
        if (bitCount <= 0)
        {
            return null;
        }
        boolean[] out = new boolean[Math.max(bitCount, KEY_USAGE_DEFINED_BITS)];
        for (int i = 0; i < bitCount; i++)
        {
            out[i] = ((value >>> (31 - i)) & 1) != 0;
        }
        return out;
    }

    // --- the key, the one accessor that needs the live handle ---

    /**
     * {@inheritDoc}
     *
     * <p>Built on demand through this factory's OWN provider instance, and
     * never cached: a certificate whose key algorithm the provider does not
     * serve must still parse and still answer every other accessor, which is
     * measured — on the 3.1.2 FIPS module an Ed25519 certificate decodes
     * completely and only its key is unavailable.
     *
     * <p>Throws {@link ProviderException} rather than returning null, with a
     * different message for each of the three causes: no KeyFactory for the
     * algorithm, DSA parameters inherited from the issuer, or a malformed
     * SubjectPublicKeyInfo.
     */

    /** The provider this certificate was built by — used by the CertPath
     *  re-bind check, which must not accept a member from another instance. */
    ProviderBinding binding()
    {
        return binding;
    }

    public PublicKey getPublicKey()
    {
        return CertKeys.publicKeyOf(binding, spkiAlgOid, spki, inheritedDsaParameters);
    }

    String spkiAlgorithmOid()
    {
        return spkiAlgOid;
    }

    /** The certificate's SubjectPublicKeyInfo, as the key is rebuilt from. */
    byte[] subjectPublicKeyInfo()
    {
        return Arrays.clone(spki);
    }

    // --- everything else is answered from the fields decoded at construction ---

    public byte[] getEncoded()
        throws CertificateEncodingException
    {
        return Arrays.clone(encoded);
    }

    public byte[] getTBSCertificate()
        throws CertificateEncodingException
    {
        return Arrays.clone(tbs);
    }

    public int getVersion()
    {
        return version;
    }

    public BigInteger getSerialNumber()
    {
        return serialNumber;
    }

    /**
     * {@inheritDoc}
     *
     * <p>Answers from the same {@link X500Principal} as
     * {@link #getIssuerX500Principal()}, wrapped so that {@code getName()} —
     * the only method the declared {@code Principal} type offers — renders as
     * the JDK does. Returning the principal itself made that one accessor the
     * only one to disagree, on every certificate. Deprecated in the JCA.
     */
    public Principal getIssuerDN()
    {
        return new JcaDistinguishedName(issuer);
    }

    public Principal getSubjectDN()
    {
        return new JcaDistinguishedName(subject);
    }

    public X500Principal getIssuerX500Principal()
    {
        return issuer;
    }

    public X500Principal getSubjectX500Principal()
    {
        return subject;
    }

    public Date getNotBefore()
    {
        return new Date(notBefore.getTime());
    }

    public Date getNotAfter()
    {
        return new Date(notAfter.getTime());
    }

    public void checkValidity()
        throws CertificateExpiredException, CertificateNotYetValidException
    {
        checkValidity(new Date());
    }

    public void checkValidity(Date date)
        throws CertificateExpiredException, CertificateNotYetValidException
    {
        if (date.before(notBefore))
        {
            throw new CertificateNotYetValidException("certificate is not valid until " + notBefore);
        }
        if (date.after(notAfter))
        {
            throw new CertificateExpiredException("certificate expired on " + notAfter);
        }
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

    public boolean[] getIssuerUniqueID()
    {
        return Arrays.clone(issuerUniqueId);
    }

    public boolean[] getSubjectUniqueID()
    {
        return Arrays.clone(subjectUniqueId);
    }

    public boolean[] getKeyUsage()
    {
        return Arrays.clone(keyUsage);
    }

    public int getBasicConstraints()
    {
        return basicConstraints;
    }

    /**
     * {@inheritDoc}
     *
     * <p>Decoded from the extension value this object already holds. The
     * inherited {@code X509Certificate} default would instead hand
     * {@code getEncoded()} to {@code sun.security.x509} and re-parse the whole
     * certificate — a SECOND parser inside an object whose whole point is that
     * OpenSSL is the first one. It lives in {@code java.base} rather than in
     * the SUN provider, so it survives the registry being emptied and is
     * invisible to the regression test; only overriding removes it.
     */
    public List<String> getExtendedKeyUsage()
        throws CertificateParsingException
    {
        byte[] value = getExtensionValue(X509ObjectIdentifiers.id_ce_extKeyUsage.getId());
        if (value == null)
        {
            return null;
        }
        try
        {
            // ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
            // (RFC 5280 4.2.1.12), inside the extension's OCTET STRING.
            Der.Reader outer = new Der.Reader(value);
            byte[] inner = outer.readTLV(Der.OCTET_STRING, "extKeyUsage").remaining();
            Der.Reader seq = new Der.Reader(inner).readTLV(Der.SEQUENCE, "ExtKeyUsageSyntax");
            List<String> oids = new ArrayList<String>();
            while (!seq.atEnd())
            {
                oids.add(seq.readObjectIdentifier("KeyPurposeId"));
            }
            return Collections.unmodifiableList(oids);
        }
        catch (IOException e)
        {
            throw new CertificateParsingException("unable to decode extKeyUsage", e);
        }
    }

    public Collection<List<?>> getSubjectAlternativeNames()
        throws CertificateParsingException
    {
        return generalNames(getExtensionValue(X509ObjectIdentifiers.id_ce_subjectAltName.getId()), "subjectAltName");
    }

    public Collection<List<?>> getIssuerAlternativeNames()
        throws CertificateParsingException
    {
        return generalNames(getExtensionValue(X509ObjectIdentifiers.id_ce_issuerAltName.getId()), "issuerAltName");
    }

    /**
     * The JCA shape for an alternative-names extension: a collection of
     * two-element lists, each {@code [tagNumber, value]}.
     *
     * <p>RFC 5280 §4.2.1.6 {@code GeneralName} is a CHOICE, so the context tag
     * number IS the name type. The JCA renders types 1, 2, 6 and 8 as Strings
     * and hands back the raw DER for the rest; type 4 (directoryName) is
     * rendered as an X.500 name, which is why it is built through
     * {@link X500Principal} here rather than left as bytes.
     */
    private Collection<List<?>> generalNames(byte[] value, String what)
        throws CertificateParsingException
    {
        if (value == null)
        {
            return null;
        }
        try
        {
            Der.Reader outer = new Der.Reader(value);
            byte[] inner = outer.readTLV(Der.OCTET_STRING, what).remaining();
            Der.Reader seq = new Der.Reader(inner).readTLV(Der.SEQUENCE, "GeneralNames");
            List<List<?>> out = new ArrayList<List<?>>();
            while (!seq.atEnd())
            {
                int tag = seq.peekTag();
                int type = tag & 0x1F;
                byte[] body = seq.readTLV(tag, "GeneralName").remaining();
                List<Object> entry = new ArrayList<Object>(2);
                entry.add(Integer.valueOf(type));
                switch (type)
                {
                case 1:     // rfc822Name
                case 2:     // dNSName
                case 6:     // uniformResourceIdentifier
                    entry.add(new String(body, "US-ASCII"));
                    break;
                case 4:
                    // directoryName. RFC 2253 form, getName() — NOT toString().
                    // Measured: the JDK renders a SAN directoryName unspaced
                    // ("CN=x,OU=y") while rendering getIssuerDN() spaced
                    // ("CN=x, OU=y"). The two conventions disagree inside one
                    // implementation, so matching it means following each
                    // separately rather than picking one rendering.
                    entry.add(new X500Principal(body).getName());
                    break;
                case 7:     // iPAddress, raw octets
                    entry.add(Arrays.clone(body));
                    break;
                case 8:     // registeredID
                    entry.add(new Der.Reader(Der.tlv(Der.OBJECT_IDENTIFIER, body))
                            .readObjectIdentifier("registeredID"));
                    break;
                default:    // otherName, x400Address, ediPartyName: raw DER
                    entry.add(Arrays.clone(body));
                    break;
                }
                out.add(Collections.unmodifiableList(entry));
            }
            return Collections.unmodifiableCollection(out);
        }
        catch (IOException | RuntimeException e)
        {
            throw new CertificateParsingException("unable to decode " + what, e);
        }
    }

    // --- X509Extension ---

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
            if (!SupportedExtensions.isSupportedOnCertificate(oid))
            {
                return true;
            }
        }
        return false;
    }

    // --- verification ---

    /**
     * {@inheritDoc}
     *
     * <p>Resolves the {@link Signature} through this factory's OWN provider
     * instance, never by name and never through JCA search order — the same
     * rule that governs the key.
     */
    public void verify(PublicKey key)
        throws CertificateException, NoSuchAlgorithmException, InvalidKeyException,
               NoSuchProviderException, SignatureException
    {
        doVerify(key, CertKeys.signatureFor(binding, getSigAlgName()));
    }

    /**
     * {@inheritDoc}
     *
     * <p>The caller named a provider, so that deliberate choice is honoured.
     */
    public void verify(PublicKey key, String sigProvider)
        throws CertificateException, NoSuchAlgorithmException, InvalidKeyException,
               NoSuchProviderException, SignatureException
    {
        // A null provider resolves through the provider this certificate BELONGS
        // TO, never through JCA search order. "The default provider" for an
        // object this provider built is this provider: reaching for the
        // installed list would verify a JSLFIPS certificate outside the module,
        // and nothing behavioural could see it.
        Signature signature = (sigProvider == null)
                ? CertKeys.signatureFor(binding, getSigAlgName())
                : Signature.getInstance(getSigAlgName(), sigProvider);
        doVerify(key, signature);
    }

    /**
     * Provider-instance overload. MUST be overridden: the
     * {@link java.security.cert.Certificate} default throws
     * {@code UnsupportedOperationException}, so a caller passing a
     * {@link Provider} rather than a name would break against us.
     */
    public void verify(PublicKey key, Provider sigProvider)
        throws CertificateException, NoSuchAlgorithmException, InvalidKeyException,
               SignatureException
    {
        // No NoSuchProviderException arm: this overload takes the INSTANCE, so
        // nothing here resolves a name, and the compiler agrees it cannot be
        // thrown. Its absence from the throws clause is the JCA contract's.
        doVerify(key, (sigProvider == null)
                ? CertKeys.signatureFor(binding, getSigAlgName())
                : Signature.getInstance(getSigAlgName(), sigProvider));
    }

    /**
     * Verify over the TBS with the certificate's OWN signature parameters.
     *
     * <p>The parameters matter: an RSASSA-PSS certificate carries a 54-byte
     * {@code RSASSA-PSS-params} naming its digest, mask function and salt
     * length, and verifying with defaults is simply a different operation.
     * They are decoded through the AlgorithmParameters registered on the
     * Signature's own provider.
     */
    private void doVerify(PublicKey key, Signature verifier)
        throws CertificateException, NoSuchAlgorithmException, InvalidKeyException,
               SignatureException
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
                throw new CertificateException(
                        "unable to apply the certificate's signature parameters for "
                                + getSigAlgName(), e);
            }
        }
        verifier.initVerify(key);
        verifier.update(tbs);
        if (!verifier.verify(signature))
        {
            throw new SignatureException("certificate signature did not verify");
        }
    }

    public String toString()
    {
        return "X.509 Certificate [" + subject.getName() + "] serial " + serialNumber;
    }

}
