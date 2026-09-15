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

import org.openssl.jostle.util.asn1.oids.PKCSObjectIdentifiers;
import org.openssl.jostle.util.asn1.Der;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

/**
 * An X.509 certification path, encodable as PkiPath and PKCS7.
 *
 * <p>A plain immutable list plus the two encoders. It holds no native handle —
 * it holds certificates, and since the certificate copies every field at
 * construction, nothing here owns native memory either.
 *
 * <p><b>The four encoding rules are MEASURED against SUN, not inferred</b>
 * (lengths 1, 2 and 3, plus three permutations of one 3-certificate chain):
 *
 * <ol>
 *   <li>PkiPath writes the certificates in the REVERSE of this list's order,
 *       so the trust anchor is first on the wire.</li>
 *   <li>PkiPath decode reverses them back.</li>
 *   <li>The PKCS7 certificate SET is DER canonical — sorted by encoding. This
 *       is why PKCS7 bytes are identical whatever order the caller supplied,
 *       where PkiPath bytes are not.</li>
 *   <li>PKCS7 decode PRESERVES the wire order. SUN's decoded order was measured
 *       equal to the wire order in every case.</li>
 * </ol>
 *
 * <p><b>Deliberate divergence from BouncyCastle, on ordering.</b> SUN preserves
 * the caller's order; BC SORTS into chain order, on construction from a list
 * and again on decode. We follow SUN, per the ruling that serves SUN's list in
 * SUN's order. Worked case, the chain EE &rarr; Good CA &rarr; Trust Anchor
 * encoded as PKCS7: SUN and we decode {@code Trust Anchor, EE, Good CA}; BC
 * decodes {@code EE, Good CA, Trust Anchor} from the same bytes.
 */
public final class JOCertPath
    extends CertPath
{
    private static final long serialVersionUID = 1L;

    static final String PKI_PATH = "PkiPath";
    static final String PKCS7 = "PKCS7";

    /**
     * SUN's list, in SUN's order — the first entry is the default encoding.
     * A CONSTANT: it describes what this class implements, so it cannot be
     * derived from anything and must not vary with input.
     */
    private static final List<String> ENCODINGS =
            Collections.unmodifiableList(Arrays.asList(PKI_PATH, PKCS7));

    private static final String OID_SIGNED_DATA = PKCSObjectIdentifiers.signedData.getId();
    private static final String OID_DATA = PKCSObjectIdentifiers.data.getId();

    /** [0] IMPLICIT, constructed — the certificates in a SignedData. */
    private static final int TAG_CERTIFICATES = 0xA0;
    /** [0] EXPLICIT, constructed — the content in a ContentInfo. */
    private static final int TAG_CONTENT = 0xA0;
    private static final int SET = 0x31;

    private final List<X509Certificate> certificates;

    JOCertPath(List<X509Certificate> certificates)
    {
        super("X.509");
        this.certificates = Collections.unmodifiableList(
                new ArrayList<X509Certificate>(certificates));
    }

    static List<String> encodings()
    {
        return ENCODINGS;
    }

    @Override
    public List<? extends Certificate> getCertificates()
    {
        return certificates;
    }

    @Override
    public Iterator<String> getEncodings()
    {
        return ENCODINGS.iterator();
    }

    @Override
    public byte[] getEncoded()
        throws CertificateEncodingException
    {
        return getEncoded(PKI_PATH);
    }

    @Override
    public byte[] getEncoded(String encoding)
        throws CertificateEncodingException
    {
        if (PKI_PATH.equals(encoding))
        {
            return encodePkiPath();
        }
        if (PKCS7.equals(encoding))
        {
            return encodePkcs7();
        }
        throw new CertificateEncodingException("unsupported encoding: " + encoding);
    }

    // -----------------------------------------------------------------
    // Encoding
    // -----------------------------------------------------------------

    private byte[] encodePkiPath()
        throws CertificateEncodingException
    {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        // Reverse: the wire puts the trust anchor first, the JCA list the end
        // entity first.
        for (int i = certificates.size() - 1; i >= 0; i--)
        {
            writeTo(out, certificates.get(i).getEncoded());
        }
        return Der.tlv(Der.SEQUENCE, out.toByteArray());
    }

    private byte[] encodePkcs7()
        throws CertificateEncodingException
    {
        byte[][] encoded = new byte[certificates.size()][];
        for (int i = 0; i < encoded.length; i++)
        {
            encoded[i] = certificates.get(i).getEncoded();
        }
        // DER canonical SET OF: sorted by encoding. Measured to reproduce SUN's
        // wire order exactly, which is what makes the bytes independent of the
        // order the caller supplied.
        Arrays.sort(encoded, new DerOrder());

        ByteArrayOutputStream certs = new ByteArrayOutputStream();
        for (byte[] e : encoded)
        {
            writeTo(certs, e);
        }

        byte[] signedData = Der.sequence(
                Der.integer(1),                                   // version
                Der.tlv(SET, new byte[0]),                        // digestAlgorithms, empty
                Der.sequence(Der.objectIdentifier(OID_DATA)),     // contentInfo, no content
                Der.tlv(TAG_CERTIFICATES, certs.toByteArray()),
                Der.tlv(SET, new byte[0]));                       // signerInfos, empty

        return Der.sequence(
                Der.objectIdentifier(OID_SIGNED_DATA),
                Der.tlv(TAG_CONTENT, signedData));
    }

    /**
     * DER SET OF ordering: unsigned lexicographic over the whole encoding, a
     * shorter encoding that is a prefix of a longer one sorting first.
     */
    private static final class DerOrder
        implements java.util.Comparator<byte[]>, java.io.Serializable
    {
        private static final long serialVersionUID = 1L;

        public int compare(byte[] a, byte[] b)
        {
            int n = Math.min(a.length, b.length);
            for (int i = 0; i < n; i++)
            {
                int d = (a[i] & 0xFF) - (b[i] & 0xFF);
                if (d != 0)
                {
                    return d;
                }
            }
            return a.length - b.length;
        }
    }

    private static void writeTo(ByteArrayOutputStream out, byte[] b)
    {
        out.write(b, 0, b.length);
    }

    // -----------------------------------------------------------------
    // Decoding — returns the member certificates' DER, in JCA list order.
    // -----------------------------------------------------------------

    /**
     * Refuse a member count over the cap, BEFORE anything is allocated for it.
     *
     * <p>One place, called by every site that can grow a member list, so the
     * bound cannot be applied to three of four. The message names the property
     * because a bound a deployment cannot find is a bound it cannot raise, and
     * it refuses rather than truncating — a short chain that looks complete is
     * the worse failure.
     */
    static void checkMemberCount(int count, String what)
        throws IOException
    {
        int cap = X509NI.maxMembers();
        if (count > cap)
        {
            throw new IOException(what + " carries more than " + cap
                    + " members; raise " + X509NI.MAX_MEMBERS_PROPERTY);
        }
    }

    /**
     * The certificate encodings carried by a PkiPath, in JCA order (reversed
     * back from the wire).
     */
    static List<byte[]> decodePkiPath(byte[] der)
        throws IOException
    {
        Der.Reader outer = new Der.Reader(der);
        Der.Reader seq = outer.readTLV(Der.SEQUENCE, "PkiPath");
        outer.requireEnd("trailing data after PkiPath");

        List<byte[]> certs = new ArrayList<byte[]>();
        while (!seq.atEnd())
        {
            checkMemberCount(certs.size() + 1, "PkiPath");
            certs.add(seq.readEncodedTLV(Der.SEQUENCE, "PkiPath certificate"));
        }
        Collections.reverse(certs);
        return certs;
    }

    /**
     * The certificate encodings carried by a PKCS#7 SignedData, in WIRE order.
     *
     * <p>Everything except the certificates is skipped rather than validated:
     * this is a transport container for certificates, and refusing a bag
     * because its unused signerInfos displeased us would turn a parse we can
     * satisfy into a failure no reference makes.
     */
    static List<byte[]> decodePkcs7(byte[] der)
        throws IOException
    {
        Der.Reader outer = new Der.Reader(der);
        Der.Reader contentInfo = outer.readTLV(Der.SEQUENCE, "PKCS7 ContentInfo");
        outer.requireEnd("trailing data after PKCS7");

        String contentType = contentInfo.readObjectIdentifier("PKCS7 contentType");
        if (!OID_SIGNED_DATA.equals(contentType))
        {
            throw new IOException("PKCS7 contentType is not signedData: " + contentType);
        }

        Der.Reader content = contentInfo.readTLV(TAG_CONTENT, "PKCS7 content");
        Der.Reader signedData = content.readTLV(Der.SEQUENCE, "PKCS7 SignedData");

        signedData.readTLV(Der.INTEGER, "SignedData version");
        signedData.readTLV(SET, "SignedData digestAlgorithms");
        signedData.readTLV(Der.SEQUENCE, "SignedData encapContentInfo");

        List<byte[]> certs = new ArrayList<byte[]>();
        if (!signedData.atEnd() && signedData.peekTag() == TAG_CERTIFICATES)
        {
            Der.Reader bag = signedData.readTLV(TAG_CERTIFICATES, "SignedData certificates");
            while (!bag.atEnd())
            {
                checkMemberCount(certs.size() + 1, "PKCS7 bag");
                // Only certificates. A [1] attribute-certificate member is not
                // an X.509 certificate and has no place in a CertPath.
                certs.add(bag.readEncodedTLV(Der.SEQUENCE, "PKCS7 certificate"));
            }
        }
        return certs;
    }
}
