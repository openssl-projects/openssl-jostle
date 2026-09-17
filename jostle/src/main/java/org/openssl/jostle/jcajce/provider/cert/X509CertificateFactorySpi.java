/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.cert;

import org.openssl.jostle.jcajce.provider.CertificateParseException;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.jcajce.provider.binding.ProviderBinding;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Provider;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactorySpi;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

/**
 * X.509 CertificateFactory, parsing over OpenSSL.
 *
 * <p>Nothing here delegates to another provider. The previous implementation
 * resolved {@code CertificateFactory.getInstance("X.509", "SUN")} in its
 * CONSTRUCTOR, so on a JVM with the JDK providers removed the service could
 * not even be created — the failure arrived at {@code getInstance} rather than
 * at the operation.
 *
 * <p><b>Non-DER input is accepted and normalised to DER.</b> See
 * {@link JOX509Certificate} for what that means to a caller.
 *
 * <p>Certificates and CRLs are read from DER or PEM, singly or concatenated,
 * per the {@code CertificateFactory} contract. {@code CertPath} input is DER
 * only ({@code PkiPath} / {@code PKCS7}); PEM there is not yet served and
 * refuses typed rather than silently returning nothing.
 */
public class X509CertificateFactorySpi
    extends CertificateFactorySpi
{
    /** One fact, one field — an instance or a name, never both. */
    private final ProviderBinding binding;
    private final X509NI ni;

    public X509CertificateFactorySpi()
    {
        this(JostleProvider.PROVIDER_NAME, false);
    }

    /**
     * Name-only form, kept because it is public API and an out-of-tree caller
     * may hold it. It keeps NAME resolution, which is all it ever had: the
     * provider is looked up when a key is built, so a caller that swaps what
     * the name points at gets the new one. Prefer the {@link Provider} form.
     *
     * @param providerName  the Jostle provider certificates' keys are rebuilt
     *                      through
     * @param providerBound retained for the registrations; the distinction it
     *                      used to carry — fall back to a JDK key, or fail
     *                      loud — no longer exists, because nothing delegates
     *                      to the JDK and so there is no JDK key to fall back
     *                      to.
     */
    public X509CertificateFactorySpi(String providerName, boolean providerBound)
    {
        this(NISelector.X509NI, ProviderBinding.ofName(providerName));
    }

    /**
     * @param providerInstance the provider this factory belongs to. The
     *                         certificates it returns rebuild their public keys
     *                         through THIS instance: a name is re-resolvable,
     *                         and a key from another instance is refused by the
     *                         isolation check on first use, so a name-resolved
     *                         factory hands back what its own provider rejects.
     * @param providerBound    see the name-only form.
     */
    public X509CertificateFactorySpi(Provider providerInstance, boolean providerBound)
    {
        if (providerInstance == null)
        {
            throw new IllegalArgumentException(
                    "X509CertificateFactorySpi requires the provider it belongs to;"
                            + " use the name-only constructor when there is none");
        }
        this.binding = ProviderBinding.of(providerInstance);
        this.ni = NISelector.X509NI;
    }

    /**
     * The form the registrations use: the NI is a CONSTRUCTOR ARGUMENT, never
     * a static read.
     *
     * <p>An SPI that reaches {@code NISelector} in its body is welded to the
     * BASE interface library and its lib ctx, so it can never serve JSLFIPS.
     * This class was first written that way and the consequence was not
     * theoretical: on a FIPS-only run it aborted the JVM at
     * {@code get_global_jostle_ossl_lib_ctx}'s assert, because the base lib
     * ctx had never been initialised. On a JVM where both were initialised it
     * would instead have parsed in the wrong library and returned keys from
     * the wrong provider, with no symptom at all.
     */
    public X509CertificateFactorySpi(X509NI ni, ProviderBinding binding)
    {
        if (ni == null || binding == null)
        {
            throw new IllegalArgumentException(
                    "X509CertificateFactorySpi requires its NI and its provider binding");
        }
        this.ni = ni;
        this.binding = binding;
    }

    public Certificate engineGenerateCertificate(InputStream inStream)
        throws CertificateException
    {
        if (inStream == null)
        {
            throw new CertificateException("Missing input stream");
        }
        byte[] der = readOne(inStream, X509NI.maxCertificateBytes());
        if (der == null)
        {
            throw new CertificateException("Empty input");
        }
        return parse(der);
    }

    public Collection<? extends Certificate> engineGenerateCertificates(InputStream inStream)
        throws CertificateException
    {
        if (inStream == null)
        {
            throw new CertificateException("Missing input stream");
        }
        List<Certificate> out = new ArrayList<Certificate>();
        while (true)
        {
            byte[] der;
            try
            {
                der = readOne(inStream, X509NI.maxCertificateBytes());
            }
            catch (CertificateException unreadable)
            {
                // Measured on both references: trailing garbage AFTER at least
                // one certificate returns what was parsed, and only a FIRST
                // object that cannot be read throws. An earlier draft threw in
                // both cases, which would have refused a stream the JDK and
                // BouncyCastle both accept.
                if (out.isEmpty())
                {
                    throw unreadable;
                }
                break;
            }
            if (der == null)
            {
                break;
            }
            if (out.size() + 1 > X509NI.maxMembers())
            {
                // Before the parse, so the cap costs nothing to enforce and
                // nothing is allocated for the member that breaks it.
                throw new CertificateException("certificate stream carries more than " + X509NI.maxMembers()
                        + " members; raise " + X509NI.MAX_MEMBERS_PROPERTY);
            }
            out.add(parse(der));
        }
        // An empty stream yields an EMPTY COLLECTION, not an exception — the
        // opposite of the singular form above, and what both references do.
        return Collections.unmodifiableList(out);
    }

    /**
     * Read exactly one object from the stream — DER (first octet
     * {@code 0x30}) or PEM (first octet {@code '-'}) — leaving the remainder.
     *
     * <p>Reading one object and stopping is the JCA contract: measured, both
     * the JDK and BouncyCastle leave the stream positioned immediately after
     * the certificate, so a caller can read a concatenated series (DER, PEM,
     * or a mix). That is the OPPOSITE of the whole-blob decoders elsewhere in
     * the tree, which refuse trailing data — and each site says which
     * contract it serves.
     *
     * @return the object's octets, or null at end of stream
     */
    private byte[] readOne(InputStream in, int ceiling)
        throws CertificateException
    {
        try
        {
            int first = in.read();
            if (first < 0)
            {
                return null;
            }
            if (first != 0x30)
            {
                // Not DER. SUN and BC both tolerate blank lines, comments and
                // prose before a PEM block, so scan forward to the BEGIN line
                // rather than refusing on the first octet; content with no
                // block at all is refused, as SUN refuses it.
                return readPem(in, first, ceiling);
            }
            ByteArrayOutputStream header = new ByteArrayOutputStream();
            header.write(first);

            int l = in.read();
            if (l < 0)
            {
                throw new CertificateException("Incomplete BER/DER data");
            }
            header.write(l);

            long contentLen;
            if ((l & 0x80) == 0)
            {
                contentLen = l;
            }
            else
            {
                int n = l & 0x7F;
                if (n == 0)
                {
                    throw new CertificateException(
                            "indefinite length is not read by this phase");
                }
                if (n > 4)
                {
                    throw new CertificateException("unsupported DER length");
                }
                contentLen = 0;
                for (int i = 0; i < n; i++)
                {
                    int b = in.read();
                    if (b < 0)
                    {
                        throw new CertificateException("Incomplete BER/DER data");
                    }
                    header.write(b);
                    contentLen = (contentLen << 8) | b;
                }
            }

            if (contentLen > ceiling)
            {
                throw new CertificateParseException(
                        "object exceeds the configured ceiling; raise "
                                + (ceiling == X509NI.maxCertificateBytes()
                                   ? X509NI.MAX_CERT_BYTES_PROPERTY
                                   : X509NI.MAX_CONTAINER_BYTES_PROPERTY));
            }

            byte[] head = header.toByteArray();
            byte[] out = new byte[head.length + (int) contentLen];
            System.arraycopy(head, 0, out, 0, head.length);
            int got = 0;
            while (got < contentLen)
            {
                int r = in.read(out, head.length + got, (int) contentLen - got);
                if (r < 0)
                {
                    throw new CertificateException("Incomplete BER/DER data");
                }
                got += r;
            }
            return out;
        }
        catch (IOException e)
        {
            throw new CertificateException("Could not parse certificate: " + e, e);
        }
    }

    /**
     * Read one PEM block — "-----BEGIN &lt;label&gt;-----" through the
     * newline ending "-----END &lt;label&gt;-----" — decode it and return the
     * decoded bytes. Leaves the stream positioned immediately after that
     * newline, the same one-object-and-stop contract {@link #readOne} keeps
     * for DER.
     *
     * <p>The label is read from the header and required to match the footer
     * (RFC 7468), but is not otherwise validated against what this call site
     * expects ("CERTIFICATE" vs "X509 CRL"): measured, neither the JDK nor
     * BouncyCastle check it either — a PEM block of the wrong type decodes
     * here and is refused later, when the bytes fail to parse as the
     * structure this call site wants, exactly as wrong-type DER input is.
     */
    private byte[] readPem(InputStream in, int first, int ceiling)
        throws CertificateException
    {
        // Base64 expands by 4/3; doubling the DER ceiling is a generous
        // bound on the encoded body that costs nothing to check before the
        // decode, so a PEM block cannot be used to force an allocation the
        // DER path would have refused. The same bound covers the preamble
        // scan below, so a stream with no BEGIN line at all cannot be
        // scanned forever either.
        long bodyCeiling = 2L * ceiling + 1024;
        try
        {
            String line = readPemLine(in, first, bodyCeiling);
            long scanned = line.length();
            while (!line.startsWith("-----BEGIN "))
            {
                String next = readPemLineOrNull(in, bodyCeiling);
                if (next == null)
                {
                    // A genuinely empty stream never reaches here (readOne
                    // returns null for that before calling this method), so
                    // reaching end of stream here means content was read but
                    // no BEGIN line was in it — refused, not treated as empty.
                    throw new CertificateException("malformed PEM data: no header found");
                }
                line = next;
                scanned += line.length();
                if (scanned > bodyCeiling)
                {
                    throw new CertificateParseException(
                            "PEM preamble exceeds the configured ceiling; raise "
                                    + (ceiling == X509NI.maxCertificateBytes()
                                       ? X509NI.MAX_CERT_BYTES_PROPERTY
                                       : X509NI.MAX_CONTAINER_BYTES_PROPERTY));
                }
            }
            String label = pemLabel(line, "BEGIN", "header");

            StringBuilder body = new StringBuilder();
            while (true)
            {
                line = readPemLineOrNull(in, bodyCeiling);
                if (line == null)
                {
                    throw new CertificateException("malformed PEM data: no footer found");
                }
                if (line.startsWith("-----END "))
                {
                    break;
                }
                body.append(line);
                if (body.length() > bodyCeiling)
                {
                    throw new CertificateParseException(
                            "PEM body exceeds the configured ceiling; raise "
                                    + (ceiling == X509NI.maxCertificateBytes()
                                       ? X509NI.MAX_CERT_BYTES_PROPERTY
                                       : X509NI.MAX_CONTAINER_BYTES_PROPERTY));
                }
            }
            String footerLabel = pemLabel(line, "END", "footer");
            if (!label.equals(footerLabel))
            {
                throw new CertificateException(
                        "malformed PEM data: header and footer do not match: "
                                + label + " / " + footerLabel);
            }
            try
            {
                return java.util.Base64.getMimeDecoder().decode(body.toString());
            }
            catch (IllegalArgumentException e)
            {
                throw new CertificateException("malformed PEM data: invalid base64", e);
            }
        }
        catch (IOException e)
        {
            throw new CertificateException("Could not parse certificate: " + e, e);
        }
    }

    /** The label out of a "-----BEGIN X-----" / "-----END X-----" line, or a typed refusal. */
    private static String pemLabel(String line, String keyword, String what)
        throws CertificateException
    {
        String prefix = "-----" + keyword + " ";
        if (!line.startsWith(prefix) || !line.endsWith("-----")
                || line.length() < prefix.length() + 5)
        {
            throw new CertificateException("malformed PEM data: no " + what + " found");
        }
        return line.substring(prefix.length(), line.length() - 5);
    }

    /**
     * One line (trailing {@code \r}/{@code \n} stripped), or null only when
     * the stream ends before any byte of a new line is read.
     */
    private static String readPemLineOrNull(InputStream in, long maxLen)
        throws IOException, CertificateException
    {
        StringBuilder sb = new StringBuilder();
        int c;
        while ((c = in.read()) >= 0 && c != '\n')
        {
            if (c != '\r')
            {
                sb.append((char) c);
            }
            if (sb.length() > maxLen)
            {
                throw new CertificateException("malformed PEM data: line exceeds the configured ceiling");
            }
        }
        if (c < 0 && sb.length() == 0)
        {
            return null;
        }
        return sb.toString();
    }

    /**
     * Like {@link #readPemLineOrNull}, but the line's first character was
     * already read from the stream (by {@link #readOne}, to decide this
     * wasn't DER) — always returns a line, even an empty one.
     */
    private static String readPemLine(InputStream in, int firstChar, long maxLen)
        throws IOException, CertificateException
    {
        StringBuilder sb = new StringBuilder();
        if (firstChar != '\r' && firstChar != '\n')
        {
            sb.append((char) firstChar);
        }
        if (firstChar != '\n')
        {
            int c;
            while ((c = in.read()) >= 0 && c != '\n')
            {
                if (c != '\r')
                {
                    sb.append((char) c);
                }
                if (sb.length() > maxLen)
                {
                    throw new CertificateException("malformed PEM data: line exceeds the configured ceiling");
                }
            }
        }
        return sb.toString();
    }

    private Certificate parse(byte[] der)
        throws CertificateException
    {
        long ref = 0;
        try
        {
            int[] consumed = new int[1];
            ref = ni.allocate(der, 0, der.length, X509NI.maxCertificateBytes(), consumed);

            int blobLen = ni.fieldsLen(ref);
            byte[] blob = new byte[blobLen];
            int[] sizes = new int[X509NI.SLOT_COUNT];
            int[] info = new int[X509NI.INFO_COUNT];
            ni.fields(ref, blob, sizes, info);

            int extCount = info[X509NI.INFO_EXT_COUNT];
            byte[] extBlob = new byte[0];
            int[] oidSizes = new int[0];
            int[] valSizes = new int[0];
            int[] critical = new int[0];
            if (extCount > 0)
            {
                // Skipped entirely when there are none: zero-length arrays are
                // a capacity the native side refuses, and a certificate with
                // no extensions is a legitimate v1.
                extBlob = new byte[ni.extensionsLen(ref)];
                oidSizes = new int[extCount];
                valSizes = new int[extCount];
                critical = new int[extCount];
                ni.extensions(ref, extBlob, oidSizes, valSizes, critical);
            }

            return new JOX509Certificate(binding, blob, sizes, info,
                    extBlob, oidSizes, valSizes, critical);
        }
        catch (CertificateParseException e)
        {
            // The NI's typed runtime refusal becomes the JCE-canonical checked
            // one at the parse boundary, which is where both the JDK and
            // BouncyCastle raise for the same inputs.
            throw new CertificateParsingException(e.getMessage(), e);
        }
        catch (OpenSSLException e)
        {
            // Everything else the NI can raise is still a RuntimeException,
            // and generateCertificate's contract is CertificateException. An
            // OpenSSL failure or an injected fault would otherwise escape as
            // an unchecked throw past every caller's catch.
            throw new CertificateException("could not parse certificate: " + e.getMessage(), e);
        }
        catch (IllegalArgumentException | IllegalStateException e)
        {
            // The limit arms — a null handle, an out-of-range length — reach
            // here only through a programming error on our side, but they must
            // not escape unchecked either.
            throw new CertificateException("could not parse certificate: " + e.getMessage(), e);
        }
        finally
        {
            if (ref != 0)
            {
                // The certificate object keeps no native handle — every field
                // was copied out above — so the handle is freed here rather
                // than left to the disposal daemon.
                ni.dispose(ref);
            }
        }
    }

    public CRL engineGenerateCRL(InputStream inStream)
        throws CRLException
    {
        if (inStream == null)
        {
            throw new CRLException("Missing input stream");
        }
        byte[] der;
        try
        {
            der = readOne(inStream, X509NI.maxContainerBytes());
        }
        catch (CertificateException e)
        {
            throw new CRLException(e.getMessage(), e);
        }
        if (der == null)
        {
            throw new CRLException("Empty input");
        }
        return parseCrl(der);
    }

    public Collection<? extends CRL> engineGenerateCRLs(InputStream inStream)
        throws CRLException
    {
        if (inStream == null)
        {
            throw new CRLException("Missing input stream");
        }
        List<CRL> out = new ArrayList<CRL>();
        while (true)
        {
            byte[] der;
            try
            {
                der = readOne(inStream, X509NI.maxContainerBytes());
            }
            catch (CertificateException unreadable)
            {
                // Same rule as the certificate collection: only a FIRST object
                // that cannot be read throws.
                if (out.isEmpty())
                {
                    throw new CRLException(unreadable.getMessage(), unreadable);
                }
                break;
            }
            if (der == null)
            {
                break;
            }
            if (out.size() + 1 > X509NI.maxMembers())
            {
                // Before the parse, so the cap costs nothing to enforce and
                // nothing is allocated for the member that breaks it.
                throw new CRLException("CRL stream carries more than " + X509NI.maxMembers()
                        + " members; raise " + X509NI.MAX_MEMBERS_PROPERTY);
            }
            out.add(parseCrl(der));
        }
        return Collections.unmodifiableList(out);
    }

    private CRL parseCrl(byte[] der)
        throws CRLException
    {
        long ref = 0;
        try
        {
            int[] consumed = new int[1];
            ref = ni.allocateCrl(der, 0, der.length, X509NI.maxContainerBytes(), consumed);

            int blobLen = ni.crlFieldsLen(ref);
            byte[] blob = new byte[blobLen];
            int[] sizes = new int[X509NI.CRL_SLOT_COUNT];
            int[] info = new int[X509NI.CRL_INFO_COUNT];
            ni.crlFields(ref, blob, sizes, info);

            int extCount = info[X509NI.CRL_INFO_EXT_COUNT];
            byte[] extBlob = new byte[0];
            int[] oidSizes = new int[0];
            int[] valSizes = new int[0];
            int[] critical = new int[0];
            if (extCount > 0)
            {
                extBlob = new byte[ni.crlExtensionsLen(ref)];
                oidSizes = new int[extCount];
                valSizes = new int[extCount];
                critical = new int[extCount];
                ni.crlExtensions(ref, extBlob, oidSizes, valSizes, critical);
            }

            int entryCount = info[X509NI.CRL_INFO_ENTRY_COUNT];
            byte[] entryBlob = new byte[0];
            int[] entrySizes = new int[0];
            int[] entryDates = new int[0];
            if (entryCount > 0)
            {
                entryBlob = new byte[ni.crlEntriesLen(ref)];
                entrySizes = new int[entryCount];
                entryDates = new int[2 * entryCount];
                ni.crlEntries(ref, entryBlob, entrySizes, entryDates);
            }

            return new JOX509CRL(binding, blob, sizes, info,
                    extBlob, oidSizes, valSizes, critical,
                    entryBlob, entrySizes, entryDates);
        }
        catch (CertificateParseException e)
        {
            throw new CRLException(e.getMessage(), e);
        }
        catch (OpenSSLException | IllegalArgumentException | IllegalStateException e)
        {
            throw new CRLException("could not parse CRL: " + e.getMessage(), e);
        }
        finally
        {
            if (ref != 0)
            {
                ni.disposeCrl(ref);
            }
        }
    }

    public CertPath engineGenerateCertPath(InputStream inStream)
        throws CertificateException
    {
        return engineGenerateCertPath(inStream, JOCertPath.PKI_PATH);
    }

    public CertPath engineGenerateCertPath(InputStream inStream, String encoding)
        throws CertificateException
    {
        if (inStream == null)
        {
            throw new CertificateException("missing input stream");
        }
        boolean pkiPath = JOCertPath.PKI_PATH.equals(encoding);
        if (!pkiPath && !JOCertPath.PKCS7.equals(encoding))
        {
            throw new CertificateException("unsupported encoding: " + encoding);
        }

        // One container, bounded by the container ceiling rather than the
        // certificate one: a path is many certificates.
        byte[] der = readOne(inStream, X509NI.maxContainerBytes());

        List<byte[]> members;
        try
        {
            members = pkiPath ? JOCertPath.decodePkiPath(der) : JOCertPath.decodePkcs7(der);
        }
        catch (IOException e)
        {
            throw new CertificateException("could not parse " + encoding + ": " + e.getMessage(), e);
        }

        List<X509Certificate> certs = new ArrayList<X509Certificate>(members.size());
        for (byte[] member : members)
        {
            // Through our own parser, so every member of the path is ours and
            // answers with our keys — the whole point of the exercise.
            certs.add((X509Certificate) parse(member));
        }
        return new JOCertPath(certs);
    }

    public CertPath engineGenerateCertPath(List<? extends Certificate> certificates)
        throws CertificateException
    {
        if (certificates == null)
        {
            throw new CertificateException("certificate list is null");
        }
        if (certificates.size() > X509NI.maxMembers())
        {
            throw new CertificateException("certificate list carries more than "
                    + X509NI.maxMembers() + " members; raise " + X509NI.MAX_MEMBERS_PROPERTY);
        }
        List<X509Certificate> certs = new ArrayList<X509Certificate>(certificates.size());
        int position = 0;
        for (Certificate c : certificates)
        {
            if (c == null)
            {
                // A TYPED refusal naming the position, which is NEITHER
                // reference's behaviour: SUN raises a bare
                // NullPointerException and BouncyCastle accepts the null
                // silently. SUN's NPE is the defect side and BC's acceptance
                // only defers the failure to whoever reads the path, so this
                // is a deliberate divergence from both.
                throw new CertificateException(
                        "certificate list contains a null element at position " + position);
            }
            if (!(c instanceof X509Certificate))
            {
                throw new CertificateException(
                        "certificate list contains a non-X.509 certificate at position "
                                + position + ": " + c.getType());
            }
            certs.add(rebind((X509Certificate) c));
            position++;
        }
        return new JOCertPath(certs);
    }

    /**
     * A path member that belongs to THIS factory's provider, re-parsing it
     * when it does not.
     *
     * <p>SUN takes the caller's objects as given; we do not, and the reason is
     * MT-14 rather than tidiness. A key belongs to the provider INSTANCE that
     * created it and is refused by any other on first use, so a path built by
     * one instance out of another's certificates carries keys its own provider
     * rejects — the same defect as an {@code unwrap} returning a key its
     * unwrapping provider refuses. Re-parsing costs a decode and makes the path
     * uniformly ours.
     *
     * <p>The fast path compares provider IDENTITY, never the name: two
     * instances share a name, which is exactly the case this has to separate.
     */
    private X509Certificate rebind(X509Certificate c)
        throws CertificateException
    {
        if (c instanceof JOX509Certificate
                && binding.sameAs(((JOX509Certificate) c).binding()))
        {
            return c;
        }
        byte[] der = c.getEncoded();
        if (der == null)
        {
            throw new CertificateException(
                    "certificate in the list does not support encoding, so it cannot be"
                            + " rebuilt through provider " + binding.name());
        }
        return (X509Certificate) parse(der);
    }

    /**
     * The encodings a CertPath of ours would carry. A CONSTANT: it is a
     * property of the FORMAT rather than of any parser, this method declares no
     * checked exception, and the JDK serves exactly these two in this order.
     * BouncyCastle additionally serves PEM; that divergence is deliberate.
     */
    public Iterator<String> engineGetCertPathEncodings()
    {
        return JOCertPath.encodings().iterator();
    }
}
