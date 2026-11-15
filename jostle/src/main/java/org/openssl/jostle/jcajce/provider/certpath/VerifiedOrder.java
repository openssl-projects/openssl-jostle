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

package org.openssl.jostle.jcajce.provider.certpath;

import org.openssl.jostle.jcajce.provider.binding.ProviderBinding;
import org.openssl.jostle.util.Arrays;

import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.CRLException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.PriorityQueue;
import java.util.Set;
import javax.security.auth.x500.X500Principal;

/**
 * The verified order of a set of untrusted certificates, shared by the PKIX builder and validator.
 *
 * <p>OpenSSL takes the FIRST certificate in untrusted-stack order that fits, both as an issuer
 * (x509_vfy.c, 3.5.9, get0_best_issuer_sk) and as a CRL's issuer, and never tries another; so whatever order the
 * caller's stores return becomes the answer. This class computes an order from the trust anchors instead.
 *
 * <p>A certificate has a ROUTE of 1 when a trust anchor named as its issuer verifies its signature, and of k + 1 when a
 * certificate with a route of k that {@link #canIssue can issue} does (basic constraints cA true, keyCertSign where key
 * usage is present, and within the largest path length a verified route allows). Routes are found once, downward from
 * the anchors, through the bound provider's own Signature on that provider's own decode. Issuer-only nodes (the
 * validator's path certificates) take part in the routes as issuers and are not ordered. The order of the ordered
 * certificates: those with a route first; among those, a certificate whose key VERIFIES a supplied CRL issued under its
 * subject name before one of that name whose key verifies none; then the ones that can issue; then the shorter route;
 * then later notAfter; then the encoding, as a total order. A certificate without a route is ordered last, never
 * dropped. The CRL-signer test exists because OpenSSL's CRL-issuer walk reads the same stack and takes the first
 * certificate with the CRL issuer's name that passes the key-identifier check (x509_vfy.c, 3.5.9, crl_akid_check): a
 * separate CRL-signing certificate must stay ahead of another certificate of that name (the CA's own, renewed or
 * cross-certified), or the CRL fails its signature and the answer changes. It is evaluated only among certificates that
 * already have a route, only where a name has several of them and a supplied CRL names it; an unrouted certificate
 * whose key verifies a forged CRL gains nothing. Strict checking is always on, so OpenSSL refuses an issuer that cannot
 * issue, and every certificate above the target on a valid path can issue and has a route: the order loses no valid
 * path. A route needs the bound provider's own Signature to verify each edge, so a path through a signature algorithm
 * it does not serve has no route and is ordered after, never dropped; a certificate the provider cannot decode is
 * likewise unverified, ordered last by its encoding, never an error.
 *
 * <p>A CRL is caller input: it is decoded with the bound provider's factory, and a CRL that fails to decode, or to
 * verify under a candidate's key, counts as verified by none, never an error. Those checks number at most the
 * routed candidates of a name times the CRLs of that name, and CRLs cost whoever adds them nothing, so they draw on
 * their own allowance, {@link #MAX_CRL_VERIFICATIONS}, never on the certificate budget. Routes are computed first;
 * once the allowance is spent the signer flag is absent for the certificates not yet checked, and the order falls
 * back to the keys after it.
 *
 * <p>Cost: each certificate is expanded at most once (its path length is settled the first time it is taken,
 * largest first), so there are at most the anchors plus the nodes expansions, each a walk over the nodes. Only
 * certificates that can issue are expanded; each issuer's key is imported once, and answers are kept by issuer key,
 * so the checks number at most the distinct keys of such certificates, anchors included, times the nodes, and never
 * more than {@link #MAX_VERIFICATIONS}. A pool can add such keys only by holding a CA certificate issued under a
 * trust anchor; a subscriber's end-entity key extends nothing.
 */
final class VerifiedOrder
{
    /** A route that does not exist. */
    static final int NONE = Integer.MAX_VALUE;

    /**
     * Most signature checks one order makes. Once spent, further checks answer unverified: the rest is ordered
     * after, never dropped, and OpenSSL still validates every path. Beyond about one check per certificate, only
     * keys that can issue and have a route spend it, and only a CA certified under a trust anchor can add those; an
     * outsider or a subscriber costs each forged certificate one check per genuine issuing key of the name it
     * claims, so cannot reach it.
     */
    static final int MAX_VERIFICATIONS = 8 * CertPathCall.MAX_CERTS;

    /**
     * Most CRL signature checks one order makes, for the CRL-signer flag; separate from, and smaller than,
     * {@link #MAX_VERIFICATIONS}. Once spent, a certificate not yet checked has no flag.
     */
    static final int MAX_CRL_VERIFICATIONS = CertPathCall.MAX_CERTS;

    private final ProviderBinding binding;
    private final List<X509Certificate> anchorCerts;
    /** The ordered certificates, by index; an entry is null where the provider could not decode it. */
    private final List<X509Certificate> ordered;
    private final List<byte[]> der;
    /** Every node of the graph: the ordered certificates first (same indices), then the issuer-only ones. */
    private final List<X509Certificate> nodes = new ArrayList<X509Certificate>();
    /** Path length left below each certificate a route reached; anchors included. */
    private final Map<X509Certificate, Integer> remaining = new IdentityHashMap<X509Certificate, Integer>();
    private final int[] route;
    /**
     * Each issuer's public key and its encoding, built once; a key the provider cannot build is kept as a null
     * encoding. A repeat check is then a lookup, with no key import before the memo.
     */
    private final Map<X509Certificate, PublicKey> keys = new IdentityHashMap<X509Certificate, PublicKey>();
    private final Map<X509Certificate, ByteBuffer> keyIds = new IdentityHashMap<X509Certificate, ByteBuffer>();
    /** Verification answers, by issuer key encoding, then by certificate. */
    private final Map<ByteBuffer, Map<X509Certificate, Boolean>> verified =
            new HashMap<ByteBuffer, Map<X509Certificate, Boolean>>();
    /** Certificate signature checks made so far; see {@link #MAX_VERIFICATIONS}. */
    private int verifications;
    /** CRL signature checks made so far; see {@link #MAX_CRL_VERIFICATIONS}. */
    private int crlVerifications;
    /** For each ordered certificate: its key verifies a supplied CRL issued under its subject name. */
    private final boolean[] signsCrl;
    /** CRL verification answers, by issuer key encoding, then by CRL. */
    private final Map<ByteBuffer, Map<X509CRL, Boolean>> crlVerified = new HashMap<ByteBuffer, Map<X509CRL, Boolean>>();

    /**
     * @param binding     the provider whose Signature checks every edge
     * @param anchorCerts the trust anchors, decoded by that provider
     * @param ordered     the certificates to order, decoded by that provider, null where it could not
     * @param der         their encodings, index for index
     * @param issuersOnly further certificates that act as issuers and are not ordered (the validator's path)
     * @param crls        the supplied CRLs, as the caller holds them
     */
    VerifiedOrder(ProviderBinding binding, List<X509Certificate> anchorCerts, List<X509Certificate> ordered,
                  List<byte[]> der, List<X509Certificate> issuersOnly, List<X509CRL> crls)
    {
        this.binding = binding;
        this.anchorCerts = anchorCerts;
        this.ordered = ordered;
        this.der = der;
        nodes.addAll(ordered);
        nodes.addAll(issuersOnly);
        this.route = routes();
        this.signsCrl = crlSigners(crls);
    }

    /**
     * For each routed certificate whose subject name several routed certificates share and a supplied CRL names:
     * whether its key verifies one of those CRLs. Everything else is false without a check.
     */
    private boolean[] crlSigners(List<X509CRL> crls)
    {
        boolean[] out = new boolean[ordered.size()];
        if (crls.isEmpty())
        {
            return out;
        }
        Map<X500Principal, List<X509CRL>> byIssuer = new HashMap<X500Principal, List<X509CRL>>();
        CertificateFactory cf;
        try
        {
            cf = factoryFor(binding);
        }
        catch (CertificateException e)
        {
            return out;
        }
        for (X509CRL crl : crls)
        {
            X509CRL ours;
            try
            {
                ours = (X509CRL) cf.generateCRL(new ByteArrayInputStream(crl.getEncoded()));
            }
            catch (CRLException e)
            {
                continue;
            }
            catch (RuntimeException e)
            {
                continue;
            }
            List<X509CRL> list = byIssuer.get(ours.getIssuerX500Principal());
            if (list == null)
            {
                list = new ArrayList<X509CRL>();
                byIssuer.put(ours.getIssuerX500Principal(), list);
            }
            list.add(ours);
        }
        Map<X500Principal, Integer> routedOfName = new HashMap<X500Principal, Integer>();
        for (int i = 0; i < ordered.size(); i++)
        {
            X509Certificate c = ordered.get(i);
            if (c != null && route[i] != NONE)
            {
                Integer n = routedOfName.get(c.getSubjectX500Principal());
                routedOfName.put(c.getSubjectX500Principal(), n == null ? 1 : n + 1);
            }
        }
        for (int i = 0; i < ordered.size(); i++)
        {
            X509Certificate c = ordered.get(i);
            if (c == null || route[i] == NONE)
            {
                continue;
            }
            List<X509CRL> named = byIssuer.get(c.getSubjectX500Principal());
            if (named == null || routedOfName.get(c.getSubjectX500Principal()) < 2)
            {
                continue;
            }
            for (X509CRL crl : named)
            {
                if (verifiesCrl(crl, c))
                {
                    out[i] = true;
                    break;
                }
            }
        }
        return out;
    }

    /** The provider's X.509 factory: the instance when bound, else by its name, never another provider. */
    static CertificateFactory factoryFor(ProviderBinding binding) throws CertificateException
    {
        if (binding.instance() != null)
        {
            return CertificateFactory.getInstance("X.509", binding.instance());
        }
        try
        {
            return CertificateFactory.getInstance("X.509", binding.name());
        }
        catch (NoSuchProviderException e)
        {
            CertificateException ce = new CertificateException("Jostle provider is not registered");
            ce.initCause(e);
            throw ce;
        }
    }

    /** Unsigned lexicographic order of two encodings, the shorter first on a common prefix. */
    static int compareDer(byte[] a, byte[] b)
    {
        int n = Math.min(a.length, b.length);
        for (int i = 0; i < n; i++)
        {
            int d = (a[i] & 0xff) - (b[i] & 0xff);
            if (d != 0)
            {
                return d;
            }
        }
        return a.length - b.length;
    }

    /**
     * Whether the certificate may issue certificates: basic constraints with cA true, and keyCertSign where key
     * usage is present. The structural half of {@link #canIssue}.
     */
    static boolean mayIssue(X509Certificate cert)
    {
        if (cert.getBasicConstraints() < 0)
        {
            return false;
        }
        boolean[] usage = cert.getKeyUsage();
        return usage == null || (usage.length > 5 && usage[5]);
    }

    /** A CA's pathLenConstraint, or the pool limit when it has none (more than any path here can use). */
    private static int pathLenOf(X509Certificate cert)
    {
        int p = cert.getBasicConstraints();
        return (p < 0 || p == Integer.MAX_VALUE) ? CertPathCall.MAX_CERTS : p;
    }

    /** The route of the ordered certificate at this index; {@link #NONE} when it has none. */
    int route(int index)
    {
        return route[index];
    }

    /** Certificate signature checks made so far. */
    int verifications()
    {
        return verifications;
    }

    /** CRL signature checks made so far. */
    int crlVerifications()
    {
        return crlVerifications;
    }

    /** The order of the ordered certificates, by index, as described on this class. */
    Comparator<Integer> comparator()
    {
        return new Comparator<Integer>()
        {
            public int compare(Integer xi, Integer yi)
            {
                X509Certificate x = ordered.get(xi);
                X509Certificate y = ordered.get(yi);
                int d = Boolean.compare(route[yi] != NONE, route[xi] != NONE);
                if (d != 0)
                {
                    return d;
                }
                d = Boolean.compare(signsCrl[yi], signsCrl[xi]);
                if (d != 0)
                {
                    return d;
                }
                d = Boolean.compare(y != null && canIssue(y), x != null && canIssue(x));
                if (d != 0)
                {
                    return d;
                }
                d = Integer.compare(route[xi], route[yi]);
                if (d != 0)
                {
                    return d;
                }
                if (x != null && y != null)
                {
                    d = y.getNotAfter().compareTo(x.getNotAfter());
                    if (d != 0)
                    {
                        return d;
                    }
                }
                return compareDer(der.get(xi), der.get(yi));
            }
        };
    }

    /**
     * Whether the certificate can act as an issuer: {@link #mayIssue} and, where a route reached it, within the
     * largest path length any verified route allows. Ordering only.
     */
    boolean canIssue(X509Certificate cert)
    {
        if (!mayIssue(cert))
        {
            return false;
        }
        Integer left = remaining.get(cert);
        return left == null || left >= 0;
    }

    /** The shortest route of a verifying issuer of the certificate, plus one; {@link #NONE} when it has none. */
    int routeOf(X509Certificate cert)
    {
        int best = NONE;
        for (X509Certificate a : anchorCerts)
        {
            if (a.getSubjectX500Principal().equals(cert.getIssuerX500Principal()) && verifies(cert, a))
            {
                return 1;
            }
        }
        for (int i = 0; i < ordered.size(); i++)
        {
            X509Certificate c = ordered.get(i);
            if (c != null && route[i] != NONE && route[i] + 1 < best && c != cert && canIssue(c)
                    && c.getSubjectX500Principal().equals(cert.getIssuerX500Principal()) && verifies(cert, c))
            {
                best = route[i] + 1;
            }
        }
        return best;
    }

    /** Every ordered certificate's route, {@link #NONE} where there is none, found downward from the anchors. */
    private int[] routes()
    {
        Map<X509Certificate, Integer> indexOf = new IdentityHashMap<X509Certificate, Integer>();
        for (int i = 0; i < nodes.size(); i++)
        {
            if (nodes.get(i) != null)
            {
                indexOf.put(nodes.get(i), i);
            }
        }
        // Pass one: the largest path length each certificate may use. The value only shrinks along a route, so
        // issuers are taken largest first and a certificate's value is final the first time it is taken: each is
        // expanded at most once. The verified edges found are kept for pass two.
        Map<X509Certificate, List<X509Certificate>> issued =
                new IdentityHashMap<X509Certificate, List<X509Certificate>>();
        Set<X509Certificate> settled = Collections.newSetFromMap(new IdentityHashMap<X509Certificate, Boolean>());
        PriorityQueue<Object[]> queue = new PriorityQueue<Object[]>(11, new Comparator<Object[]>()
        {
            public int compare(Object[] x, Object[] y)
            {
                return Integer.compare((Integer) y[1], (Integer) x[1]);
            }
        });
        for (X509Certificate a : anchorCerts)
        {
            remaining.put(a, pathLenOf(a));
            queue.add(new Object[]{a, pathLenOf(a)});
        }
        while (!queue.isEmpty())
        {
            Object[] head = queue.poll();
            X509Certificate issuer = (X509Certificate) head[0];
            int value = (Integer) head[1];
            if (settled.contains(issuer) || remaining.get(issuer) != value)
            {
                continue;
            }
            settled.add(issuer);
            if (value < 0)
            {
                continue;
            }
            List<X509Certificate> children = new ArrayList<X509Certificate>();
            issued.put(issuer, children);
            for (X509Certificate c : nodes)
            {
                if (c == null || c == issuer
                        || !c.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())
                        || !verifies(c, issuer))
                {
                    continue;
                }
                children.add(c);
                if (!mayIssue(c) || settled.contains(c))
                {
                    continue;
                }
                // A CA that is not self-issued uses one.
                boolean selfIssued = c.getSubjectX500Principal().equals(c.getIssuerX500Principal());
                int left = Math.min(value - (selfIssued ? 0 : 1), pathLenOf(c));
                Integer before = remaining.get(c);
                if (before == null || left > before)
                {
                    remaining.put(c, left);
                    queue.add(new Object[]{c, left});
                }
            }
        }
        // Pass two: the route, the shortest number of verified steps from an anchor, breadth first over the edges
        // of certificates that can issue.
        int[] all = new int[nodes.size()];
        Arrays.fill(all, NONE);
        Map<X509Certificate, Integer> depth = new IdentityHashMap<X509Certificate, Integer>();
        Deque<X509Certificate> frontier = new ArrayDeque<X509Certificate>(anchorCerts);
        for (X509Certificate a : anchorCerts)
        {
            depth.put(a, 0);
        }
        while (!frontier.isEmpty())
        {
            X509Certificate issuer = frontier.poll();
            List<X509Certificate> children = issued.get(issuer);
            if (children == null)
            {
                continue;
            }
            for (X509Certificate child : children)
            {
                int i = indexOf.get(child);
                if (all[i] != NONE)
                {
                    continue;
                }
                all[i] = depth.get(issuer) + 1;
                if (canIssue(child))
                {
                    depth.put(child, all[i]);
                    frontier.add(child);
                }
            }
        }
        int[] out = new int[ordered.size()];
        System.arraycopy(all, 0, out, 0, out.length);
        return out;
    }

    /**
     * Whether the certificate's signature verifies under the issuer's key, through the bound provider's own
     * Signature. Anything that goes wrong while trying (a key the provider cannot build, a signature algorithm it
     * does not serve, a failed check, a refusal from the native layer) leaves the candidate unverified; it never
     * ends the caller's operation. Each answer is kept by the issuer's KEY and the certificate, so many certificates
     * of one key cost one verification per candidate.
     */
    boolean verifies(X509Certificate cert, X509Certificate issuer)
    {
        PublicKey key;
        ByteBuffer keyId;
        if (keyIds.containsKey(issuer))
        {
            keyId = keyIds.get(issuer);
            if (keyId == null)
            {
                return false;
            }
            key = keys.get(issuer);
        }
        else
        {
            try
            {
                key = issuer.getPublicKey();
                keyId = ByteBuffer.wrap(key.getEncoded());
            }
            catch (RuntimeException e)
            {
                keyIds.put(issuer, null);
                return false;
            }
            keyIds.put(issuer, keyId);
            keys.put(issuer, key);
        }
        Map<X509Certificate, Boolean> answers = verified.get(keyId);
        if (answers == null)
        {
            answers = new IdentityHashMap<X509Certificate, Boolean>();
            verified.put(keyId, answers);
        }
        Boolean known = answers.get(cert);
        if (known == null)
        {
            if (verifications == MAX_VERIFICATIONS)
            {
                // Spent: unverified from here on, and not remembered, since it was never checked.
                return false;
            }
            verifications++;
            known = check(cert, key);
            answers.put(cert, known);
        }
        return known;
    }

    /**
     * Whether the CRL's signature verifies under the certificate's key, through the bound provider's own Signature,
     * with the same key cache as {@link #verifies}, its own memo and its own allowance,
     * {@link #MAX_CRL_VERIFICATIONS}; anything that goes wrong is "does not".
     */
    private boolean verifiesCrl(X509CRL crl, X509Certificate cert)
    {
        PublicKey key;
        ByteBuffer keyId;
        if (keyIds.containsKey(cert))
        {
            keyId = keyIds.get(cert);
            if (keyId == null)
            {
                return false;
            }
            key = keys.get(cert);
        }
        else
        {
            try
            {
                key = cert.getPublicKey();
                keyId = ByteBuffer.wrap(key.getEncoded());
            }
            catch (RuntimeException e)
            {
                keyIds.put(cert, null);
                return false;
            }
            keyIds.put(cert, keyId);
            keys.put(cert, key);
        }
        Map<X509CRL, Boolean> answers = crlVerified.get(keyId);
        if (answers == null)
        {
            answers = new IdentityHashMap<X509CRL, Boolean>();
            crlVerified.put(keyId, answers);
        }
        Boolean known = answers.get(crl);
        if (known == null)
        {
            if (crlVerifications == MAX_CRL_VERIFICATIONS)
            {
                return false;
            }
            crlVerifications++;
            try
            {
                if (binding.instance() != null)
                {
                    crl.verify(key, binding.instance());
                }
                else
                {
                    crl.verify(key, binding.name());
                }
                known = Boolean.TRUE;
            }
            catch (GeneralSecurityException e)
            {
                known = Boolean.FALSE;
            }
            catch (RuntimeException e)
            {
                known = Boolean.FALSE;
            }
            answers.put(crl, known);
        }
        return known;
    }

    private boolean check(X509Certificate cert, PublicKey key)
    {
        try
        {
            if (binding.instance() != null)
            {
                cert.verify(key, binding.instance());
            }
            else
            {
                cert.verify(key, binding.name());
            }
            return true;
        }
        catch (GeneralSecurityException e)
        {
            return false;
        }
        catch (RuntimeException e)
        {
            return false;
        }
    }

    /**
     * The store's certificates in the verified order (see {@link VerifiedOrder}), so the same inputs give one answer
     * whatever order the caller's stores return them in. Only the extras are reordered: the anchors, the path in its
     * given order and the target last stay as {@link CertPathCall} lays them out. The anchors and the path's
     * certificates take part in the routes as issuers, so a CRL signer issued by a path CA has one. A certificate
     * the provider cannot decode, or whose signature it cannot check, is unverified and ordered last, never an
     * error; OpenSSL still decodes and validates everything it is given. When the provider cannot decode the path or
     * the anchors (or, for a directly constructed SPI, when no Jostle provider is registered by name to decode
     * them), the store keeps the order the caller's stores gave it.
     *
     * <p>A store certificate with the subject and public key of a path certificate or a trust anchor goes after
     * all the others, in encoding order, identical or not, never dropped: OpenSSL meets the path's and the anchors'
     * own certificates first, both as issuers and as the CRL issuer of that key, so it is never needed ahead of
     * them, while one placed ahead of a separate CRL-signing certificate of the same name changes OpenSSL's
     * revocation answer (a byte copy, a renewal, or the other half of a cross-certification). Measured on PKITS
     * 4.4.19, 4.4.20, 4.5.5 and 4.5.7 with the path in the store, as the PKITS harness holds it. A certificate whose
     * key the provider cannot rebuild is never treated as such a copy.
     */
    static List<X509Certificate> storeOrder(ProviderBinding binding, PKIXParameters pkix,
                                            List<? extends Certificate> path, List<X509Certificate> extras,
                                            List<X509CRL> crls)
            throws CertPathValidatorException
    {
        if (extras.size() < 2)
        {
            return extras;
        }
        CertificateFactory cf;
        List<X509Certificate> anchors = new ArrayList<X509Certificate>();
        List<X509Certificate> pathCerts = new ArrayList<X509Certificate>();
        try
        {
            cf = factoryFor(binding);
            for (TrustAnchor a : pkix.getTrustAnchors())
            {
                anchors.add(decode(cf, a.getTrustedCert().getEncoded()));
            }
            for (Certificate c : path)
            {
                pathCerts.add(decode(cf, c.getEncoded()));
            }
        }
        catch (CertificateException e)
        {
            // The path and the anchors are decoded by OpenSSL next, where a failure is reported with its index.
            return extras;
        }
        List<X509Certificate> knownCerts = new ArrayList<X509Certificate>(pathCerts);
        knownCerts.addAll(anchors);
        // Each known certificate's subject and key, built once; a key the provider cannot rebuild matches nothing.
        List<Object[]> known = new ArrayList<Object[]>();
        for (X509Certificate k : knownCerts)
        {
            byte[] key = keyOf(k);
            if (key != null)
            {
                known.add(new Object[]{k.getSubjectX500Principal(), key});
            }
        }
        List<X509Certificate> copies = new ArrayList<X509Certificate>();
        final Map<X509Certificate, byte[]> copyDer = new IdentityHashMap<X509Certificate, byte[]>();
        List<X509Certificate> others = new ArrayList<X509Certificate>();
        List<X509Certificate> ours = new ArrayList<X509Certificate>(extras.size());
        List<byte[]> ders = new ArrayList<byte[]>(extras.size());
        for (X509Certificate c : extras)
        {
            byte[] der;
            try
            {
                der = c.getEncoded();
            }
            catch (CertificateEncodingException e)
            {
                throw new CertPathValidatorException("a certificate could not be encoded", e);
            }
            X509Certificate decoded;
            try
            {
                decoded = decode(cf, der);
            }
            catch (CertificateException e)
            {
                decoded = null;
            }
            if (decoded != null && sameSubjectAndKey(known, decoded))
            {
                copies.add(c);
                copyDer.put(c, der);
                continue;
            }
            others.add(c);
            ders.add(der);
            ours.add(decoded);
        }
        List<X509Certificate> issuers = new ArrayList<X509Certificate>();
        for (X509Certificate c : pathCerts)
        {
            if (c != null)
            {
                issuers.add(c);
            }
        }
        List<X509Certificate> anchorCerts = new ArrayList<X509Certificate>();
        for (X509Certificate a : anchors)
        {
            if (a != null)
            {
                anchorCerts.add(a);
            }
        }
        VerifiedOrder order = new VerifiedOrder(binding, anchorCerts, ours, ders, issuers, crls);
        List<Integer> idx = new ArrayList<Integer>(others.size());
        for (int i = 0; i < others.size(); i++)
        {
            idx.add(i);
        }
        Collections.sort(idx, order.comparator());
        List<X509Certificate> out = new ArrayList<X509Certificate>(extras.size());
        for (int i : idx)
        {
            out.add(others.get(i));
        }
        Collections.sort(copies, new Comparator<X509Certificate>()
        {
            public int compare(X509Certificate x, X509Certificate y)
            {
                return compareDer(copyDer.get(x), copyDer.get(y));
            }
        });
        out.addAll(copies);
        return out;
    }

    private static boolean sameSubjectAndKey(List<Object[]> known, X509Certificate cert)
    {
        byte[] key = keyOf(cert);
        if (key == null)
        {
            return false;
        }
        for (Object[] k : known)
        {
            if (k[0].equals(cert.getSubjectX500Principal()) && Arrays.areEqual((byte[]) k[1], key))
            {
                return true;
            }
        }
        return false;
    }

    /**
     * The certificate's public key encoding, or null when the provider cannot reconstruct the key; such a
     * certificate is never treated as a copy.
     */
    private static byte[] keyOf(X509Certificate cert)
    {
        try
        {
            return cert.getPublicKey().getEncoded();
        }
        catch (RuntimeException e)
        {
            return null;
        }
    }

    private static X509Certificate decode(CertificateFactory cf, byte[] der) throws CertificateException
    {
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
    }
}
