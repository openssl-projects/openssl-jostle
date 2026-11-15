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

import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.jcajce.provider.binding.ProviderBinding;
import org.openssl.jostle.util.Arrays;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathBuilderResult;
import java.security.cert.CertPathBuilderSpi;
import java.security.cert.CertPathParameters;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertSelector;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.Collections;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.PriorityQueue;
import java.util.Set;

/**
 * PKIX certification path building.
 * <p>
 * The target is selected in JAVA, by the caller's {@link X509CertSelector} over
 * the {@code CertStore} contents; OpenSSL then builds the chain from every
 * certificate supplied. Parameter handling is shared with
 * {@link JostleCertPathValidatorSpi} — see its javadoc for what is honoured,
 * refused and ignored, all of which applies here too.
 */
public class JostleCertPathBuilderSpi
    extends CertPathBuilderSpi
{
    private final CertPathNI ni;

    /**
     * Which provider this SPI belongs to — instance when registered, name in
     * MT-14's unbound realm. One fact, one field; see {@link ProviderBinding}.
     */
    private final ProviderBinding binding;

    public JostleCertPathBuilderSpi()
    {
        this(NISelector.CertPathNI, null);
    }

    public JostleCertPathBuilderSpi(Provider providerInstance)
    {
        this(NISelector.CertPathNI, providerInstance);
    }

    public JostleCertPathBuilderSpi(CertPathNI ni)
    {
        this(ni, null);
    }

    public JostleCertPathBuilderSpi(CertPathNI ni, Provider providerInstance)
    {
        this.ni = ni;
        this.binding = (providerInstance != null)
                ? ProviderBinding.of(providerInstance)
                : ProviderBinding.ofName(
                        JostleProvider.PROVIDER_NAME);
    }

    /**
     * The X.509 factory the built chain is decoded through.
     *
     * <p>The certificates it produces are this SPI's result — they carry the
     * public key returned in the {@link PKIXCertPathBuilderResult} — so an
     * unpinned resolution would let an arbitrary provider decide what we hand
     * back. {@code getInstance(String, Provider)} reads the provider OBJECT
     * and never consults the registry.
     *
     * <p>A directly-constructed SPI has no provider and can only resolve by
     * name, which still refuses to reach outside Jostle.
     */
    private CertificateFactory x509Factory() throws CertificateException
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
            CertificateException ce =
                    new CertificateException("Jostle provider is not registered");
            ce.initCause(e);
            throw ce;
        }
    }

    @Override
    public CertPathBuilderResult engineBuild(CertPathParameters params)
            throws CertPathBuilderException, InvalidAlgorithmParameterException
    {
        if (!(params instanceof PKIXBuilderParameters))
        {
            throw new InvalidAlgorithmParameterException(
                    "expected PKIXBuilderParameters, got "
                            + (params == null ? "null" : params.getClass().getName()));
        }
        PKIXBuilderParameters pkix = (PKIXBuilderParameters) params;
        CertPathParams.refuseUnsupported(pkix);

        CertSelector selector = pkix.getTargetCertConstraints();
        if (selector == null)
        {
            // Native asserts a target; refuse here so the assert is
            // unreachable from a caller.
            throw new InvalidAlgorithmParameterException(
                    "no target certificate constraints: this builder selects the target in Java, "
                            + "so a selector is required");
        }

        List<Candidate> pool;
        List<X509CRL> crls;
        try
        {
            pool = pool(pkix);
            crls = CertPathCall.crlsFrom(pkix);
        }
        catch (CertStoreException e)
        {
            throw new CertPathBuilderException("a CertStore could not be read", e);
        }
        List<Candidate> targets = new ArrayList<Candidate>();
        for (Candidate c : pool)
        {
            // The caller's selector reads the caller's object, as it always has.
            if (selector.match(c.callers))
            {
                targets.add(c);
            }
        }
        if (targets.isEmpty())
        {
            throw new CertPathBuilderException(
                    "no certificate in the supplied CertStores matches the target constraints");
        }

        Search search = new Search(pkix, pool, crls);
        for (Candidate target : search.orderTargets(targets))
        {
            CertPathBuilderResult result = search.from(target);
            if (result != null)
            {
                return result;
            }
        }
        String message = "no path could be built to any matching target";
        if (search.stoppedBy != null)
        {
            message += "; the search stopped at its bound of " + search.stoppedBy;
        }
        throw new CertPathBuilderException(message, search.cause());
    }

    /**
     * B1: {@code maxPathLength} is the caller's constraint, so ignoring it
     * would accept a path they ruled out. JCE counts the NON-SELF-ISSUED
     * intermediate certificates — the target is not an intermediate, and a
     * self-issued certificate does not lengthen a path (RFC 5280 6.1).
     * Enforced in Java: OpenSSL's own depth limit counts differently and is
     * deliberately left out of it.
     */
    private static void enforceMaxPathLength(PKIXBuilderParameters pkix,
                                             List<X509Certificate> pathCerts)
            throws CertPathBuilderException
    {
        int max = pkix.getMaxPathLength();
        if (max < 0)
        {
            return;   // -1 is unlimited
        }
        int intermediates = 0;
        for (int i = 1; i < pathCerts.size(); i++)   // index 0 is the target
        {
            X509Certificate c = pathCerts.get(i);
            if (!c.getSubjectX500Principal().equals(c.getIssuerX500Principal()))
            {
                intermediates++;
            }
        }
        if (intermediates > max)
        {
            throw new CertPathBuilderException(
                    "the built path has " + intermediates + " non-self-issued intermediate "
                            + "certificates, which exceeds maxPathLength " + max);
        }
    }

    /**
     * Most RETRIES for one build, over every target the selector matches: the pool limit. Walking past n
     * candidates at one position costs n + 1 calls, so the bound grows with the pool and stops only an
     * exponential search. A target's first attempt is never counted, so every matched target is tried at least
     * once, as before the search existed; a build makes at most its targets plus this many OpenSSL calls.
     */
    static final int MAX_RETRIES = CertPathCall.MAX_CERTS;

    /**
     * Most signature checks the ordering makes in one build. Once spent, further checks answer unverified: the
     * rest of the pool is ordered after, never dropped, and OpenSSL still validates every path it builds. Beyond
     * about one check per pool certificate, only keys that can issue and have a route spend it, and only a CA
     * certified under a trust anchor can add those; an outsider or a subscriber costs each forged certificate one
     * check per genuine issuing key of the name it claims, so cannot reach it.
     */
    static final int MAX_VERIFICATIONS = 8 * CertPathCall.MAX_CERTS;

    /**
     * A pool certificate: the caller's object, which the selector reads, and this provider's decode of the same
     * encoding, which the search reads; each distinct encoding once.
     */
    private static final class Candidate
    {
        final X509Certificate callers;
        final X509Certificate cert;
        final byte[] der;
        final int index;

        Candidate(X509Certificate callers, X509Certificate cert, byte[] der, int index)
        {
            this.callers = callers;
            this.cert = cert;
            this.der = der;
            this.index = index;
        }
    }

    /**
     * The CertStores' certificates, each distinct encoding once, decoded by this provider's factory. A
     * CertStoreException is the caller's to type; a RuntimeException from a store passes through unchanged.
     */
    private List<Candidate> pool(PKIXBuilderParameters pkix)
            throws InvalidAlgorithmParameterException, CertStoreException, CertPathBuilderException
    {
        CertificateFactory cf;
        try
        {
            cf = x509Factory();
        }
        catch (CertificateException e)
        {
            throw new CertPathBuilderException("the X.509 factory is not available", e);
        }
        List<Candidate> out = new ArrayList<Candidate>();
        Set<ByteBuffer> seen = new HashSet<ByteBuffer>();
        for (CertStore store : pkix.getCertStores())
        {
            for (Certificate c : store.getCertificates(null))
            {
                if (!(c instanceof X509Certificate))
                {
                    throw new InvalidAlgorithmParameterException(
                            "a CertStore holds a non-X509Certificate: " + c.getClass().getName());
                }
                byte[] der;
                try
                {
                    der = c.getEncoded();
                }
                catch (CertificateEncodingException e)
                {
                    throw new CertPathBuilderException("a certificate could not be encoded", e);
                }
                if (!seen.add(ByteBuffer.wrap(der)))
                {
                    continue;
                }
                X509Certificate ours;
                try
                {
                    ours = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
                }
                catch (CertificateException e)
                {
                    throw new CertPathBuilderException("a supplied certificate is not valid DER X.509", e);
                }
                out.add(new Candidate((X509Certificate) c, ours, der, out.size()));
            }
        }
        return out;
    }

    /** Unsigned lexicographic order of two encodings, the shorter first on a common prefix. */
    private static int compareDer(byte[] a, byte[] b)
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

    /** One OpenSSL call and the Java checks after it: a result, or a failure with the chain it reached. */
    private static final class Attempt
    {
        CertPathBuilderResult result;
        Exception failure;
        List<byte[]> chain = new ArrayList<byte[]>();
        boolean reachedAnchor;
        /** OpenSSL's reported error depth, an index into the chain; -1 when the failure is not OpenSSL's. */
        int errorDepth = -1;
    }

    /**
     * The bounded search for one build.
     *
     * <p>OpenSSL takes the FIRST matching issuer in untrusted-stack order and never tries another
     * (x509_vfy.c, 3.5.9, get0_best_issuer_sk), so a cross-certified CA builds or not by the stores' order.
     * Each attempt hands OpenSSL the SAME certificates, in an order: the authenticated order below, with the
     * certificates excluded so far moved to the end. A demoted certificate is still there for CRL-issuer
     * lookups, so every attempt sees the same revocation inputs. After a failure, each certificate of the chain
     * OpenSSL reached that has an alternative (another pool certificate with its subject, not excluded and not
     * in that chain) is demoted in turn, deepest first.
     *
     * <p>Completeness: for a valid path P and an excluded set holding none of P, a failed attempt first
     * differs from P at a position whose certificate shares a subject with P's, so the branch demoting it
     * exists and demotes nothing of P; there are finitely many certificates outside P, so the search reaches
     * P within its bounds. Every branch adds one certificate to the excluded set and no set is tried twice,
     * so loops in the certificate graph cannot loop the search.
     *
     * <p>The order: a certificate has a ROUTE of 1 when a trust anchor named as its issuer verifies its signature, and
     * of k + 1 when a certificate with a route of k that {@link #canIssue can issue} does (basic constraints cA true,
     * keyCertSign where key usage is present, and within the largest path length a verified route allows); routes are
     * found once per build, downward from the anchors, through this provider's own Signature on this provider's own
     * decode. Certificates with a route come first; among those, the ones that can issue; then the shorter route; then
     * later notAfter; then the encoding, as a total order. A certificate without a route is ordered last, never
     * dropped, so certificates that claim an issuer they cannot prove, or that could never issue, are tried after the
     * real path. Having a route comes before the issue test because the untrusted stack is also where OpenSSL looks for
     * a CRL's issuer, in order: a separate CRL-signing certificate (which cannot issue certificates) issued under an
     * anchor must stay ahead of an unrouted copy of its CA, or the revocation answer changes. Strict checking is always
     * on, so OpenSSL refuses an issuer that cannot issue, and every certificate above the target on a valid path can
     * issue and has a route: the order loses no valid path. The path length is the largest any verified route allows,
     * and the order is a preference, never a filter. A route needs this provider's own Signature to verify each edge,
     * so a path through a signature algorithm it does not serve has no route and is ordered after, never dropped.
     *
     * <p>Cost: each certificate is expanded at most once (its path length is settled the first time it is taken,
     * largest first), so a build makes at most the anchors plus the pool expansions, each a walk over the pool.
     * Only certificates that can issue are expanded; each issuer's key is imported once per build, and answers
     * are kept by issuer key, so the verifications number at most the distinct keys of such certificates,
     * anchors included, times the pool, and never more than {@link #MAX_VERIFICATIONS}. A pool can add such keys
     * only by holding a CA certificate issued under a trust anchor; a subscriber's end-entity key extends nothing.
     *
     * <p>Targets are tried shortest verified route first (the route of a verifying issuer, plus one), then by
     * encoding. Each target's first attempt is always made; retries are bounded per build by the pool limit.
     * After a failure the certificate at OpenSSL's reported error depth is demoted first, then the others,
     * deepest first.
     * When the search fails the cause is the most specific failure seen over every target tried, not
     * necessarily the last target's: the first whose chain reached a trust anchor, else the first.
     */
    private final class Search
    {
        private static final int NONE = Integer.MAX_VALUE;

        private final PKIXBuilderParameters pkix;
        private final List<Candidate> pool;
        private final List<X509CRL> crls;
        private final List<byte[]> anchors = new ArrayList<byte[]>();
        private final List<X509Certificate> anchorCerts = new ArrayList<X509Certificate>();
        private final List<Attempt> failures = new ArrayList<Attempt>();
        /** Path length left below each certificate a route reached, along that route; anchors included. */
        private final Map<X509Certificate, Integer> remaining = new IdentityHashMap<X509Certificate, Integer>();
        private final int[] route;
        /**
         * Each issuer's public key and its encoding, built once per build; a key this provider cannot build is
         * kept as a null encoding. A repeat check is then a lookup, with no key import before the memo.
         */
        private final Map<X509Certificate, PublicKey> keys = new IdentityHashMap<X509Certificate, PublicKey>();
        private final Map<X509Certificate, ByteBuffer> keyIds = new IdentityHashMap<X509Certificate, ByteBuffer>();
        /** Verification answers for this build, by issuer key encoding, then by certificate. */
        private final Map<ByteBuffer, Map<X509Certificate, Boolean>> verified =
                new HashMap<ByteBuffer, Map<X509Certificate, Boolean>>();
        private int retriesTotal;
        /** Signature checks made so far in this build; see {@link #MAX_VERIFICATIONS}. */
        private int verifications;
        String stoppedBy;

        Search(PKIXBuilderParameters pkix, List<Candidate> pool, List<X509CRL> crls)
                throws CertPathBuilderException
        {
            this.pkix = pkix;
            this.pool = pool;
            this.crls = crls;
            try
            {
                CertificateFactory cf = x509Factory();
                for (TrustAnchor anchor : pkix.getTrustAnchors())
                {
                    byte[] der = anchor.getTrustedCert().getEncoded();
                    anchors.add(der);
                    anchorCerts.add((X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der)));
                }
            }
            catch (CertificateException e)
            {
                throw new CertPathBuilderException("a trust anchor could not be decoded", e);
            }
            this.route = routes();
        }

        /** Every pool certificate's route to an anchor, NONE where there is none, found downward from the anchors. */
        private int[] routes()
        {
            Map<X509Certificate, Integer> indexOf = new IdentityHashMap<X509Certificate, Integer>();
            for (Candidate c : pool)
            {
                indexOf.put(c.cert, c.index);
            }
            // Pass one: the largest path length each certificate may use. The value only shrinks along a route,
            // so issuers are taken largest first and a certificate's value is final the first time it is taken:
            // each is expanded at most once, so the expansions number at most the anchors plus the pool, each a
            // walk over the pool. The verified edges found are kept for pass two.
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
                for (Candidate c : pool)
                {
                    if (c.cert == issuer
                            || !c.cert.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())
                            || !verifies(c.cert, issuer))
                    {
                        continue;
                    }
                    children.add(c.cert);
                    if (!mayIssue(c.cert) || settled.contains(c.cert))
                    {
                        continue;
                    }
                    // A CA that is not self-issued uses one.
                    boolean selfIssued = c.cert.getSubjectX500Principal().equals(c.cert.getIssuerX500Principal());
                    int left = Math.min(value - (selfIssued ? 0 : 1), pathLenOf(c.cert));
                    Integer before = remaining.get(c.cert);
                    if (before == null || left > before)
                    {
                        remaining.put(c.cert, left);
                        queue.add(new Object[]{c.cert, left});
                    }
                }
            }
            // Pass two: the route, the shortest number of verified steps from an anchor, breadth first over the
            // edges of certificates that can issue.
            int[] out = new int[pool.size()];
            Arrays.fill(out, NONE);
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
                    if (out[i] != NONE)
                    {
                        continue;
                    }
                    out[i] = depth.get(issuer) + 1;
                    if (canIssue(child))
                    {
                        depth.put(child, out[i]);
                        frontier.add(child);
                    }
                }
            }
            return out;
        }

        /** A CA's pathLenConstraint, or the pool limit when it has none (more than any path here can use). */
        private int pathLenOf(X509Certificate cert)
        {
            int p = cert.getBasicConstraints();
            return (p < 0 || p == Integer.MAX_VALUE) ? CertPathCall.MAX_CERTS : p;
        }

        /**
         * Whether the certificate can act as an issuer: {@link #mayIssue} and, where a route reached it, within the
         * largest path length any verified route allows. Ordering only: among certificates with a route it is the
         * second key, before the route's length.
         */
        private boolean canIssue(X509Certificate cert)
        {
            if (!mayIssue(cert))
            {
                return false;
            }
            Integer left = remaining.get(cert);
            return left == null || left >= 0;
        }

        /** The shortest route of a verifying issuer of the certificate, plus one; NONE when it has none. */
        private int routeOf(X509Certificate cert)
        {
            int best = NONE;
            for (X509Certificate a : anchorCerts)
            {
                if (a.getSubjectX500Principal().equals(cert.getIssuerX500Principal()) && verifies(cert, a))
                {
                    return 1;
                }
            }
            for (Candidate c : pool)
            {
                if (route[c.index] != NONE && route[c.index] + 1 < best && c.cert != cert && canIssue(c.cert)
                        && c.cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal())
                        && verifies(cert, c.cert))
                {
                    best = route[c.index] + 1;
                }
            }
            return best;
        }

        /** The targets, shortest verified route first, then by encoding. */
        List<Candidate> orderTargets(List<Candidate> targets)
        {
            final Map<Candidate, Integer> r = new IdentityHashMap<Candidate, Integer>();
            for (Candidate t : targets)
            {
                r.put(t, routeOf(t.cert));
            }
            List<Candidate> out = new ArrayList<Candidate>(targets);
            Collections.sort(out, new Comparator<Candidate>()
            {
                public int compare(Candidate x, Candidate y)
                {
                    int d = Integer.compare(r.get(x), r.get(y));
                    return d != 0 ? d : compareDer(x.der, y.der);
                }
            });
            return out;
        }

        /** The most specific failure seen: the first whose chain reached a trust anchor, else the first. */
        Exception cause()
        {
            for (Attempt a : failures)
            {
                if (a.reachedAnchor)
                {
                    return a.failure;
                }
            }
            return failures.isEmpty() ? null : failures.get(0).failure;
        }

        CertPathBuilderResult from(Candidate target)
                throws CertPathBuilderException, InvalidAlgorithmParameterException
        {
            List<Candidate> order = order(target);
            Deque<BitSet> pending = new ArrayDeque<BitSet>();
            Set<BitSet> tried = new HashSet<BitSet>();
            BitSet none = new BitSet();
            pending.push(none);
            tried.add(none);
            boolean first = true;
            while (!pending.isEmpty())
            {
                if (!first)
                {
                    if (retriesTotal == MAX_RETRIES)
                    {
                        stoppedBy = MAX_RETRIES + " retries for one build";
                        return null;
                    }
                    retriesTotal++;
                }
                first = false;
                BitSet excluded = pending.pop();
                Attempt attempt = attempt(target, demote(order, excluded));
                if (attempt.result != null)
                {
                    return attempt.result;
                }
                failures.add(attempt);
                List<Candidate> chain = inPool(attempt.chain);
                // Pushed shallowest first, so the deepest is tried next; the certificate at OpenSSL's reported
                // error depth is pushed last of all, so it is the first demoted.
                Candidate atError = attempt.errorDepth > 0 && attempt.errorDepth < attempt.chain.size()
                        ? candidateFor(attempt.chain.get(attempt.errorDepth)) : null;
                for (Candidate c : chain)
                {
                    if (c != atError)
                    {
                        branch(c, target, excluded, chain, tried, pending);
                    }
                }
                if (atError != null)
                {
                    branch(atError, target, excluded, chain, tried, pending);
                }
            }
            return null;
        }

        private void branch(Candidate c, Candidate target, BitSet excluded, List<Candidate> chain,
                            Set<BitSet> tried, Deque<BitSet> pending)
        {
            if (c == target || excluded.get(c.index) || !hasAlternative(c, excluded, chain))
            {
                return;
            }
            BitSet next = (BitSet) excluded.clone();
            next.set(c.index);
            if (tried.add(next))
            {
                pending.push(next);
            }
        }

        private Candidate candidateFor(byte[] der)
        {
            for (Candidate c : pool)
            {
                if (Arrays.areEqual(c.der, der))
                {
                    return c;
                }
            }
            return null;
        }

        /** The chain's certificates that are pool certificates, in chain order. */
        private List<Candidate> inPool(List<byte[]> chain)
        {
            List<Candidate> out = new ArrayList<Candidate>();
            for (byte[] der : chain)
            {
                for (Candidate c : pool)
                {
                    if (Arrays.areEqual(c.der, der))
                    {
                        out.add(c);
                        break;
                    }
                }
            }
            return out;
        }

        private boolean hasAlternative(Candidate c, BitSet excluded, List<Candidate> chain)
        {
            for (Candidate other : pool)
            {
                if (other != c && !excluded.get(other.index) && !chain.contains(other)
                        && other.cert.getSubjectX500Principal().equals(c.cert.getSubjectX500Principal()))
                {
                    return true;
                }
            }
            return false;
        }

        private List<Candidate> demote(List<Candidate> order, BitSet excluded)
        {
            List<Candidate> out = new ArrayList<Candidate>(order.size());
            for (Candidate c : order)
            {
                if (!excluded.get(c.index))
                {
                    out.add(c);
                }
            }
            for (Candidate c : order)
            {
                if (excluded.get(c.index))
                {
                    out.add(c);
                }
            }
            return out;
        }

        /** The pool without the target, in the authenticated order described on this class. */
        private List<Candidate> order(Candidate target)
        {
            List<Candidate> rest = new ArrayList<Candidate>();
            for (Candidate c : pool)
            {
                if (c != target)
                {
                    rest.add(c);
                }
            }
            Collections.sort(rest, new Comparator<Candidate>()
            {
                public int compare(Candidate x, Candidate y)
                {
                    int d = Boolean.compare(route[y.index] != NONE, route[x.index] != NONE);
                    if (d != 0)
                    {
                        return d;
                    }
                    d = Boolean.compare(canIssue(y.cert), canIssue(x.cert));
                    if (d != 0)
                    {
                        return d;
                    }
                    d = Integer.compare(route[x.index], route[y.index]);
                    if (d != 0)
                    {
                        return d;
                    }
                    d = y.cert.getNotAfter().compareTo(x.cert.getNotAfter());
                    if (d != 0)
                    {
                        return d;
                    }
                    return compareDer(x.der, y.der);
                }
            });
            return rest;
        }

        /**
         * Whether the certificate's signature verifies under the issuer's key, through this provider's own
         * Signature. Anything that goes wrong while trying (a key this provider cannot build, a signature
         * algorithm it does not serve, a failed check, a refusal from the native layer) leaves the candidate
         * unverified; it never ends the build. Each answer is kept per build by the issuer's KEY and the
         * certificate, so many certificates of one key cost one verification per candidate.
         */
        private boolean verifies(X509Certificate cert, X509Certificate issuer)
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
         * One OpenSSL call with the untrusted certificates in the given order, then the Java checks after it.
         * A verify failure and a failed Java check are a failed attempt; a call that could not run, or a
         * chain that could not be decoded, ends the build.
         */
        private Attempt attempt(Candidate target, List<Candidate> untrusted)
                throws CertPathBuilderException, InvalidAlgorithmParameterException
        {
            List<X509Certificate> certs = new ArrayList<X509Certificate>(untrusted.size());
            for (Candidate c : untrusted)
            {
                certs.add(c.cert);
            }
            Attempt out = new Attempt();
            CertPathCall call;
            try
            {
                call = CertPathCall.forBuild(pkix, certs, target.cert, crls);
            }
            catch (CertPathValidatorException e)
            {
                throw new CertPathBuilderException(e.getMessage(), e);
            }
            int rc = ni.ni_verify(call.der, call.sizes, call.count, call.crlCount, call.anchorCount,
                    call.timeSecs, 1, call.revocation, call.policyFlags, call.policies, call.policyCount,
                    call.chainOut, call.outInfo, call.treeOut);
            if (rc == ErrorCode.JO_CERT_DECODE_FAILED.getCode())
            {
                throw new CertPathBuilderException("a supplied certificate is not valid DER X.509",
                        new CertPathValidatorException("a supplied certificate is not valid DER X.509"));
            }
            if (rc == ErrorCode.JO_CRL_DECODE_FAILED.getCode())
            {
                throw new CertPathBuilderException("a supplied CRL is not valid DER X.509",
                        new CertPathValidatorException("a supplied CRL is not valid DER X.509"));
            }
            try
            {
                ni.baseErrorHandler(rc);
            }
            catch (OpenSSLException e)
            {
                throw new CertPathBuilderException("certification path building could not run", e);
            }

            out.chain = call.builtChain();
            out.reachedAnchor = !out.chain.isEmpty() && isAnchor(out.chain.get(out.chain.size() - 1));
            int error = call.outInfo[0];
            if (error != 0)
            {
                out.failure = CertPathErrors.toValidatorException(ni, error, call.outInfo[1], null);
                out.errorDepth = call.outInfo[1];
                return out;
            }
            try
            {
                CertificateFactory cf = x509Factory();
                List<X509Certificate> built = call.builtCertificates(cf);
                if (built.size() < 2)
                {
                    // The target is itself a trust anchor: a CertPath of no certificates. A failed attempt for
                    // this target, so the others are still tried.
                    out.failure = new CertPathBuilderException("the target is a trust anchor, so no path is built");
                    return out;
                }
                // The last element is the anchor; a CertPath excludes it.
                List<X509Certificate> pathCerts = new ArrayList<X509Certificate>(
                        built.subList(0, built.size() - 1));
                try
                {
                    enforceMaxPathLength(pkix, pathCerts);
                }
                catch (CertPathBuilderException e)
                {
                    out.failure = e;
                    return out;
                }
                CertPath cp = cf.generateCertPath(pathCerts);
                PKIXCertPathValidatorResult vr = new PKIXCertPathValidatorResult(
                        call.resolveAnchor(pkix), null, pathCerts.get(0).getPublicKey());
                out.result = new PKIXCertPathBuilderResult(cp, vr.getTrustAnchor(), call.policyTree(),
                        pathCerts.get(0).getPublicKey());
                return out;
            }
            catch (CertPathValidatorException e)
            {
                throw new CertPathBuilderException(e.getMessage(), e);
            }
            catch (CertificateException e)
            {
                throw new CertPathBuilderException("the built chain could not be decoded", e);
            }
            catch (IOException e)
            {
                throw new CertPathBuilderException("the policy tree could not be decoded", e);
            }
        }

        /**
         * Whether the certificate may issue certificates: basic constraints with cA true, and keyCertSign where
         * key usage is present. The structural half of {@link #canIssue}, which extends routes and orders the
         * candidates.
         */
        private boolean mayIssue(X509Certificate cert)
        {
            if (cert.getBasicConstraints() < 0)
            {
                return false;
            }
            boolean[] usage = cert.getKeyUsage();
            return usage == null || (usage.length > 5 && usage[5]);
        }

        private boolean isAnchor(byte[] der)
        {
            for (byte[] a : anchors)
            {
                if (Arrays.areEqual(a, der))
                {
                    return true;
                }
            }
            return false;
        }
    }
}
