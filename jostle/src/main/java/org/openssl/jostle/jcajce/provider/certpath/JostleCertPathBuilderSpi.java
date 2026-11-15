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
import java.security.InvalidAlgorithmParameterException;
import java.security.Provider;
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
        return VerifiedOrder.factoryFor(binding);
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

        CrlOrder crlOrder;
        try
        {
            crlOrder = new CrlOrder(binding, pkix, crls);
        }
        catch (CertPathValidatorException e)
        {
            throw new CertPathBuilderException(e.getMessage(), e);
        }
        Search search = new Search(pkix, pool, crls, crlOrder);
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

    /** One OpenSSL call and the Java checks after it: a result, or a failure with the chain it reached. */
    private static final class Attempt
    {
        CertPathBuilderResult result;
        Exception failure;
        List<byte[]> chain = new ArrayList<byte[]>();
        boolean reachedAnchor;
        /** OpenSSL's reported error depth, an index into the chain; -1 when the failure is not OpenSSL's. */
        int errorDepth = -1;
        /** OpenSSL's X509_V_ERR code; 0 when the failure is not OpenSSL's. */
        int error;
    }

    /**
     * The X509_V_ERR codes (x509_vfy.h, 3.5.9) after which the reached chain is re-verified as a path: the
     * revocation status could not be determined or a CRL could not be used. UNABLE_TO_GET_CRL 3,
     * UNABLE_TO_DECRYPT_CRL_SIGNATURE 5, UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY 6 (also raised for a CRL's signer, where
     * another certificate of the name could serve; where it comes from the chain it costs one retry),
     * CRL_SIGNATURE_FAILURE 8, CRL_NOT_YET_VALID 11, CRL_HAS_EXPIRED 12,
     * ERROR_IN_CRL_LAST_UPDATE_FIELD 15, ERROR_IN_CRL_NEXT_UPDATE_FIELD 16, UNABLE_TO_GET_CRL_ISSUER 33,
     * KEYUSAGE_NO_CRL_SIGN 35, UNHANDLED_CRITICAL_CRL_EXTENSION 36, DIFFERENT_CRL_SCOPE 44,
     * CRL_PATH_VALIDATION_ERROR 54. CERT_REVOKED is not one: an order can make OpenSSL miss a CRL or its signer,
     * never invent a revocation.
     */
    /** X509_V_ERR_CERT_REVOKED (x509_vfy.h, 3.5.9). */
    private static final int CERT_REVOKED = 23;

    private static final int[] REVOCATION_CLASS = {3, 5, 6, 8, 11, 12, 15, 16, 33, 35, 36, 44, 54};

    private static boolean revocationClass(int error)
    {
        for (int e : REVOCATION_CLASS)
        {
            if (e == error)
            {
                return true;
            }
        }
        return false;
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
     * <p>The order, its routes, its cost and its verification budget are {@link VerifiedOrder}'s, shared with
     * the validator: certificates with a verified route from an anchor first, the ones that can issue among them,
     * the shorter route, later notAfter, then the encoding; nothing is dropped.
     *
     * <p>Targets are tried shortest verified route first (the route of a verifying issuer, plus one), then by
     * encoding. Each target's first attempt is always made; retries are bounded per build by the pool limit.
     * After a failure the certificate at OpenSSL's reported error depth is demoted first, then the others,
     * deepest first.
     * <p>The CRLs go to OpenSSL in {@link CrlOrder}'s order without a path. One mechanism adds a call: a chain
     * is re-verified as a path, with the validator's order of the rest of the pool and of the CRLs, when an
     * attempt succeeds and the CRLs hold a tie group, or fails with a revocation-class error after reaching a
     * trust anchor (see {@link #needsConfirmation}). It is at most one call per distinct chain, counted as a
     * retry; its success is the result, and a successful attempt whose re-verification fails is a failed attempt.
     * So what the builder returns validates under the validator's order.
     *
     * When the search fails the cause is the most specific failure seen over every target tried, not
     * necessarily the last target's (see {@link #cause}).
     */
    private final class Search
    {
        private final PKIXBuilderParameters pkix;
        private final List<Candidate> pool;
        private final List<X509CRL> crls;
        private final CrlOrder crlOrder;
        /** The CRLs in the builder's order, the same for every attempt. */
        private final List<X509CRL> builderCrls;
        /** Each chain re-verified as a path, by its encodings, with its outcome: never verified twice. */
        private final Map<List<ByteBuffer>, Attempt> confirmations = new HashMap<List<ByteBuffer>, Attempt>();
        private final List<byte[]> anchors = new ArrayList<byte[]>();
        private final List<X509Certificate> anchorCerts = new ArrayList<X509Certificate>();
        private final List<Attempt> failures = new ArrayList<Attempt>();
        /** The verified order of the pool, shared with the validator. */
        private final VerifiedOrder ranking;
        private int retriesTotal;
        String stoppedBy;

        Search(PKIXBuilderParameters pkix, List<Candidate> pool, List<X509CRL> crls, CrlOrder crlOrder)
                throws CertPathBuilderException
        {
            this.pkix = pkix;
            this.pool = pool;
            this.crls = crls;
            this.crlOrder = crlOrder;
            this.builderCrls = crlOrder.withoutPath();
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
            List<X509Certificate> ours = new ArrayList<X509Certificate>(pool.size());
            List<byte[]> ders = new ArrayList<byte[]>(pool.size());
            for (Candidate c : pool)
            {
                ours.add(c.cert);
                ders.add(c.der);
            }
            this.ranking = new VerifiedOrder(binding, anchorCerts, ours, ders,
                    Collections.<X509Certificate>emptyList(), crls);
        }

        /** The targets, shortest verified route first, then by encoding. */
        List<Candidate> orderTargets(List<Candidate> targets)
        {
            final Map<Candidate, Integer> r = new IdentityHashMap<Candidate, Integer>();
            for (Candidate t : targets)
            {
                r.put(t, ranking.routeOf(t.cert));
            }
            List<Candidate> out = new ArrayList<Candidate>(targets);
            Collections.sort(out, new Comparator<Candidate>()
            {
                public int compare(Candidate x, Candidate y)
                {
                    int d = Integer.compare(r.get(x), r.get(y));
                    return d != 0 ? d : VerifiedOrder.compareDer(x.der, y.der);
                }
            });
            return out;
        }

        /**
         * The failure reported as the build's cause, among those whose chain reached a trust anchor: a CERT_REVOKED
         * first (the lowest depth among them), since it is the one failure resting on a verified CRL about a real
         * certificate; else the one OpenSSL reported at the lowest depth (everything above it verified); the first
         * among equals. Then the first that reached an anchor; else the first. It is a diagnostic, not a verdict: it
         * names one failure the search met, not necessarily the one on the path the caller meant. A wrong candidate
         * failing at the target (depth 0) can still outrank the intended path's failure higher up when that failure
         * is not a revocation, such as an expired intermediate.
         */
        Exception cause()
        {
            Attempt best = null;
            for (Attempt a : failures)
            {
                if (!a.reachedAnchor || a.errorDepth < 0)
                {
                    continue;
                }
                if (best == null)
                {
                    best = a;
                    continue;
                }
                boolean revoked = a.error == CERT_REVOKED;
                boolean bestRevoked = best.error == CERT_REVOKED;
                if (revoked != bestRevoked)
                {
                    if (revoked)
                    {
                        best = a;
                    }
                }
                else if (a.errorDepth < best.errorDepth)
                {
                    best = a;
                }
            }
            if (best != null)
            {
                return best.failure;
            }
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
                boolean confirming = needsConfirmation(attempt);
                if (attempt.result != null && !confirming)
                {
                    return attempt.result;
                }
                if (confirming)
                {
                    Attempt asPath = confirm(attempt);
                    if (asPath == null)
                    {
                        if (attempt.result != null)
                        {
                            // An unconfirmed path is never returned.
                            return null;
                        }
                    }
                    else if (asPath.result != null)
                    {
                        return asPath.result;
                    }
                    else if (attempt.result != null)
                    {
                        attempt.result = null;
                        attempt.failure = asPath.failure;
                        attempt.error = asPath.error;
                        attempt.errorDepth = asPath.errorDepth;
                    }
                    else
                    {
                        failures.add(asPath);
                    }
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

        /**
         * Whether the attempt's chain is re-verified as a path, with the validator's order of the store and the
         * CRLs: when the attempt succeeded and the CRLs hold a tie group (see {@link CrlOrder#hasTieGroup}), so
         * that what is returned validates under the validator's order; and when it failed with a revocation-class
         * error after reaching a trust anchor (see {@link #REVOCATION_CLASS}), since only then is the path known
         * that decides which certificates are copies of it and which CRL lists it. Otherwise no extra call.
         */
        private boolean needsConfirmation(Attempt a)
        {
            if (a.result != null)
            {
                return crlOrder.hasTieGroup();
            }
            return a.reachedAnchor && revocationClass(a.error);
        }

        /**
         * The attempt's chain verified as a path: ONE more OpenSSL call, the validator's for exactly that path,
         * counted as a retry; at most once per distinct chain. Null when the retry bound is spent.
         */
        private Attempt confirm(Attempt attempt)
                throws CertPathBuilderException, InvalidAlgorithmParameterException
        {
            List<ByteBuffer> key = new ArrayList<ByteBuffer>(attempt.chain.size());
            for (byte[] der : attempt.chain)
            {
                key.add(ByteBuffer.wrap(der));
            }
            if (confirmations.containsKey(key))
            {
                return confirmations.get(key);
            }
            if (retriesTotal == MAX_RETRIES)
            {
                stoppedBy = MAX_RETRIES + " retries for one build";
                return null;
            }
            retriesTotal++;
            Attempt out = asPath(attempt.chain);
            confirmations.put(key, out);
            return out;
        }

        /*
         * The rest of the pool is the store part. A caller validating the returned path would also hand its store
         * copies of the path's certificates, which the validator orders last; they are left out here. Equivalent:
         * a certificate with the subject and key of a path certificate is never consulted ahead of the path's own,
         * as an issuer or as a CRL's issuer, so the two calls decide alike.
         */
        private Attempt asPath(List<byte[]> chain)
                throws CertPathBuilderException, InvalidAlgorithmParameterException
        {
            List<X509Certificate> path = new ArrayList<X509Certificate>();
            Set<Candidate> members = Collections.newSetFromMap(new IdentityHashMap<Candidate, Boolean>());
            for (int i = 0; i < chain.size() - 1; i++)
            {
                Candidate c = candidateFor(chain.get(i));
                if (c == null)
                {
                    Attempt out = new Attempt();
                    out.chain = chain;
                    out.failure = new CertPathBuilderException("the built chain holds a certificate not supplied");
                    return out;
                }
                members.add(c);
                path.add(c.cert);
            }
            List<X509Certificate> rest = new ArrayList<X509Certificate>();
            for (Candidate c : pool)
            {
                if (!members.contains(c))
                {
                    rest.add(c.cert);
                }
            }
            CertPathCall call;
            try
            {
                List<X509Certificate> extras = VerifiedOrder.storeOrder(binding, pkix, path, rest, crls);
                call = CertPathCall.build(pkix, path, crlOrder.forPath(path), extras);
            }
            catch (CertPathValidatorException e)
            {
                throw new CertPathBuilderException(e.getMessage(), e);
            }
            Attempt out = run(call);
            if (out.failure != null)
            {
                return out;
            }
            if (out.chain.size() != chain.size())
            {
                out.failure = new CertPathBuilderException("the path re-verified to a different chain");
                return out;
            }
            for (int i = 0; i < chain.size(); i++)
            {
                if (!Arrays.areEqual(chain.get(i), out.chain.get(i)))
                {
                    out.failure = new CertPathBuilderException("the path re-verified to a different chain");
                    return out;
                }
            }
            return complete(call, out);
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

        /** The pool without the target, in the verified order (see {@link VerifiedOrder}). */
        private List<Candidate> order(Candidate target)
        {
            List<Integer> rest = new ArrayList<Integer>();
            for (Candidate c : pool)
            {
                if (c != target)
                {
                    rest.add(c.index);
                }
            }
            Collections.sort(rest, ranking.comparator());
            List<Candidate> out = new ArrayList<Candidate>(rest.size());
            for (int i : rest)
            {
                out.add(pool.get(i));
            }
            return out;
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
            CertPathCall call;
            try
            {
                call = CertPathCall.forBuild(pkix, certs, target.cert, builderCrls);
            }
            catch (CertPathValidatorException e)
            {
                throw new CertPathBuilderException(e.getMessage(), e);
            }
            Attempt out = run(call);
            if (out.failure != null)
            {
                return out;
            }
            return complete(call, out);
        }

        /**
         * One OpenSSL call: the chain it reached and, on a verify failure, the failure. A call that could not run
         * ends the build.
         */
        private Attempt run(CertPathCall call) throws CertPathBuilderException
        {
            Attempt out = new Attempt();
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
                out.error = error;
                out.errorDepth = call.outInfo[1];
            }
            return out;
        }

        /** The Java checks after a call that verified: a result, or a failed attempt. */
        private Attempt complete(CertPathCall call, Attempt out)
                throws CertPathBuilderException, InvalidAlgorithmParameterException
        {
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
