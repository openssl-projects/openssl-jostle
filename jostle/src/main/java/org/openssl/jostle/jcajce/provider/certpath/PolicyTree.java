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

import org.openssl.jostle.util.asn1.ASN1ObjectIdentifier;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.cert.PolicyNode;
import java.security.cert.PolicyQualifierInfo;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * The JCA policy tree from OpenSSL's, read from the CERTPATH_TREE layout in
 * certpath.h.
 *
 * <p>OpenSSL returns the tree before RFC 5280 6.1.5 (g)(iii) and marks the
 * user-constrained nodes; the intersection with the initial policy set is
 * applied here. anyPolicy is the root's own valid policy, as OpenSSL encoded
 * it.
 */
final class PolicyTree
{
    private PolicyTree()
    {
    }

    /** A node as OpenSSL reported it, before the intersection. */
    private static final class Raw
    {
        final int depth;
        final Raw parent;
        final String policy;
        final boolean inUserSet;
        final boolean critical;
        final Set<PolicyQualifierInfo> qualifiers;
        final Set<String> expected;
        final List<Raw> children = new ArrayList<Raw>();
        boolean deleted;

        Raw(int depth, Raw parent, String policy, int flags, Set<PolicyQualifierInfo> qualifiers,
            Set<String> expected)
        {
            this.depth = depth;
            this.parent = parent;
            this.policy = policy;
            this.inUserSet = (flags & IN_USER_SET) != 0;
            this.critical = (flags & CRITICAL) != 0;
            this.qualifiers = qualifiers;
            this.expected = expected;
        }

        void delete()
        {
            deleted = true;
            for (Raw c : children)
            {
                c.delete();
            }
        }

        boolean hasLiveChild()
        {
            for (Raw c : children)
            {
                if (!c.deleted)
                {
                    return true;
                }
            }
            return false;
        }
    }

    /* Node flags, matching CERTPATH_TREE_* in certpath.h. */
    private static final int IN_USER_SET = 1;
    private static final int CRITICAL = 2;

    /**
     * @param tree the native encoding, or null when OpenSSL returned no tree
     * @return the valid policy tree's root, or null when no tree remains
     */
    static PolicyNode decode(byte[] tree) throws IOException
    {
        if (tree == null)
        {
            return null;
        }
        ByteBuffer in = ByteBuffer.wrap(tree);
        int count = i32(in);
        int last = i32(in) - 1;
        boolean anyPolicyUserSet = i32(in) != 0;
        List<Raw> nodes = new ArrayList<Raw>();
        for (int i = 0; i < count; i++)
        {
            int depth = i32(in);
            int parent = i32(in);
            int flags = i32(in);
            String policy = oid(in);
            Set<PolicyQualifierInfo> qualifiers = new LinkedHashSet<PolicyQualifierInfo>();
            for (int q = i32(in); q > 0; q--)
            {
                qualifiers.add(new PolicyQualifierInfo(der(in)));
            }
            Set<String> expected = new LinkedHashSet<String>();
            for (int e = i32(in); e > 0; e--)
            {
                expected.add(oid(in));
            }
            if (parent >= nodes.size() || (parent < 0) != (i == 0))
            {
                throw new IOException("policy tree node " + i + " names parent " + parent);
            }
            Raw r = new Raw(depth, parent < 0 ? null : nodes.get(parent), policy, flags, qualifiers, expected);
            if (r.parent != null)
            {
                r.parent.children.add(r);
            }
            nodes.add(r);
        }
        if (nodes.isEmpty() || in.hasRemaining())
        {
            throw new IOException("policy tree encoding is malformed");
        }

        Raw root = nodes.get(0);
        if (!anyPolicyUserSet)
        {
            intersect(nodes, root.policy, last);
        }
        return root.deleted ? null : build(root, null);
    }

    /**
     * RFC 5280 6.1.5 (g)(iii), steps 2 to 4; OpenSSL has already added step 3's
     * nodes. OpenSSL flags one node per user policy, so step 2 tests the
     * policy, not the flag: a second node with that policy is kept too. No
     * PKITS path puts two nodes of one policy in the set, so that arm is
     * unwitnessed.
     */
    private static void intersect(List<Raw> nodes, String anyPolicy, int last)
    {
        Set<String> userPolicies = new HashSet<String>();
        for (Raw r : nodes)
        {
            if (r.inUserSet)
            {
                userPolicies.add(r.policy);
            }
        }
        for (Raw r : nodes)
        {
            if (!r.deleted && r.parent != null && r.parent.policy.equals(anyPolicy)
                    && !r.policy.equals(anyPolicy) && !userPolicies.contains(r.policy))
            {
                r.delete();
            }
        }
        for (Raw r : nodes)
        {
            if (r.depth == last && r.policy.equals(anyPolicy))
            {
                r.delete();
            }
        }
        for (int d = last - 1; d >= 0; d--)
        {
            for (Raw r : nodes)
            {
                if (r.depth == d && !r.deleted && !r.hasLiveChild())
                {
                    r.deleted = true;
                }
            }
        }
    }

    private static Node build(Raw r, Node parent)
    {
        Node n = new Node(r, parent);
        for (Raw c : r.children)
        {
            if (!c.deleted)
            {
                n.children.add(build(c, n));
            }
        }
        return n;
    }

    private static int i32(ByteBuffer in) throws IOException
    {
        if (in.remaining() < 4)
        {
            throw new IOException("policy tree encoding is truncated");
        }
        return in.getInt();
    }

    private static byte[] der(ByteBuffer in) throws IOException
    {
        int len = i32(in);
        if (len <= 0 || len > in.remaining())
        {
            throw new IOException("policy tree DER length " + len + " is out of range");
        }
        byte[] b = new byte[len];
        in.get(b);
        return b;
    }

    /* A DER OBJECT IDENTIFIER: tag, then a short-form or long-form length. */
    private static String oid(ByteBuffer in) throws IOException
    {
        byte[] der = der(in);
        if (der.length < 2)
        {
            throw new IOException("policy tree OID is truncated");
        }
        int off = (der[1] & 0x80) == 0 ? 2 : 2 + (der[1] & 0x7f);
        try
        {
            return ASN1ObjectIdentifier.fromContents(der, off, der.length - off).getId();
        }
        catch (IllegalArgumentException e)
        {
            throw new IOException("policy tree OID is malformed", e);
        }
    }

    /**
     * An immutable PolicyNode. Children run in OpenSSL's level order; the
     * JCA sets no order on them.
     */
    static final class Node
        implements PolicyNode
    {
        private final int depth;
        private final Node parent;
        private final String validPolicy;
        private final boolean critical;
        private final Set<PolicyQualifierInfo> qualifiers;
        private final Set<String> expected;
        /* Filled by build() before the root is returned, never after. */
        private final List<Node> children = new ArrayList<Node>();

        private Node(Raw r, Node parent)
        {
            this.depth = r.depth;
            this.parent = parent;
            this.validPolicy = r.policy;
            this.critical = r.critical;
            this.qualifiers = Collections.unmodifiableSet(r.qualifiers);
            this.expected = Collections.unmodifiableSet(r.expected);
        }

        @Override
        public PolicyNode getParent()
        {
            return parent;
        }

        @Override
        public Iterator<? extends PolicyNode> getChildren()
        {
            return Collections.unmodifiableList(children).iterator();
        }

        @Override
        public int getDepth()
        {
            return depth;
        }

        @Override
        public String getValidPolicy()
        {
            return validPolicy;
        }

        @Override
        public Set<? extends PolicyQualifierInfo> getPolicyQualifiers()
        {
            return qualifiers;
        }

        @Override
        public Set<String> getExpectedPolicies()
        {
            return expected;
        }

        @Override
        public boolean isCritical()
        {
            return critical;
        }

        @Override
        public String toString()
        {
            return "PolicyNode[" + depth + " " + validPolicy + " expected " + expected + "]";
        }
    }
}
