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

import javax.security.auth.x500.X500Principal;
import java.security.Principal;

/**
 * The {@link Principal} returned by the deprecated {@code getIssuerDN()} and
 * {@code getSubjectDN()}.
 *
 * <p>It exists for ONE reason: {@code Principal} declares exactly one method,
 * {@code getName()}, so that is the only thing a caller holding the declared
 * type can call — and returning an {@link X500Principal} directly made it the
 * one accessor that did not match the JDK. Measured over the PKITS corpus,
 * {@code X500Principal.getName()} is RFC 2253 and agreed with the JDK's
 * rendering on 0 of 405 certificates, while {@code toString()} agreed on all
 * 405. So both are answered here with the rendering the JDK uses.
 *
 * <p>Neither the JDK (which returns {@code sun.security.x509.JcaDistinguishedName}) nor
 * BouncyCastle returns an {@code X500Principal} from these getters, so no
 * portable caller can be casting to one; {@link #asX500Principal()} is here
 * for a caller that wants the RFC 2253 or RFC 1779 forms.
 *
 * <p>Equality delegates to the {@link X500Principal}, so two names compare on
 * their canonical form rather than on rendered text.
 
 * <p>NOT named {@code X500Name}, deliberately. Both
 * {@code sun.security.x509.X500Name} and
 * {@code org.bouncycastle.asn1.x500.X500Name} exist, the tests and the design
 * paper name both, and a third class sharing that simple name would leave a
 * reader of a stack trace or a grep hit guessing which one they had.
 */
final class JcaDistinguishedName
    implements Principal
{
    private final X500Principal principal;

    JcaDistinguishedName(X500Principal principal)
    {
        this.principal = principal;
    }

    /**
     * {@inheritDoc}
     *
     * <p>The JDK's rendering — {@code CN=Good CA, O=…, C=US}, with a space
     * after each comma — which is {@code X500Principal.toString()} and NOT
     * {@code getName()}.
     */
    public String getName()
    {
        return principal.toString();
    }

    /** The underlying principal, for the RFC 2253 and RFC 1779 forms. */
    X500Principal asX500Principal()
    {
        return principal;
    }

    public boolean equals(Object other)
    {
        if (this == other)
        {
            return true;
        }
        // JcaDistinguishedName to JcaDistinguishedName ONLY. An arm accepting a bare X500Principal
        // reads as helpful and breaks symmetry: we would equal a principal
        // that can never equal us, because X500Principal.equals knows nothing
        // of this class. Asymmetric equals misbehaves in any collection that
        // compares in the other direction, so the helpful arm is the defect.
        if (other instanceof JcaDistinguishedName)
        {
            return principal.equals(((JcaDistinguishedName) other).principal);
        }
        return false;
    }

    public int hashCode()
    {
        return principal.hashCode();
    }

    public String toString()
    {
        return principal.toString();
    }
}
