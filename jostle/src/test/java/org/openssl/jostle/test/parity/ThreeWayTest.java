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

package org.openssl.jostle.test.parity;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import java.security.InvalidKeyException;
import java.util.EnumSet;
import java.util.Set;

/**
 * {@link ThreeWay} on CONSTRUCTED triples, before any live cell drives it.
 *
 * <p>The attribution is the whole reason the third column was added, so it is
 * unit-tested the same way the classifier was: every population and every
 * attribution reachable from hand-built observations, including the two the
 * MessageDigest surface actually produced.
 */
public class ThreeWayTest
{
    private static Observation t(Throwable x)
    {
        return Observation.threw(x);
    }

    @Test
    public void allThreeAgreeing()
    {
        ThreeWay r = ThreeWay.classify(t(new InvalidKeyException("a")),
                t(new InvalidKeyException("b")), t(new InvalidKeyException("c")));
        Assertions.assertEquals(ThreeWay.Population.ATTRIBUTABLE, r.population());
        Assertions.assertEquals(ThreeWay.Attribution.ALL_AGREE, r.attribution());
        Assertions.assertFalse(r.isDivergence());
    }

    @Test
    public void weAreOddWhenBouncyCastleAndTheJdkAgree()
    {
        // The live MessageDigest case: update(buf,-1,4) - we raise
        // IllegalArgumentException, BouncyCastle and the JDK both AIOOBE.
        ThreeWay r = ThreeWay.classify(t(new IllegalArgumentException("input offset is negative")),
                t(new ArrayIndexOutOfBoundsException("-1")), t(new ArrayIndexOutOfBoundsException("-1")));
        Assertions.assertEquals(ThreeWay.Attribution.WE_ARE_ODD, r.attribution());
        // And the other direction of the same pair: all three REFUSED, so by
        // decision they agree. Reporting only the decision axis would hide this
        // finding entirely.
        Assertions.assertEquals(ThreeWay.Attribution.ALL_AGREE, r.decisionAttribution());
        Assertions.assertTrue(r.isDivergence());
    }

    @Test
    public void bouncyCastleIsOddWhenWeAndTheJdkAgree()
    {
        // The other live MessageDigest case: BouncyCastle alone ACCEPTS a
        // negative length; we and the JDK both refuse.
        // This is the case that forced TWO axes. By EXACT behaviour all three
        // differ - we raise IllegalArgumentException, the JDK raises
        // ArrayIndexOutOfBoundsException, BouncyCastle accepts. By DECISION
        // BouncyCastle is alone, and that is the reading the finding rests on.
        ThreeWay r = ThreeWay.classify(t(new IllegalArgumentException("input len is negative")),
                Observation.accepted(new byte[32]), t(new ArrayIndexOutOfBoundsException("-1")));
        Assertions.assertEquals(ThreeWay.Attribution.ALL_DIFFER, r.attribution());
        Assertions.assertEquals(ThreeWay.Attribution.BC_IS_ODD, r.decisionAttribution());
    }

    @Test
    public void theJdkIsOddWhenWeAndBouncyCastleAgree()
    {
        ThreeWay r = ThreeWay.classify(t(new InvalidKeyException("a")),
                t(new InvalidKeyException("b")), t(new BadPaddingException("c")));
        Assertions.assertEquals(ThreeWay.Attribution.JDK_IS_ODD, r.attribution());
    }

    @Test
    public void threeDifferentAnswersMeansTheContractIsUnderspecified()
    {
        // digest(out,-1,32): IllegalArgumentException / AIOOBE / DigestException.
        ThreeWay r = ThreeWay.classify(t(new IllegalArgumentException("output offset is negative")),
                t(new ArrayIndexOutOfBoundsException("-1")), t(new java.security.DigestException("short")));
        Assertions.assertEquals(ThreeWay.Attribution.ALL_DIFFER, r.attribution());
    }

    @Test
    public void twoComparatorsIsUnattributedNotAttributed()
    {
        ThreeWay r = ThreeWay.classify(t(new InvalidKeyException("a")),
                t(new BadPaddingException("b")), Observation.absent());
        Assertions.assertEquals(ThreeWay.Population.UNATTRIBUTED, r.population());
        Assertions.assertEquals(ThreeWay.Attribution.NOT_ATTRIBUTABLE, r.attribution());
        // Still a divergence - it is real, we just cannot say whose fault it is.
        Assertions.assertTrue(r.isDivergence());
        Assertions.assertNull(r.vsJdk());
        Assertions.assertNotNull(r.vsBc());
    }

    @Test
    public void noComparatorIsUncomparedAndNeverADivergence()
    {
        ThreeWay r = ThreeWay.classify(t(new InvalidKeyException("a")),
                Observation.absent(), Observation.absent());
        Assertions.assertEquals(ThreeWay.Population.UNCOMPARED, r.population());
        Assertions.assertFalse(r.isDivergence(),
                "a cell with nothing to compare against cannot be a finding about anyone");
        Assertions.assertNull(r.vsBc());
        Assertions.assertNull(r.vsJdk());
    }

    @Test
    public void aRefusalByReturnCountsAsAgreementForAttribution()
    {
        // Attribution asks "did these two do the same thing", which is wider
        // than "does this need a ruling" - both returning false is agreement.
        ThreeWay r = ThreeWay.classify(Observation.returned(false),
                Observation.returned(false), Observation.returned(false));
        Assertions.assertEquals(ThreeWay.Attribution.ALL_AGREE, r.attribution());
    }

    @Test
    public void allThreeObservationsAreRequired()
    {
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> ThreeWay.classify(t(new InvalidKeyException("a")), Observation.absent(), null));
    }

    @Test
    public void everyPopulationAndAttributionIsExercisedAbove()
    {
        // Same vacuity discipline as the classifier: adding a value without a
        // case fails this by name rather than going quietly untested.
        Set<ThreeWay.Population> pops = EnumSet.noneOf(ThreeWay.Population.class);
        Set<ThreeWay.Attribution> atts = EnumSet.noneOf(ThreeWay.Attribution.class);
        Observation iae = t(new IllegalArgumentException("x"));
        Observation aioobe = t(new ArrayIndexOutOfBoundsException("x"));
        Observation bpe = t(new BadPaddingException("x"));
        Observation dex = t(new java.security.DigestException("x"));
        for (ThreeWay r : new ThreeWay[]{
                ThreeWay.classify(iae, iae, iae),
                ThreeWay.classify(iae, aioobe, aioobe),
                ThreeWay.classify(iae, bpe, iae),
                ThreeWay.classify(iae, iae, bpe),
                ThreeWay.classify(iae, aioobe, dex),
                ThreeWay.classify(iae, bpe, Observation.absent()),
                ThreeWay.classify(iae, Observation.absent(), Observation.absent())})
        {
            pops.add(r.population());
            atts.add(r.attribution());
            atts.add(r.decisionAttribution());
        }
        Assertions.assertEquals(EnumSet.allOf(ThreeWay.Population.class), pops,
                "a Population value has no case above");
        Assertions.assertEquals(EnumSet.allOf(ThreeWay.Attribution.class), atts,
                "an Attribution value has no case above");
    }
}
