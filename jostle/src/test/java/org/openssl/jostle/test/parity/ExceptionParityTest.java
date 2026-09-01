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

import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import java.util.EnumSet;
import java.util.Set;

/**
 * Falsifies {@link ExceptionParity} directly, on CONSTRUCTED pairs.
 *
 * <p><b>Why not test it only through the live survey.</b> An end-to-end run
 * verifies the classifier for whichever verdicts the tree happens to produce
 * today and leaves the rest unverified - and the unverified ones are exactly
 * those that matter when something regresses. At the time of writing no live
 * cell is known to produce {@code CHECKED_DIVERGENCE}, so end-to-end coverage
 * of the severity class this whole survey exists to find would have been zero.
 * Constructed pairs cost nothing and cover every arm.
 *
 * <p>The live falsifications are complementary, not redundant: they cover the
 * observation path (does {@code observe} really record what a provider did),
 * which constructed pairs cannot reach.
 */
public class ExceptionParityTest
{
    private static Observation t(Throwable x)
    {
        return Observation.threw(x);
    }

    // ---------- both refused ----------

    @Test
    public void sameExactClassIsTheOnlyMatch()
    {
        ParityResult r = ExceptionParity.classify(
                t(new BadPaddingException("ours")), t(new BadPaddingException("bc")));
        Assertions.assertEquals(ParityVerdict.MATCH, r.verdict());
        // Exact types are carried even when they agree - a reader must be able
        // to tell a match on BadPaddingException from one on RuntimeException.
        Assertions.assertEquals("javax.crypto.BadPaddingException", r.ourType());
        Assertions.assertEquals("javax.crypto.BadPaddingException", r.bcType());
    }

    @Test
    public void weThrowUncheckedWhereBouncyCastleThrowsChecked_isTheSeverityClass()
    {
        ParityResult r = ExceptionParity.classify(
                t(new RuntimeException("ours")), t(new BadPaddingException("bc")));
        Assertions.assertEquals(ParityVerdict.CHECKED_DIVERGENCE, r.verdict());
        Assertions.assertTrue(r.qualifier().contains("we-unchecked"),
                "direction must be recorded, got: " + r.qualifier());
        Assertions.assertTrue(r.isDivergence());
    }

    @Test
    public void weThrowCheckedWhereBouncyCastleThrowsUnchecked_isRecordedWithTheOtherDirection()
    {
        ParityResult r = ExceptionParity.classify(
                t(new BadPaddingException("ours")), t(new RuntimeException("bc")));
        Assertions.assertEquals(ParityVerdict.CHECKED_DIVERGENCE, r.verdict());
        Assertions.assertTrue(r.qualifier().contains("we-checked"),
                "direction must be recorded, got: " + r.qualifier());
    }

    @Test
    public void differentCheckedTypesAreATypeDivergenceNotACheckedOne()
    {
        ParityResult r = ExceptionParity.classify(
                t(new IllegalBlockSizeException("ours")), t(new BadPaddingException("bc")));
        Assertions.assertEquals(ParityVerdict.TYPE_DIVERGENCE, r.verdict());
    }

    @Test
    public void differentUncheckedTypesAreATypeDivergence()
    {
        ParityResult r = ExceptionParity.classify(
                t(new IllegalStateException("ours")), t(new IllegalArgumentException("bc")));
        Assertions.assertEquals(ParityVerdict.TYPE_DIVERGENCE, r.verdict());
    }

    // ---------- the subtype rule, both directions ----------

    @Test
    public void ourSubclassOfBouncyCastlesTypeIsNotAMatch_butIsCatchCompatible()
    {
        // AEADBadTagException extends BadPaddingException. A caller's
        // catch (BadPaddingException) DOES fire on ours.
        ParityResult r = ExceptionParity.classify(
                t(new AEADBadTagException("ours")), t(new BadPaddingException("bc")));
        Assertions.assertEquals(ParityVerdict.TYPE_DIVERGENCE, r.verdict(),
                "a subclass must never classify as MATCH");
        Assertions.assertTrue(r.qualifier().contains("catch-compatible"), r.qualifier());
    }

    @Test
    public void bouncyCastlesSubclassOfOurTypeIsCatchIncompatible()
    {
        // Reversed: a caller's catch (AEADBadTagException) does NOT fire on our
        // plain BadPaddingException. Same subtype relation, opposite consequence.
        ParityResult r = ExceptionParity.classify(
                t(new BadPaddingException("ours")), t(new AEADBadTagException("bc")));
        Assertions.assertEquals(ParityVerdict.TYPE_DIVERGENCE, r.verdict());
        Assertions.assertTrue(r.qualifier().contains("catch-incompatible"), r.qualifier());
    }

    @Test
    public void aSubtypePairAcrossTheCheckedLineIsClassifiedByTheLine()
    {
        // RuntimeException IS a subclass of Exception and IS on the other side
        // of the checked line. Severity wins; the subtype fact is still recorded.
        ParityResult r = ExceptionParity.classify(
                t(new RuntimeException("ours")), t(new Exception("bc")));
        Assertions.assertEquals(ParityVerdict.CHECKED_DIVERGENCE, r.verdict());
        Assertions.assertTrue(r.qualifier().contains("we-unchecked"), r.qualifier());
        Assertions.assertTrue(r.qualifier().contains("SUBTYPE"), r.qualifier());
    }

    // ---------- one refused ----------

    @Test
    public void oneSideRefusingIsADecisionDivergence()
    {
        Assertions.assertEquals(ParityVerdict.DECISION_DIVERGENCE, ExceptionParity.classify(
                t(new BadPaddingException("ours")), Observation.accepted(new byte[]{1})).verdict());
        Assertions.assertEquals(ParityVerdict.DECISION_DIVERGENCE, ExceptionParity.classify(
                Observation.accepted(new byte[]{1}), t(new BadPaddingException("bc"))).verdict());
    }

    // ---------- neither refused: the arm an exception survey cannot see ----------

    @Test
    public void bothAcceptedWithDifferentOutputIsASilentDivergence()
    {
        // The MT-3 key-wrap shape: no exception either side, different bytes.
        ParityResult r = ExceptionParity.classify(
                Observation.accepted(new byte[]{1, 2, 3}),
                Observation.accepted(new byte[]{1, 2, 4}));
        Assertions.assertEquals(ParityVerdict.SILENT_DIVERGENCE, r.verdict());
        Assertions.assertTrue(r.isDivergence());
    }

    @Test
    public void bothAcceptedWithDifferentLengthIsASilentDivergence()
    {
        // Wrap's actual failure mode was output LENGTH growing with the number
        // of update() calls, so unequal lengths must not slip past.
        Assertions.assertEquals(ParityVerdict.SILENT_DIVERGENCE, ExceptionParity.classify(
                Observation.accepted(new byte[24]), Observation.accepted(new byte[16])).verdict());
    }

    @Test
    public void bothAcceptedWithEqualOutputMatches()
    {
        ParityResult r = ExceptionParity.classify(
                Observation.accepted(new byte[]{9, 9}), Observation.accepted(new byte[]{9, 9}));
        Assertions.assertEquals(ParityVerdict.MATCH_ACCEPT, r.verdict());
        Assertions.assertEquals("outputs-equal", r.qualifier());
        Assertions.assertFalse(r.isDivergence());
    }

    @Test
    public void bothAcceptedWithNothingToCompareIsRecordedAsSuch()
    {
        ParityResult r = ExceptionParity.classify(
                Observation.acceptedNoOutput(), Observation.acceptedNoOutput());
        Assertions.assertEquals(ParityVerdict.MATCH_ACCEPT, r.verdict());
        Assertions.assertEquals("no-output", r.qualifier(),
                "a no-output cell must be distinguishable from a compared-equal one");
    }

    @Test
    public void aZeroLengthOutputIsNotTheSameAsNoOutput()
    {
        // Both accepted and both produced zero bytes: genuinely equal.
        Assertions.assertEquals("outputs-equal", ExceptionParity.classify(
                Observation.accepted(new byte[0]), Observation.accepted(new byte[0])).qualifier());
    }

    // ---------- absence ----------

    @Test
    public void anAbsentTransformationIsNotAMatch()
    {
        Assertions.assertEquals(ParityVerdict.BC_ABSENT, ExceptionParity.classify(
                Observation.accepted(new byte[]{1}), Observation.absent()).verdict());
    }

    @Test
    public void whichSideIsAbsentIsRecorded()
    {
        // Without the direction a row asserts BouncyCastle lacks the
        // transformation when it may be us - a false statement in the packet.
        Assertions.assertEquals("bc-absent", ExceptionParity.classify(
                Observation.accepted(new byte[1]), Observation.absent()).qualifier());
        Assertions.assertEquals("ours-absent", ExceptionParity.classify(
                Observation.absent(), Observation.accepted(new byte[1])).qualifier());
        Assertions.assertEquals("both-absent", ExceptionParity.classify(
                Observation.absent(), Observation.absent()).qualifier());
    }

    // ---------- pin drift ----------

    @Test
    public void pinDriftFiresWhenLiveBouncyCastleLeavesTheTranscribedType()
    {
        Assertions.assertEquals(ParityVerdict.MATCH, ExceptionParity.classifyPinDrift(
                t(new IllegalBlockSizeException("bc")), IllegalBlockSizeException.class).verdict());
        Assertions.assertEquals(ParityVerdict.PIN_DRIFT, ExceptionParity.classifyPinDrift(
                t(new BadPaddingException("bc")), IllegalBlockSizeException.class).verdict());
        Assertions.assertEquals(ParityVerdict.PIN_DRIFT, ExceptionParity.classifyPinDrift(
                Observation.accepted(new byte[]{1}), IllegalBlockSizeException.class).verdict());
    }

    // ---------- boolean-returning refusal (Signature.verify) ----------

    @Test
    public void bothReturningFalseIsAMatchThatIsNotAnAccept()
    {
        ParityResult r = ExceptionParity.classify(
                Observation.returned(false), Observation.returned(false));
        Assertions.assertEquals(ParityVerdict.MATCH_REFUSED_BY_RETURN, r.verdict());
        Assertions.assertFalse(r.isDivergence());
    }

    @Test
    public void oneAcceptingWhatTheOtherRefusedIsTheSevereVerdict()
    {
        // The forgery shape, both directions. Must NOT fold into
        // DECISION_DIVERGENCE, where it would sit in a 22-row bucket.
        ParityResult weAccept = ExceptionParity.classify(
                Observation.returned(true), Observation.returned(false));
        Assertions.assertEquals(ParityVerdict.VERIFICATION_DIVERGENCE, weAccept.verdict());
        Assertions.assertEquals("we-accept-bc-refuses", weAccept.qualifier());

        ParityResult bcAccepts = ExceptionParity.classify(
                Observation.returned(false), Observation.returned(true));
        Assertions.assertEquals(ParityVerdict.VERIFICATION_DIVERGENCE, bcAccepts.verdict());
        Assertions.assertEquals("bc-accepts-we-refuse", bcAccepts.qualifier());
    }

    @Test
    public void acceptingWhereTheOtherThrewIsAlsoTheSevereVerdict()
    {
        // returned(true) against a throw is still one side accepting.
        Assertions.assertEquals(ParityVerdict.VERIFICATION_DIVERGENCE, ExceptionParity.classify(
                Observation.returned(true),
                Observation.threw(new java.security.SignatureException("bc"))).verdict());
    }

    @Test
    public void throwVersusReturnedFalseIsARefusalShapeDivergence()
    {
        // Both REFUSED, so not a decision divergence - but a caller migrating
        // either meets an uncaught exception or takes the wrong branch.
        ParityResult weThrow = ExceptionParity.classify(
                Observation.threw(new java.security.SignatureException("ours")),
                Observation.returned(false));
        Assertions.assertEquals(ParityVerdict.REFUSAL_SHAPE_DIVERGENCE, weThrow.verdict());
        Assertions.assertEquals("we-throw-bc-returns-false", weThrow.qualifier());

        ParityResult bcThrows = ExceptionParity.classify(
                Observation.returned(false),
                Observation.threw(new java.security.SignatureException("bc")));
        Assertions.assertEquals(ParityVerdict.REFUSAL_SHAPE_DIVERGENCE, bcThrows.verdict());
        Assertions.assertEquals("we-return-false-bc-throws", bcThrows.qualifier());
    }

    @Test
    public void bothReturningTrueIsNotADivergence()
    {
        // The positive baseline: both verified. Must be silent - AND must not
        // be labelled a refusal. The first version returned
        // MATCH_REFUSED_BY_RETURN with the qualifier "both returned false" for
        // a both-TRUE pair: not a divergence, so this test passed, while every
        // baseline row in the Signature survey would have read as a refusal.
        // Asserting only isDivergence() is what let that through.
        ParityResult both = ExceptionParity.classify(
                Observation.returned(true), Observation.returned(true));
        Assertions.assertFalse(both.isDivergence());
        Assertions.assertEquals(ParityVerdict.MATCH_ACCEPT, both.verdict());
        Assertions.assertEquals("both verified", both.qualifier());
    }

    // ---------- vacuity: the case table must reach every arm ----------

    @Test
    public void everyVerdictTheClassifierCanProduceIsExercisedAbove()
    {
        // Completeness, not corruption. Five self-consistent checks caught a
        // truncated NIST table only when an EXPECTED COUNT was added; the same
        // applies here. Adding a verdict without a case fails this by name.
        Set<ParityVerdict> produced = EnumSet.noneOf(ParityVerdict.class);
        produced.add(ExceptionParity.classify(t(new BadPaddingException("a")), t(new BadPaddingException("b"))).verdict());
        produced.add(ExceptionParity.classify(t(new RuntimeException("a")), t(new BadPaddingException("b"))).verdict());
        produced.add(ExceptionParity.classify(t(new IllegalBlockSizeException("a")), t(new BadPaddingException("b"))).verdict());
        produced.add(ExceptionParity.classify(t(new ShortBufferException("a")), Observation.accepted(new byte[1])).verdict());
        produced.add(ExceptionParity.classify(Observation.accepted(new byte[]{1}), Observation.accepted(new byte[]{2})).verdict());
        produced.add(ExceptionParity.classify(Observation.acceptedNoOutput(), Observation.acceptedNoOutput()).verdict());
        produced.add(ExceptionParity.classify(Observation.accepted(new byte[1]), Observation.absent()).verdict());
        produced.add(ExceptionParity.classifyPinDrift(Observation.accepted(new byte[1]), BadPaddingException.class).verdict());
        produced.add(ExceptionParity.classify(Observation.returned(false), Observation.returned(false)).verdict());
        produced.add(ExceptionParity.classify(Observation.returned(true), Observation.returned(false)).verdict());
        produced.add(ExceptionParity.classify(t(new java.security.SignatureException("a")), Observation.returned(false)).verdict());

        Set<ParityVerdict> expected = EnumSet.allOf(ParityVerdict.class);
        // NO_BASELINE is produced by the HARNESS, never by the classifier - the
        // classifier is never handed a cell whose baseline failed. Asserting the
        // classifier cannot produce it is a stronger statement than exempting it.
        expected.remove(ParityVerdict.NO_BASELINE);

        Assertions.assertEquals(expected, produced,
                "every classifier verdict needs a constructed case; NO_BASELINE must stay harness-only");
    }
}
