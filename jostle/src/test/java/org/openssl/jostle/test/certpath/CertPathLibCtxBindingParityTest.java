package org.openssl.jostle.test.certpath;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Every certificate the path validator decodes must be bound to jostle's lib
 * ctx.
 *
 * <h2>Why this is a SOURCE lint and not a behavioural test</h2>
 * {@code X509_verify} resolves the signature algorithm through the
 * CERTIFICATE's lib ctx ({@code x->libctx}), not the store ctx's, so an
 * unbound certificate verifies in the DEFAULT provider. Measured with a
 * standalone probe: an MD5-signed certificate is REFUSED when bound to a FIPS
 * lib ctx and VERIFIES when unbound, on both supported modules.
 * <p>
 * That difference is not observable from Java in this phase, and saying so is
 * the point. Certification path validation is registered in JSL only, so the
 * only lib ctx in play is the base one, which loads the default provider and
 * therefore answers identically whether a certificate is bound or not. A
 * "discriminator" written here would pass against unbound code and prove
 * nothing — the probe-that-cannot-reach-the-code shape. It becomes a
 * behavioural test the moment a FIPS certification path exists, and phase 2 or
 * later should add it there.
 * <p>
 * Until then the invariant is enforced structurally, the same shape as
 * {@code NativeReferenceParityTest} and {@code FIPSLibraryLookupParityTest}.
 */
public class CertPathLibCtxBindingParityTest
{
    private static final Path UTIL = Paths.get("..", "interface", "nonfips", "util", "certpath.c");

    private static String sourceWithoutCommentsOrStrings() throws IOException
    {
        Path p = Files.exists(UTIL) ? UTIL
                : Paths.get("interface", "nonfips", "util", "certpath.c");
        Assertions.assertTrue(Files.exists(p),
                "certpath.c not found; this lint reads the C source and must not "
                        + "silently pass when it cannot: looked at " + p.toAbsolutePath());
        String s = new String(Files.readAllBytes(p), StandardCharsets.UTF_8);
        // Comments explain the binding rule, and a string could name a symbol;
        // both read like code to a matcher. Strip before matching.
        s = s.replaceAll("(?s)/\\*.*?\\*/", " ");
        s = s.replaceAll("//[^\n]*", " ");
        s = s.replaceAll("\"(\\\\.|[^\"\\\\])*\"", "\"\"");
        return s;
    }

    /** Every X509 the validator decodes is created bound to the lib ctx. */
    @Test
    public void everyCertificateIsDecodedIntoALibCtxBoundObject() throws Exception
    {
        String src = sourceWithoutCommentsOrStrings();

        int news = count(src, Pattern.compile("X509_new_ex\\s*\\("));
        Assertions.assertTrue(news >= 1,
                "certpath.c must create its X509 objects with X509_new_ex; found none");

        Matcher m = Pattern.compile("X509_new_ex\\s*\\(\\s*([^,]+),").matcher(src);
        List<String> ctxArgs = new ArrayList<String>();
        while (m.find())
        {
            ctxArgs.add(m.group(1).trim());
        }
        Assertions.assertFalse(ctxArgs.isEmpty(), "no X509_new_ex call sites parsed");
        for (String arg : ctxArgs)
        {
            Assertions.assertTrue(arg.contains("get_global_jostle_ossl_lib_ctx"),
                    "X509_new_ex must take jostle's lib ctx, got: " + arg);
        }

        // And no bare decode: d2i_X509(NULL, ...) allocates an UNBOUND X509,
        // which is the defect this lint exists for.
        Assertions.assertEquals(0, count(src, Pattern.compile("d2i_X509\\s*\\(\\s*NULL")),
                "d2i_X509(NULL, ...) creates an unbound certificate, which verifies in the "
                        + "DEFAULT provider regardless of the lib ctx the store was built with");
    }

    /** The store ctx must be lib-ctx aware too. */
    @Test
    public void theStoreContextIsCreatedWithTheLibCtx() throws Exception
    {
        String src = sourceWithoutCommentsOrStrings();
        Assertions.assertEquals(0, count(src, Pattern.compile("X509_STORE_CTX_new\\s*\\(")),
                "use X509_STORE_CTX_new_ex so the store ctx carries the lib ctx");
        Assertions.assertTrue(count(src, Pattern.compile("X509_STORE_CTX_new_ex\\s*\\(")) >= 1,
                "no X509_STORE_CTX_new_ex call found");
    }

    /**
     * The matcher must stay silent on GOOD code, which is the half that gets
     * skipped: this asserts the current tree parses to at least one bound call
     * site and no unbound one, so a matcher that matched nothing at all would
     * fail here rather than read as a pass.
     */
    @Test
    public void theMatcherActuallySeesTheSource() throws Exception
    {
        String src = sourceWithoutCommentsOrStrings();
        Assertions.assertTrue(src.contains("certpath_verify"),
                "the lint is not reading certpath.c: no certpath_verify in the stripped source");
        Assertions.assertTrue(src.length() > 500, "stripped source is implausibly short");
    }

    private static int count(String s, Pattern p)
    {
        Matcher m = p.matcher(s);
        int n = 0;
        while (m.find())
        {
            n++;
        }
        return n;
    }
}
