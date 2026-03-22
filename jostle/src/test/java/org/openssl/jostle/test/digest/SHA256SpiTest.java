package org.openssl.jostle.test.digest;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Assumptions;

import java.security.MessageDigest;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.*;

public class SHA256SpiTest {

    private static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) {
            sb.append(String.format("%02x", x & 0xff));
        }
        return sb.toString();
    }

    @Test
    public void testEmptyAndABC_KAT() throws Exception {
        // Ensure provider is installed; many projects do this at bootstrap already.
        // If JostleProvider is on classpath, add it so we can resolve by provider name.
        try {
            Class<?> provCls = Class.forName("org.openssl.jostle.jcajce.provider.JostleProvider");
            java.security.Provider p = (java.security.Provider) provCls.getDeclaredConstructor().newInstance();
            if (Security.getProvider(p.getName()) == null) {
                Security.addProvider(p);
            }
        } catch (Throwable t) {
            // If native is unavailable in this test JVM, skip the test rather than failing the suite.
            Assumptions.assumeTrue(false, "JostleProvider not available in this environment: " + t.getMessage());
            return;
        }

        // SHA-256 known answers
        // empty string
        String emptyHex = "e3b0c44298fc1c149afbf4c8996fb924"
                + "27ae41e4649b934ca495991b7852b855";
        // "abc"
        String abcHex = "ba7816bf8f01cfea414140de5dae2223"
                + "b00361a396177a9cb410ff61f20015ad";

        // If provider still not present, skip
        Assumptions.assumeTrue(Security.getProvider("JSL") != null, "JSL provider not present");
        MessageDigest md = MessageDigest.getInstance("SHA-256", "JSL");
        assertEquals(32, md.getDigestLength());

        // empty
        byte[] d1 = md.digest(new byte[0]);
        assertEquals(emptyHex, toHex(d1));

        // abc
        md.reset();
        md.update("abc".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        byte[] d2 = md.digest();
        assertEquals(abcHex, toHex(d2));
    }

    @Test
    public void testIncrementalVsOneShot() throws Exception {
        Assumptions.assumeTrue(Security.getProvider("JSL") != null, "JSL provider not present");
        MessageDigest md = MessageDigest.getInstance("SHA-256", "JSL");

        byte[] part1 = "The quick brown ".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] part2 = "fox jumps over ".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] part3 = "the lazy dog".getBytes(java.nio.charset.StandardCharsets.UTF_8);

        // incremental
        md.reset();
        md.update(part1);
        md.update(part2);
        md.update(part3);
        byte[] inc = md.digest();

        // one-shot
        md.reset();
        byte[] all = new byte[part1.length + part2.length + part3.length];
        System.arraycopy(part1, 0, all, 0, part1.length);
        System.arraycopy(part2, 0, all, part1.length, part2.length);
        System.arraycopy(part3, 0, all, part1.length + part2.length, part3.length);
        byte[] one = md.digest(all);

        assertArrayEquals(one, inc);
    }
}
