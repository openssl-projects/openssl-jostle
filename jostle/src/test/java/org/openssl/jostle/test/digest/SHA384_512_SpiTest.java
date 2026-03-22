package org.openssl.jostle.test.digest;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import java.security.MessageDigest;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class SHA384_512_SpiTest {

    private static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) {
            sb.append(String.format("%02x", x & 0xff));
        }
        return sb.toString();
    }

    private static void ensureProviderOrSkip() {
        try {
            Class<?> provCls = Class.forName("org.openssl.jostle.jcajce.provider.JostleProvider");
            java.security.Provider p = (java.security.Provider) provCls.getDeclaredConstructor().newInstance();
            if (Security.getProvider(p.getName()) == null) {
                Security.addProvider(p);
            }
        } catch (Throwable t) {
            Assumptions.assumeTrue(false, "JostleProvider not available in this environment: " + t.getMessage());
        }
        Assumptions.assumeTrue(Security.getProvider("JSL") != null, "JSL provider not present");
    }

    @Test
    public void testSHA384_KAT() throws Exception {
        ensureProviderOrSkip();
        MessageDigest md = MessageDigest.getInstance("SHA-384", "JSL");
        // empty string KAT
        String emptyHex = "38b060a751ac96384cd9327eb1b1e36a\n"
                + "21fdb71114be07434c0cc7bf63f6e1da\n"
                + "274edebfe76f65fbd51ad2f14898b95b";
        emptyHex = emptyHex.replace("\n", "");
        assertEquals(48, md.getDigestLength());
        String got = toHex(md.digest(new byte[0]));
        assertEquals(emptyHex, got);
    }

    @Test
    public void testSHA512_KAT() throws Exception {
        ensureProviderOrSkip();
        MessageDigest md = MessageDigest.getInstance("SHA-512", "JSL");
        // empty string KAT
        String emptyHex = "cf83e1357eefb8bdf1542850d66d8007\n"
                + "d620e4050b5715dc83f4a921d36ce9ce\n"
                + "47d0d13c5d85f2b0ff8318d2877eec2f\n"
                + "63b931bd47417a81a538327af927da3e";
        emptyHex = emptyHex.replace("\n", "");
        assertEquals(64, md.getDigestLength());
        String got = toHex(md.digest(new byte[0]));
        assertEquals(emptyHex, got);
    }
}
