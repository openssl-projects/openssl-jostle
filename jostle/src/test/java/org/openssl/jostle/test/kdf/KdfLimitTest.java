package org.openssl.jostle.test.kdf;

import org.junit.jupiter.api.Test;
import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.jcajce.provider.kdf.KdfNI;
import org.openssl.jostle.test.crypto.TestNISelector;
import org.openssl.jostle.util.encoders.Hex;

import java.nio.charset.StandardCharsets;

public class KdfLimitTest
{
    static
    {
        CryptoServicesRegistrar.isNativeAvailable(); // Trigger Loading
    }

    KdfNI kdfNI = TestNISelector.getKDFNI();


    @Test
    public void foo() throws Exception
    {
        byte[] password = "password".getBytes(StandardCharsets.UTF_8);
        byte[] salt = "salt".getBytes(StandardCharsets.UTF_8);
        String digest = "SHA-256";
        byte[] out = new byte[32];
        kdfNI.handleErrorCodes(kdfNI.pbkdf2(password, salt, 100, digest, out, 0, out.length));
        System.out.println(Hex.toHexString(out));

    }

    @Test
    public void bar() throws Exception
    {
        byte[] password = "password".getBytes(StandardCharsets.UTF_8);
        byte[] salt = "salt".getBytes(StandardCharsets.UTF_8);
        byte[] out = new byte[32];
        kdfNI.handleErrorCodes(kdfNI.scrypt(password, salt, 32768, 1, 1, out, 0, out.length));
        System.out.println(Hex.toHexString(out));

    }
}
