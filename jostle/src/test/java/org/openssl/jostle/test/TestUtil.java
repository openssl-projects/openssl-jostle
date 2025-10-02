package org.openssl.jostle.test;

public class TestUtil
{
    public static int jvmVersion()
    {
        String env = System.getProperty("java.version");
        if (env.startsWith("1.8"))
        {
            return 8;
        } else if (env.startsWith("9"))
        {
            return 9;
        } else if (env.startsWith("17"))
        {
            return 17;
        } else if (env.startsWith("21"))
        {
            return 21;
        } else if (env.startsWith("22"))
        {
            return 22;
        } else if (env.startsWith("23"))
        {
            return 23;
        } else if (env.startsWith("24"))
        {
            return 24;
        } else if (env.startsWith("25"))
        {
            return 25;
        }
        throw new RuntimeException("Unknown Java version: " + env);
    }

    public static boolean versionIn(int... versions)
    {
        int v = jvmVersion();
        for (int i = 0; i < versions.length; i++)
        {
            if (versions[i] == v)
            {
                return true;
            }
        }
        return false;
    }

    public static boolean versionIs(int notBefore, int notAfter) {
        int v = jvmVersion();
        return v >= notBefore && v <= notAfter;
    }
}
