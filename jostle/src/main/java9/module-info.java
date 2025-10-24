module org.openssl.jostle.prov {
    requires java.logging;

    provides java.security.Provider with org.openssl.jostle.jcajce.provider.JostleProvider;

    opens org.openssl.jostle.jcajce.provider.mldsa to java.base;
    opens org.openssl.jostle.jcajce.provider.mlkem to java.base;
    opens org.openssl.jostle.jcajce.provider.slhdsa to java.base;
    opens org.openssl.jostle.jcajce.provider to java.base;

    exports org.openssl.jostle;
    exports org.openssl.jostle.disposal;
    exports org.openssl.jostle.util;
    exports org.openssl.jostle.util.test;
    exports org.openssl.jostle.util.ops;
    exports org.openssl.jostle.util.io;
    exports org.openssl.jostle.util.io.pem;
    exports org.openssl.jostle.util.encoders;
    exports org.openssl.jostle.util.asn1;
    exports org.openssl.jostle.math.raw;
    exports org.openssl.jostle.jcajce;
    exports org.openssl.jostle.jcajce.spec;
    exports org.openssl.jostle.jcajce.provider;
    exports org.openssl.jostle.jcajce.interfaces;
    exports org.openssl.jostle.jcajce.util;
}