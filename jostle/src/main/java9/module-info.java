module org.openssl.jostle.prov {
    requires java.logging;

    provides java.security.Provider with org.openssl.jostle.jcajce.provider.JostleProvider,
            org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;

    // No opens: java.base is exempt from the setAccessible check, so an opens
    // qualified to it grants nothing. Seven such clauses were removed.


    exports org.openssl.jostle;
    exports org.openssl.jostle.disposal;
    exports org.openssl.jostle.util;
    exports org.openssl.jostle.util.ops;
    exports org.openssl.jostle.util.io;
    exports org.openssl.jostle.util.encoders;
    exports org.openssl.jostle.util.asn1;
    exports org.openssl.jostle.util.asn1.oids;
    exports org.openssl.jostle.jcajce;
    exports org.openssl.jostle.jcajce.spec;
    exports org.openssl.jostle.jcajce.provider;
    exports org.openssl.jostle.jcajce.provider.fips;
    exports org.openssl.jostle.jcajce.interfaces;
    exports org.openssl.jostle.jcajce.util;
}
