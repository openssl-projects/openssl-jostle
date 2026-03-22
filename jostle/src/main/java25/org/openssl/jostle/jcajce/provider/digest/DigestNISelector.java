package org.openssl.jostle.jcajce.provider.digest;

import org.openssl.jostle.Loader;

/**
 * Java 25 selector for {@link DigestNI}: prefer FFI when available, else JNI.
 * <p>
 * Loader.isFFI() reflects runtime detection and configuration
 * (org.openssl.jostle.loader.interface = auto/jni/ffi/none). When FFI is
 * available on Java 25+, this selector binds to the {@link DigestNIFFI}
 * implementation; otherwise it falls back to {@link DigestNIJNI}.
 */
final class DigestNISelector
{
    static final DigestNI DigestNI;

    static
    {
        if (Loader.isFFI())
        {
            DigestNI = new DigestNIFFI();
        }
        else
        {
            DigestNI = new DigestNIJNI();
        }
    }

    private DigestNISelector() {}
}
