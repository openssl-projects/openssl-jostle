package org.openssl.jostle.jcajce.provider;

import javax.security.auth.Destroyable;

class KeyUtil
{
    static void checkDestroyed(Destroyable destroyable)
    {
        if (destroyable.isDestroyed())
        {
            throw new IllegalStateException("key has been destroyed");
        }
    }


}
