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

package org.openssl.jostle.jcajce.provider.bcfks;

import java.util.Base64;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;

import org.bouncycastle.crypto.util.ScryptConfig;
import org.bouncycastle.jcajce.BCFKSLoadStoreParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * BCFKS store fixtures BouncyCastle 1.86 itself wrote, byte-identical to
 * BCFKSStoreTest.java at r1rv86. Shared by {@link BcFKSFormatTest} (outer
 * ObjectStore structure only) and {@link BcFKSKeyStoreSpiTest} (full decrypt
 * and decode).
 *
 * <p>The fixture byte arrays below are copied verbatim from BouncyCastle's
 * own test source, so BouncyCastle's licence notice accompanies them:
 *
 * <pre>
 * MIT License (https://opensource.org/licenses/MIT)
 *
 * Copyright (c) 2000-2026 The Legion of the Bouncy Castle Inc.
 * (https://www.bouncycastle.org).
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sub license, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions: The above copyright notice and this
 * permission notice shall be included in all copies or substantial
 * portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 * </pre>
 */
final class BcFKSFixtures
{
    private BcFKSFixtures()
    {
    }

    // r1rv86 BCFKSStoreTest.java:71-77.
    static final byte[] TRUSTED_CERT_DATA = Base64.getDecoder().decode(
        "MIIB/DCCAaagAwIBAgIBATANBgkqhkiG9w0BAQQFADCBhjELMAkGA1UEBhMCQVUxKDAmBgNVBAoMH1RoZSBMZWdpb24gb2YgdGhlIE" +
            "JvdW5jeSBDYXN0bGUxEjAQBgNVBAcMCU1lbGJvdXJuZTERMA8GA1UECAwIVmljdG9yaWExJjAkBgkqhkiG9w0BCQEWF2lzc3VlckBi" +
            "b3VuY3ljYXN0bGUub3JnMB4XDTE0MDIyODExMjcxMVoXDTE0MDQyOTExMjcxMVowgYcxCzAJBgNVBAYTAkFVMSgwJgYDVQQKDB9UaG" +
            "UgTGVnaW9uIG9mIHRoZSBCb3VuY3kgQ2FzdGxlMRIwEAYDVQQHDAlNZWxib3VybmUxETAPBgNVBAgMCFZpY3RvcmlhMScwJQYJKoZI" +
            "hvcNAQkBFhhzdWJqZWN0QGJvdW5jeWNhc3RsZS5vcmcwWjANBgkqhkiG9w0BAQEFAANJADBGAkEAtKfkYXBXTxapcIKyK+WLaipil5" +
            "hBm+EocqS9umJs+umQD3ar+xITnc5d5WVk+rK2VDFloEDGBoh0IOM9ke1+1wIBETANBgkqhkiG9w0BAQQFAANBAJ/ZhfF21NykhbEY" +
            "RQrAo/yRr9XfpmBTVUSlLJXYoNVVRT5u9SGQqmPNfHElrTvNMZQPC0ridDZtBWb6S2tg9/E=");

    // r1rv86 BCFKSStoreTest.java:83-118.
    static final byte[] KWP_KEY_STORE = Base64.getDecoder().decode(
        "MIIJ/TCCCT8wgZUGCSqGSIb3DQEFDTCBhzBlBgkqhkiG9w0BBQwwWARAKXQjiKdsRc8lgCbMh8wLqjNPCiLcXVxArXA4/n6Y72G8jn" +
            "jWUsXqvMQFmruTbQF6USSVaMgS1UlTbdLtu7yH9wIDAMgAAgEgMAwGCCqGSIb3DQILBQAwHgYJYIZIAWUDBAEvMBEEDJMoeNdAkcnM" +
            "QjtxowIBCASCCKMU5dCIAkTb84CUiUGy4no3nGgVZL+2t4MNPKhMiL+2Xv7Ok9rucD2SMitzm+kxnkVU+aYGLVUrwEPFCvq5GWdnzO" +
            "yjCd3XzTieySlfxhIxYMixGfz8NAvPu+P2LwtE+j2C4poHS7+MG22OXpxTTLGzWGuYusxb1zVLTujP6gSVGbtBikLxOXRiYXapZQzL" +
            "32bOIKV/tHLv3JCKvIGyJAnTQBDlHQxVsm8fcYBhc101qc9vd3qMborJEZK3E+znJ++lI0yIb+WcZJ3PDI11Fzf22M1D6qtV8RELsL" +
            "b5zfLheFLc4rJcY0YSja24se0tFvT7X9cSyrpvXdNDmzBlBThPdINsKPf3N6fO/9ibn/0QIJPY5bQc3SwbN8c7vboHOJzbWjq7n7Q7" +
            "1ZkFeiYO/NIXKZ4/KN8sqlRLjvEy4BFnbGoufim+K1zpFGdUPbYpDkuzCkfQfiEaQ9Zt69p5w5e6qh04kgHue0Ac/0IsnRIFy78k4J" +
            "lK5TlrB3exqpuISZEWP72WDa+0yTaRM6ecMfIqieDNQmpD9U3HpmdMgiWZXTpCTtM/3I62Bv7EkwcVccRP9z4QUcoGZy81EemQ4d3e" +
            "OVfYgvgZBCsbSpf+V8HlsnApTbJubTY1wJQAA19h49E7l3VCxSmeNcUSSE68xJjdJPPAzU1v83+RkYUDPlRx1YsO77zYBSuOwJr0g4" +
            "BDTfnyd1vZCM6APt9N7Z2MfALoSSg4EF68nr144GLAMZw4ZVjfUeZ+kF3mjTDPujOoyI3vDztA5ZFa0JCQpp8Yh0CuO+sGnWLh+7Tb" +
            "irH2ifEscmNI++csUwDPSInjfGzv722JY6c9XzbaqDGqstpykwwUVN01IceolCvgeHZW7P0feDyqbpgmpdRxiGuBWshFEdcttXDSl9" +
            "mQVEyYAMHQFVQKIx2RrFD7QPWZhITGqCvF44GNst/3962Au9oyGAY6rRQfN/HdF4+ygWjOS0t/50c1eAyBj1Rfk/M4sHBi8dKDjOpX" +
            "QzqfqLqHjevxQPw1761q629iTagOO/3AIebbraD2qLqDHjmqUAW0ZVLkdS5n8zYyiqGsVeKok7SSDDKQfqwouPHJvRmKzHAK6bZDdr" +
            "qMBqNfNcRghWHSH0jM4j8G1w3H2FQsNfBHqTb+kiFx1jEovKkf2HumctWwI5hqV2R2I23ThRNQbh6bdtFc8D3a8YnuXpUK+Tw/RTzM" +
            "eGtUsVeakGOZDHh9AlxsdcLChY9xTLMzbpLfb6VAE9kpZ86Uwe60i+S4ropyIp5cwXizAgJPh1T51ZWTzEu+s8BDEAkXSDgxs1PFML" +
            "Ha2pWnHPMNSs4VF6eeyK0Vj66m4LcQ0AgE35jAGxWQm31KbWI/h8EMxiC/tDJfMJ3UUKxYCRdbcneDBRc4E4cNmZVqajc8o9Fexr97" +
            "GLQ6Is1HVoG65qtq6I9Wt6wmA/5i8ptG7bl7NrIzn3Fg0bMbwHEaKIoXrFHTM0EjwnOkVtQWBNDhnBa66IDJXMxJzXDB2uoMU/wX2y" +
            "4dGpM+mgomJt0U3i29HqeihEQjHDc0hTJLkp2SJ2tKw3+VtoXUinV1W7tsG9TMj3F+XNSeiGFrcZpryi6+Fml3Tohg/FaiJQLpB9pL" +
            "tzNd61ln1Q6RTHcOMChNocCRaagH6ntX5j8GcVp0auPfw8zyR5iNGueQdnV38Q6MhiGxlMQKC/gjBdKAHRI2q+31tGK8ZslHFxDee1" +
            "fy3wtRZpLDwgecH74g4+1TYTLPj/PNeYRQicRCa1BbvI3zB1d8t+LKTg/f34MeEzdMpRT8fRb6vw/O1CRhtdl/0pBQ7RZQSrZFPdEr" +
            "KPRv4/1IG46crTCw1/AOMTXKjPeaUeADjff7aLKizJHUSPr6sTRxoMWQeOYfBDnRiLDZ/XYvSDkjnzesa0hdQIIe/tHnqSZ23Jbi46" +
            "bLD7Lhf3lfZzbEOqKXAlq0m/ooidubndc0K1xVex4M/T+M0mMPRwO0uICJM4EtivU9Fp5/12GXdvimGEhr/adGodf+JduhsUoIUiz5" +
            "TghRV0dSuLtQkcD2d0GkfxgHkCBlhbS3WifMWLTa3lHWrCVyhdIf6m5UOtqfzj5CEEkwE+L6urNBo3D4zHUjm8XJekjI3xjGbQHjBo" +
            "sr+BFHkwGNfTXXBHVqRE0L8lH6kSpLaCF5iMpU2NuAeaJ/xdS7LUXBtn4Zvi34PR3/akwMYIr4X+uDM0eB0KkOyyqSXZVPsT7uGMef" +
            "wOHmbx1eHe22mR/q1r1iczDwOtXNYo8OB9jSsL3XWFdt4STxdA7kFEsAvK001x0pjrpTa/j/4ixjKhBGu8V/WVuBl0Hlicybtdl7xF" +
            "CgoeF3FrAsn2Rw0EjVJm4uLpdEHGIVCWWTgadhZ9YyMWoMenLOUoGMlWXGE9hLGUfJG1wOMlFg33zq4dwCj17O0ULdpHh7QFQFEEpM" +
            "+zscDhOHKmrZZEuiJvhR0JFkZz2rml0TEfSjCmdQ8XfJMzLbQ8BKZhWLOQdVh8Scn96Hm0EGkFBkcb4dO/Ubw+cu+bGskxHL1Q6uW0" +
            "hGOdejiS7yWclE//uzSlSTa7GRtZ1F/vziWIVno0IInEyiOsCGagagWmxMvv1GTnRJwJl8Bt0BPJmWS2L4CClD6ocH2DrCEEYjMraP" +
            "dquGbe0/0eYv3qANDWjvzJs4o4/4SoKZuRBuVj5YQMs69XdaxPgnC3Xfx59pf1Q5qOQe94R8oVTnT6z6G1Radsoweh1UnwItjjt4pt" +
            "pfjyUn4bF2Ovz6bs/Tprbo2B4gmBraimCVHT5pruScBY2q4Vd8XiGbiviS8SgqUnxhH/4XmRRdeYpHpZyet1DT+nNTdJdOCfrsE630" +
            "9CEQNhQRXt9j5c9S8fnwEA3x/FsriCOAnXsmjVZTnMmctnEYs0aChPxnCBgW1vb2dVUTJQ+KR+2CD3xPNiIEwdk9rA+80k1z3JXek8" +
            "tac4cwgbcwDAYIKoZIhvcNAgsFADBlBgkqhkiG9w0BBQwwWARAvH3U5H5R/XeTJYthNF/5aUAsqnHPEeperLR1iXVAiVH8t4iby2WP" +
            "FbvQtoKDbREOo9NaULKIWlDlimxCJosvygIDAMgAAgFAMAwGCCqGSIb3DQILBQAEQGeIvocQlW6yjPCczqj+yNdn6sTcmuHI9AnFtn" +
            "aY0K7Ki2oIlXl5D9TLznFhJuHDtrIA3VYy2XTCvyrY3qEIySo=");

    // r1rv86 BCFKSStoreTest.java:119-141.
    static final byte[] OLD_KEY_STORE_NO_PW = Base64.getDecoder().decode(
        "MIIF/jCCBUEwgZQGCSqGSIb3DQEFDTCBhjBkBgkqhkiG9w0BBQwwVwRAr1ik7Ut78AkRAXYcwhwjOjlSjfjzLzCqFFFsT2OHXWtCK1h" +
            "FEnbVpdi5OFL+TQ6g8kU9w8EYrIZH7elwkMt+6wICBAACASAwDAYIKoZIhvcNAgsFADAeBglghkgBZQMEAS8wEQQMi3d/cdRmlkhW1" +
            "B43AgEIBIIEpvp3Y9FgZwdOCGGd3pJmhTy4z3FQ+xQD5yQizR3GtuNwLQvrsDfaZOPdmt6bKSLQdjVXX214d2JmBlKNOj9MD6SDIsW" +
            "+yEVoqk4asmQjY5KZi/l7o9IRMTAVFBSKyXYcmnV/0Wqpv/AEOaV1ytrxwu2TOW3gZcbNHs3YQvAArxMcqCLyyGJYJ73Qt2xuccZa8" +
            "YgagCovr0t2KJYHdpeTIFvhaAU7/iHKa0z4ES0YjZoEKNu7jA91WCnKIaFdJCRLS5NKqcuHw93KgGNelEEJt9BbhmddlzZ3upxdw9Q" +
            "vZsaasD30ezK6viROxAkerfXzI5QVS8Qlz1/TQ10/ri8Lf04H3+HNRV5YS0cH9ghoBxKvvu8whcA43FdvGE7MREIEykJBWWWK5bgul" +
            "duf2ONNA5cIBTLwLOmPdT2I4PkXUjCROHBmX9m4F0p41+9DCpqS2z5H2oS4+n+sBLHFWZbsOu/NAXKswLDVRaBbSGJW270dc8Gv1Vo" +
            "B9VWlkqX4wLZTLp+Gbk2aJaKlp9zeN5EHG/vh1wJWYq138h2MB+cYZ2TCl3+orhzlzx6xfRVAtbBz9kpPDpfgpnahM0+IdcuVc5B2s" +
            "UR6hBM/GQY4cgFdsBI1XhoEjLxzD8PxF4Se2KbseB6fq0+h1GKSB8YXv+IVvroF1ueqsi8DisNcrkN3Bdbl28gopF7kG+aJ84JkEHP" +
            "bmN+EaYIZZ6yRBHa/nfXltblCIRbSfB0x4L8Uz+/lbEen5hov7v/60+v+6nAlNWs3Af0ZlmOU4KAcSgmLBJzh3+83qld8BlJH1t1HI" +
            "Ct/md7BQLXn4fRWeKUhbwvSvlut7knai1ZKaLxEhNCh+/7UDE7Y1wvzBfWJYfyAFkCxW9U0erkwp8euea7OgMd1U+6R9H8FEgEjzaj" +
            "maMCKqmAizZromgxsiPzZgMkz9J1eY/VtWqk1Gu3mq7O/6ilWh/dogxVfeVZ2kyS17rXL152pcJHIx20Vsd4gnFx8sLqfqiO5n/qoA" +
            "8BkbbwdrBmURNCVmDMuqlMl/yiOpqohQ8kcp81l6B6NHAtxAWCSz7ypfKw43G80tTKhHYDguCUvdbLCuR43DJj22SuuxoRKHjnhtYD" +
            "xKL58W5HhIcSFliI5qBuRc+EHVOdHfFfqNhisitOzuTk9z1Emg0lweVFzaWkpqxiwtNfOmiYrg+EzDYiGmiQ7/r5Uxqku+aX69khXN" +
            "OKQbx1d48PI/0mNJV7qUY6k1hhU3ZkMSnuR1akaq/Skds7BnC3yj8byDlWouJ5AYreHPc4uxoH6YwSrBGBWw9omxGPFE6aGWze8pV/" +
            "95HOrftINptVRDPtuBvV8fo9qPJ7Xr6unG3kEbKoflYTbolguI4YN338+QIc6+53I7N7H+3kkb8TJhUPj4ImS1dvN5KfkSwYuKX8sQ" +
            "r4MGUVTfJwbRCKkbimtJ1MY/Rcpe9No1xQObp/3G4Tfam1KlhhLaM3A9fCLm+WwS7zlemJ+KcWa7iOyoS5f646+aLRZ7sNeuoxYecq" +
            "9ybT5W8mYitUdvxcPwMlh2w1DqwmDqXVqkevs8WnDBJM2FYWVJenoU98oPd3pbFicZsjuMIG2MAwGCCqGSIb3DQILBQAwZAYJKoZIh" +
            "vcNAQUMMFcEQAI9+HvmFMWhbl/EmZBy/B2CDIKcCs4AuhrKu50UVHSHobnuX7phOAtxdI9VevE2ehMCbWkLrUa3Qtkv4CmozFwCAgQ" +
            "AAgFAMAwGCCqGSIb3DQILBQAEQHGAl3x6ij1f4oSoeKX/KQOYByXY/Kk4BinJM0cG0zXapG4vYidgmTMPTguuWXxL1u3+ncAGmW2EY" +
            "gEAHiOUu5c=");

    // r1rv86 BCFKSStoreTest.java:142-164.
    static final byte[] OLD_KEY_STORE = Base64.getDecoder().decode(
        "MIIF/jCCBUEwgZQGCSqGSIb3DQEFDTCBhjBkBgkqhkiG9w0BBQwwVwRA1njcCRF+e+s3pQsVaifZNKCablZ+5cLEeJXEdsAtJt7ZG2" +
            "6dq5iYzBhbol5L5D0n9RLYFW5IoK9rCd8UpD61GAICBAACASAwDAYIKoZIhvcNAgsFADAeBglghkgBZQMEAS8wEQQMhT2rGv09UX8P" +
            "pmcZAgEIBIIEpu8KeIMyG7FZL+rxPCJ7YFNRXEjykNt70W1BD8VDsN/bGuW4kCnKXNlzV2SAx/44mhdR47qiKrXziCwZUgpck9d1R5" +
            "nQQtTKw0Q2F1EuWGm9ErFpCMYl6E43/URmkmjuCMIpEbrKHTmuEjqsdHJ7+CST4cFU3lCsBj7dMl9G7tLxJhq5aCTYxhFX6R5kM5QH" +
            "t/pkxE/5Ei94nh606cKNjLA7Zlrbn1c5WlTpesOjE1pZp/QY9UuSiSA0nucNd8Ir0H4PK120QerdQQ4EWY/KHEDn4EqGpaE1Z6WVAS" +
            "qyYING7g1q4YeYeJjFA2V8fqsj0j/wxG29x5J5ghcERnrcQGTL2P3uLvy2chgHdqIaFxKStANVntW+dy9MD/uCZnYi7DzeS3qWEZcl" +
            "cpp5oImL79k08uc9jpfOnNaqbxz8b76ABH39OVQVSGRhh7fkYYSlUEWpSlaFoKaywV3yJwXlilhX7JqyiqRt/hrlVLTlQZZeJbYMrE" +
            "KA/Fn2ePmNt5hJRiHzF5w/YVd5My27QtPvInCgJ2bV+Z0Di3l+Sd4SCS1NiHtR6uB7G3xlI8E3uQVV4dRNXM8drb1Uu/eTGxGSH0hY" +
            "2Z0N8TvSGdz+TAQRNn/nXaMA2nZdfhVmwiRPPP3BaiBCJM6y5FroOT1rkPupA+gpmlw1M7Ey+rABphsqEig2XyRe4FMMmIc4i8ga6m" +
            "KH+F0e26ycsb+nSycdhLIs5Dcdo42wzmvmoG8fvM+/C1N98TfB0m2KbtS1TV9dohagJi4l685iUMnUbH3nmha7RPYUVnpZdDokiATV" +
            "WjuSezCdpIxv1m6HOqXuArvDtvExDzyVZnPoIF4DEuRypDpW8tkppvLGA6VEo1TPJvjvyrX6SqorwDa1JINVnQGPpx5StjL+eIQBzV" +
            "RHoy+NP2dcPBHUlAfwWrkk7V7CwST6uNYBL+YVhTYYIN1HnJY0CkmmraqMvkMks17WAd9hONzSLmNT3St6s3VIQMMPC7qNatB+570Q" +
            "BxgiQC7ieFu1wqy9ZNnNLU9DC69HR37uUFyiCnbCb54XY/zmCUhc8ONBi3L8DwmiDZ2oF7WIEmWvblcbWaQNFPNBMS9KzejHLpvopW" +
            "+XcfRX4jCz9PwZ9HhUwGk8R7b1MALgJhXxuAD/a4VQK2OtlTHeAgSGBrGcGgjzSa7JWM5ks+EHdTuLaiU3ViVXLrZq4lr/D8ni1Ipt" +
            "kKPaVcWnl56i7AXZtPj5xVE5v2eVual3sBOkObpoObyrDfmouZW0A9GPk69jGTm5j2FU+50p7JxSfR78BZJitBqrcYS4boVDFmTZYN" +
            "MBpgGkHqW79gWKIde/pf6nf9cSnDEjZEIZJQI5rnLqmGG6+vKxJQJt7be4vCzGTVMqiY3+QgVCuwtK7Vd44RaPDnzQDxC9OwJOhIUF" +
            "s1UwoS/vU/n5kbaYmD+py3dgffw4EicaOv5hG7NELZRKxueCjnVwdeCGH+WgJL7AIUdruK/SvsQbJX1asEFKU5KCG4Z9Sw0Sw4MjL+" +
            "OAiyIbpQpMfHtG+9ORfWWmlH8McA3rjT07fKelhPn1YauY2jGZLfBrpBrQKxvcL82og7rUMIG2MAwGCCqGSIb3DQILBQAwZAYJKoZI" +
            "hvcNAQUMMFcEQOchs+KAXDWhUaENOgpSls0plNpIUYDkgnMa/iL4RzEOCwiZBOuBdGsEfP3oKLWUS3wO83vrgetSLK5fkN6QNnoCAg" +
            "QAAgFAMAwGCCqGSIb3DQILBQAEQBLCR5e4teCd8JX0xJbGadSCFaO1oEehyXSZrnKahsYJ7yTHqJTvlcWvqTiwn7Gud/SJmMXPQkZC" +
            "SQhMQ5k+xZ4=");

    // bc-java 0bd9d2bae5 BCFKSStoreTest.java:85-93. Written by BC 1.86 with
    // N=1024, r=8, p=1: up to that release the block size was passed where
    // RFC 7914 has the parallelization parameter, so this only opens under
    // that convention. Entry "seckey" = 000102030405060708090a0b0c0d0e0f,
    // password "hello world".
    static final byte[] LEGACY_SCRYPT_KEY_STORE = Base64.getDecoder().decode(
        "MIICJjCCAZ0wXwYJKoZIhvcNAQUNMFIwMAYJKwYBBAHaRwQLMCMEFNNP1KhyD/fiwwQ45qBnNtX/ZSxWAgIEAAIBCAIBAQIBIDAeBglghkgBZQ" +
            "MEAS8wEQQMYZ+qgQjkDkV6JIGWAgEIBIIBOIX2t8xGZ3QGc5RnRPITEAbmWBNdiPmM7YD6PzljGmwrs4/IdajHZtELUr4LI3Rps+oHVxo3V4" +
            "+YwjLIw0iBKz3wiXO69iMoNuVAGLTFOYyr1s0lpY8R9pAcOLsKyeQgCtxg9CDr1mgNVynmR/MSOlJycsc3xSAAFhl5F8jc67oCLMmst4xx09" +
            "4THIpk5F0PO+6/OVVI5X48E7Yv5oz8VkwwggDGO/KQrC1TQDReBbxdLyAcnZceGO71pNlAvRg5J7lKi4qO5FkTg4PJy32autRqZKJn+U5oYT" +
            "wDj7zFPMHbKEVtvGzr5Zbh+e5X7OkOkcANyEygbyAvN1u/DQ8pwFhfqGajIWy2mZpSk3SJho5Uh/5WjVQ604dskyaEz7UCII5UNv06f3D5Ou" +
            "jw5IJhGDfpO6Mu3ox0AjCBgjAMBggqhkiG9w0CCwUAMDAGCSsGAQQB2kcECzAjBBRT/v5SZ1Zk7uXdnBaiY0f4kdWWXAICBAACAQgCAQECAU" +
            "AEQCIaST6IdxaX6n7Q5vciPd/huBfVuRyG8nLzDkPT2j412HR+AzuR46i/UjCVGSSHx7TyokAnMW8aZ84BgPi1FC0=");

    // bc-java 0bd9d2bae5 BCFKSStoreTest.java:94-104. Same store as
    // LEGACY_SCRYPT_KEY_STORE, integrity-checked with a SignatureCheck (no
    // MAC to settle the legacy-vs-encoded convention, so the decrypt-level
    // retry is what this exercises) -- verify with
    // LEGACY_SCRYPT_SIGNED_KEY_STORE_PUB.
    static final byte[] LEGACY_SCRYPT_SIGNED_KEY_STORE = Base64.getDecoder().decode(
        "MIIDITCCAZswXwYJKoZIhvcNAQUNMFIwMAYJKwYBBAHaRwQLMCMEFF2Y5CpDqmcfBqTWCT7ipFo1BZemAgIEAAIBCAIBAQIBIDAeBglghkgBZQ" +
            "MEAS8wEQQMFskoc+K4ETOddKRRAgEIBIIBNlLkf9fdsCGqpEw+nuwohy0W3iE9U2YyPTEud4uU/ZvIVbwoDQE3OZjA0Usdeo0rCcS0nHM4ud" +
            "kq82qaYHfi9KLRMM4zkmX4yFs79QNeY10TxZETbawqu7u9/eThkB4Cg+Kl45E3JxiHVOM6qNy4blQcIVtlLKkLUrkcDzz3RmYR+1ZgA/0hZw" +
            "SBE5QG9HBdhGT6T/qdkzNPfigpQb+oICl4XFFrTwEFAgRqbZrwXyRJS4D90g1j+3J7FR5CmOTnetIJ6Tp/PZWc0uwKa97vcXa7rxWnMTwwbX" +
            "l2EmXd7UAM9pHSHz4na08cyj7F47Ywvj4mMFufq4GmWocsilGDPWdUDPoyamg6i7GED8A8ah2TEAYQ4SCe3QW8PeIeqLsCq2MqO/GgCeGFq3" +
            "ivH8zesnMtRf69/xmgggF+MIIBejAKBggqhkjOPQQDBKCCASEwggEdMIIBGTCBv6ADAgECAgEBMAoGCCqGSM49BAMCMBUxEzARBgNVBAMMCk" +
            "JDRktTIFRlc3QwIBcNMjAwOTEzMTIyNjQwWhgPMjA5OTEyMDMxNjUzMjBaMBUxEzARBgNVBAMMCkJDRktTIFRlc3QwWTATBgcqhkjOPQIBBg" +
            "gqhkjOPQMBBwNCAAR9SCWqNcCFdFKDpZXRCHdRFNdN54fILw6wkQifg/XrgcJNTblD8k0itEmw/MZJwMa07w8dSyrsJkfI5ace92reMAoGCC" +
            "qGSM49BAMCA0kAMEYCIQCH7YuUatuft9l24frXikqXJLB3Feoy23qgBx3gV0ZUCgIhAMzuUzGZJZoQzs4HPlUlS+oNSXsupvKvSRKyQbOe6d" +
            "1HA0cAMEQCIFF/bAD27bd+S0jY9vagS8sqiy9zBHmsIPdsRI+Nsl5BAiBVyGGiWxZWZ5dKpDP80iuNtT6ISuxrI47iNN6hrnkv1w==");

    // bc-java 0bd9d2bae5 BCFKSStoreTest.java:106-108. The EC verification key
    // for LEGACY_SCRYPT_SIGNED_KEY_STORE's SignatureCheck.
    static final byte[] LEGACY_SCRYPT_SIGNED_KEY_STORE_PUB = Base64.getDecoder().decode(
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfUglqjXAhXRSg6WV0Qh3URTXTeeHyC8OsJEIn4P164HCTU25Q/JNIrRJsPzGScDGtO8PHUsq7C" +
            "ZHyOWnHvdq3g==");

    /**
     * A BCFKS store BouncyCastle 1.86 itself writes at test time, using
     * scrypt (r1rv86 BCFKSStoreTest.shouldStoreUsingSCRYPT's own config:
     * N=1024, r=8, p=1, salt 20 bytes) as the KDF -- BC as a TEST-time
     * witness only, never in the implementation. One certificate
     * entry, password {@link BcFKSKeyStoreSpiTest#testPassword}.
     */
    static byte[] scryptStore() throws Exception
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        Certificate cert = CertificateFactory.getInstance("X.509", "BC")
                .generateCertificate(new ByteArrayInputStream(TRUSTED_CERT_DATA));

        KeyStore store = KeyStore.getInstance("BCFKS", "BC");
        store.load(null, null);
        store.setCertificateEntry("cert", cert);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        store.store(new BCFKSLoadStoreParameter.Builder(bOut, BcFKSKeyStoreSpiTest.testPassword)
                .withStorePBKDFConfig(new ScryptConfig.Builder(1024, 8, 1).withSaltLength(20).build())
                .build());
        return bOut.toByteArray();
    }
}