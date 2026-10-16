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

package org.openssl.jostle.test.xec;

/**
 * The RFC 7748 test vectors, transcribed from the RFC: section 5.2 scalar multiplication (two per curve and the
 * results after one and 1,000 iterations) and the section 6.1 / 6.2 Diffie-Hellman values. Hex, little-endian as
 * the RFC prints them.
 */
public final class Rfc7748Vectors
{
    private Rfc7748Vectors()
    {
    }

    /** {curve, scalar, u, output}. */
    public static final String[][] SCALAR_MULT = {
            {"X25519",
                "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
                "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
                "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"},
            {"X25519",
                "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
                "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
                "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"},
            {"X448",
                "3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779c984c24f8cdd78fbff44943eba368f54b"
                + "29259a4f1c600ad3",
                "06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9814dc031ddbdc38c19c6da2583fa5429db94ada1"
                + "8aa7a7fb4ef8a086",
                "ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239fe14fbaadeb445fc66a01b0779d98223961111e21"
                + "766282f73dd96b6f"},
            {"X448",
                "203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c538345dd77c3e4806e25f46d3315c44e0a5b43712"
                + "82dd2c8d5be3095f",
                "0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b165d015894e56c4d3570bee52fe205e28a78b91c"
                + "dfbde71ce8d157db",
                "884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7ad1b3ee3a5700df34321d62077e63633c575c1c9"
                + "54514e99da7c179d"}
    };

    /** {curve, after one iteration, after 1,000 iterations}; k = u = the base point to start. */
    public static final String[][] ITERATIONS = {
            {"X25519",
                "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079",
                "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"},
            {"X448",
                "3f482c8a9f19b01e6c46ee9711d9dc14fd4bf67af30765c2ae2b846a4d23a8cd0db897086239492caf350b51f833868b"
                + "9bc2b3bca9cf4113",
                "aa3b4749d55b9daf1e5b00288826c467274ce3ebbdd5c17b975e09d4af6c67cf10d087202db88286e2b79fceea3ec353"
                + "ef54faa26e219f38"}
    };

    /** {curve, Alice private, Alice public, Bob private, Bob public, shared secret}. */
    public static final String[][] DIFFIE_HELLMAN = {
            {"X25519",
                "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
                "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
                "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
                "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
                "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"},
            {"X448",
                "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d"
                + "9ac2d8c0a598726b",
                "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53"
                + "177f80e532c41fa0",
                "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0"
                + "366f10b65173992d",
                "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae"
                + "07bdc1c67bf33609",
                "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a"
                + "449a5037514a879d"}
    };
}
