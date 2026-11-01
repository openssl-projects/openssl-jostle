/*
 * RSA-KEM through EVP_PKEY_encapsulate: does the provider need the KEM operation named, and what does RSASVE
 * return?
 *
 * Three arms on one 2048-bit RSA key: no set_kem_op, set_kem_op "RSASVE" (the control), and set_kem_op "RSAKEM".
 * Per arm: init, size query, encapsulate, decapsulate, with rc and error reasons per step. Where an arm
 * encapsulates, the secret is checked against r recomputed from the key (wrapped^d mod n), zero-padded to the
 * modulus length, over enough trials to include a secret whose leading byte is zero.
 */
#include "probe_common.h"
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/rsa.h>

#define TRIALS 2000

static EVP_PKEY *make_key(OSSL_LIB_CTX *ctx)
{
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_from_name(ctx, "RSA", NULL);
    probe_step("RSA keygen_init", kctx == NULL ? -100 : EVP_PKEY_keygen_init(kctx));
    probe_step("RSA set bits 2048", kctx == NULL ? -100 : EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 2048));
    probe_step("RSA keygen", kctx == NULL ? -100 : EVP_PKEY_keygen(kctx, &key));
    EVP_PKEY_CTX_free(kctx);
    return key;
}

/* r = wrapped^d mod n, written big-endian into out at exactly nlen bytes. */
static int expected_secret(EVP_PKEY *key, const unsigned char *wrapped, size_t wlen, unsigned char *out,
                           size_t nlen)
{
    BIGNUM *n = NULL;
    BIGNUM *d = NULL;
    BIGNUM *c = BN_bin2bn(wrapped, (int) wlen, NULL);
    BIGNUM *r = BN_new();
    BN_CTX *bn = BN_CTX_new();
    int ok = c != NULL && r != NULL && bn != NULL
             && EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_N, &n) == 1
             && EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_D, &d) == 1
             && BN_mod_exp(r, c, d, n, bn) == 1
             && BN_bn2binpad(r, out, (int) nlen) == (int) nlen;
    BN_free(n);
    BN_clear_free(d);
    BN_free(c);
    BN_clear_free(r);
    BN_CTX_free(bn);
    return ok;
}

static void arm(OSSL_LIB_CTX *ctx, EVP_PKEY *key, const char *op)
{
    const char *name = op == NULL ? "no kem_op" : op;
    char label[96];
    unsigned char wrapped[512];
    unsigned char secret[512];
    unsigned char back[512];
    unsigned char want[512];
    size_t nlen = (size_t) EVP_PKEY_get_size(key);
    size_t wlen = 0;
    size_t slen = 0;

    printf("-- arm: %s\n", name);
    EVP_PKEY_CTX *ectx = EVP_PKEY_CTX_new_from_pkey(ctx, key, NULL);
    snprintf(label, sizeof(label), "%s encapsulate_init", name);
    int rc = ectx == NULL ? -100 : EVP_PKEY_encapsulate_init(ectx, NULL);
    probe_step(label, rc);
    if (rc == 1 && op != NULL) {
        snprintf(label, sizeof(label), "%s set_kem_op", name);
        rc = EVP_PKEY_CTX_set_kem_op(ectx, op);
        probe_step(label, rc);
    }
    if (rc == 1) {
        snprintf(label, sizeof(label), "%s size query", name);
        rc = EVP_PKEY_encapsulate(ectx, NULL, &wlen, NULL, &slen);
        probe_step(label, rc);
        if (rc == 1) {
            printf("%s sizes: wrapped=%s secret=%s (modulus length)\n", name,
                   wlen == nlen ? "equal" : "DIFFERENT", slen == nlen ? "equal" : "DIFFERENT");
        }
    }
    if (rc == 1) {
        wlen = sizeof(wrapped);
        slen = sizeof(secret);
        snprintf(label, sizeof(label), "%s encapsulate", name);
        rc = EVP_PKEY_encapsulate(ectx, wrapped, &wlen, secret, &slen);
        probe_step(label, rc);
    }
    if (rc == 1) {
        EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new_from_pkey(ctx, key, NULL);
        size_t blen = sizeof(back);
        snprintf(label, sizeof(label), "%s decapsulate_init", name);
        int drc = dctx == NULL ? -100 : EVP_PKEY_decapsulate_init(dctx, NULL);
        probe_step(label, drc);
        if (drc == 1 && op != NULL) {
            drc = EVP_PKEY_CTX_set_kem_op(dctx, op);
        }
        if (drc == 1) {
            /* As the interface does: size query, then exactly that length. */
            snprintf(label, sizeof(label), "%s decapsulate size query", name);
            drc = EVP_PKEY_decapsulate(dctx, NULL, &blen, wrapped, wlen);
            probe_step(label, drc);
        }
        if (drc == 1) {
            printf("%s decapsulate size: %s (modulus length)\n", name, blen == nlen ? "equal" : "DIFFERENT");
            snprintf(label, sizeof(label), "%s decapsulate", name);
            drc = EVP_PKEY_decapsulate(dctx, back, &blen, wrapped, wlen);
            probe_step(label, drc);
            printf("%s decapsulated secret equals encapsulated: %s\n", name,
                   drc == 1 && blen == slen && memcmp(back, secret, slen) == 0 ? "yes" : "no");
        }
        if (drc == 1) {
            /* Not what the interface does: a buffer longer than the secret. */
            size_t big = sizeof(back);
            snprintf(label, sizeof(label), "%s decapsulate into a longer buffer", name);
            drc = EVP_PKEY_decapsulate(dctx, back, &big, wrapped, wlen);
            probe_step(label, drc);
            printf("%s longer buffer: length %s, bytes %s\n", name, big == slen ? "equal" : "DIFFERENT",
                   drc == 1 && big == slen && memcmp(back, secret, slen) == 0 ? "equal" : "DIFFERENT");
        }
        EVP_PKEY_CTX_free(dctx);
    }
    if (rc == 1) {
        int all = 1;
        int leading_zero = 0;
        for (int i = 0; i < TRIALS && all; i++) {
            wlen = sizeof(wrapped);
            slen = sizeof(secret);
            if (EVP_PKEY_encapsulate(ectx, wrapped, &wlen, secret, &slen) != 1 || slen != nlen
                || !expected_secret(key, wrapped, wlen, want, nlen) || memcmp(want, secret, nlen) != 0) {
                all = 0;
            }
            if (all && secret[0] == 0) {
                leading_zero = 1;
            }
        }
        ERR_clear_error();
        printf("%s every secret over %d trials is r zero-padded to the modulus length: %s\n", name, TRIALS,
               all ? "yes" : "no");
        printf("%s a secret with a leading zero byte occurred: %s\n", name, leading_zero ? "yes" : "no");
    }
    EVP_PKEY_CTX_free(ectx);
}

int main(int argc, char **argv)
{
    OSSL_LIB_CTX *ctx = probe_ctx(argc, argv);
    if (ctx == NULL) {
        fprintf(stderr, "usage: rsakem_probe mainline | fips <module_dir> <fipsmodule.cnf>\n");
        return 2;
    }
    ERR_clear_error();

    EVP_PKEY *key = make_key(ctx);
    if (key == NULL) {
        printf("no key\n");
        OSSL_LIB_CTX_free(ctx);
        return 0;
    }
    arm(ctx, key, NULL);
    arm(ctx, key, "RSASVE");
    arm(ctx, key, "RSAKEM");

    EVP_PKEY_free(key);
    OSSL_LIB_CTX_free(ctx);
    return 0;
}
