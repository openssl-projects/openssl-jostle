/*
 * Does OpenSSL pair a DH-keymgmt key with a DHX-keymgmt peer on identical p and g?
 *
 * The "DH" key carries p and g only (PKCS#3, dhKeyAgreement); the "DHX" key carries p, q and g (X9.42,
 * dhpublicnumber). Both use the RFC 5114 2048-bit group with a 256-bit subgroup. Mixed pairs are tried in both
 * directions; same-keymgmt pairs are the control and must derive.
 */
#define OPENSSL_SUPPRESS_DEPRECATED
#include "probe_common.h"
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/dh.h>
#include <openssl/param_build.h>

/*
 * Imports a key pair rather than generating one: x is drawn below q and y = g^x mod p is computed here, so the
 * PKCS#3 key needs no q from the provider. Every key, DH or DHX, is made the same way.
 */
static EVP_PKEY *make_key(OSSL_LIB_CTX *ctx, const char *keymgmt, int with_q)
{
    DH *dh = DH_get_2048_256();
    const BIGNUM *p = NULL;
    const BIGNUM *q = NULL;
    const BIGNUM *g = NULL;
    BIGNUM *x = BN_secure_new();
    BIGNUM *y = BN_new();
    BN_CTX *bn = BN_CTX_new();
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *key = NULL;
    char label[64];

    DH_get0_pqg(dh, &p, &q, &g);
    do {
        BN_rand_range(x, q);
    } while (BN_is_zero(x));
    BN_mod_exp(y, g, x, p, bn);
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, p);
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G, g);
    if (with_q) {
        OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_Q, q);
    }
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, x);
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PUB_KEY, y);
    params = OSSL_PARAM_BLD_to_param(bld);

    pctx = EVP_PKEY_CTX_new_from_name(ctx, keymgmt, NULL);
    snprintf(label, sizeof(label), "%s fromdata_init", keymgmt);
    probe_step(label, pctx == NULL ? -100 : EVP_PKEY_fromdata_init(pctx));
    snprintf(label, sizeof(label), "%s fromdata keypair", keymgmt);
    probe_step(label, pctx == NULL ? -100 : EVP_PKEY_fromdata(pctx, &key, EVP_PKEY_KEYPAIR, params));
    if (key != NULL) {
        printf("%s key type name: %s\n", keymgmt, EVP_PKEY_get0_type_name(key));
    }

    EVP_PKEY_CTX_free(pctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    BN_CTX_free(bn);
    BN_free(y);
    BN_clear_free(x);
    DH_free(dh);
    return key;
}

static void pair(OSSL_LIB_CTX *ctx, const char *name, EVP_PKEY *priv, EVP_PKEY *peer)
{
    char label[96];
    unsigned char secret[512];
    size_t len = sizeof(secret);

    printf("-- %s\n", name);
    if (priv == NULL || peer == NULL) {
        printf("skipped: a key is missing\n");
        return;
    }
    EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new_from_pkey(ctx, priv, NULL);
    snprintf(label, sizeof(label), "%s derive_init", name);
    int rc = dctx == NULL ? -100 : EVP_PKEY_derive_init(dctx);
    probe_step(label, rc);
    if (rc == 1) {
        snprintf(label, sizeof(label), "%s derive_set_peer", name);
        rc = EVP_PKEY_derive_set_peer(dctx, peer);
        probe_step(label, rc);
    }
    if (rc == 1) {
        snprintf(label, sizeof(label), "%s derive", name);
        rc = EVP_PKEY_derive(dctx, secret, &len);
        probe_step(label, rc);
        if (rc == 1) {
            printf("%s secret length: %zu\n", name, len);
        }
    }
    EVP_PKEY_CTX_free(dctx);
}

int main(int argc, char **argv)
{
    OSSL_LIB_CTX *ctx = probe_ctx(argc, argv);
    if (ctx == NULL) {
        fprintf(stderr, "usage: dhx_probe mainline | fips <module_dir> <fipsmodule.cnf>\n");
        return 2;
    }
    ERR_clear_error();

    EVP_PKEY *dh1 = make_key(ctx, "DH", 0);
    EVP_PKEY *dh2 = make_key(ctx, "DH", 0);
    EVP_PKEY *dhx1 = make_key(ctx, "DHX", 1);
    EVP_PKEY *dhx2 = make_key(ctx, "DHX", 1);

    pair(ctx, "control DH with DH peer", dh1, dh2);
    pair(ctx, "control DHX with DHX peer", dhx1, dhx2);
    pair(ctx, "mixed DH with DHX peer", dh1, dhx1);
    pair(ctx, "mixed DHX with DH peer", dhx1, dh1);

    EVP_PKEY_free(dh1);
    EVP_PKEY_free(dh2);
    EVP_PKEY_free(dhx1);
    EVP_PKEY_free(dhx2);
    OSSL_LIB_CTX_free(ctx);
    return 0;
}
