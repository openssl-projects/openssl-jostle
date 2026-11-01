/*
 * Shared setup for the standalone OpenSSL probes.
 *
 * Usage of every probe: <probe> mainline
 *                       <probe> fips <module_dir> <fipsmodule.cnf>
 *
 * The fips form builds the lib ctx the way interface/fips/util/rand/jostle_fips_ctx.c does: provider search path
 * at the module directory, a synthesised configuration that includes the module's cnf and activates the fips and
 * base providers, then fips=yes default properties. The mainline form loads the default provider.
 *
 * Output is deterministic: return codes, lengths and OpenSSL reason strings only. No pointers, paths, versions or
 * key material, so two runs on two OpenSSL versions compare with cmp.
 */
#ifndef PROBE_COMMON_H
#define PROBE_COMMON_H

#include <stdio.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

static OSSL_LIB_CTX *probe_ctx(int argc, char **argv)
{
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    if (ctx == NULL) {
        return NULL;
    }
    if (argc == 2 && strcmp(argv[1], "mainline") == 0) {
        if (OSSL_PROVIDER_load(ctx, "default") == NULL) {
            OSSL_LIB_CTX_free(ctx);
            return NULL;
        }
        return ctx;
    }
    if (argc != 4 || strcmp(argv[1], "fips") != 0) {
        OSSL_LIB_CTX_free(ctx);
        return NULL;
    }
    if (OSSL_PROVIDER_set_default_search_path(ctx, argv[2]) != 1) {
        OSSL_LIB_CTX_free(ctx);
        return NULL;
    }
    BIO *bio = BIO_new(BIO_s_mem());
    CONF *conf = NCONF_new_ex(ctx, NULL);
    int ok = bio != NULL && conf != NULL
             && BIO_printf(bio,
                           "config_diagnostics = 1\n"
                           "openssl_conf = openssl_init\n"
                           ".include %s\n"
                           "[openssl_init]\n"
                           "providers = provider_sect\n"
                           "[provider_sect]\n"
                           "fips = fips_sect\n"
                           "base = base_sect\n"
                           "[base_sect]\n"
                           "activate = 1\n", argv[3]) > 0
             && NCONF_load_bio(conf, bio, NULL) > 0
             && CONF_modules_load(conf, NULL, 0) > 0
             && OSSL_PROVIDER_available(ctx, "fips") == 1
             && EVP_default_properties_enable_fips(ctx, 1) == 1;
    NCONF_free(conf);
    BIO_free(bio);
    if (!ok) {
        ERR_print_errors_fp(stderr);
        OSSL_LIB_CTX_free(ctx);
        return NULL;
    }
    return ctx;
}

/* Print one step's rc and drain the error queue as reason strings plus any attached text. */
static void probe_step(const char *step, int rc)
{
    printf("%s rc=%d", step, rc);
    unsigned long e;
    const char *data = NULL;
    int flags = 0;
    int n = 0;
    while ((e = ERR_get_error_all(NULL, NULL, NULL, &data, &flags)) != 0) {
        const char *reason = ERR_reason_error_string(e);
        printf(" | %s", reason != NULL ? reason : "(no reason string)");
        if ((flags & ERR_TXT_STRING) != 0 && data != NULL && data[0] != '\0') {
            printf(" (%s)", data);
        }
        n++;
    }
    if (n == 0) {
        printf(" | (empty error queue)");
    }
    printf("\n");
}

#endif
