/*
 * Copyright 2025 DSMIL Security Team. All Rights Reserved.
 *
 * TLS 1.3 Hybrid KEM Integration - Implementation Skeleton
 *
 * This file provides the implementation structure for integrating hybrid KEM
 * into TLS 1.3 handshake. Full implementation requires integration with:
 * - ssl/statem/extensions_clnt.c (client supported_groups)
 * - ssl/statem/extensions_srvr.c (server supported_groups)
 * - ssl/statem/statem_clnt.c (client handshake)
 * - ssl/statem/statem_srvr.c (server handshake)
 * - ssl/tls13_enc.c (key derivation)
 *
 * STATUS: Structure defined, full integration pending
 * See: docs/reports/DSSSL_SECURITY_AUDIT_REPORT.md Section 7.1
 */

#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <string.h>
#include "ssl_local.h"
#include "tls13_hybrid_kem.h"
#include "providers/dsmil/policy.h"
#include "internal/tlsgroups.h"
#include "crypto/ml_kem/ml_kem.h"

/*
 * Initialize hybrid KEM context
 */
TLS13_HYBRID_KEM_CTX *tls13_hybrid_kem_ctx_new(void)
{
    TLS13_HYBRID_KEM_CTX *ctx;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return NULL;

    ctx->classical_secret_len = 0;
    ctx->pqc_secret_len = 0;
    ctx->combined_secret_len = 0;
    ctx->classical_group_id = 0;
    ctx->pqc_group_id = 0;
    ctx->hkdf_ctx = NULL;

    return ctx;
}

/*
 * Free hybrid KEM context
 */
void tls13_hybrid_kem_ctx_free(TLS13_HYBRID_KEM_CTX *ctx)
{
    if (ctx == NULL)
        return;

    if (ctx->hkdf_ctx != NULL)
        EVP_PKEY_CTX_free(ctx->hkdf_ctx);

    /* Clear secrets */
    OPENSSL_cleanse(ctx->classical_secret, sizeof(ctx->classical_secret));
    OPENSSL_cleanse(ctx->pqc_secret, sizeof(ctx->pqc_secret));
    OPENSSL_cleanse(ctx->combined_secret, sizeof(ctx->combined_secret));

    OPENSSL_free(ctx);
}

/*
 * Combine shared secrets via HKDF
 *
 * HKDF-Extract(salt=NULL, IKM=classical_secret || pqc_secret)
 * HKDF-Expand(info="hybrid-kem" || classical_name || pqc_name, L=32)
 */
int tls13_hybrid_kem_combine_secrets(TLS13_HYBRID_KEM_CTX *ctx,
                                      const char *classical_name,
                                      const char *pqc_name,
                                      uint8_t *combined_secret,
                                      size_t *combined_secret_len)
{
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kdf_ctx = NULL;
    OSSL_PARAM params[8], *p = params;
    uint8_t ikm[96];  /* Max: 64 (X448) + 32 (ML-KEM) */
    size_t ikm_len;
    char info[256];
    int ret = 0;

    if (ctx == NULL || classical_name == NULL || pqc_name == NULL ||
        combined_secret == NULL || combined_secret_len == NULL)
        return 0;

    /* Concatenate classical and PQC secrets */
    if (ctx->classical_secret_len + ctx->pqc_secret_len > sizeof(ikm))
        return 0;

    memcpy(ikm, ctx->classical_secret, ctx->classical_secret_len);
    memcpy(ikm + ctx->classical_secret_len, ctx->pqc_secret, ctx->pqc_secret_len);
    ikm_len = ctx->classical_secret_len + ctx->pqc_secret_len;

    /* Construct HKDF info string */
    snprintf(info, sizeof(info), "hybrid-kem-%s-%s", classical_name, pqc_name);

    /* Get HKDF implementation */
    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (kdf == NULL)
        return 0;

    kdf_ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (kdf_ctx == NULL)
        return 0;

    /* Set HKDF parameters */
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA256", 0);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, ikm, ikm_len);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info, strlen(info));
    *p++ = OSSL_PARAM_construct_size_t(OSSL_KDF_PARAM_SIZE, combined_secret_len);
    *p = OSSL_PARAM_END;

    if (EVP_KDF_derive(kdf_ctx, combined_secret, *combined_secret_len, params) <= 0)
        goto err;

    ret = 1;

err:
    OPENSSL_cleanse(ikm, sizeof(ikm));
    EVP_KDF_CTX_free(kdf_ctx);
    return ret;
}

/*
 * Check if hybrid KEM is required by policy
 */
int tls13_hybrid_kem_required(SSL *s)
{
    OSSL_LIB_CTX *libctx;
    DSMIL_POLICY_CTX *policy_ctx;
    DSMIL_PROFILE profile;
    int required = 0;

    if (s == NULL)
        return 0;

    /* Get policy context from SSL */
    /* TODO: Store policy context in SSL structure */
    libctx = SSL_get0_libctx(s);
    if (libctx == NULL)
        return 0;

    /* For now, check environment variable */
    /* TODO: Get from SSL configuration */
    {
        const char *profile_str = getenv("DSMIL_PROFILE");
        if (profile_str != NULL) {
            if (strcmp(profile_str, "DSMIL_SECURE") == 0 ||
                strcmp(profile_str, "ATOMAL") == 0) {
                required = 1;
            }
        }
    }

    return required;
}

/*
 * Get allowed hybrid groups based on security profile
 */
int tls13_hybrid_kem_get_allowed_groups(SSL *s,
                                         uint16_t *groups,
                                         size_t *groups_len)
{
    const char *profile_str;
    size_t count = 0;
    size_t max_count = *groups_len;

    if (s == NULL || groups == NULL || groups_len == NULL || max_count == 0)
        return 0;

    profile_str = getenv("DSMIL_PROFILE");
    if (profile_str == NULL)
        profile_str = "WORLD_COMPAT";

    /* WORLD_COMPAT: Offer hybrid but allow classical */
    if (strcmp(profile_str, "WORLD_COMPAT") == 0 ||
        strcmp(profile_str, "WORLD") == 0 ||
        strcmp(profile_str, "world") == 0) {
        if (max_count >= 2) {
            groups[count++] = OSSL_TLS_GROUP_ID_X25519MLKEM768;
            groups[count++] = OSSL_TLS_GROUP_ID_SecP256r1MLKEM768;
        }
    }
    /* DSMIL_SECURE: Require hybrid */
    else if (strcmp(profile_str, "DSMIL_SECURE") == 0 ||
             strcmp(profile_str, "SECURE") == 0 ||
             strcmp(profile_str, "secure") == 0) {
        if (max_count >= 2) {
            groups[count++] = OSSL_TLS_GROUP_ID_X25519MLKEM768;
            groups[count++] = OSSL_TLS_GROUP_ID_SecP256r1MLKEM768;
        }
    }
    /* ATOMAL: Require hybrid or PQC-only */
    else if (strcmp(profile_str, "ATOMAL") == 0 ||
             strcmp(profile_str, "atomal") == 0) {
        if (max_count >= 2) {
            groups[count++] = OSSL_TLS_GROUP_ID_X25519MLKEM768;  /* Use 768 for now, 1024 when available */
            groups[count++] = OSSL_TLS_GROUP_ID_SecP384r1MLKEM1024;
        }
    }

    *groups_len = count;
    return (count > 0) ? 1 : 0;
}

/*
 * Implementation Notes:
 *
 * Full TLS integration requires:
 *
 * 1. Client Hello (ssl/statem/extensions_clnt.c):
 *    - Add hybrid groups to supported_groups extension
 *    - Call tls13_hybrid_kem_get_allowed_groups() to get list
 *
 * 2. Server Hello (ssl/statem/extensions_srvr.c):
 *    - Parse hybrid groups from client supported_groups
 *    - Select hybrid group based on policy
 *    - Return selected group in server supported_groups
 *
 * 3. Key Exchange (ssl/statem/statem_clnt.c, statem_srvr.c):
 *    - Client: Perform hybrid KEX, send both ciphertexts in KeyShare
 *    - Server: Receive both ciphertexts, perform hybrid decapsulation
 *    - Combine secrets via tls13_hybrid_kem_combine_secrets()
 *
 * 4. Key Derivation (ssl/tls13_enc.c):
 *    - Use combined shared secret for TLS 1.3 key derivation
 *    - Ensure constant-time operations
 *
 * 5. Policy Enforcement:
 *    - Check tls13_hybrid_kem_required() before handshake
 *    - Fail handshake if hybrid required but not available
 *    - Log downgrade events via event telemetry
 */
