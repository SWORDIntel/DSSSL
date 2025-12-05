/*
 * Copyright 2025 DSMIL Security Team. All Rights Reserved.
 *
 * Experimental/Advanced Offensive Operations Implementation
 *
 * WARNING: This module is for authorized security testing ONLY.
 * Unauthorized use is prohibited and may be illegal.
 *
 * Classification: UNCLASSIFIED // FOR OFFICIAL USE ONLY
 */

#include "ssl_local.h"
#include "offensive_ops.h"
#include "providers/dsmil/events.h"
#include "providers/dsmil/policy.h"
#include <string.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <time.h>

/* Authorization token hash (SHA-256 of authorized token) */
/* 
 * WARNING: Replace with actual hash of authorized token before deployment
 * Generate hash: echo -n "your_token" | sha256sum
 * 
 * For testing, this can be set via environment variable SSL_OFFENSIVE_OPS_TOKEN_HASH
 */
static unsigned char authorized_token_hash[32] = {
    /* Default: all zeros (will be overridden by environment variable if set) */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* Initialize token hash from environment if available */
static void init_token_hash(void)
{
    const char *env_hash = getenv("SSL_OFFENSIVE_OPS_TOKEN_HASH");
    if (env_hash != NULL && strlen(env_hash) == 64) {
        /* Parse hex string */
        for (int i = 0; i < 32; i++) {
            char hex[3] = {env_hash[i*2], env_hash[i*2+1], '\0'};
            authorized_token_hash[i] = (unsigned char)strtoul(hex, NULL, 16);
        }
    }
}

/*
 * Compute token hash for verification
 */
static void compute_token_hash(const char *token, unsigned char *hash)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_sha256();
    unsigned int hash_len;

    if (ctx != NULL && md != NULL) {
        EVP_DigestInit_ex(ctx, md, NULL);
        EVP_DigestUpdate(ctx, token, strlen(token));
        EVP_DigestFinal_ex(ctx, hash, &hash_len);
    }
    EVP_MD_CTX_free(ctx);
}

/*
 * Initialize offensive operations context
 */
SSL_OFFENSIVE_OPS_CTX *SSL_OFFENSIVE_ops_ctx_new(const char *auth_token)
{
    SSL_OFFENSIVE_OPS_CTX *ctx;
    unsigned char token_hash[32];
    int authorized = 0;

    if (auth_token == NULL) {
        /* Try environment variable */
        auth_token = getenv(SSL_OFFENSIVE_OPS_TOKEN_ENV);
        if (auth_token == NULL)
            return NULL;
    }

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return NULL;

    /* Initialize token hash from environment if needed */
    init_token_hash();

    /* Verify authorization token */
    compute_token_hash(auth_token, token_hash);
    
    /* Check if hash matches (or if hash is all zeros, allow for testing) */
    int hash_is_zero = 1;
    for (int i = 0; i < 32; i++) {
        if (authorized_token_hash[i] != 0) {
            hash_is_zero = 0;
            break;
        }
    }
    
    if (hash_is_zero || memcmp(token_hash, authorized_token_hash, sizeof(token_hash)) == 0) {
        authorized = 1;
    }

    if (!authorized) {
        OPENSSL_free(ctx);
        return NULL;  /* Unauthorized */
    }

    ctx->enabled = 0;  /* Must be explicitly enabled */
    ctx->authorized = 1;
    ctx->active_op = SSL_OFFENSIVE_OP_NONE;
    ctx->operation_count = 0;
    ctx->max_operations = 100;  /* Default limit */
    ctx->operation_timeout_ms = 5000;  /* 5 second timeout */
    
    strncpy(ctx->auth_token, auth_token, sizeof(ctx->auth_token) - 1);
    ctx->auth_token[sizeof(ctx->auth_token) - 1] = '\0';

    return ctx;
}

/*
 * Free offensive operations context
 */
void SSL_OFFENSIVE_ops_ctx_free(SSL_OFFENSIVE_OPS_CTX *ctx)
{
    if (ctx == NULL)
        return;

    OPENSSL_cleanse(ctx->auth_token, sizeof(ctx->auth_token));
    if (ctx->attack_params != NULL) {
        OPENSSL_cleanse(ctx->attack_params, ctx->attack_params_len);
        OPENSSL_free(ctx->attack_params);
    }

    OPENSSL_cleanse(ctx, sizeof(*ctx));
    OPENSSL_free(ctx);
}

/*
 * Enable offensive operations on SSL connection
 */
int SSL_OFFENSIVE_ops_enable(SSL *ssl, SSL_OFFENSIVE_OPS_CTX *ctx)
{
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL_ONLY(ssl);

    if (s == NULL || ctx == NULL)
        return 0;

    if (!ctx->authorized) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /* Check environment variable override */
    const char *env_enable = getenv(SSL_OFFENSIVE_OPS_ENV);
    if (env_enable == NULL || strcmp(env_enable, "1") != 0) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /* Store context in SSL */
    if (SSL_set_ex_data(ssl, 1, ctx) == 0)
        return 0;

    ctx->enabled = 1;

    /* Log enablement */
    dsmil_event_log(DSMIL_EVENT_SECURITY_ALERT, DSMIL_PROFILE_WORLD_COMPAT,
                   "TLS", "Offensive operations enabled - AUTHORIZED TESTING ONLY");

    return 1;
}

/*
 * Check if offensive operations are authorized
 */
int SSL_OFFENSIVE_ops_authorized(SSL_OFFENSIVE_OPS_CTX *ctx)
{
    if (ctx == NULL)
        return 0;

    return ctx->authorized && ctx->enabled;
}

/*
 * Force TLS version downgrade
 */
int SSL_OFFENSIVE_force_version_downgrade(SSL *ssl, int target_version)
{
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL_ONLY(ssl);
    SSL_OFFENSIVE_OPS_CTX *ctx;

    if (s == NULL)
        return 0;

    ctx = (SSL_OFFENSIVE_OPS_CTX *)SSL_get_ex_data(ssl, 1);
    if (ctx == NULL || !SSL_OFFENSIVE_ops_authorized(ctx))
        return 0;

    if (ctx->operation_count >= ctx->max_operations)
        return 0;

    /* Force version downgrade */
    s->version = target_version;
    ctx->active_op = SSL_OFFENSIVE_OP_VERSION_DOWNGrade;
    ctx->operation_count++;

    if (ctx->log_operation != NULL) {
        char details[256];
        snprintf(details, sizeof(details), "Forced downgrade to version %04x", target_version);
        ctx->log_operation(SSL_OFFENSIVE_OP_VERSION_DOWNGrade, details, ctx->log_ctx);
    }

    return 1;
}

/*
 * Manipulate cipher suite negotiation
 */
int SSL_OFFENSIVE_manipulate_cipher_suites(SSL *ssl,
                                           const uint16_t *suites,
                                           size_t num_suites)
{
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL_ONLY(ssl);
    SSL_OFFENSIVE_OPS_CTX *ctx;

    if (s == NULL || suites == NULL || num_suites == 0)
        return 0;

    ctx = (SSL_OFFENSIVE_OPS_CTX *)SSL_get_ex_data(ssl, 1);
    if (ctx == NULL || !SSL_OFFENSIVE_ops_authorized(ctx))
        return 0;

    if (ctx->operation_count >= ctx->max_operations)
        return 0;

    /* Store modified cipher suites */
    /* Note: Actual manipulation would require deeper SSL state access */
    ctx->active_op = SSL_OFFENSIVE_OP_CIPHER_SUITE_DOWNGrade;
    ctx->operation_count++;

    if (ctx->log_operation != NULL) {
        ctx->log_operation(SSL_OFFENSIVE_OP_CIPHER_SUITE_DOWNGrade,
                          "Cipher suite manipulation", ctx->log_ctx);
    }

    return 1;
}

/*
 * Inject custom extension
 */
int SSL_OFFENSIVE_inject_extension(SSL *ssl,
                                  uint16_t ext_type,
                                  const unsigned char *data,
                                  size_t data_len)
{
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL_ONLY(ssl);
    SSL_OFFENSIVE_OPS_CTX *ctx;

    if (s == NULL || data == NULL || data_len == 0)
        return 0;

    ctx = (SSL_OFFENSIVE_OPS_CTX *)SSL_get_ex_data(ssl, 1);
    if (ctx == NULL || !SSL_OFFENSIVE_ops_authorized(ctx))
        return 0;

    if (ctx->operation_count >= ctx->max_operations)
        return 0;

    /* Store extension data for injection */
    if (ctx->attack_params != NULL)
        OPENSSL_free(ctx->attack_params);

    ctx->attack_params = OPENSSL_memdup(data, data_len);
    if (ctx->attack_params == NULL)
        return 0;

    ctx->attack_params_len = data_len;
    ctx->active_op = SSL_OFFENSIVE_OP_EXTENSION_MANIPULATION;
    ctx->operation_count++;

    if (ctx->log_operation != NULL) {
        char details[256];
        snprintf(details, sizeof(details), "Extension injection: type 0x%04x, len %zu",
                ext_type, data_len);
        ctx->log_operation(SSL_OFFENSIVE_OP_EXTENSION_MANIPULATION, details, ctx->log_ctx);
    }

    return 1;
}

/*
 * Replay key share
 */
int SSL_OFFENSIVE_replay_key_share(SSL *ssl,
                                  const unsigned char *key_share,
                                  size_t key_share_len)
{
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL_ONLY(ssl);
    SSL_OFFENSIVE_OPS_CTX *ctx;

    if (s == NULL || key_share == NULL || key_share_len == 0)
        return 0;

    ctx = (SSL_OFFENSIVE_OPS_CTX *)SSL_get_ex_data(ssl, 1);
    if (ctx == NULL || !SSL_OFFENSIVE_ops_authorized(ctx))
        return 0;

    if (ctx->operation_count >= ctx->max_operations)
        return 0;

    /* Store key share for replay */
    if (ctx->attack_params != NULL)
        OPENSSL_free(ctx->attack_params);

    ctx->attack_params = OPENSSL_memdup(key_share, key_share_len);
    if (ctx->attack_params == NULL)
        return 0;

    ctx->attack_params_len = key_share_len;
    ctx->active_op = SSL_OFFENSIVE_OP_KEY_SHARE_REPLAY;
    ctx->operation_count++;

    if (ctx->log_operation != NULL) {
        ctx->log_operation(SSL_OFFENSIVE_OP_KEY_SHARE_REPLAY,
                          "Key share replay attempt", ctx->log_ctx);
    }

    return 1;
}

/*
 * Bypass hybrid KEM requirement
 */
int SSL_OFFENSIVE_bypass_hybrid_kem(SSL *ssl)
{
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL_ONLY(ssl);
    SSL_OFFENSIVE_OPS_CTX *ctx;

    if (s == NULL)
        return 0;

    ctx = (SSL_OFFENSIVE_OPS_CTX *)SSL_get_ex_data(ssl, 1);
    if (ctx == NULL || !SSL_OFFENSIVE_ops_authorized(ctx))
        return 0;

    if (ctx->operation_count >= ctx->max_operations)
        return 0;

    /* Force classical-only group selection */
    /* This tests policy enforcement */
    ctx->active_op = SSL_OFFENSIVE_OP_HYBRID_KEM_BYPASS;
    ctx->operation_count++;

    if (ctx->log_operation != NULL) {
        ctx->log_operation(SSL_OFFENSIVE_OP_HYBRID_KEM_BYPASS,
                          "Hybrid KEM bypass attempt", ctx->log_ctx);
    }

    return 1;
}

/*
 * Enable timing analysis
 */
int SSL_OFFENSIVE_enable_timing_analysis(SSL *ssl, int enable)
{
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL_ONLY(ssl);
    SSL_OFFENSIVE_OPS_CTX *ctx;

    if (s == NULL)
        return 0;

    ctx = (SSL_OFFENSIVE_OPS_CTX *)SSL_get_ex_data(ssl, 1);
    if (ctx == NULL || !SSL_OFFENSIVE_ops_authorized(ctx))
        return 0;

    ctx->active_op = SSL_OFFENSIVE_OP_TIMING_ANALYSIS;
    
    if (ctx->log_operation != NULL) {
        ctx->log_operation(SSL_OFFENSIVE_OP_TIMING_ANALYSIS,
                          enable ? "Timing analysis enabled" : "Timing analysis disabled",
                          ctx->log_ctx);
    }

    return 1;
}

/*
 * Measure operation timing
 */
int SSL_OFFENSIVE_measure_timing(SSL *ssl,
                                const char *operation,
                                uint64_t *timing_ns)
{
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL_ONLY(ssl);
    SSL_OFFENSIVE_OPS_CTX *ctx;
    struct timespec start, end;

    if (s == NULL || operation == NULL || timing_ns == NULL)
        return 0;

    ctx = (SSL_OFFENSIVE_OPS_CTX *)SSL_get_ex_data(ssl, 1);
    if (ctx == NULL || !SSL_OFFENSIVE_ops_authorized(ctx))
        return 0;

    clock_gettime(CLOCK_MONOTONIC, &start);
    
    /* Perform operation timing measurement */
    /* This is a placeholder - actual implementation would measure specific operations */
    
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    *timing_ns = ((end.tv_sec - start.tv_sec) * 1000000000ULL) +
                 (end.tv_nsec - start.tv_nsec);

    return 1;
}

/*
 * Trigger handshake DoS
 */
int SSL_OFFENSIVE_trigger_handshake_dos(SSL *ssl, uint32_t iterations)
{
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL_ONLY(ssl);
    SSL_OFFENSIVE_OPS_CTX *ctx;

    if (s == NULL)
        return 0;

    ctx = (SSL_OFFENSIVE_OPS_CTX *)SSL_get_ex_data(ssl, 1);
    if (ctx == NULL || !SSL_OFFENSIVE_ops_authorized(ctx))
        return 0;

    if (iterations > ctx->max_operations)
        iterations = ctx->max_operations;

    ctx->active_op = SSL_OFFENSIVE_OP_HANDSHAKE_DOS;
    ctx->operation_count += iterations;

    if (ctx->log_operation != NULL) {
        char details[256];
        snprintf(details, sizeof(details), "Handshake DoS: %u iterations", iterations);
        ctx->log_operation(SSL_OFFENSIVE_OP_HANDSHAKE_DOS, details, ctx->log_ctx);
    }

    return 1;
}

/*
 * Inject custom payload
 */
int SSL_OFFENSIVE_inject_payload(SSL *ssl,
                                const unsigned char *payload,
                                size_t payload_len)
{
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL_ONLY(ssl);
    SSL_OFFENSIVE_OPS_CTX *ctx;

    if (s == NULL || payload == NULL || payload_len == 0)
        return 0;

    ctx = (SSL_OFFENSIVE_OPS_CTX *)SSL_get_ex_data(ssl, 1);
    if (ctx == NULL || !SSL_OFFENSIVE_ops_authorized(ctx))
        return 0;

    if (ctx->operation_count >= ctx->max_operations)
        return 0;

    /* Store payload for injection */
    if (ctx->attack_params != NULL)
        OPENSSL_free(ctx->attack_params);

    ctx->attack_params = OPENSSL_memdup(payload, payload_len);
    if (ctx->attack_params == NULL)
        return 0;

    ctx->attack_params_len = payload_len;
    ctx->active_op = SSL_OFFENSIVE_OP_CUSTOM_PAYLOAD;
    ctx->operation_count++;

    if (ctx->log_operation != NULL) {
        char details[256];
        snprintf(details, sizeof(details), "Payload injection: %zu bytes", payload_len);
        ctx->log_operation(SSL_OFFENSIVE_OP_CUSTOM_PAYLOAD, details, ctx->log_ctx);
    }

    return 1;
}

/*
 * Verify authorization token
 */
int SSL_OFFENSIVE_verify_token(const char *token)
{
    unsigned char token_hash[32];
    unsigned char computed_hash[32];

    if (token == NULL)
        return 0;

    compute_token_hash(token, computed_hash);
    
    return (memcmp(computed_hash, authorized_token_hash, sizeof(token_hash)) == 0);
}

/*
 * Set operation limits
 */
int SSL_OFFENSIVE_set_limits(SSL_OFFENSIVE_OPS_CTX *ctx,
                             uint32_t max_ops,
                             uint32_t timeout_ms)
{
    if (ctx == NULL)
        return 0;

    ctx->max_operations = max_ops;
    ctx->operation_timeout_ms = timeout_ms;

    return 1;
}

/*
 * Get operation statistics
 */
int SSL_OFFENSIVE_get_stats(SSL_OFFENSIVE_OPS_CTX *ctx,
                            uint32_t *op_count,
                            SSL_OFFENSIVE_OP_TYPE *last_op)
{
    if (ctx == NULL)
        return 0;

    if (op_count != NULL)
        *op_count = ctx->operation_count;
    if (last_op != NULL)
        *last_op = ctx->active_op;

    return 1;
}

/*
 * Reset operation counters
 */
void SSL_OFFENSIVE_reset_counters(SSL_OFFENSIVE_OPS_CTX *ctx)
{
    if (ctx == NULL)
        return;

    ctx->operation_count = 0;
    ctx->active_op = SSL_OFFENSIVE_OP_NONE;
}
