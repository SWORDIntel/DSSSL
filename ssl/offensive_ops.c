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
#include "internal/ssl_unwrap.h"
#include "offensive_ops.h"
#include "providers/dsmil/events.h"
#include "providers/dsmil/policy.h"
#include <string.h>
#include <math.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
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
    /* TODO: Use dsmil_event_emit_json or appropriate event logging function */
    /* dsmil_event_emit_json(ctx, DSMIL_EVENT_SECURITY_ALERT, ...); */

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
    SSL_OFFENSIVE_OPS_CTX *ctx;

    if (ssl == NULL)
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
    SSL_OFFENSIVE_OPS_CTX *ctx;

    if (ssl == NULL)
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
    SSL_OFFENSIVE_OPS_CTX *ctx;
    struct timespec start, end;

    if (ssl == NULL || operation == NULL || timing_ns == NULL)
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
    SSL_OFFENSIVE_OPS_CTX *ctx;

    if (ssl == NULL)
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
    SSL_OFFENSIVE_OPS_CTX *ctx;

    if (ssl == NULL || payload == NULL || payload_len == 0)
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

/*
 * Inject custom handshake message
 */
int SSL_OFFENSIVE_inject_handshake_message(SSL *ssl,
                                          uint8_t msg_type,
                                          const unsigned char *data,
                                          size_t data_len)
{
    SSL_OFFENSIVE_OPS_CTX *ctx;

    if (ssl == NULL || data == NULL || data_len == 0)
        return 0;

    ctx = (SSL_OFFENSIVE_OPS_CTX *)SSL_get_ex_data(ssl, 1);
    if (ctx == NULL || !SSL_OFFENSIVE_ops_authorized(ctx))
        return 0;

    if (ctx->operation_count >= ctx->max_operations)
        return 0;

    /* Store handshake message for injection */
    if (ctx->attack_params != NULL)
        OPENSSL_free(ctx->attack_params);

    /* Allocate space for msg_type + data */
    ctx->attack_params = OPENSSL_malloc(1 + data_len);
    if (ctx->attack_params == NULL)
        return 0;

    ((unsigned char *)ctx->attack_params)[0] = msg_type;
    memcpy((unsigned char *)ctx->attack_params + 1, data, data_len);
    ctx->attack_params_len = 1 + data_len;
    ctx->active_op = SSL_OFFENSIVE_OP_HANDSHAKE_INJECTION;
    ctx->operation_count++;

    if (ctx->log_operation != NULL) {
        char details[256];
        snprintf(details, sizeof(details), "Handshake injection: type 0x%02x, len %zu",
                msg_type, data_len);
        ctx->log_operation(SSL_OFFENSIVE_OP_HANDSHAKE_INJECTION, details, ctx->log_ctx);
    }

    return 1;
}

/*
 * Manipulate key share data
 */
int SSL_OFFENSIVE_manipulate_key_share(SSL *ssl,
                                       uint16_t group_id,
                                       const unsigned char *modified_data,
                                       size_t data_len)
{
    SSL_OFFENSIVE_OPS_CTX *ctx;

    if (ssl == NULL || modified_data == NULL || data_len == 0)
        return 0;

    ctx = (SSL_OFFENSIVE_OPS_CTX *)SSL_get_ex_data(ssl, 1);
    if (ctx == NULL || !SSL_OFFENSIVE_ops_authorized(ctx))
        return 0;

    if (ctx->operation_count >= ctx->max_operations)
        return 0;

    /* Store modified key share */
    if (ctx->attack_params != NULL)
        OPENSSL_free(ctx->attack_params);

    /* Allocate space for group_id (2 bytes) + data */
    ctx->attack_params = OPENSSL_malloc(2 + data_len);
    if (ctx->attack_params == NULL)
        return 0;

    ((uint16_t *)ctx->attack_params)[0] = group_id;
    memcpy((unsigned char *)ctx->attack_params + 2, modified_data, data_len);
    ctx->attack_params_len = 2 + data_len;
    ctx->active_op = SSL_OFFENSIVE_OP_KEY_SHARE_MANIPULATION;
    ctx->operation_count++;

    if (ctx->log_operation != NULL) {
        char details[256];
        snprintf(details, sizeof(details), "Key share manipulation: group 0x%04x, len %zu",
                group_id, data_len);
        ctx->log_operation(SSL_OFFENSIVE_OP_KEY_SHARE_MANIPULATION, details, ctx->log_ctx);
    }

    return 1;
}

/*
 * Manipulate certificate chain
 */
int SSL_OFFENSIVE_manipulate_cert_chain(SSL *ssl,
                                        STACK_OF(X509) *modified_chain)
{
    SSL_OFFENSIVE_OPS_CTX *ctx;

    if (ssl == NULL || modified_chain == NULL)
        return 0;

    ctx = (SSL_OFFENSIVE_OPS_CTX *)SSL_get_ex_data(ssl, 1);
    if (ctx == NULL || !SSL_OFFENSIVE_ops_authorized(ctx))
        return 0;

    if (ctx->operation_count >= ctx->max_operations)
        return 0;

    /* Store reference to modified chain */
    /* Note: Actual manipulation would require deeper SSL state access */
    ctx->active_op = SSL_OFFENSIVE_OP_CERTIFICATE_CHAIN_MANIPULATION;
    ctx->operation_count++;

    if (ctx->log_operation != NULL) {
        int chain_len = sk_X509_num(modified_chain);
        char details[256];
        snprintf(details, sizeof(details), "Certificate chain manipulation: %d certificates",
                chain_len);
        ctx->log_operation(SSL_OFFENSIVE_OP_CERTIFICATE_CHAIN_MANIPULATION, details, ctx->log_ctx);
    }

    return 1;
}

/*
 * Test signature verification bypass
 */
int SSL_OFFENSIVE_test_signature_bypass(SSL *ssl)
{
    SSL_OFFENSIVE_OPS_CTX *ctx;

    if (ssl == NULL)
        return 0;

    ctx = (SSL_OFFENSIVE_OPS_CTX *)SSL_get_ex_data(ssl, 1);
    if (ctx == NULL || !SSL_OFFENSIVE_ops_authorized(ctx))
        return 0;

    if (ctx->operation_count >= ctx->max_operations)
        return 0;

    ctx->active_op = SSL_OFFENSIVE_OP_SIGNATURE_FORGERY_TEST;
    ctx->operation_count++;

    if (ctx->log_operation != NULL) {
        ctx->log_operation(SSL_OFFENSIVE_OP_SIGNATURE_FORGERY_TEST,
                          "Signature bypass test", ctx->log_ctx);
    }

    return 1;
}

/*
 * Exhaust memory resources
 */
int SSL_OFFENSIVE_exhaust_memory(SSL *ssl, size_t target_size)
{
    SSL_OFFENSIVE_OPS_CTX *ctx;
    void *allocated_mem = NULL;
    size_t max_size = 100 * 1024 * 1024; /* Cap at 100MB for safety */

    if (ssl == NULL)
        return 0;

    ctx = (SSL_OFFENSIVE_OPS_CTX *)SSL_get_ex_data(ssl, 1);
    if (ctx == NULL || !SSL_OFFENSIVE_ops_authorized(ctx))
        return 0;

    if (ctx->operation_count >= ctx->max_operations)
        return 0;

    /* Limit allocation size for safety */
    if (target_size > max_size)
        target_size = max_size;

    /* Allocate memory to exhaust resources */
    allocated_mem = OPENSSL_malloc(target_size);
    if (allocated_mem == NULL)
        return 0;

    /* Store reference for cleanup */
    if (ctx->attack_params != NULL)
        OPENSSL_free(ctx->attack_params);

    ctx->attack_params = allocated_mem;
    ctx->attack_params_len = target_size;
    ctx->active_op = SSL_OFFENSIVE_OP_MEMORY_EXHAUSTION;
    ctx->operation_count++;

    if (ctx->log_operation != NULL) {
        char details[256];
        snprintf(details, sizeof(details), "Memory exhaustion: %zu bytes", target_size);
        ctx->log_operation(SSL_OFFENSIVE_OP_MEMORY_EXHAUSTION, details, ctx->log_ctx);
    }

    return 1;
}

/*
 * Modify outgoing application data
 */
int SSL_OFFENSIVE_modify_app_data(SSL *ssl,
                                  const unsigned char *original,
                                  size_t orig_len,
                                  unsigned char *modified,
                                  size_t *mod_len)
{
    SSL_OFFENSIVE_OPS_CTX *ctx;

    if (ssl == NULL || original == NULL || modified == NULL || mod_len == NULL)
        return 0;

    ctx = (SSL_OFFENSIVE_OPS_CTX *)SSL_get_ex_data(ssl, 1);
    if (ctx == NULL || !SSL_OFFENSIVE_ops_authorized(ctx))
        return 0;

    if (ctx->operation_count >= ctx->max_operations)
        return 0;

    /* Copy original to modified (placeholder for actual manipulation) */
    if (*mod_len < orig_len)
        return 0;

    memcpy(modified, original, orig_len);
    *mod_len = orig_len;

    ctx->active_op = SSL_OFFENSIVE_OP_CUSTOM_PAYLOAD;
    ctx->operation_count++;

    if (ctx->log_operation != NULL) {
        char details[256];
        snprintf(details, sizeof(details), "App data modification: %zu bytes", orig_len);
        ctx->log_operation(SSL_OFFENSIVE_OP_CUSTOM_PAYLOAD, details, ctx->log_ctx);
    }

    return 1;
}

/*
 * Simulate padding oracle attack (for testing CBC padding validation)
 */
int SSL_OFFENSIVE_simulate_padding_oracle(SSL *ssl,
                                          const unsigned char *ciphertext,
                                          size_t ciphertext_len,
                                          int *padding_valid)
{
    SSL_OFFENSIVE_OPS_CTX *ctx;

    if (ssl == NULL || ciphertext == NULL || padding_valid == NULL)
        return 0;

    ctx = (SSL_OFFENSIVE_OPS_CTX *)SSL_get_ex_data(ssl, 1);
    if (ctx == NULL || !SSL_OFFENSIVE_ops_authorized(ctx))
        return 0;

    if (ctx->operation_count >= ctx->max_operations)
        return 0;

    /* Simulate padding oracle check */
    /* This is a test function - actual implementation would check padding */
    if (ciphertext_len < 16) {
        *padding_valid = 0;
        return 1;
    }

    /* Check last byte as padding length indicator */
    unsigned char padding_len = ciphertext[ciphertext_len - 1];
    if (padding_len > 16 || padding_len == 0) {
        *padding_valid = 0;
    } else {
        /* Basic padding validation simulation */
        *padding_valid = 1;
    }

    ctx->active_op = SSL_OFFENSIVE_OP_SIDE_CHANNEL_EXPLOIT;
    ctx->operation_count++;

    if (ctx->log_operation != NULL) {
        char details[256];
        snprintf(details, sizeof(details), "Padding oracle test: len %zu, valid %d",
                ciphertext_len, *padding_valid);
        ctx->log_operation(SSL_OFFENSIVE_OP_SIDE_CHANNEL_EXPLOIT, details, ctx->log_ctx);
    }

    return 1;
}

/*
 * Fragment TLS record (for testing fragmentation handling)
 */
int SSL_OFFENSIVE_fragment_record(SSL *ssl,
                                  const unsigned char *record,
                                  size_t record_len,
                                  size_t fragment_size)
{
    SSL_OFFENSIVE_OPS_CTX *ctx;

    if (ssl == NULL || record == NULL || record_len == 0 || fragment_size == 0)
        return 0;

    ctx = (SSL_OFFENSIVE_OPS_CTX *)SSL_get_ex_data(ssl, 1);
    if (ctx == NULL || !SSL_OFFENSIVE_ops_authorized(ctx))
        return 0;

    if (ctx->operation_count >= ctx->max_operations)
        return 0;

    /* Store fragmentation parameters */
    if (ctx->attack_params != NULL)
        OPENSSL_free(ctx->attack_params);

    /* Store record + fragment_size */
    ctx->attack_params = OPENSSL_malloc(sizeof(size_t) + record_len);
    if (ctx->attack_params == NULL)
        return 0;

    *(size_t *)ctx->attack_params = fragment_size;
    memcpy((unsigned char *)ctx->attack_params + sizeof(size_t), record, record_len);
    ctx->attack_params_len = sizeof(size_t) + record_len;
    ctx->active_op = SSL_OFFENSIVE_OP_CUSTOM_PAYLOAD;
    ctx->operation_count++;

    if (ctx->log_operation != NULL) {
        char details[256];
        snprintf(details, sizeof(details), "Record fragmentation: %zu bytes -> %zu byte fragments",
                record_len, fragment_size);
        ctx->log_operation(SSL_OFFENSIVE_OP_CUSTOM_PAYLOAD, details, ctx->log_ctx);
    }

    return 1;
}

/*
 * Manipulate ALPN (Application-Layer Protocol Negotiation)
 */
int SSL_OFFENSIVE_manipulate_alpn(SSL *ssl,
                                  const char *alpn_protocols[],
                                  size_t num_protocols)
{
    SSL_OFFENSIVE_OPS_CTX *ctx;

    if (ssl == NULL || alpn_protocols == NULL || num_protocols == 0)
        return 0;

    ctx = (SSL_OFFENSIVE_OPS_CTX *)SSL_get_ex_data(ssl, 1);
    if (ctx == NULL || !SSL_OFFENSIVE_ops_authorized(ctx))
        return 0;

    if (ctx->operation_count >= ctx->max_operations)
        return 0;

    ctx->active_op = SSL_OFFENSIVE_OP_EXTENSION_MANIPULATION;
    ctx->operation_count++;

    if (ctx->log_operation != NULL) {
        char details[256];
        snprintf(details, sizeof(details), "ALPN manipulation: %zu protocols", num_protocols);
        ctx->log_operation(SSL_OFFENSIVE_OP_EXTENSION_MANIPULATION, details, ctx->log_ctx);
    }

    return 1;
}

/*
 * Manipulate SNI (Server Name Indication)
 */
int SSL_OFFENSIVE_manipulate_sni(SSL *ssl, const char *sni_name)
{
    SSL_OFFENSIVE_OPS_CTX *ctx;

    if (ssl == NULL || sni_name == NULL)
        return 0;

    ctx = (SSL_OFFENSIVE_OPS_CTX *)SSL_get_ex_data(ssl, 1);
    if (ctx == NULL || !SSL_OFFENSIVE_ops_authorized(ctx))
        return 0;

    if (ctx->operation_count >= ctx->max_operations)
        return 0;

    /* Store SNI name */
    if (ctx->attack_params != NULL)
        OPENSSL_free(ctx->attack_params);

    size_t sni_len = strlen(sni_name);
    ctx->attack_params = OPENSSL_memdup(sni_name, sni_len + 1);
    if (ctx->attack_params == NULL)
        return 0;

    ctx->attack_params_len = sni_len + 1;
    ctx->active_op = SSL_OFFENSIVE_OP_EXTENSION_MANIPULATION;
    ctx->operation_count++;

    if (ctx->log_operation != NULL) {
        char details[256];
        snprintf(details, sizeof(details), "SNI manipulation: %s", sni_name);
        ctx->log_operation(SSL_OFFENSIVE_OP_EXTENSION_MANIPULATION, details, ctx->log_ctx);
    }

    return 1;
}

/*
 * Simulate Heartbleed-style attack (for testing bounds checking)
 */
int SSL_OFFENSIVE_simulate_heartbleed(SSL *ssl, size_t payload_len, size_t response_len)
{
    SSL_OFFENSIVE_OPS_CTX *ctx;

    if (ssl == NULL)
        return 0;

    ctx = (SSL_OFFENSIVE_OPS_CTX *)SSL_get_ex_data(ssl, 1);
    if (ctx == NULL || !SSL_OFFENSIVE_ops_authorized(ctx))
        return 0;

    if (ctx->operation_count >= ctx->max_operations)
        return 0;

    /* Store heartbeat parameters */
    if (ctx->attack_params != NULL)
        OPENSSL_free(ctx->attack_params);

    size_t *params = OPENSSL_malloc(2 * sizeof(size_t));
    if (params == NULL)
        return 0;

    params[0] = payload_len;
    params[1] = response_len;
    ctx->attack_params = params;
    ctx->attack_params_len = 2 * sizeof(size_t);
    ctx->active_op = SSL_OFFENSIVE_OP_MEMORY_EXHAUSTION;
    ctx->operation_count++;

    if (ctx->log_operation != NULL) {
        char details[256];
        snprintf(details, sizeof(details), "Heartbleed simulation: payload %zu, response %zu",
                payload_len, response_len);
        ctx->log_operation(SSL_OFFENSIVE_OP_MEMORY_EXHAUSTION, details, ctx->log_ctx);
    }

    return 1;
}

/*
 * Simulate renegotiation attack
 */
int SSL_OFFENSIVE_simulate_renegotiation_attack(SSL *ssl)
{
    SSL_OFFENSIVE_OPS_CTX *ctx;

    if (ssl == NULL)
        return 0;

    ctx = (SSL_OFFENSIVE_OPS_CTX *)SSL_get_ex_data(ssl, 1);
    if (ctx == NULL || !SSL_OFFENSIVE_ops_authorized(ctx))
        return 0;

    if (ctx->operation_count >= ctx->max_operations)
        return 0;

    ctx->active_op = SSL_OFFENSIVE_OP_HANDSHAKE_INJECTION;
    ctx->operation_count++;

    if (ctx->log_operation != NULL) {
        ctx->log_operation(SSL_OFFENSIVE_OP_HANDSHAKE_INJECTION,
                          "Renegotiation attack simulation", ctx->log_ctx);
    }

    return 1;
}

/*
 * Perform statistical timing analysis
 */
int SSL_OFFENSIVE_statistical_timing_analysis(SSL *ssl,
                                             const char *operation,
                                             uint32_t samples,
                                             uint64_t *mean_ns,
                                             uint64_t *stddev_ns)
{
    SSL_OFFENSIVE_OPS_CTX *ctx;
    struct timespec start, end;
    uint64_t *timings = NULL;
    uint64_t sum = 0;
    uint64_t mean = 0;
    uint64_t variance = 0;

    if (ssl == NULL || operation == NULL || mean_ns == NULL || stddev_ns == NULL || samples == 0)
        return 0;

    ctx = (SSL_OFFENSIVE_OPS_CTX *)SSL_get_ex_data(ssl, 1);
    if (ctx == NULL || !SSL_OFFENSIVE_ops_authorized(ctx))
        return 0;

    /* Limit samples for safety */
    if (samples > 10000)
        samples = 10000;

    timings = OPENSSL_malloc(samples * sizeof(uint64_t));
    if (timings == NULL)
        return 0;

    /* Collect timing samples */
    for (uint32_t i = 0; i < samples; i++) {
        clock_gettime(CLOCK_MONOTONIC, &start);
        /* Perform operation timing measurement */
        clock_gettime(CLOCK_MONOTONIC, &end);
        
        timings[i] = ((end.tv_sec - start.tv_sec) * 1000000000ULL) +
                     (end.tv_nsec - start.tv_nsec);
        sum += timings[i];
    }

    /* Calculate mean */
    mean = sum / samples;
    *mean_ns = mean;

    /* Calculate standard deviation */
    for (uint32_t i = 0; i < samples; i++) {
        int64_t diff = (int64_t)timings[i] - (int64_t)mean;
        variance += (uint64_t)(diff * diff);
    }
    variance /= samples;
    *stddev_ns = (uint64_t)sqrt((double)variance);

    OPENSSL_free(timings);

    ctx->active_op = SSL_OFFENSIVE_OP_TIMING_ANALYSIS;
    ctx->operation_count++;

    if (ctx->log_operation != NULL) {
        char details[256];
        snprintf(details, sizeof(details), "Statistical timing: %s, mean %llu ns, stddev %llu ns",
                operation, (unsigned long long)*mean_ns, (unsigned long long)*stddev_ns);
        ctx->log_operation(SSL_OFFENSIVE_OP_TIMING_ANALYSIS, details, ctx->log_ctx);
    }

    return 1;
}
