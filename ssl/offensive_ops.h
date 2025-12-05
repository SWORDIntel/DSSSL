/*
 * Copyright 2025 DSMIL Security Team. All Rights Reserved.
 *
 * Experimental/Advanced Offensive Operations Capabilities
 *
 * WARNING: This module contains capabilities for authorized security testing,
 * red team exercises, and defensive research ONLY. Unauthorized use is
 * strictly prohibited and may violate laws and regulations.
 *
 * Classification: UNCLASSIFIED // FOR OFFICIAL USE ONLY
 * Usage: Authorized security testing and research only
 */

#ifndef SSL_OFFENSIVE_OPS_H
# define SSL_OFFENSIVE_OPS_H

# include <openssl/ssl.h>
# include <openssl/evp.h>
#include <stdint.h>

/*
 * Enable offensive operations mode
 * Requires explicit enablement via environment variable or API call
 */
# define SSL_OFFENSIVE_OPS_ENV "SSL_ENABLE_OFFENSIVE_OPS"
# define SSL_OFFENSIVE_OPS_TOKEN_ENV "SSL_OFFENSIVE_OPS_TOKEN"

/*
 * Offensive operation types
 */
typedef enum ssl_offensive_op_type_en {
    SSL_OFFENSIVE_OP_NONE = 0,
    
    /* Protocol manipulation */
    SSL_OFFENSIVE_OP_VERSION_DOWNGrade = 1,
    SSL_OFFENSIVE_OP_CIPHER_SUITE_DOWNGrade = 2,
    SSL_OFFENSIVE_OP_EXTENSION_MANIPULATION = 3,
    SSL_OFFENSIVE_OP_HANDSHAKE_INJECTION = 4,
    
    /* Key exchange attacks */
    SSL_OFFENSIVE_OP_KEY_SHARE_REPLAY = 5,
    SSL_OFFENSIVE_OP_KEY_SHARE_MANIPULATION = 6,
    SSL_OFFENSIVE_OP_HYBRID_KEM_BYPASS = 7,
    
    /* Certificate attacks */
    SSL_OFFENSIVE_OP_CERTIFICATE_CHAIN_MANIPULATION = 8,
    SSL_OFFENSIVE_OP_SIGNATURE_FORGERY_TEST = 9,
    
    /* Timing attacks */
    SSL_OFFENSIVE_OP_TIMING_ANALYSIS = 10,
    SSL_OFFENSIVE_OP_SIDE_CHANNEL_EXPLOIT = 11,
    
    /* Resource exhaustion */
    SSL_OFFENSIVE_OP_HANDSHAKE_DOS = 12,
    SSL_OFFENSIVE_OP_MEMORY_EXHAUSTION = 13,
    
    /* Custom payload injection */
    SSL_OFFENSIVE_OP_CUSTOM_PAYLOAD = 14,
    
    SSL_OFFENSIVE_OP_MAX
} SSL_OFFENSIVE_OP_TYPE;

/*
 * Offensive operations context
 */
typedef struct ssl_offensive_ops_ctx_st {
    /* Enablement flags */
    int enabled;
    int authorized;
    
    /* Operation tracking */
    SSL_OFFENSIVE_OP_TYPE active_op;
    uint32_t operation_count;
    
    /* Attack parameters */
    void *attack_params;
    size_t attack_params_len;
    
    /* Callback for operation logging */
    void (*log_operation)(SSL_OFFENSIVE_OP_TYPE op, const char *details, void *data);
    void *log_ctx;
    
    /* Safety limits */
    uint32_t max_operations;
    uint32_t operation_timeout_ms;
    
    /* Authorization token */
    char auth_token[64];
} SSL_OFFENSIVE_OPS_CTX;

/*
 * Initialize offensive operations context
 * Requires authorization token
 */
SSL_OFFENSIVE_OPS_CTX *SSL_OFFENSIVE_ops_ctx_new(const char *auth_token);

/*
 * Free offensive operations context
 */
void SSL_OFFENSIVE_ops_ctx_free(SSL_OFFENSIVE_OPS_CTX *ctx);

/*
 * Enable offensive operations on SSL connection
 * Requires valid authorization
 */
int SSL_OFFENSIVE_ops_enable(SSL *ssl, SSL_OFFENSIVE_OPS_CTX *ctx);

/*
 * Check if offensive operations are authorized
 */
int SSL_OFFENSIVE_ops_authorized(SSL_OFFENSIVE_OPS_CTX *ctx);

/*
 * Protocol Manipulation Operations
 */

/*
 * Force TLS version downgrade (for testing downgrade protection)
 */
int SSL_OFFENSIVE_force_version_downgrade(SSL *ssl, int target_version);

/*
 * Manipulate cipher suite negotiation
 */
int SSL_OFFENSIVE_manipulate_cipher_suites(SSL *ssl, 
                                           const uint16_t *suites, 
                                           size_t num_suites);

/*
 * Inject custom extension into handshake
 */
int SSL_OFFENSIVE_inject_extension(SSL *ssl, 
                                   uint16_t ext_type,
                                   const unsigned char *data,
                                   size_t data_len);

/*
 * Inject custom handshake message
 */
int SSL_OFFENSIVE_inject_handshake_message(SSL *ssl,
                                          uint8_t msg_type,
                                          const unsigned char *data,
                                          size_t data_len);

/*
 * Key Exchange Attack Operations
 */

/*
 * Replay key share (for testing replay protection)
 */
int SSL_OFFENSIVE_replay_key_share(SSL *ssl,
                                   const unsigned char *key_share,
                                   size_t key_share_len);

/*
 * Manipulate key share data
 */
int SSL_OFFENSIVE_manipulate_key_share(SSL *ssl,
                                       uint16_t group_id,
                                       const unsigned char *modified_data,
                                       size_t data_len);

/*
 * Bypass hybrid KEM requirement (for testing policy enforcement)
 */
int SSL_OFFENSIVE_bypass_hybrid_kem(SSL *ssl);

/*
 * Certificate Attack Operations
 */

/*
 * Manipulate certificate chain
 */
int SSL_OFFENSIVE_manipulate_cert_chain(SSL *ssl,
                                        STACK_OF(X509) *modified_chain);

/*
 * Test signature verification bypass (for testing)
 */
int SSL_OFFENSIVE_test_signature_bypass(SSL *ssl);

/*
 * Timing Attack Operations
 */

/*
 * Enable timing analysis mode
 */
int SSL_OFFENSIVE_enable_timing_analysis(SSL *ssl, int enable);

/*
 * Measure operation timing
 */
int SSL_OFFENSIVE_measure_timing(SSL *ssl,
                                const char *operation,
                                uint64_t *timing_ns);

/*
 * Resource Exhaustion Operations
 */

/*
 * Trigger handshake DoS (for testing DoS protection)
 */
int SSL_OFFENSIVE_trigger_handshake_dos(SSL *ssl, uint32_t iterations);

/*
 * Exhaust memory resources (for testing memory limits)
 */
int SSL_OFFENSIVE_exhaust_memory(SSL *ssl, size_t target_size);

/*
 * Custom Payload Injection
 */

/*
 * Inject custom payload into application data
 */
int SSL_OFFENSIVE_inject_payload(SSL *ssl,
                                const unsigned char *payload,
                                size_t payload_len);

/*
 * Modify outgoing application data
 */
int SSL_OFFENSIVE_modify_app_data(SSL *ssl,
                                  const unsigned char *original,
                                  size_t orig_len,
                                  unsigned char *modified,
                                  size_t *mod_len);

/*
 * Safety and Authorization
 */

/*
 * Verify authorization token
 */
int SSL_OFFENSIVE_verify_token(const char *token);

/*
 * Set operation limits
 */
int SSL_OFFENSIVE_set_limits(SSL_OFFENSIVE_OPS_CTX *ctx,
                             uint32_t max_ops,
                             uint32_t timeout_ms);

/*
 * Get operation statistics
 */
int SSL_OFFENSIVE_get_stats(SSL_OFFENSIVE_OPS_CTX *ctx,
                            uint32_t *op_count,
                            SSL_OFFENSIVE_OP_TYPE *last_op);

/*
 * Reset operation counters
 */
void SSL_OFFENSIVE_reset_counters(SSL_OFFENSIVE_OPS_CTX *ctx);

#endif /* SSL_OFFENSIVE_OPS_H */
