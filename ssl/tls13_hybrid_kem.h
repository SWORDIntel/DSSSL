/*
 * Copyright 2025 DSMIL Security Team. All Rights Reserved.
 *
 * TLS 1.3 Hybrid KEM Integration - Header
 *
 * This header defines the structure for integrating hybrid KEM (X25519+ML-KEM,
 * P-256+ML-KEM) into TLS 1.3 handshake.
 *
 * STATUS: Structure defined, implementation pending
 * See: DSSSL_SECURITY_AUDIT_REPORT.md Section 7.1
 */

#ifndef TLS13_HYBRID_KEM_H
# define TLS13_HYBRID_KEM_H

# include <openssl/ssl.h>
# include <openssl/evp.h>

/*
 * Hybrid Named Groups for TLS 1.3
 *
 * These group IDs are in the experimental range (0xFF00-0xFFFF)
 * and should be registered with IANA when standardized.
 */
# define TLSEXT_NAMED_GROUP_X25519_MLKEM768    0xFF01
# define TLSEXT_NAMED_GROUP_P256_MLKEM768      0xFF02
# define TLSEXT_NAMED_GROUP_X25519_MLKEM1024   0xFF03
# define TLSEXT_NAMED_GROUP_P384_MLKEM1024     0xFF04

/*
 * Hybrid KEM Context
 *
 * Stores both classical and PQC shared secrets during handshake
 */
typedef struct tls13_hybrid_kem_ctx_st {
    /* Classical KEM shared secret */
    uint8_t classical_secret[64];  /* Max for X448 */
    size_t classical_secret_len;
    
    /* PQC KEM shared secret */
    uint8_t pqc_secret[ML_KEM_SHARED_SECRET_BYTES];
    size_t pqc_secret_len;
    
    /* Combined shared secret (HKDF output) */
    uint8_t combined_secret[64];
    size_t combined_secret_len;
    
    /* Algorithm identifiers */
    int classical_group_id;  /* e.g., TLSEXT_NAMED_GROUP_X25519 */
    int pqc_group_id;       /* e.g., TLSEXT_NAMED_GROUP_MLKEM768 */
    
    /* Key material for HKDF */
    EVP_PKEY_CTX *hkdf_ctx;
} TLS13_HYBRID_KEM_CTX;

/*
 * Initialize hybrid KEM context
 */
TLS13_HYBRID_KEM_CTX *tls13_hybrid_kem_ctx_new(void);

/*
 * Free hybrid KEM context
 */
void tls13_hybrid_kem_ctx_free(TLS13_HYBRID_KEM_CTX *ctx);

/*
 * Perform hybrid KEM key exchange (client side)
 *
 * Generates both classical and PQC shared secrets, combines via HKDF
 */
int tls13_hybrid_kem_client_keyexch(SSL *s,
                                     TLS13_HYBRID_KEM_CTX *ctx,
                                     int classical_group,
                                     int pqc_group,
                                     uint8_t *shared_secret,
                                     size_t *shared_secret_len);

/*
 * Perform hybrid KEM key exchange (server side)
 *
 * Decapsulates both classical and PQC ciphertexts, combines via HKDF
 */
int tls13_hybrid_kem_server_keyexch(SSL *s,
                                     TLS13_HYBRID_KEM_CTX *ctx,
                                     const uint8_t *classical_ctext,
                                     size_t classical_ctext_len,
                                     const uint8_t *pqc_ctext,
                                     size_t pqc_ctext_len,
                                     uint8_t *shared_secret,
                                     size_t *shared_secret_len);

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
                                      size_t *combined_secret_len);

/*
 * Check if hybrid KEM is required by policy
 */
int tls13_hybrid_kem_required(SSL *s);

/*
 * Get allowed hybrid groups based on security profile
 */
int tls13_hybrid_kem_get_allowed_groups(SSL *s,
                                         uint16_t *groups,
                                         size_t *groups_len);

/*
 * Implementation Notes:
 *
 * 1. Integration Points:
 *    - Client: ssl/statem/extensions_clnt.c (supported_groups extension)
 *    - Server: ssl/statem/extensions_srvr.c (supported_groups extension)
 *    - Handshake: ssl/statem/statem_clnt.c, ssl/statem/statem_srvr.c
 *    - Key derivation: ssl/tls13_enc.c
 *
 * 2. TLS 1.3 Handshake Flow:
 *    - ClientHello: Include hybrid groups in supported_groups
 *    - ServerHello: Select hybrid group (or fall back to classical)
 *    - KeyShare: Send both classical and PQC ciphertexts
 *    - Key derivation: Use combined shared secret
 *
 * 3. Policy Enforcement:
 *    - DSMIL_SECURE: Require hybrid KEM, fail if not available
 *    - ATOMAL: Require hybrid or PQC-only, fail on classical-only
 *    - WORLD_COMPAT: Offer hybrid, allow classical fallback
 *
 * 4. Backwards Compatibility:
 *    - Peers without PQC support: Use classical-only (WORLD_COMPAT)
 *    - Peers with PQC support: Negotiate hybrid (DSMIL_SECURE/ATOMAL)
 *
 * 5. Security Considerations:
 *    - Both classical and PQC secrets must be constant-time
 *    - HKDF combination must be constant-time
 *    - Ciphertext sizes: ~32 bytes (classical) + ~1120 bytes (ML-KEM-768)
 */

#endif /* TLS13_HYBRID_KEM_H */
