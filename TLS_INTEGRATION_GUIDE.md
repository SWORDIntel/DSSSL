# TLS 1.3 Hybrid KEM Integration Guide

**Status**: Structure Complete, Implementation Pending  
**Effort**: 2-3 weeks  
**Priority**: Critical (blocks primary feature)

---

## Overview

This guide details the implementation steps for integrating hybrid KEM (X25519+ML-KEM, P-256+ML-KEM) into TLS 1.3 handshake. The structure is defined in `ssl/tls13_hybrid_kem.h` and `ssl/tls13_hybrid_kem.c`.

---

## Implementation Steps

### Step 1: Add Hybrid Group Definitions

**File**: `include/openssl/tls1.h`

Add hybrid group definitions after existing named groups:

```c
/* Hybrid KEM Groups (experimental range 0xFF00-0xFFFF) */
#define TLSEXT_NAMED_GROUP_X25519_MLKEM768    0xFF01
#define TLSEXT_NAMED_GROUP_P256_MLKEM768      0xFF02
#define TLSEXT_NAMED_GROUP_X25519_MLKEM1024   0xFF03
#define TLSEXT_NAMED_GROUP_P384_MLKEM1024     0xFF04
```

### Step 2: Register Hybrid Groups in TLS Group Table

**File**: `ssl/t1_lib.c` or `providers/common/capabilities.c`

Add entries to TLS group capabilities table:

```c
/* Hybrid KEM groups */
{ TLSEXT_NAMED_GROUP_X25519_MLKEM768, ML_KEM_768_SECBITS, TLS1_3_VERSION, 0, -1, -1, 1 },
{ TLSEXT_NAMED_GROUP_P256_MLKEM768, ML_KEM_768_SECBITS, TLS1_3_VERSION, 0, -1, -1, 1 },
```

### Step 3: Modify Client Supported Groups Extension

**File**: `ssl/statem/extensions_clnt.c`

In `tls_construct_ctos_supported_groups()`, add hybrid groups based on policy:

```c
EXT_RETURN tls_construct_ctos_supported_groups(SSL_CONNECTION *s, WPACKET *pkt, ...)
{
    // ... existing code ...
    
    /* Add hybrid groups if policy requires */
    uint16_t hybrid_groups[4];
    size_t hybrid_groups_len = sizeof(hybrid_groups) / sizeof(hybrid_groups[0]);
    
    if (tls13_hybrid_kem_get_allowed_groups(s, hybrid_groups, &hybrid_groups_len)) {
        for (i = 0; i < hybrid_groups_len; i++) {
            if (!WPACKET_put_bytes_u16(pkt, hybrid_groups[i])) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                return EXT_RETURN_FAIL;
            }
            if (max_version == TLS1_3_VERSION)
                tls13added++;
            added++;
        }
    }
    
    // ... rest of function ...
}
```

### Step 4: Modify Server Supported Groups Extension

**File**: `ssl/statem/extensions_srvr.c`

In `tls_construct_stoc_supported_groups()`, parse and select hybrid groups:

```c
EXT_RETURN tls_construct_stoc_supported_groups(SSL_CONNECTION *s, WPACKET *pkt, ...)
{
    // Parse client's supported groups
    // Check if hybrid groups are present
    // Select hybrid group based on policy
    // Return selected group
}
```

### Step 5: Implement Client Key Exchange

**File**: `ssl/statem/statem_clnt.c`

In TLS 1.3 client handshake, perform hybrid KEX:

```c
/* In tls_construct_client_key_share() or similar */
if (selected_group_is_hybrid) {
    TLS13_HYBRID_KEM_CTX *hybrid_ctx = tls13_hybrid_kem_ctx_new();
    
    /* Perform classical KEX */
    EVP_PKEY_encapsulate(classical_ctx, classical_ctext, &ctext_len, 
                         classical_secret, &secret_len);
    
    /* Perform PQC KEX */
    EVP_PKEY_encapsulate(pqc_ctx, pqc_ctext, &pqc_ctext_len,
                        pqc_secret, &pqc_secret_len);
    
    /* Combine secrets */
    tls13_hybrid_kem_combine_secrets(hybrid_ctx, "X25519", "ML-KEM-768",
                                     combined_secret, &combined_len);
    
    /* Send both ciphertexts in KeyShare extension */
    /* Format: [classical_ctext_len][classical_ctext][pqc_ctext_len][pqc_ctext] */
}
```

### Step 6: Implement Server Key Exchange

**File**: `ssl/statem/statem_srvr.c`

In TLS 1.3 server handshake, perform hybrid decapsulation:

```c
/* In tls_process_client_key_share() or similar */
if (received_group_is_hybrid) {
    /* Parse hybrid ciphertexts from KeyShare */
    /* Decapsulate classical */
    EVP_PKEY_decapsulate(classical_ctx, classical_secret, &secret_len,
                         classical_ctext, ctext_len);
    
    /* Decapsulate PQC */
    EVP_PKEY_decapsulate(pqc_ctx, pqc_secret, &pqc_secret_len,
                         pqc_ctext, pqc_ctext_len);
    
    /* Combine secrets */
    tls13_hybrid_kem_combine_secrets(hybrid_ctx, "X25519", "ML-KEM-768",
                                     combined_secret, &combined_len);
    
    /* Use combined secret for TLS key derivation */
}
```

### Step 7: Modify Key Derivation

**File**: `ssl/tls13_enc.c`

Ensure TLS 1.3 key derivation uses hybrid shared secret:

```c
/* In tls13_generate_master_secret() or similar */
if (s->ext.hybrid_kem_ctx != NULL) {
    /* Use combined secret from hybrid KEM */
    shared_secret = s->ext.hybrid_kem_ctx->combined_secret;
    shared_secret_len = s->ext.hybrid_kem_ctx->combined_secret_len;
} else {
    /* Use classical shared secret */
    shared_secret = classical_shared_secret;
    shared_secret_len = classical_secret_len;
}
```

### Step 8: Add Policy Enforcement

**File**: `ssl/statem/statem_clnt.c`, `ssl/statem/statem_srvr.c`

Enforce policy requirements:

```c
/* Before handshake */
if (tls13_hybrid_kem_required(s)) {
    /* Check if peer supports hybrid */
    if (!peer_supports_hybrid) {
        SSLfatal(s, SSL_AD_HANDSHAKE_FAILURE, SSL_R_NO_SUITABLE_GROUPS);
        return 0;
    }
}
```

---

## KeyShare Extension Format

For hybrid KEM, KeyShare extension contains both ciphertexts:

```
KeyShareEntry {
    NamedGroup group = X25519_MLKEM768 (0xFF01);
    opaque key_exchange<1..2^16-1>;
}

key_exchange format:
    uint16 classical_ctext_len;
    opaque classical_ctext[classical_ctext_len];  /* ~32 bytes for X25519 */
    uint16 pqc_ctext_len;
    opaque pqc_ctext[pqc_ctext_len];              /* ~1120 bytes for ML-KEM-768 */
```

**Total size**: ~1152 bytes for X25519+ML-KEM-768

---

## Testing Plan

1. **Unit Tests**:
   - Test hybrid secret combination
   - Test policy enforcement
   - Test group selection

2. **Integration Tests**:
   - Client-server handshake with hybrid KEM
   - Fallback to classical when peer doesn't support hybrid
   - Policy enforcement (fail when hybrid required but unavailable)

3. **Interop Tests**:
   - Test with browsers (when they support PQC)
   - Test with other TLS implementations
   - Test classical-only fallback

---

## Security Considerations

1. **Constant-Time**: Both classical and PQC operations must be constant-time
2. **Secret Combination**: HKDF combination must be constant-time
3. **Policy Enforcement**: Fail securely when policy requires hybrid but unavailable
4. **Downgrade Protection**: Log and detect classical-only fallback

---

## Backwards Compatibility

- **WORLD_COMPAT**: Offer hybrid, allow classical fallback
- **DSMIL_SECURE**: Require hybrid, fail if unavailable
- **ATOMAL**: Require hybrid or PQC-only, fail on classical-only

---

## References

- `ssl/tls13_hybrid_kem.h` - API definitions
- `ssl/tls13_hybrid_kem.c` - Implementation skeleton
- `DSSSL_SECURITY_AUDIT_REPORT.md` Section 7.1 - Full specification
- RFC 8446 (TLS 1.3) - Base protocol
- Draft-ietf-tls-hybrid-design - Hybrid KEX draft (when published)

---

**Status**: Structure Complete, Implementation Pending  
**Next**: Begin Step 1 (Add group definitions)
