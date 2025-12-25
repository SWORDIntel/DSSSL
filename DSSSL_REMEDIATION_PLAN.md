# DSSSL Remediation Plan

**Date:** 2025-01-XX  
**Based on:** DSSSL_AUDIT_REPORT.md  
**Goal:** Full implementation of all violations (no placeholders acceptable)

---

## Executive Summary

This remediation plan addresses **11+ violations** identified in the DSSSL audit. **All placeholders are work items requiring full implementation.** The plan is prioritized by risk and dependencies.

### Total Work Items: 11+

- **High Priority:** 3 items (security-critical)
- **Medium Priority:** 3 items (feature-completing)
- **Low Priority:** 5+ items (code quality)
- **OpenSSL Base Review:** 20+ items (individual assessment needed)

### Estimated Total Effort: 24-36 hours

---

## Priority 1: High-Risk Security Violations

### Fix #1: TPM RNG Implementation

**File:** `providers/dsmil/tpm_integration.c`  
**Lines:** 341-357  
**Violation:** TPM random number generation always falls back to software  
**Risk:** High (security feature not working)

**Current Code:**
```c
int dsmil_tpm_random(DSMIL_TPM_CTX *ctx,
                     uint8_t *buffer,
                     size_t length)
{
    /* TPM RNG would be implemented via tpm2-tools or direct TPM2_GetRandom */
    if (!dsmil_tpm_is_available(ctx) || !ctx->config.use_tpm_rng) {
        ctx->software_fallbacks++;
        return 0;
    }

    ctx->tpm_operations++;

    /* TODO: Implement TPM2_GetRandom call */
    /* For now, fall back to software */
    ctx->software_fallbacks++;
    return 0;
}
```

**Required Actions:**
1. Search for TPM2_GetRandom API in codebase
2. Check for tpm2-tools integration patterns
3. Implement actual TPM2_GetRandom call
4. Remove fallback logic (or make it only for errors, not default)

**API Search:**
- Search for: `TPM2_GetRandom`, `tpm2_getrandom`, `tpm2-tools`, `Tss2_Sys_GetRandom`
- Check: `toolchains/DSLLVM/tpm2_compat/` for TPM integration patterns
- Check: System libraries for TPM2 API

**Implementation Options:**
1. **Direct TPM2 API:** Use TSS2 library if available
2. **tpm2-tools:** Call `tpm2_getrandom` command via system call
3. **Kernel interface:** Use `/dev/tpmrm0` if available

**Estimated Effort:** 4-6 hours  
**Dependencies:** None  
**Priority:** High

---

### Fix #2: SSL Structure Policy Context Integration

**File:** `ssl/tls13_hybrid_kem.c`  
**Lines:** 135-157  
**Violation:** Uses environment variable instead of proper SSL structure integration  
**Risk:** High (policy enforcement depends on this)

**Current Code:**
```c
int tls13_hybrid_kem_required(SSL *s)
{
    int required = 0;

    if (s == NULL)
        return 0;

    /* Get policy context from SSL */
    /* TODO: Store policy context in SSL structure */
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
```

**Required Actions:**
1. Find SSL_CONNECTION structure definition
2. Add policy context field to SSL_CONNECTION structure
3. Store policy context during SSL initialization
4. Retrieve policy context from SSL structure
5. Remove environment variable fallback

**API Search:**
- Search for: `struct ssl_connection_st`, `SSL_CONNECTION`, `SSL_CTX` policy storage
- Check: `include/internal/statem.h` for structure definition
- Check: `ssl/ssl_lib.c` for SSL initialization patterns
- Check: `providers/dsmil/dsmilprov.c` for policy context creation

**Implementation Steps:**
1. Locate `struct ssl_connection_st` definition
2. Add field: `DSMIL_POLICY_CTX *dsmil_policy_ctx;`
3. Initialize in SSL connection creation
4. Update `tls13_hybrid_kem_required()` to use structure field
5. Update `tls13_hybrid_kem_get_allowed_groups()` similarly

**Estimated Effort:** 3-4 hours  
**Dependencies:** None  
**Priority:** High

---

### Fix #3: SSL_CONNECTION CVE Detection Context Field

**File:** `ssl/cve_detection.c`  
**Lines:** 56-70  
**Violation:** Uses ex_data instead of proper SSL_CONNECTION field  
**Risk:** Medium (data structure usage)

**Current Code:**
```c
int SSL_CVE_detection_enable(SSL *ssl, SSL_CVE_DETECTION_CTX *ctx)
{
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL_ONLY(ssl);

    if (s == NULL || ctx == NULL)
        return 0;

    /* Store context in SSL connection */
    /* TODO: Add field to SSL_CONNECTION structure */
    /* For now, use ex_data */
    if (SSL_set_ex_data(ssl, 0, ctx) == 0)
        return 0;

    return 1;
}
```

**Required Actions:**
1. Find SSL_CONNECTION structure definition
2. Add CVE detection context field to structure
3. Update enable/disable functions to use structure field
4. Remove ex_data usage

**API Search:**
- Search for: `struct ssl_connection_st` definition
- Check: Similar pattern to Fix #2

**Implementation Steps:**
1. Add field: `SSL_CVE_DETECTION_CTX *cve_detection_ctx;` to `struct ssl_connection_st`
2. Update `SSL_CVE_detection_enable()` to set structure field
3. Update all `SSL_CVE_*` functions to use structure field instead of `SSL_get_ex_data()`

**Estimated Effort:** 2-3 hours  
**Dependencies:** None (can be done in parallel with Fix #2)  
**Priority:** Medium

---

## Priority 2: Medium-Risk Feature Violations

### Fix #4: PQC Key Storage in Hybrid KEM Context

**File:** `ssl/statem/extensions_clnt.c`  
**Lines:** 780, 789  
**Violation:** Missing implementation for storing PQC key  
**Risk:** Medium (hybrid KEM feature incomplete)

**Current Code:**
```c
/* TODO: Store PQC key in hybrid KEM context */
/* TODO: Store PQC key separately for hybrid operations */
```

**Required Actions:**
1. Find hybrid KEM context structure
2. Add PQC key storage fields
3. Implement key storage during handshake
4. Implement key retrieval for hybrid operations

**API Search:**
- Search for: `TLS13_HYBRID_KEM_CTX`, `tls13_hybrid_kem_ctx`, hybrid KEM context
- Check: `ssl/tls13_hybrid_kem.h` for structure definition
- Check: `ssl/tls13_hybrid_kem.c` for context management

**Implementation Steps:**
1. Review `TLS13_HYBRID_KEM_CTX` structure
2. Add PQC key storage fields if missing
3. Store PQC key during client key exchange
4. Retrieve PQC key for hybrid secret combination

**Estimated Effort:** 4-6 hours  
**Dependencies:** None  
**Priority:** Medium

---

### Fix #5: Enhanced CVE Detection Implementation

**File:** `ssl/cve_detection.c`  
**Line:** 147  
**Violation:** Acknowledges simplified implementation  
**Risk:** Medium (security feature may miss attacks)

**Current Code:**
```c
/* Check for known injection patterns */
/* This is a simplified check - real implementation would be more sophisticated */
const char *suspicious_patterns[] = {
    "\x00\x00\x00",  /* Null bytes */
    "\xFF\xFF\xFF",  /* Max bytes */
    NULL
};
```

**Required Actions:**
1. Research sophisticated CVE detection patterns
2. Implement multi-pattern matching
3. Add statistical analysis
4. Add ML-based detection (if models available) OR remove comment if current is sufficient

**API Search:**
- Search for: CVE detection patterns, attack pattern matching, anomaly detection
- Check: `docs/CVE_DETECTION_AND_MITIGATION.md` for requirements
- Check: If ML models exist for attack detection

**Implementation Options:**
1. **Pattern-based:** Expand pattern library, add regex matching
2. **Statistical:** Add frequency analysis, entropy checks
3. **ML-based:** If models available, integrate ML detection
4. **Remove comment:** If current implementation is sufficient, remove misleading comment

**Estimated Effort:** 8-12 hours (if enhancing) or 1 hour (if removing comment)  
**Dependencies:** None  
**Priority:** Medium

---

## Priority 3: Low-Risk Code Quality Violations

### Fix #6: ML-KEM-1024 Support Clarification

**File:** `ssl/tls13_hybrid_kem.c`  
**Line:** 199  
**Violation:** "Use 768 for now, 1024 when available" comment  
**Risk:** Low (feature works, comment is misleading)

**Current Code:**
```c
groups[count++] = OSSL_TLS_GROUP_ID_X25519MLKEM768;  /* Use 768 for now, 1024 when available */
```

**Required Actions:**
1. Check if ML-KEM-1024 is available in codebase
2. If available: Add 1024 support
3. If not available: Remove misleading comment

**API Search:**
- Search for: `ML-KEM-1024`, `MLKEM1024`, `OSSL_TLS_GROUP_ID.*1024`
- Check: `crypto/ml_kem/` for available ML-KEM sizes
- Check: `providers/implementations/kem/` for KEM implementations

**Estimated Effort:** 2-3 hours (if adding support) or 15 minutes (if removing comment)  
**Dependencies:** None  
**Priority:** Low

---

### Fix #7: MKI Value Handling

**File:** `ssl/statem/extensions_srvr.c`  
**Line:** 588  
**Violation:** MKI value extracted but discarded  
**Risk:** Low (MKI may not be critical)

**Current Code:**
```c
/* Now extract the MKI value as a sanity check, but discard it for now */
```

**Required Actions:**
1. Research MKI (Master Key Identifier) requirements
2. If required: Implement proper MKI handling
3. If not required: Remove extraction code or comment

**API Search:**
- Search for: MKI, Master Key Identifier, TLS MKI
- Check: TLS 1.3 specification for MKI requirements
- Check: If MKI is used elsewhere in codebase

**Estimated Effort:** 1-2 hours  
**Dependencies:** None  
**Priority:** Low

---

## Implementation Order

### Phase 1: Critical Security Fixes (Week 1)
1. Fix #1: TPM RNG Implementation (4-6 hours)
2. Fix #2: SSL Structure Policy Context (3-4 hours)
3. Fix #3: SSL_CONNECTION CVE Field (2-3 hours)

**Total:** 9-13 hours

### Phase 2: Feature Completion (Week 2)
4. Fix #4: PQC Key Storage (4-6 hours)
5. Fix #5: Enhanced CVE Detection (8-12 hours or 1 hour)

**Total:** 12-18 hours or 5-7 hours

### Phase 3: Code Quality (Week 3)
6. Fix #6: ML-KEM-1024 Support (2-3 hours or 15 min)
7. Fix #7: MKI Handling (1-2 hours)

**Total:** 3-5 hours or 1.25 hours

### Phase 4: OpenSSL Base Review (Ongoing)
- Review 20+ OpenSSL base code violations
- Determine which need fixes vs. acceptable upstream patterns
- Prioritize DSMIL-specific enhancements

---

## API Search Checklist

For each fix, complete this checklist:

- [ ] Searched codebase for existing API/function
- [ ] Searched for similar implementations
- [ ] Checked header files for structure definitions
- [ ] Checked documentation for requirements
- [ ] Verified API exists and is usable
- [ ] Checked for kernel→userspace boundaries
- [ ] Verified no fake implementations in search results

---

## Testing Requirements

After each fix:

- [ ] Code compiles without errors
- [ ] Existing tests pass
- [ ] New functionality tested
- [ ] No regressions introduced
- [ ] Security features verified working

---

## Success Criteria

**All fixes complete when:**
1. No "for now" comments remain
2. No "TODO" comments for these violations
3. All functions use real APIs
4. All structure fields properly defined
5. All tests pass
6. Documentation updated

---

**Plan Created:** 2025-01-XX  
**Classification:** UNCLASSIFIED // FOR OFFICIAL USE ONLY

