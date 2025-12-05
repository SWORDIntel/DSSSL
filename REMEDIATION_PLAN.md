# DSSSL Security Remediation Plan
**Prioritized Action Items**

## Phase 1: Critical Fixes (Week 1-4)

### 1.1 Complete TLS Integration for Hybrid KEM 🔴 CRITICAL
**Priority**: P0 - Blocks primary feature  
**Effort**: 2-3 weeks  
**Owner**: TLS Team

**Tasks**:
- [ ] Add hybrid named groups to TLS 1.3 `supported_groups` extension
  - File: `ssl/statem/extensions_clnt.c`, `ssl/statem/extensions_srvr.c`
  - Define: `TLSEXT_NAMED_GROUP_X25519_MLKEM768`, etc.
- [ ] Implement TLS handshake logic for hybrid KEX
  - File: `ssl/statem/statem_clnt.c`, `ssl/statem/statem_srvr.c`
  - Parse hybrid groups, select based on policy, perform KEX
- [ ] Verify key derivation uses hybrid shared secret
  - File: `ssl/tls13_enc.c`
- [ ] Add TLS interop tests
  - File: `test/ssl-tests/`
  - Test: Hybrid KEM negotiation with browsers

**Acceptance Criteria**:
- TLS 1.3 handshake successfully negotiates hybrid KEM
- Works with DSMIL_SECURE and ATOMAL profiles
- Interoperates with major browsers (when they support PQC)

---

### 1.2 Implement Policy Provider Algorithm Filtering 🔴 CRITICAL
**Priority**: P0 - Security profiles ineffective  
**Effort**: 1 week  
**Owner**: Provider Team

**Tasks**:
- [ ] Implement `dsmil_query()` to return filtered algorithms
  - File: `providers/dsmil/dsmilprov.c:91`
  - Filter based on active security profile
- [ ] Add helper functions for algorithm filtering
  - `dsmil_get_allowed_kems()`
  - `dsmil_get_allowed_signatures()`
  - `dsmil_get_allowed_ciphers()`
- [ ] Add policy enforcement tests
  - File: `test/dsmil/test-policy-enforcement.c`
  - Verify weak algorithms blocked in DSMIL_SECURE/ATOMAL

**Acceptance Criteria**:
- DSMIL_SECURE profile blocks non-hybrid KEMs
- ATOMAL profile blocks pure classical algorithms
- Policy violations logged via event telemetry

---

## Phase 2: High Priority Fixes (Week 5-8)

### 2.1 Add CSNA Annotations to Crypto Code 🟡 HIGH
**Priority**: P1 - Side-channel risk  
**Effort**: 1 week  
**Owner**: Crypto Team

**Tasks**:
- [ ] Add CSNA annotations to ML-KEM decapsulation
  - File: `crypto/ml_kem/ml_kem.c`
  - Annotate: `ml_kem_decapsulate()` function
- [ ] Add CSNA annotations to ML-DSA signature generation
  - File: `crypto/ml_dsa/ml_dsa_sign.c`
  - Annotate: Private key operations
- [ ] Add CSNA annotations to hybrid KEM operations
  - File: `providers/implementations/kem/mlx_kem.c`
  - Annotate: Secret combination functions
- [ ] Verify annotations with DSLLVM compiler
  - Build with `-DCSNA_CONSTANT_TIME_CHECK`
  - Fix any compiler warnings

**Acceptance Criteria**:
- All secret-dependent operations annotated
- DSLLVM build succeeds with constant-time checks enabled
- Timing variance tests pass (<1% coefficient of variation)

---

### 2.2 Integrate Real TPM2 Library 🟡 HIGH
**Priority**: P1 - Blocks ATOMAL profile  
**Effort**: 2 weeks  
**Owner**: TPM Team

**Tasks**:
- [ ] Choose TPM2 library (recommend: tpm2-tss)
- [ ] Replace stub functions in `tpm2_compat.h`
  - Implement: `tpm2_crypto_init()`
  - Implement: `tpm2_key_seal()` / `tpm2_key_unseal()`
  - Implement: `tpm2_hash()`, `tpm2_hmac()`
- [ ] Add TPM2 dependency to build system
  - File: `Configurations/10-dsllvm.conf`
  - Link: `-ltss2-sys`, `-ltss2-tcti-device`
- [ ] Add TPM2 integration tests
  - File: `test/dsmil/test-tpm-integration.c`
  - Test: Key sealing/unsealing, hash operations

**Acceptance Criteria**:
- TPM2 operations work on systems with TPM hardware
- Graceful fallback when TPM unavailable (except ATOMAL)
- ATOMAL profile requires TPM and fails if unavailable

---

### 2.3 Fix Security Vulnerabilities 🟡 HIGH
**Priority**: P1 - Security issues  
**Effort**: 2 days  
**Owner**: Security Team

**Tasks**:
- [ ] Fix unsafe `strncpy` in events.c
  - File: `providers/dsmil/events.c:83`
  - Add null termination
- [ ] Fix JSON injection in event telemetry
  - File: `providers/dsmil/events.c:193`
  - Add JSON escaping function
- [ ] Add input validation to policy context creation
  - File: `providers/dsmil/policy.c:37`
  - Validate environment variable values

**Acceptance Criteria**:
- No buffer overflows or injection vulnerabilities
- Static analysis tools pass (clang-tidy, cppcheck)

---

## Phase 3: Medium Priority Improvements (Week 9-12)

### 3.1 Enhance Build System 🟢 MEDIUM
**Priority**: P2 - Code quality  
**Effort**: 3 days  
**Owner**: Build Team

**Tasks**:
- [ ] Add stricter compiler warnings
  - File: `Configurations/10-dsllvm.conf`
  - Add: `-Wall -Wextra -Wformat=2 -Wstrict-prototypes`
- [ ] Enable `-Werror` after fixing warnings
- [ ] Add CFI and stack clash protection
  - Add: `-fcf-protection=full`
  - Add: `-fstack-clash-protection`
- [ ] Integrate static analysis tools
  - Add: `clang-tidy` to CI/CD
  - Add: `cppcheck` to CI/CD
  - Add: `scan-build` (clang static analyzer)

**Acceptance Criteria**:
- Build succeeds with `-Werror`
- Static analysis passes with no high-severity issues
- All warnings addressed or documented

---

### 3.2 Comprehensive Testing 🟢 MEDIUM
**Priority**: P2 - Quality assurance  
**Effort**: 1 week  
**Owner**: QA Team

**Tasks**:
- [ ] Add timing variance tests
  - File: `test/dsmil/test-timing-variance.c`
  - Test: ML-KEM decap, ML-DSA sign, hybrid operations
  - Verify: Coefficient of variation < 1%
- [ ] Add TLS handshake tests
  - File: `test/ssl-tests/`
  - Test: Hybrid KEM negotiation
  - Test: Policy enforcement in TLS
- [ ] Add policy enforcement tests
  - File: `test/dsmil/test-policy-enforcement.c`
  - Test: Algorithm filtering per profile
- [ ] Enhance fuzzing coverage
  - File: `fuzz/`
  - Add: TLS handshake fuzzer
  - Add: Event telemetry JSON fuzzer

**Acceptance Criteria**:
- All tests pass
- Test coverage > 80% for DSMIL-specific code
- Fuzzing finds no crashes

---

### 3.3 Deprecate Legacy Algorithms 🟢 MEDIUM
**Priority**: P2 - Defense in depth  
**Effort**: 2 days  
**Owner**: Policy Team

**Tasks**:
- [ ] Add disabled algorithm list to policy provider
  - File: `providers/dsmil/policy.c`
  - Disable: RSA key exchange, 3DES, RC4, MD5, SHA1 (signatures)
- [ ] Add policy checks for legacy algorithms
- [ ] Add tests for legacy algorithm blocking

**Acceptance Criteria**:
- Legacy algorithms blocked in all profiles
- Tests verify blocking behavior

---

## Phase 4: Low Priority Enhancements (Week 13+)

### 4.1 Documentation & Usability 🟢 LOW
**Priority**: P3 - User experience  
**Effort**: 3 days

**Tasks**:
- [ ] Make socket path configurable
  - File: `providers/dsmil/events.c`
  - Support: OpenSSL config file, `XDG_RUNTIME_DIR`
- [ ] Improve error messages
  - Add: Clear error messages for policy violations
  - Add: Guidance on fixing configuration issues
- [ ] Update migration guide
  - Document: TLS integration usage
  - Document: Policy configuration examples

---

## Testing Checklist

After each phase, verify:

- [ ] All unit tests pass
- [ ] Integration tests pass
- [ ] TLS interop tests pass (Phase 1)
- [ ] Timing variance tests pass (Phase 2)
- [ ] Static analysis passes
- [ ] Fuzzing finds no crashes
- [ ] Documentation updated

---

## Risk Assessment

| Phase | Risk | Mitigation |
|-------|------|------------|
| Phase 1 | TLS integration complexity | Start with basic hybrid KEX, iterate |
| Phase 2 | TPM2 library compatibility | Test on multiple platforms early |
| Phase 3 | Breaking existing code | Comprehensive testing before merge |

---

## Timeline Summary

| Phase | Duration | Dependencies |
|-------|----------|--------------|
| Phase 1 | 4 weeks | None |
| Phase 2 | 4 weeks | Phase 1 (TLS integration) |
| Phase 3 | 4 weeks | Phase 1, Phase 2 |
| Phase 4 | 2 weeks | Phase 1-3 |

**Total**: ~14 weeks (3.5 months)

---

## Success Metrics

**Security**:
- ✅ All critical vulnerabilities fixed
- ✅ Policy enforcement working
- ✅ Constant-time operations verified

**Functionality**:
- ✅ Hybrid KEM usable in TLS
- ✅ TPM integration working
- ✅ All profiles functional

**Quality**:
- ✅ Test coverage > 80%
- ✅ Static analysis clean
- ✅ No memory safety issues

---

**Last Updated**: 2025-01-XX  
**Next Review**: After Phase 1 completion
