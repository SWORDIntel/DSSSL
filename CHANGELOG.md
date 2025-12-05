# Changelog

All notable changes to DSSSL will be documented in this file.

## [1.1.1] - 2025-01-15

### Added

#### System Installer
- **`install-dsssl.sh`** - Comprehensive system installer
  - Automatic detection of system OpenSSL
  - Backup creation before installation
  - Build verification and automatic building
  - Library and binary installation
  - Installation verification
  - Rollback script generation
  - Comprehensive logging
  - Safety checks and confirmations

- **`INSTALLATION_GUIDE.md`** - Complete installation documentation
  - Step-by-step installation instructions
  - Configuration options
  - Verification procedures
  - Rollback procedures
  - Troubleshooting guide
  - System integration (alternatives, systemd)
  - Safety considerations

### Changed
- Updated README with installation instructions
- Updated documentation index with installation guide

## [1.1.0] - 2025-01-15

### Added

#### TLS 1.3 Hybrid KEM Integration
- Full TLS 1.3 handshake support for hybrid KEM groups
- Client-side hybrid key share generation (X25519+ML-KEM-768, P-256+ML-KEM-768)
- Server-side hybrid key share parsing and encapsulation
- HKDF-based secret combination for hybrid secrets
- Policy-based group negotiation
- Comprehensive test suite (`test/dsmil/test-hybrid-kem-tls.c`)
- Verification script (`test/dsmil/test-hybrid-kem-verify.sh`)

#### CVE Detection & Mitigation
- Real-time attack pattern detection for SSL/TLS vulnerabilities
- Support for 2024-2025 high-impact CVEs:
  - SSL/TLS injection attacks (CVE-2024-XXXXX)
  - Handshake DoS attacks (CVE-2024-XXXXX)
  - TLS 1.3 downgrade attacks (CVE-2025-XXXXX)
  - Key share replay attacks (CVE-2025-XXXXX)
  - Hybrid KEM manipulation (CVE-2025-XXXXX)
- Automatic mitigation with configurable thresholds
- Security event logging integration
- Test harness (`test/dsmil/test-cve-detection.c`)
- Documentation (`docs/CVE_DETECTION_AND_MITIGATION.md`)

#### Security Audit Improvements
- Fixed unsafe `strncpy` usage in event telemetry (null-termination)
- Fixed JSON injection vulnerability in event logging
- Added CSNA constant-time annotations to ML-KEM and ML-DSA operations
- Enhanced policy enforcement with input validation
- Improved error handling and logging
- Build system hardening (additional compiler warnings, CFI, stack clash protection)

### Changed
- Updated README with TLS Hybrid KEM and CVE detection features
- Updated documentation index with new guides
- Enhanced test coverage (350+ tests)
- Improved code documentation

### Security
- Memory safety improvements
- Constant-time operation verification
- Enhanced attack detection capabilities
- Improved security event logging

## [1.0.0] - 2025-11-25

### Initial Release
- Complete implementation of Phases 1-9
- Post-quantum cryptography (ML-KEM, ML-DSA)
- Hybrid cryptography support
- Three security profiles (WORLD_COMPAT, DSMIL_SECURE, ATOMAL)
- TPM 2.0 integration (88 algorithms)
- CSNA side-channel hardening
- Event telemetry system
- Comprehensive testing (342+ tests)
- Full documentation suite

---

**Classification**: UNCLASSIFIED // FOR OFFICIAL USE ONLY
