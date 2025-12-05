# Offensive Operations Capabilities

## ⚠️ WARNING

**This module contains capabilities for authorized security testing, red team exercises, and defensive research ONLY.**

Unauthorized use of these capabilities is:
- **Strictly prohibited**
- **May violate laws and regulations**
- **Subject to disciplinary action**
- **May result in criminal prosecution**

**Use only with explicit authorization and proper oversight.**

---

## Overview

The offensive operations module provides capabilities for:
- **Security Testing**: Testing defensive mechanisms and mitigations
- **Red Team Exercises**: Simulating attacks in controlled environments
- **Defensive Research**: Understanding attack vectors and developing defenses
- **Vulnerability Assessment**: Testing system resilience

## Authorization Required

All offensive operations require:
1. **Valid authorization token**
2. **Environment variable enablement** (`SSL_ENABLE_OFFENSIVE_OPS=1`)
3. **Explicit API enablement** per SSL connection
4. **Operation limits** and timeouts

## Capabilities

### Protocol Manipulation

#### Version Downgrade
```c
#include "ssl/offensive_ops.h"

SSL_OFFENSIVE_OPS_CTX *ctx = SSL_OFFENSIVE_ops_ctx_new(auth_token);
SSL_OFFENSIVE_ops_enable(ssl, ctx);

// Force TLS version downgrade (tests downgrade protection)
SSL_OFFENSIVE_force_version_downgrade(ssl, TLS1_2_VERSION);
```

#### Cipher Suite Manipulation
```c
// Manipulate cipher suite negotiation
uint16_t weak_suites[] = {0x0035, 0x002F};  // RC4, 3DES
SSL_OFFENSIVE_manipulate_cipher_suites(ssl, weak_suites, 2);
```

#### Extension Injection
```c
// Inject custom extension into handshake
unsigned char ext_data[] = {0x00, 0x01, 0x02, 0x03};
SSL_OFFENSIVE_inject_extension(ssl, 0xFF00, ext_data, sizeof(ext_data));
```

### Key Exchange Attacks

#### Key Share Replay
```c
// Replay key share (tests replay protection)
unsigned char key_share[2048];
size_t key_share_len = /* ... */;
SSL_OFFENSIVE_replay_key_share(ssl, key_share, key_share_len);
```

#### Hybrid KEM Bypass
```c
// Attempt to bypass hybrid KEM requirement (tests policy enforcement)
SSL_OFFENSIVE_bypass_hybrid_kem(ssl);
```

### Certificate Attacks

#### Certificate Chain Manipulation
```c
// Manipulate certificate chain (tests chain validation)
STACK_OF(X509) *modified_chain = /* ... */;
SSL_OFFENSIVE_manipulate_cert_chain(ssl, modified_chain);
```

### Timing Attacks

#### Timing Analysis
```c
// Enable timing analysis mode
SSL_OFFENSIVE_enable_timing_analysis(ssl, 1);

// Measure operation timing
uint64_t timing_ns;
SSL_OFFENSIVE_measure_timing(ssl, "decapsulation", &timing_ns);
```

### Resource Exhaustion

#### Handshake DoS
```c
// Trigger handshake DoS (tests DoS protection)
SSL_OFFENSIVE_trigger_handshake_dos(ssl, 1000);
```

#### Memory Exhaustion
```c
// Exhaust memory resources (tests memory limits)
SSL_OFFENSIVE_exhaust_memory(ssl, 1024 * 1024 * 100);  // 100 MB
```

### Custom Payload Injection

#### Application Data Injection
```c
// Inject custom payload
unsigned char payload[] = "ATTACK_PAYLOAD";
SSL_OFFENSIVE_inject_payload(ssl, payload, sizeof(payload) - 1);
```

## Usage Example

### Basic Setup

```c
#include "ssl/offensive_ops.h"

// 1. Set environment variable
setenv("SSL_ENABLE_OFFENSIVE_OPS", "1", 1);
setenv("SSL_OFFENSIVE_OPS_TOKEN", "your_auth_token", 1);

// 2. Create context with authorization token
SSL_OFFENSIVE_OPS_CTX *ctx = SSL_OFFENSIVE_ops_ctx_new("your_auth_token");
if (ctx == NULL) {
    fprintf(stderr, "Authorization failed\n");
    return 1;
}

// 3. Set operation limits
SSL_OFFENSIVE_set_limits(ctx, 100, 5000);  // Max 100 ops, 5s timeout

// 4. Enable on SSL connection
SSL_CTX *ssl_ctx = SSL_CTX_new_ex(NULL, NULL, TLS_client_method());
SSL *ssl = SSL_new(ssl_ctx);

if (!SSL_OFFENSIVE_ops_enable(ssl, ctx)) {
    fprintf(stderr, "Failed to enable offensive operations\n");
    return 1;
}

// 5. Perform authorized testing operations
SSL_OFFENSIVE_force_version_downgrade(ssl, TLS1_2_VERSION);

// 6. Cleanup
SSL_free(ssl);
SSL_CTX_free(ssl_ctx);
SSL_OFFENSIVE_ops_ctx_free(ctx);
```

## Authorization Token

### Token Generation

The authorization token must be:
- **Cryptographically secure** (minimum 32 bytes)
- **Stored securely** (not in code or version control)
- **Rotated regularly**
- **Access-controlled** (limited to authorized personnel)

### Token Verification

Tokens are verified using SHA-256 hash comparison. The authorized token hash must be:
- **Set at compile time** (in `offensive_ops.c`)
- **Not exposed** in binaries or documentation
- **Changed** if compromised

### Setting Authorization Token

```bash
# Set token hash in source code (offensive_ops.c)
# Compute hash of authorized token:
echo -n "your_secret_token" | sha256sum

# Update authorized_token_hash[] in offensive_ops.c
```

## Safety Features

### Operation Limits
- **Maximum operations**: Default 100, configurable
- **Timeout**: Default 5 seconds, configurable
- **Automatic disablement**: After limits exceeded

### Logging
- **All operations logged** via event telemetry
- **Operation details** recorded
- **Authorization checks** logged
- **Audit trail** maintained

### Authorization Checks
- **Token verification** required
- **Environment variable** check
- **Per-connection** authorization
- **Operation counting** and limits

## Testing Scenarios

### Scenario 1: Downgrade Protection Testing
```c
// Test that system prevents TLS version downgrade
SSL_OFFENSIVE_force_version_downgrade(ssl, TLS1_1_VERSION);
// System should reject or alert
```

### Scenario 2: Replay Protection Testing
```c
// Test that system detects key share replay
unsigned char captured_key_share[2048];
// ... capture from previous handshake ...
SSL_OFFENSIVE_replay_key_share(ssl, captured_key_share, len);
// System should detect and reject
```

### Scenario 3: Policy Enforcement Testing
```c
// Test that hybrid KEM requirement is enforced
setenv("DSMIL_PROFILE", "DSMIL_SECURE", 1);
SSL_OFFENSIVE_bypass_hybrid_kem(ssl);
// System should reject classical-only connection
```

### Scenario 4: DoS Protection Testing
```c
// Test DoS protection mechanisms
SSL_OFFENSIVE_trigger_handshake_dos(ssl, 10000);
// System should rate-limit or block
```

## Security Considerations

### Authorization
- **Never** enable in production without explicit authorization
- **Always** verify authorization token
- **Rotate** tokens regularly
- **Limit** access to authorized personnel only

### Logging
- **All operations** are logged for audit
- **Logs** should be monitored
- **Alerts** should be configured
- **Retention** per security policy

### Isolation
- **Use** in isolated test environments
- **Never** enable on production systems
- **Separate** test and production builds
- **Control** access to test systems

### Legal Compliance
- **Obtain** proper authorization
- **Document** all testing activities
- **Comply** with applicable laws
- **Report** findings through proper channels

## Configuration

### Environment Variables

```bash
# Enable offensive operations
export SSL_ENABLE_OFFENSIVE_OPS=1

# Set authorization token
export SSL_OFFENSIVE_OPS_TOKEN=your_auth_token

# Run test
./your_test_program
```

### Build Configuration

To include offensive operations in build:

```bash
# Build with offensive ops support
./Configure dsllvm-world --enable-offensive-ops
make
```

**Note**: Offensive operations are **disabled by default** and require explicit enablement.

## API Reference

See `ssl/offensive_ops.h` for complete API documentation.

### Key Functions

- `SSL_OFFENSIVE_ops_ctx_new()` - Create context
- `SSL_OFFENSIVE_ops_enable()` - Enable on connection
- `SSL_OFFENSIVE_force_version_downgrade()` - Version downgrade
- `SSL_OFFENSIVE_replay_key_share()` - Key share replay
- `SSL_OFFENSIVE_bypass_hybrid_kem()` - Hybrid KEM bypass
- `SSL_OFFENSIVE_inject_payload()` - Payload injection
- `SSL_OFFENSIVE_set_limits()` - Set operation limits
- `SSL_OFFENSIVE_get_stats()` - Get operation statistics

## Testing

### Run Tests

```bash
cd test/dsmil
make test-offensive-ops
./test-offensive-ops
```

### Test Authorization

```bash
# Without authorization (should fail)
./test-offensive-ops

# With authorization
export SSL_ENABLE_OFFENSIVE_OPS=1
export SSL_OFFENSIVE_OPS_TOKEN=authorized_token
./test-offensive-ops
```

## Reporting Issues

**DO NOT** report offensive operations issues publicly.

**Contact**: Security team via secure channels only.

---

## Legal Notice

Use of offensive operations capabilities:
- **Requires** explicit authorization
- **Must comply** with applicable laws
- **Subject to** organizational policies
- **May be** subject to legal restrictions

**Unauthorized use is prohibited and may result in:**
- Disciplinary action
- Legal prosecution
- Civil liability
- Criminal charges

---

**Classification**: UNCLASSIFIED // FOR OFFICIAL USE ONLY  
**Usage**: Authorized security testing and research only  
**Distribution**: Authorized personnel only
