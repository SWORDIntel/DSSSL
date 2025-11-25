# DSMIL OpenSSL Deployment Guide
**Phase 9: Production Deployment**

Classification: UNCLASSIFIED // FOR OFFICIAL USE ONLY
Version: 1.0.0
Date: 2025-11-25

---

## Table of Contents

1. [Overview](#overview)
2. [Pre-Deployment Checklist](#pre-deployment-checklist)
3. [Package Installation](#package-installation)
4. [Profile Configuration](#profile-configuration)
5. [System Integration](#system-integration)
6. [Monitoring & Telemetry](#monitoring--telemetry)
7. [Update Procedures](#update-procedures)
8. [Rollback Procedures](#rollback-procedures)
9. [Security Hardening](#security-hardening)
10. [Troubleshooting](#troubleshooting)

---

## Overview

This guide covers deploying DSMIL-grade OpenSSL to production environments across all three security profiles.

### Deployment Scenarios

| Scenario | Profile | TPM Required | Monitoring |
|----------|---------|--------------|------------|
| **Public Web Services** | WORLD_COMPAT | No | Optional |
| **Internal Services** | DSMIL_SECURE | Recommended | Required |
| **Classified Systems** | ATOMAL | **Mandatory** | **Mandatory** |

### System Requirements

**Minimum:**
- Linux kernel 4.4+
- x86_64 architecture
- 2 GB RAM
- 500 MB disk space

**Recommended:**
- Linux kernel 5.15+
- Intel Meteor Lake CPU (for NPU/GNA)
- TPM 2.0
- 4 GB RAM
- 1 GB disk space

---

## Pre-Deployment Checklist

### Planning Phase

- [ ] **Determine Security Profile**
  - Public internet → WORLD_COMPAT
  - Internal/allied → DSMIL_SECURE
  - Classified → ATOMAL

- [ ] **Verify Hardware**
  - [ ] CPU supports AES-NI, AVX2
  - [ ] TPM 2.0 available (if required)
  - [ ] Intel NPU/GNA (optional, for performance)

- [ ] **Network Planning**
  - [ ] Event telemetry endpoint configured
  - [ ] Firewall rules for telemetry socket
  - [ ] Certificate infrastructure ready

- [ ] **Backup Existing Installation**
  - [ ] Backup current OpenSSL installation
  - [ ] Backup application configurations
  - [ ] Test rollback procedure

### Testing Phase

- [ ] **Run Test Suite**
  ```bash
  cd test/dsmil
  ./test-comprehensive.sh --all
  ```

- [ ] **Security Validation**
  ```bash
  ./test-security-validation.sh
  ```
  - Target: 90%+ security score

- [ ] **Performance Baseline**
  ```bash
  ./test-performance-benchmarks.sh > baseline.txt
  ```

---

## Package Installation

### Method 1: Debian Package (.deb)

```bash
# Download package
wget https://internal-repo/dsssl/dsssl-1.0.0-world.deb

# Verify signature
gpg --verify dsssl-1.0.0-world.deb.sig dsssl-1.0.0-world.deb

# Install
sudo dpkg -i dsssl-1.0.0-world.deb

# Install dependencies
sudo apt-get install -f

# Verify installation
/opt/dsssl-world/bin/openssl version
```

**Available Packages:**
- `dsssl-1.0.0-world.deb` - WORLD_COMPAT profile (portable)
- `dsssl-1.0.0-dsmil.deb` - DSMIL_SECURE/ATOMAL (Meteor Lake optimized)

### Method 2: Build from Source

```bash
# Clone repository
git clone https://github.com/SWORDIntel/DSSSL.git
cd DSSSL

# Build portable version
./util/build-dsllvm-world.sh --clean

# Install
sudo make install

# Set up environment
export PATH=/opt/dsssl-world/bin:$PATH
export LD_LIBRARY_PATH=/opt/dsssl-world/lib64:$LD_LIBRARY_PATH
```

### Method 3: Container Deployment

```bash
# Pull DSMIL OpenSSL container
docker pull dsssl/dsssl-world:1.0.0

# Run container
docker run -d --name dsssl-world \
  -v /etc/dsssl:/etc/dsssl:ro \
  -v /run:/run \
  dsssl/dsssl-world:1.0.0
```

### Installation Paths

```
/opt/dsssl-world/          # WORLD_COMPAT installation
├── bin/
│   └── openssl           # OpenSSL CLI
├── lib64/
│   ├── libssl.so.3       # TLS library
│   ├── libcrypto.so.3    # Crypto library
│   └── ossl-modules/
│       └── dsmil.so      # DSMIL policy provider
└── etc/
    ├── world.cnf         # WORLD_COMPAT config
    ├── dsmil-secure.cnf  # DSMIL_SECURE config
    └── atomal.cnf        # ATOMAL config
```

---

## Profile Configuration

### WORLD_COMPAT Profile

**Use Case**: Public-facing web services

**Configuration** (`/etc/dsssl/world.cnf`):
```ini
[openssl_init]
providers = provider_sect
alg_section = algorithm_sect

[provider_sect]
default = default_sect
base = base_sect
dsmil-policy = dsmil_policy_sect

[dsmil_policy_sect]
profile = WORLD_COMPAT
require_hybrid_kex = false
min_security_bits = 128
event_socket = /run/crypto-events.sock

[algorithm_sect]
default_properties = provider!=dsmil-policy

MinProtocol = TLSv1.3
Ciphersuites = TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
Groups = X25519:P-256
SignatureAlgorithms = ECDSA+SHA256:ed25519
```

**Enable**:
```bash
export OPENSSL_CONF=/etc/dsssl/world.cnf
```

### DSMIL_SECURE Profile

**Use Case**: Internal DoD networks, allied forces

**Configuration** (`/etc/dsssl/dsmil-secure.cnf`):
```ini
[dsmil_policy_sect]
profile = DSMIL_SECURE
require_hybrid_kex = true
allow_classical_fallback = true
min_security_bits = 192
event_socket = /run/crypto-events.sock

Ciphersuites = TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
Groups = X25519+MLKEM768:P-256+MLKEM768:X25519:P-256
SignatureAlgorithms = ECDSA+SHA256+MLDSA65:ECDSA+SHA256:ed25519+MLDSA65
```

**Enable**:
```bash
export OPENSSL_CONF=/etc/dsssl/dsmil-secure.cnf
export THREATCON_LEVEL=NORMAL
```

### ATOMAL Profile

**Use Case**: ATOMAL-classified operations

**Configuration** (`/etc/dsssl/atomal.cnf`):
```ini
[dsmil_policy_sect]
profile = ATOMAL
require_hybrid_kex = true
allow_classical_fallback = false
block_classical_only = true
min_security_bits = 256
event_socket = /run/crypto-events.sock
require_tpm = true

Ciphersuites = TLS_AES_256_GCM_SHA384
Groups = X25519+MLKEM1024:MLKEM1024
SignatureAlgorithms = ECDSA+SHA256+MLDSA87:MLDSA87
```

**Enable**:
```bash
export OPENSSL_CONF=/etc/dsssl/atomal.cnf
export THREATCON_LEVEL=HIGH
export TPM_REQUIRED=1
```

**Pre-requisites**:
- TPM 2.0 hardware present and initialized
- TPM ownership established
- `/dev/tpm0` accessible

---

## System Integration

### Systemd Service (Example: nginx)

Create `/etc/systemd/system/nginx-dsssl.service.d/override.conf`:

```ini
[Service]
# Set DSMIL environment
Environment="OPENSSL_CONF=/etc/dsssl/dsmil-secure.cnf"
Environment="DSMIL_PROFILE=DSMIL_SECURE"
Environment="THREATCON_LEVEL=NORMAL"
Environment="LD_LIBRARY_PATH=/opt/dsssl-world/lib64"

# Start event telemetry collector first
Requires=dsssl-telemetry.service
After=dsssl-telemetry.service
```

Reload and restart:
```bash
sudo systemctl daemon-reload
sudo systemctl restart nginx
```

### Event Telemetry Collector

Create `/etc/systemd/system/dsssl-telemetry.service`:

```ini
[Unit]
Description=DSMIL OpenSSL Event Telemetry Collector
Documentation=https://internal/dsssl/docs
After=network.target

[Service]
Type=simple
ExecStart=/opt/dsssl/bin/dsssl-telemetry-collector
Restart=always
RestartSec=5

# Security hardening
PrivateTmp=yes
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes

[Install]
WantedBy=multi-user.target
```

### Application Integration

**C Application**:
```c
#include <openssl/ssl.h>

int main() {
    /* Set configuration */
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CONFIG, NULL);

    /* Use OpenSSL normally */
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());

    /* DSMIL policy automatically enforced */
    /* ... */
}
```

**Python Application**:
```python
import os
import ssl

# Set profile
os.environ['OPENSSL_CONF'] = '/etc/dsssl/dsmil-secure.cnf'

# Use SSL normally
context = ssl.create_default_context()
# DSMIL policy automatically enforced
```

**Node.js Application**:
```javascript
process.env.OPENSSL_CONF = '/etc/dsssl/dsmil-secure.cnf';
const https = require('https');

// DSMIL policy automatically enforced
https.get('https://internal.example.com', (res) => {
    console.log(`Protocol: ${res.socket.getProtocol()}`);
    console.log(`Cipher: ${res.socket.getCipher().name}`);
});
```

---

## Monitoring & Telemetry

### Event Collection

**Event Socket**: `/run/crypto-events.sock`

**Event Format** (JSON):
```json
{
  "version": "1.0",
  "timestamp": "2025-11-25T12:34:56Z",
  "event_type": "handshake_complete",
  "profile": "DSMIL_SECURE",
  "protocol": "TLSv1.3",
  "kex_type": "X25519+ML-KEM-768",
  "cipher_suite": "TLS_AES_256_GCM_SHA384",
  "signature_type": "ECDSA+ML-DSA-65",
  "peer_info": "client.example.com"
}
```

### Monitoring Setup

**1. Start Event Collector**:
```bash
sudo systemctl start dsssl-telemetry.service
sudo systemctl enable dsssl-telemetry.service
```

**2. Configure Log Forwarding**:

Edit `/etc/dsssl/telemetry.conf`:
```ini
[collector]
socket_path = /run/crypto-events.sock
log_path = /var/log/dsssl/events.log
forward_to = deframework.internal:514
format = json

[alerting]
policy_violations = critical
downgrade_attempts = critical
handshake_failures = warning
```

**3. Monitor Events**:
```bash
# Tail live events
tail -f /var/log/dsssl/events.log

# Query specific events
jq '.event_type == "policy_violation"' /var/log/dsssl/events.log

# Count by type
jq -r '.event_type' /var/log/dsssl/events.log | sort | uniq -c
```

### Key Metrics to Monitor

- **Policy Violations**: Should be 0 in production
- **Downgrade Attempts**: Investigate any occurrence
- **Handshake Failures**: Normal rate < 1%
- **Algorithm Usage**: Verify hybrid crypto adoption
- **TPM Operations**: Success rate > 99%

### Alerting Rules

**Critical Alerts**:
- Policy violation detected
- Downgrade attack attempted
- TPM hardware failure
- Classical-only crypto in ATOMAL profile

**Warning Alerts**:
- Handshake failure rate > 5%
- TPM operation latency > 100ms
- Event telemetry queue backup

---

## Update Procedures

### Rolling Update (Zero Downtime)

**For load-balanced services**:

```bash
#!/bin/bash
# rolling-update.sh

NODES=("node1" "node2" "node3")
PACKAGE="dsssl-1.1.0-world.deb"

for node in "${NODES[@]}"; do
    echo "Updating $node..."

    # Remove from load balancer
    ssh $node "sudo systemctl stop haproxy"

    # Update DSSSL
    scp $PACKAGE $node:/tmp/
    ssh $node "sudo dpkg -i /tmp/$PACKAGE"

    # Restart services
    ssh $node "sudo systemctl restart nginx"

    # Verify
    ssh $node "/opt/dsssl-world/bin/openssl version"

    # Add back to load balancer
    ssh $node "sudo systemctl start haproxy"

    # Wait for health check
    sleep 30

    echo "$node updated successfully"
done
```

### In-Place Update

```bash
# Backup current installation
sudo cp -r /opt/dsssl-world /opt/dsssl-world.backup

# Stop services
sudo systemctl stop nginx

# Install new version
sudo dpkg -i dsssl-1.1.0-world.deb

# Run tests
cd /opt/dsssl-world
./test/dsmil/run-all-tests.sh

# Start services
sudo systemctl start nginx

# Verify
openssl version
curl -I https://localhost/
```

### Canary Deployment

1. **Deploy to 10% of fleet**
2. **Monitor for 24 hours**:
   - Error rates
   - Performance metrics
   - Security events
3. **Expand to 50%** if stable
4. **Full deployment** after 48 hours

---

## Rollback Procedures

### Quick Rollback

```bash
# Stop services
sudo systemctl stop nginx

# Restore backup
sudo rm -rf /opt/dsssl-world
sudo mv /opt/dsssl-world.backup /opt/dsssl-world

# Restart services
sudo systemctl start nginx

# Verify
openssl version
```

### Package Rollback

```bash
# List installed versions
dpkg -l | grep dsssl

# Reinstall previous version
sudo dpkg -i dsssl-1.0.0-world.deb

# Restart services
sudo systemctl restart nginx
```

### Database/State Rollback

DSMIL OpenSSL is stateless, no database rollback needed.

**Configuration rollback**:
```bash
# Restore configuration
sudo cp /etc/dsssl/world.cnf.backup /etc/dsssl/world.cnf

# Restart services
sudo systemctl restart nginx
```

---

## Security Hardening

### File Permissions

```bash
# Restrict configuration files
sudo chmod 640 /etc/dsssl/*.cnf
sudo chown root:ssl-cert /etc/dsssl/*.cnf

# Protect libraries
sudo chmod 755 /opt/dsssl-world/lib64/*.so*

# Secure private keys
sudo chmod 600 /etc/ssl/private/*.key
sudo chown root:ssl-cert /etc/ssl/private/*.key
```

### SELinux/AppArmor

**SELinux Policy** (`/etc/selinux/local/dsssl.te`):
```
module dsssl 1.0;

require {
    type httpd_t;
    type devtpmrm_t;
    class chr_file { read write };
}

# Allow nginx to access TPM
allow httpd_t devtpmrm_t:chr_file { read write };
```

Compile and load:
```bash
sudo checkmodule -M -m -o dsssl.mod dsssl.te
sudo semodule_package -o dsssl.pp -m dsssl.mod
sudo semodule -i dsssl.pp
```

### Network Security

**Firewall Rules**:
```bash
# Allow TLS traffic
sudo ufw allow 443/tcp

# Block telemetry socket from external
sudo iptables -A INPUT -i eth0 -p tcp --dport 514 -j DROP

# Allow internal telemetry
sudo iptables -A INPUT -s 10.0.0.0/8 -p tcp --dport 514 -j ACCEPT
```

### Audit Logging

Enable audit logging for DSSSL:
```bash
# Add audit rules
sudo auditctl -w /opt/dsssl-world/lib64/ -p wa -k dsssl
sudo auditctl -w /etc/dsssl/ -p wa -k dsssl-config
sudo auditctl -w /dev/tpm0 -p rwa -k dsssl-tpm
```

---

## Troubleshooting

### Common Issues

#### Issue: TPM not available

**Symptom**:
```
DSMIL TPM: Hardware not available, using software fallback
```

**Solution**:
```bash
# Check TPM device
ls -l /dev/tpm*

# Verify TPM ownership
tpm2_getcap handles-persistent

# Check permissions
sudo usermod -aG tss nginx

# Verify TPM2 tools
tpm2_getrandom 8 --hex
```

#### Issue: Event telemetry not working

**Symptom**: No events in `/var/log/dsssl/events.log`

**Solution**:
```bash
# Check socket exists
ls -l /run/crypto-events.sock

# Verify collector running
sudo systemctl status dsssl-telemetry

# Test socket
echo '{"test": "message"}' | nc -U /run/crypto-events.sock

# Check permissions
sudo chmod 666 /run/crypto-events.sock
```

#### Issue: Handshake failures

**Symptom**: TLS handshake errors in logs

**Diagnosis**:
```bash
# Enable debug logging
export SSLKEYLOGFILE=/tmp/ssl-keys.log
openssl s_client -connect host:443 -debug

# Check profile mismatch
openssl s_client -connect host:443 -showcerts | grep -i "cipher\|protocol"

# Verify algorithms
openssl ciphers -v 'TLS_AES_256_GCM_SHA384'
```

**Common causes**:
- Client doesn't support TLS 1.3
- PQC algorithms not available on client
- Profile mismatch (ATOMAL server, WORLD client)

#### Issue: Performance degradation

**Symptom**: Slow TLS handshakes

**Diagnosis**:
```bash
# Benchmark
./test/dsmil/test-performance-benchmarks.sh

# Check hardware acceleration
grep -i aes /proc/cpuinfo
lsmod | grep tpm

# Monitor TPM latency
tpm2_getrandom --benchmark 1000
```

**Solutions**:
- Enable hardware acceleration in BIOS
- Use NPU-enabled build for Meteor Lake
- Consider WORLD_COMPAT for performance-critical

---

## Production Checklist

### Pre-Deployment

- [ ] Hardware verified (TPM, CPU features)
- [ ] Test suite passed (342+ tests)
- [ ] Security score ≥ 90%
- [ ] Performance baseline established
- [ ] Backup procedures tested
- [ ] Rollback procedures tested

### Deployment

- [ ] Package installed successfully
- [ ] Configuration verified
- [ ] Services restarted
- [ ] Health checks passing
- [ ] Event telemetry flowing
- [ ] Logs monitoring configured

### Post-Deployment

- [ ] Monitor for 24 hours
- [ ] Verify no policy violations
- [ ] Check performance metrics
- [ ] Review security events
- [ ] Update documentation
- [ ] Notify stakeholders

---

## References

1. **[OPENSSL_SECURE_SPEC.md](../OPENSSL_SECURE_SPEC.md)** - Complete specification
2. **[PHASE8_COMPREHENSIVE_TESTING.md](PHASE8_COMPREHENSIVE_TESTING.md)** - Testing procedures
3. **[TPM_INTEGRATION.md](TPM_INTEGRATION.md)** - TPM troubleshooting
4. **[CSNA_SIDE_CHANNEL_HARDENING.md](CSNA_SIDE_CHANNEL_HARDENING.md)** - Security details

---

**Classification**: UNCLASSIFIED // FOR OFFICIAL USE ONLY
**Version**: 1.0.0
**Last Updated**: 2025-11-25
