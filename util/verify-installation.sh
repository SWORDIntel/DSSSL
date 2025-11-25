#!/bin/bash
#
# DSMIL OpenSSL Installation Verification
# Validates post-installation state
#
# Copyright 2025 DSMIL Security Team. All Rights Reserved.
#

set -u

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}DSMIL OpenSSL Installation Verification${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Configuration
INSTALL_PREFIX="${INSTALL_PREFIX:-/opt/dsssl-world}"
CONFIG_DIR="${CONFIG_DIR:-/etc/dsssl}"
RUNTIME_DIR="${RUNTIME_DIR:-/run/dsssl}"

# Test counters
PASSED=0
FAILED=0
WARNINGS=0

# Test helper
check_test() {
    local test_name="$1"
    local condition="$2"

    if eval "$condition"; then
        echo -e "${GREEN}✓${NC} $test_name"
        ((PASSED++))
        return 0
    else
        echo -e "${RED}✗${NC} $test_name"
        ((FAILED++))
        return 1
    fi
}

check_warning() {
    local test_name="$1"
    local condition="$2"

    if eval "$condition"; then
        echo -e "${GREEN}✓${NC} $test_name"
        ((PASSED++))
        return 0
    else
        echo -e "${YELLOW}⚠${NC} $test_name (optional)"
        ((WARNINGS++))
        return 1
    fi
}

echo -e "${BLUE}[1/6] Checking installation directories${NC}"
check_test "Install prefix exists" "[ -d '$INSTALL_PREFIX' ]"
check_test "Binary directory exists" "[ -d '$INSTALL_PREFIX/bin' ]"
check_test "Library directory exists" "[ -d '$INSTALL_PREFIX/lib64' ]"
check_test "Configuration directory exists" "[ -d '$CONFIG_DIR' ]"
check_test "Runtime directory exists" "[ -d '$RUNTIME_DIR' ]"
echo ""

echo -e "${BLUE}[2/6] Checking binaries and libraries${NC}"
check_test "OpenSSL binary exists" "[ -x '$INSTALL_PREFIX/bin/openssl' ]"
check_test "OpenSSL binary is executable" "[ -x '$INSTALL_PREFIX/bin/openssl' ]"
check_test "libssl.so exists" "[ -f '$INSTALL_PREFIX/lib64/libssl.so' ] || [ -f '$INSTALL_PREFIX/lib64/libssl.so.3' ]"
check_test "libcrypto.so exists" "[ -f '$INSTALL_PREFIX/lib64/libcrypto.so' ] || [ -f '$INSTALL_PREFIX/lib64/libcrypto.so.3' ]"
echo ""

echo -e "${BLUE}[3/6] Checking configuration files${NC}"
check_test "WORLD_COMPAT config exists" "[ -f '$CONFIG_DIR/world.cnf' ]"
check_test "DSMIL_SECURE config exists" "[ -f '$CONFIG_DIR/dsmil-secure.cnf' ]"
check_test "ATOMAL config exists" "[ -f '$CONFIG_DIR/atomal.cnf' ]"
echo ""

echo -e "${BLUE}[4/6] Checking OpenSSL functionality${NC}"
if [ -x "$INSTALL_PREFIX/bin/openssl" ]; then
    VERSION=$("$INSTALL_PREFIX/bin/openssl" version 2>/dev/null)
    check_test "OpenSSL version command works" "[ -n '$VERSION' ]"
    echo "  Version: $VERSION"

    # Check for DSMIL provider
    PROVIDERS=$("$INSTALL_PREFIX/bin/openssl" list -providers 2>/dev/null)
    check_test "DSMIL provider available" "echo '$PROVIDERS' | grep -q 'dsmil'"

    # Check for PQC algorithms
    CIPHERS=$("$INSTALL_PREFIX/bin/openssl" list -cipher-algorithms 2>/dev/null)
    check_warning "ML-KEM available" "echo '$CIPHERS' | grep -iq 'kyber\\|ml-kem'"
    check_warning "ML-DSA available" "echo '$CIPHERS' | grep -iq 'dilithium\\|ml-dsa'"
else
    echo -e "${RED}✗ Cannot test OpenSSL functionality (binary not found)${NC}"
    ((FAILED+=4))
fi
echo ""

echo -e "${BLUE}[5/6] Checking library dependencies${NC}"
if command -v ldd >/dev/null 2>&1 && [ -f "$INSTALL_PREFIX/lib64/libssl.so.3" ]; then
    MISSING_DEPS=$(ldd "$INSTALL_PREFIX/lib64/libssl.so.3" 2>/dev/null | grep "not found" || true)
    check_test "All library dependencies satisfied" "[ -z '$MISSING_DEPS' ]"
    if [ -n "$MISSING_DEPS" ]; then
        echo "  Missing: $MISSING_DEPS"
    fi
else
    echo -e "${YELLOW}⊘ Skipping dependency check (ldd not available)${NC}"
fi
echo ""

echo -e "${BLUE}[6/6] Checking environment${NC}"
check_warning "OPENSSL_CONF is set" "[ -n '${OPENSSL_CONF:-}' ]"
check_warning "DSMIL_PROFILE is set" "[ -n '${DSMIL_PROFILE:-}' ]"
check_warning "LD_LIBRARY_PATH includes DSSSL" "echo '${LD_LIBRARY_PATH:-}' | grep -q '$INSTALL_PREFIX/lib64'"

# Check library cache
if command -v ldconfig >/dev/null 2>&1; then
    check_warning "Library cache includes DSSSL" "ldconfig -p | grep -q '$INSTALL_PREFIX/lib64'"
fi
echo ""

# Summary
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Verification Summary${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
TOTAL=$((PASSED + FAILED))
echo "Tests run:     $TOTAL"
echo -e "${GREEN}Passed:${NC}        $PASSED"
echo -e "${RED}Failed:${NC}        $FAILED"
echo -e "${YELLOW}Warnings:${NC}      $WARNINGS"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✓✓✓ Installation verification passed! ✓✓✓${NC}"
    echo ""
    echo "DSSSL is correctly installed and operational."
    echo ""
    echo "Next steps:"
    echo "  1. Configure security profile:"
    echo "     export OPENSSL_CONF=$CONFIG_DIR/world.cnf"
    echo "     export DSMIL_PROFILE=WORLD_COMPAT"
    echo ""
    echo "  2. Add to system library path:"
    echo "     export LD_LIBRARY_PATH=$INSTALL_PREFIX/lib64:\$LD_LIBRARY_PATH"
    echo ""
    echo "  3. Test functionality:"
    echo "     $INSTALL_PREFIX/bin/openssl version -a"
    echo "     $INSTALL_PREFIX/bin/openssl list -providers"
    echo ""
    echo "  4. See deployment guide:"
    echo "     $INSTALL_PREFIX/share/doc/dsssl-world/DEPLOYMENT_GUIDE.md"
    echo ""
    exit 0
else
    echo -e "${RED}✗✗✗ Installation verification failed ✗✗✗${NC}"
    echo ""
    echo "Please review the failures above and ensure:"
    echo "  1. Package was installed correctly"
    echo "  2. All dependencies are satisfied"
    echo "  3. File permissions are correct"
    echo "  4. Library paths are configured"
    echo ""
    echo "See docs/DEPLOYMENT_GUIDE.md for troubleshooting."
    echo ""
    exit 1
fi
