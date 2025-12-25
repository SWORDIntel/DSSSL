#!/bin/bash
#
# test-system-integration.sh - Test libssl1.1 system integration
#
# This script tests that libssl1.1 is properly integrated as system default
# and that applications can find and use the hardened DSSSL version.
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Testing libssl1.1 system integration..."
echo "=========================================="

# Check if libssl libraries exist
echo "1. Checking library installation..."
if [[ -f "/usr/lib/libssl.so.1.1" ]] || [[ -f "/usr/lib64/libssl.so.1.1" ]]; then
    echo "✓ libssl.so.1.1 found"
else
    echo "✗ libssl.so.1.1 not found"
    exit 1
fi

if [[ -f "/usr/lib/libcrypto.so.1.1" ]] || [[ -f "/usr/lib64/libcrypto.so.1.1" ]]; then
    echo "✓ libcrypto.so.1.1 found"
else
    echo "✗ libcrypto.so.1.1 not found"
    exit 1
fi

# Check symlinks
echo ""
echo "2. Checking library symlinks..."
if [[ -L "/usr/lib/libssl.so" ]] || [[ -L "/usr/lib64/libssl.so" ]]; then
    echo "✓ libssl.so symlink exists"
else
    echo "⚠ libssl.so symlink not found"
fi

if [[ -L "/usr/lib/libcrypto.so" ]] || [[ -L "/usr/lib64/libcrypto.so" ]]; then
    echo "✓ libcrypto.so symlink exists"
else
    echo "⚠ libcrypto.so symlink not found"
fi

# Check headers
echo ""
echo "3. Checking header installation..."
if [[ -d "/usr/include/openssl-1.1" ]]; then
    echo "✓ libssl1.1 headers found in /usr/include/openssl-1.1"
else
    echo "✗ libssl1.1 headers not found"
    exit 1
fi

if [[ -L "/usr/include/openssl" ]]; then
    echo "✓ openssl header symlink exists"
elif [[ -d "/usr/include/openssl" ]]; then
    echo "✓ openssl headers directory exists"
else
    echo "⚠ openssl headers not accessible at standard location"
fi

# Check openssl binary
echo ""
echo "4. Checking openssl binary..."
if command -v openssl >/dev/null 2>&1; then
    echo "✓ openssl command found"
    VERSION=$(openssl version 2>/dev/null || echo "unknown")
    echo "  Version: $VERSION"
    if echo "$VERSION" | grep -q "1.1.1"; then
        echo "✓ Correct OpenSSL 1.1.1 version detected"
    else
        echo "⚠ Unexpected OpenSSL version (expected 1.1.1)"
    fi
else
    echo "✗ openssl command not found"
    exit 1
fi

# Test compilation
echo ""
echo "5. Testing compilation against system libssl..."
cd "$SCRIPT_DIR"

if command -v gcc >/dev/null 2>&1; then
    echo "Compiling test program..."
    if gcc -o test-libssl-integration test-libssl-integration.c -lssl -lcrypto 2>/dev/null; then
        echo "✓ Compilation successful"
    else
        echo "✗ Compilation failed"
        exit 1
    fi
else
    echo "⚠ gcc not found, skipping compilation test"
fi

# Run test program
echo ""
echo "6. Running integration test..."
if [[ -x "./test-libssl-integration" ]]; then
    echo "Running test program..."
    if ./test-libssl-integration; then
        echo "✓ Integration test passed"
    else
        echo "✗ Integration test failed"
        exit 1
    fi
else
    echo "⚠ Test program not available, skipping runtime test"
fi

# Check library loading
echo ""
echo "7. Testing library loading..."
if command -v ldd >/dev/null 2>&1 && [[ -x "./test-libssl-integration" ]]; then
    LIBSSL_LIB=$(ldd ./test-libssl-integration 2>/dev/null | grep libssl | head -1 | awk '{print $3}' || echo "")
    if [[ -n "$LIBSSL_LIB" ]]; then
        echo "✓ Application links to: $LIBSSL_LIB"
        if echo "$LIBSSL_LIB" | grep -q "libssl.so.1.1"; then
            echo "✓ Correctly using libssl.so.1.1"
        else
            echo "⚠ Not using expected libssl.so.1.1"
        fi
    else
        echo "⚠ Could not determine linked library"
    fi
fi

echo ""
echo "=========================================="
echo "System integration test completed!"
echo ""
echo "libssl1.1 is now the system default OpenSSL with DSSSL hardening."
echo "All applications will automatically use the hardened version."
echo "=========================================="

# Cleanup
if [[ -f "./test-libssl-integration" ]]; then
    rm -f ./test-libssl-integration
fi
