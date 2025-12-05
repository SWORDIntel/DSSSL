#!/bin/bash
#
# Verification script for Hybrid KEM TLS Integration
# This script checks that the implementation is in place
#

set -e

echo "=== Hybrid KEM TLS Integration Verification ==="
echo ""

# Check if key files exist
echo "1. Checking key implementation files..."
FILES=(
    "ssl/tls13_hybrid_kem.h"
    "ssl/tls13_hybrid_kem.c"
    "ssl/statem/extensions_clnt.c"
    "ssl/statem/extensions_srvr.c"
)

for file in "${FILES[@]}"; do
    if [ -f "$file" ]; then
        echo "   ✓ $file exists"
    else
        echo "   ✗ $file MISSING"
        exit 1
    fi
done

echo ""

# Check for hybrid group definitions
echo "2. Checking hybrid group definitions..."
if grep -q "OSSL_TLS_GROUP_ID_X25519MLKEM768" include/internal/tlsgroups.h 2>/dev/null; then
    echo "   ✓ Hybrid group IDs defined"
else
    echo "   ✗ Hybrid group IDs NOT FOUND"
    exit 1
fi

echo ""

# Check for hybrid KEM functions in client code
echo "3. Checking client-side implementation..."
if grep -q "is_hybrid_kem_group" ssl/statem/extensions_clnt.c; then
    echo "   ✓ Hybrid group detection in client"
else
    echo "   ✗ Hybrid group detection MISSING in client"
    exit 1
fi

if grep -q "add_hybrid_key_share" ssl/statem/extensions_clnt.c; then
    echo "   ✓ Hybrid key share generation in client"
else
    echo "   ✗ Hybrid key share generation MISSING in client"
    exit 1
fi

if grep -q "tls13_hybrid_kem_combine_secrets" ssl/statem/extensions_clnt.c; then
    echo "   ✓ Hybrid secret combination in client"
else
    echo "   ✗ Hybrid secret combination MISSING in client"
    exit 1
fi

echo ""

# Check for hybrid KEM functions in server code
echo "4. Checking server-side implementation..."
if grep -q "is_hybrid_kem_group" ssl/statem/extensions_srvr.c; then
    echo "   ✓ Hybrid group detection in server"
else
    echo "   ✗ Hybrid group detection MISSING in server"
    exit 1
fi

if grep -q "tls13_hybrid_kem_combine_secrets" ssl/statem/extensions_srvr.c; then
    echo "   ✓ Hybrid secret combination in server"
else
    echo "   ✗ Hybrid secret combination MISSING in server"
    exit 1
fi

if grep -q "ssl_encapsulate.*pqc" ssl/statem/extensions_srvr.c || grep -q "pqc_ct" ssl/statem/extensions_srvr.c; then
    echo "   ✓ Hybrid encapsulation in server"
else
    echo "   ✗ Hybrid encapsulation MISSING in server"
    exit 1
fi

echo ""

# Check for HKDF implementation
echo "5. Checking HKDF secret combination..."
if grep -q "EVP_KDF.*HKDF" ssl/tls13_hybrid_kem.c || grep -q "HKDF" ssl/tls13_hybrid_kem.c; then
    echo "   ✓ HKDF implementation found"
else
    echo "   ✗ HKDF implementation NOT FOUND"
    exit 1
fi

echo ""

# Check for proper key parsing
echo "6. Checking key share parsing..."
if grep -q "PACKET_get_net_2.*classical_len" ssl/statem/extensions_srvr.c; then
    echo "   ✓ Length-prefixed key parsing in server"
else
    echo "   ✗ Length-prefixed key parsing MISSING in server"
    exit 1
fi

if grep -q "PACKET_get_net_2.*classical_ctlen" ssl/statem/extensions_clnt.c; then
    echo "   ✓ Length-prefixed ciphertext parsing in client"
else
    echo "   ✗ Length-prefixed ciphertext parsing MISSING in client"
    exit 1
fi

echo ""

# Summary
echo "=== Verification Summary ==="
echo "✓ All key components are in place"
echo ""
echo "Next steps for full testing:"
echo "1. Build OpenSSL with hybrid KEM support"
echo "2. Run: make test TESTS=test_hybrid_kem"
echo "3. Verify handshake succeeds with hybrid groups"
echo "4. Verify data exchange works"
echo "5. Verify hybrid secrets are properly combined"
echo ""
echo "To test manually:"
echo "  export DSMIL_PROFILE=WORLD_COMPAT"
echo "  openssl s_client -groups X25519MLKEM768:SecP256r1MLKEM768 ..."
echo "  openssl s_server -groups X25519MLKEM768:SecP256r1MLKEM768 ..."
echo ""
