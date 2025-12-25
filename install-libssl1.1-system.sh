#!/bin/bash
#
# install-libssl1.1-system.sh - Install DSSSL libraries as system libssl1.1
#
# This script installs the hardened DSSSL libraries as system libssl1.1
# so applications automatically use DSSSL-hardened SSL/TLS.
#

set -e

echo "Installing DSSSL as system libssl1.1..."
echo "=========================================="

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root (sudo)"
    echo ""
    echo "Run the following commands as root:"
    echo "  sudo mkdir -p /opt/dsssl-system"
    echo "  sudo cp -r /home/john/DSMILSystem/toolchains/DSSSL /opt/dsssl-system/"
    echo "  sudo cp /opt/dsssl-system/libssl.so.4 /usr/lib/libssl.so.1.1"
    echo "  sudo cp /opt/dsssl-system/libcrypto.so.4 /usr/lib/libcrypto.so.1.1"
    echo "  sudo ln -sf /usr/lib/libssl.so.1.1 /usr/lib/libssl.so"
    echo "  sudo ln -sf /usr/lib/libcrypto.so.1.1 /usr/lib/libcrypto.so"
    echo "  sudo cp -r /opt/dsssl-system/include/openssl /usr/include/"
    echo "  sudo ldconfig"
    echo ""
    echo "Then test with:"
    echo "  openssl version"
    echo "  ldd /bin/ls | grep libssl"
    exit 1
fi

# Create installation directory
echo "Creating installation directory..."
mkdir -p /opt/dsssl-system

# Copy DSSSL to system location
echo "Copying DSSSL libraries..."
cp -r /home/john/DSMILSystem/toolchains/DSSSL/* /opt/dsssl-system/

# Install as libssl1.1
echo "Installing as system libssl1.1..."
cp /opt/dsssl-system/libssl.so.4 /usr/lib/libssl.so.1.1
cp /opt/dsssl-system/libcrypto.so.4 /usr/lib/libcrypto.so.1.1

# Create default symlinks
echo "Creating library symlinks..."
ln -sf /usr/lib/libssl.so.1.1 /usr/lib/libssl.so
ln -sf /usr/lib/libcrypto.so.1.1 /usr/lib/libcrypto.so

# Install headers
echo "Installing headers..."
cp -r /opt/dsssl-system/include/openssl /usr/include/

# Update library cache
echo "Updating library cache..."
ldconfig

echo ""
echo "=========================================="
echo "✅ DSSSL installed as system libssl1.1!"
echo ""
echo "System now uses DSSSL-hardened SSL/TLS:"
echo "  - libssl.so.1.1 → DSSSL-hardened libssl"
echo "  - libcrypto.so.1.1 → DSSSL-hardened libcrypto"
echo "  - All applications automatically use hardened SSL"
echo ""
echo "Test installation:"
echo "  openssl version  # Should show DSSSL version"
echo "  ldd /bin/ls | grep libssl  # Should show libssl.so.1.1"
echo "=========================================="
