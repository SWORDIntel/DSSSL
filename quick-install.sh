#!/bin/bash
#
# DSSSL Quick Install Script
# One-command installation with optimal settings
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "🚀 DSSSL Quick Install - Enhanced Build System"
echo "=============================================="
echo ""

# Check if running on supported platform
if ! command -v lsb_release &> /dev/null && ! [[ -f /etc/os-release ]]; then
    echo "❌ Unsupported platform. DSSSL requires Linux."
    exit 1
fi

# Detect if we're running with appropriate permissions for system install
if [[ $EUID -eq 0 ]]; then
    echo "✅ Running as root - full system integration available"
    INSTALL_MODE="--replace-system"
else
    echo "ℹ️  Running as user - local installation to /usr/local"
    echo "   For system-wide installation: sudo $0"
    INSTALL_MODE="--prefix=/usr/local"
fi

echo ""
echo "🔧 Starting DSSSL installation with optimal settings..."
echo "   • METEOR hardware-aware optimization"
echo "   • Thermal management (105°C/110°C limits)"
echo "   • OQS provider for post-quantum crypto"
echo "   • Build resume capability"
echo ""

# Run the full build pipeline
"$SCRIPT_DIR/build.sh" \
    --all \
    --with-oqs-provider \
    --thermal-max=105 \
    --thermal-critical=110 \
    $INSTALL_MODE \
    "$@"

echo ""
echo "🎉 DSSSL installation complete!"
echo ""
echo "📖 Next steps:"
echo "   1. Restart your shell or run: source ~/.bashrc"
echo "   2. Test DSSSL: openssl version"
echo "   3. Check providers: openssl list -providers"
echo ""
echo "📚 Documentation: $SCRIPT_DIR/README.md"
echo "📋 Build log: Check the latest log file in $SCRIPT_DIR/"
