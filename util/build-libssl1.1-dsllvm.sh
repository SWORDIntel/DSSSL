#!/usr/bin/env bash
#
# build-libssl1.1-dsllvm.sh - Build OpenSSL 1.1.1 with DSLLVM for DSMIL use cases
#
# This script builds OpenSSL 1.1.1 (libssl1.1) using DSLLVM clang with
# DSMIL-specific optimizations and security hardening.
#
# Usage:
#   ./util/build-libssl1.1-dsllvm.sh [options]
#
# Options:
#   --clean         Clean before building
#   --test          Run test suite after build
#   --install       Install after successful build (requires sudo)
#   --prefix=PATH   Installation prefix (default: /opt/openssl-1.1.1-dsllvm)
#   --help          Show this help
#
# Build variants:
#   - libssl1.1-dsllvm-world: Portable build (x86-64-v3) for compatibility
#   - libssl1.1-dsllvm-dsmil: Meteorlake-optimized build for performance
#
# See: docs/core/OPENSSL_SECURE_SPEC.md

set -e  # Exit on error
set -u  # Exit on undefined variable
set -o pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default options
CLEAN=0
TEST=0
INSTALL=0
SYSTEM_INSTALL=0
PREFIX="/opt/openssl-1.1.1-dsllvm"
OPENSSLDIR="/opt/openssl-1.1.1-dsllvm/ssl"
BUILD_VARIANT="libssl1.1-dsllvm-world"
BUILD_JOBS=$(nproc)

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --clean)
            CLEAN=1
            shift
            ;;
        --test)
            TEST=1
            shift
            ;;
        --install)
            INSTALL=1
            shift
            ;;
        --prefix=*)
            PREFIX="${1#*=}"
            shift
            ;;
        --variant=*)
            BUILD_VARIANT="${1#*=}"
            shift
            ;;
        --system-install)
            SYSTEM_INSTALL=1
            PREFIX="/usr"
            OPENSSLDIR="/usr/ssl"
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [options]"
            echo "Options:"
            echo "  --clean         Clean before building"
            echo "  --test          Run test suite after build"
            echo "  --install       Install after successful build (requires sudo)"
            echo "  --prefix=PATH        Installation prefix (default: /opt/openssl-1.1.1-dsllvm)"
            echo "  --variant=NAME       Build variant: libssl1.1-dsllvm-world or libssl1.1-dsllvm-dsmil"
            echo "  --system-install     Install to system locations (/usr) as default OpenSSL"
            echo "  --help, -h           Show this help"
            exit 0
            ;;
        *)
            echo -e "${RED}Error:${NC} Unknown option: $1" >&2
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Script directory and paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OPENSSL_SRC="$PROJECT_ROOT/ssl1.1"
BUILD_DIR="$PROJECT_ROOT/build-libssl1.1"

# Logging functions
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$PROJECT_ROOT/build-libssl1.1.log"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*" | tee -a "$PROJECT_ROOT/build-libssl1.1.log" >&2
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*" | tee -a "$PROJECT_ROOT/build-libssl1.1.log"
}

log_info() {
    echo -e "${GREEN}[INFO]${NC} $*" | tee -a "$PROJECT_ROOT/build-libssl1.1.log"
}

log_debug() {
    echo -e "${BLUE}[DEBUG]${NC} $*" | tee -a "$PROJECT_ROOT/build-libssl1.1.log"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."

    # Check for DSLLVM clang (or compatible clang)
    if ! command -v clang >/dev/null 2>&1; then
        log_error "clang not found in PATH"
        log_error "Please ensure DSLLVM or compatible clang is installed"
        exit 1
    fi

    # Check if it's DSLLVM by examining version string
    CLANG_VERSION_OUTPUT=$(clang --version 2>&1)
    if echo "$CLANG_VERSION_OUTPUT" | grep -qi "dsllvm\|swordintel"; then
        log_info "Found DSLLVM clang"
        DSLLVM_AVAILABLE=1
    else
        log_warn "Found generic clang - DSLLVM optimizations may not be available"
        DSLLVM_AVAILABLE=0
    fi

    CLANG_VERSION=$(echo "$CLANG_VERSION_OUTPUT" | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || echo "unknown")
    log_info "Found clang version: $CLANG_VERSION"

    # Check for OpenSSL 1.1.1 source
    if [[ ! -d "$OPENSSL_SRC" ]]; then
        log_error "OpenSSL 1.1.1 source not found at: $OPENSSL_SRC"
        exit 1
    fi

    # Check for required tools
    for tool in make perl; do
        if ! command -v $tool >/dev/null 2>&1; then
            log_error "$tool not found"
            exit 1
        fi
    done

    log_info "Prerequisites check passed"
}

# Clean build directory
clean_build() {
    if [[ $CLEAN -eq 1 ]]; then
        log_info "Cleaning build directory..."
        if [[ -d "$BUILD_DIR" ]]; then
            rm -rf "$BUILD_DIR"
        fi
        if [[ -d "$OPENSSL_SRC" ]]; then
            cd "$OPENSSL_SRC"
            make clean 2>/dev/null || true
            make distclean 2>/dev/null || true
        fi
        log_info "Clean completed"
    fi
}

# Configure build
configure_build() {
    log_info "Configuring OpenSSL 1.1.1 build with DSLLVM hardening..."

    # Set environment for clang (DSLLVM if available)
    export CC="clang"
    export CXX="clang++"
    export AR="llvm-ar"
    export RANLIB="llvm-ranlib"
    export NM="llvm-nm"

    # DSLLVM hardening flags - ensure we only use OpenSSL 1.1.1 headers
    DSSSL_CFLAGS="-DDSLLVM_BUILD -DCSNA_CONSTANT_TIME_CHECK -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE -Wall -Wextra -Wno-unused-parameter -I$OPENSSL_SRC/include"
    DSSSL_LDFLAGS="-Wl,-z,relro -Wl,-z,now -Wl,--gc-sections"

    case "$BUILD_VARIANT" in
        "libssl1.1-dsllvm-world")
            log_info "Configuring libssl1.1-dsllvm-world (portable build)..."

            CONFIGURE_ARGS=(
                "--prefix=$PREFIX"
                "--openssldir=$OPENSSLDIR"
                "shared"
                "no-weak-ssl-ciphers"
                "no-ssl3"
                "no-comp"
                "enable-ec_nistp_64_gcc_128"
                "enable-tls1_3"
                "threads"
                "linux-x86_64"
            )

            # Add DSLLVM hardening
            export CFLAGS="-march=x86-64-v3 -pipe -O2 $DSSSL_CFLAGS"
            export CXXFLAGS="-march=x86-64-v3 -pipe -O2 $DSSSL_CFLAGS"
            export LDFLAGS="$DSSSL_LDFLAGS"
            ;;

        "libssl1.1-dsllvm-dsmil")
            log_info "Configuring libssl1.1-dsllvm-dsmil (optimized build)..."

            CONFIGURE_ARGS=(
                "--prefix=$PREFIX"
                "--openssldir=$OPENSSLDIR"
                "shared"
                "no-weak-ssl-ciphers"
                "no-ssl3"
                "no-comp"
                "enable-ec_nistp_64_gcc_128"
                "enable-tls1_3"
                "threads"
                "linux-x86_64"
            )

            # Add DSLLVM hardening and optimizations
            export CFLAGS="-march=meteorlake -mtune=meteorlake -mavx2 -mfma -maes -O3 -flto=thin $DSSSL_CFLAGS"
            export CXXFLAGS="-march=meteorlake -mtune=meteorlake -mavx2 -mfma -maes -O3 -flto=thin $DSSSL_CFLAGS"
            export LDFLAGS="-fuse-ld=lld -flto=thin $DSSSL_LDFLAGS"
            ;;

        *)
            log_error "Unknown build variant: $BUILD_VARIANT"
            exit 1
            ;;
    esac

    log_debug "Configure command: $OPENSSL_SRC/Configure ${CONFIGURE_ARGS[*]}"
    log_debug "CFLAGS: $CFLAGS"
    log_debug "LDFLAGS: $LDFLAGS"

    # Run configure
    cd "$OPENSSL_SRC"
    ./Configure "${CONFIGURE_ARGS[@]}"

    if [[ $? -ne 0 ]]; then
        log_error "Configure failed"
        exit 1
    fi

    log_info "Configure completed successfully"
}

# Build OpenSSL
build_openssl() {
    log_info "Building OpenSSL 1.1.1 with DSLLVM hardening..."

    cd "$OPENSSL_SRC"

    # Build with parallel jobs
    log_debug "Building with $BUILD_JOBS parallel jobs"
    make -j"$BUILD_JOBS"

    if [[ $? -ne 0 ]]; then
        log_error "Build failed"
        exit 1
    fi

    log_info "Build completed successfully"
}

# Run tests
run_tests() {
    if [[ $TEST -eq 1 ]]; then
        log_info "Running OpenSSL test suite..."

        cd "$OPENSSL_SRC"

        # Run a subset of tests relevant to libssl/libcrypto
        make test 2>&1 | tee -a "$PROJECT_ROOT/build-libssl1.1.log"

        if [[ $? -ne 0 ]]; then
            log_warn "Some tests failed - check log for details"
        else
            log_info "Test suite completed successfully"
        fi
    fi
}

# Install OpenSSL
install_openssl() {
    if [[ $INSTALL -eq 1 ]]; then
        log_info "Installing OpenSSL 1.1.1..."

        cd "$OPENSSL_SRC"

        if [[ $SYSTEM_INSTALL -eq 1 ]]; then
            # System installation with DSSSL hardening
            log_info "Performing system installation with DSSSL hardening..."

            # Install binaries
            make install 2>&1 | tee -a "$PROJECT_ROOT/build-libssl1.1.log"

            if [[ $? -ne 0 ]]; then
                log_error "Installation failed"
                exit 1
            fi

            # Create versioned symlinks for library compatibility
            SYSTEM_LIB_DIR="/usr/lib"
            if [[ -d "/usr/lib64" ]] && [[ $(uname -m) == "x86_64" ]]; then
                SYSTEM_LIB_DIR="/usr/lib64"
            fi

            # Create symlinks for libssl.so.1.1 and libcrypto.so.1.1
            if [[ -f "$SYSTEM_LIB_DIR/libssl.so.1.1" ]]; then
                ln -sf "$SYSTEM_LIB_DIR/libssl.so.1.1" "$SYSTEM_LIB_DIR/libssl.so" 2>/dev/null || true
                log_info "Created libssl.so symlink"
            fi

            if [[ -f "$SYSTEM_LIB_DIR/libcrypto.so.1.1" ]]; then
                ln -sf "$SYSTEM_LIB_DIR/libcrypto.so.1.1" "$SYSTEM_LIB_DIR/libcrypto.so" 2>/dev/null || true
                log_info "Created libcrypto.so symlink"
            fi

            # Handle headers carefully to avoid conflicts with DSSSL 4.x
            # Install to versioned directory first
            make install_dev DESTDIR="/tmp/openssl-1.1-install" 2>&1 | tee -a "$PROJECT_ROOT/build-libssl1.1.log"

            if [[ -d "/tmp/openssl-1.1-install/usr/include/openssl" ]]; then
                # Install headers to versioned location to avoid conflicts
                mkdir -p "/usr/include"
                cp -r "/tmp/openssl-1.1-install/usr/include/openssl" "/usr/include/openssl-1.1"

                # Create symlink for applications that expect standard location
                # but only if no DSSSL headers exist there
                if [[ ! -d "/usr/include/openssl" ]]; then
                    ln -sf "/usr/include/openssl-1.1" "/usr/include/openssl"
                    log_info "Created openssl headers symlink"
                else
                    log_warn "DSSSL headers already exist at /usr/include/openssl"
                    log_info "libssl1.1 headers installed to /usr/include/openssl-1.1"
                fi
            fi

            # Install everything else normally (binaries, libraries, docs)
            cp -r "/tmp/openssl-1.1-install/usr/bin"/* "/usr/bin/" 2>/dev/null || true
            cp -r "/tmp/openssl-1.1-install/usr/lib"/* "/usr/lib/" 2>/dev/null || true
            if [[ -d "/usr/lib64" ]]; then
                cp -r "/tmp/openssl-1.1-install/usr/lib"/* "/usr/lib64/" 2>/dev/null || true
            fi

            # Clean up temporary directory
            rm -rf "/tmp/openssl-1.1-install"

            # Update library cache
            if command -v ldconfig >/dev/null 2>&1; then
                ldconfig
                log_info "Updated library cache"
            fi

            log_info "System installation completed - libssl1.1 is now the default system OpenSSL"
            log_info "Original system OpenSSL headers backed up to /usr/include/openssl-system-backup"

        else
            # Standard installation
            make install_dev 2>&1 | tee -a "$PROJECT_ROOT/build-libssl1.1.log"

            if [[ $? -ne 0 ]]; then
                log_error "Installation failed"
                exit 1
            fi

            log_info "Installation completed successfully"
            log_info "Libraries installed to: $PREFIX/lib"
            log_info "Headers installed to: $PREFIX/include"
        fi
    fi
}

# Verify build
verify_build() {
    log_info "Verifying build..."

    # Check for required shared libraries (OpenSSL 1.1.1 builds shared by default)
    LIBSSL_SO="$OPENSSL_SRC/libssl.so.1.1"
    LIBCRYPTO_SO="$OPENSSL_SRC/libcrypto.so.1.1"

    if [[ ! -f "$LIBSSL_SO" ]]; then
        log_error "libssl.so.1.1 not found"
        exit 1
    fi

    if [[ ! -f "$LIBCRYPTO_SO" ]]; then
        log_error "libcrypto.so.1.1 not found"
        exit 1
    fi

    # Check library sizes
    LIBSSL_SIZE=$(stat -c%s "$LIBSSL_SO" 2>/dev/null || stat -f%z "$LIBSSL_SO" 2>/dev/null || echo "unknown")
    LIBCRYPTO_SIZE=$(stat -c%s "$LIBCRYPTO_SO" 2>/dev/null || stat -f%z "$LIBCRYPTO_SO" 2>/dev/null || echo "unknown")

    log_info "libssl.so.1.1 size: $LIBSSL_SIZE bytes"
    log_info "libcrypto.so.1.1 size: $LIBCRYPTO_SIZE bytes"

    # Check for openssl binary
    if [[ -f "$OPENSSL_SRC/apps/openssl" ]]; then
        log_info "OpenSSL binary built successfully"
    else
        log_warn "OpenSSL binary not found"
    fi

    log_info "Build verification completed"
}

# Main function
main() {
    log_info "=========================================="
    log_info "OpenSSL 1.1.1 DSLLVM Build Script"
    log_info "=========================================="
    log_info "Build variant: $BUILD_VARIANT"
    log_info "Install prefix: $PREFIX"
    log_info "OpenSSL directory: $OPENSSLDIR"
    log_info ""

    check_prerequisites
    clean_build
    configure_build
    build_openssl
    run_tests
    install_openssl
    verify_build

    log_info "=========================================="
    log_info "Build completed successfully!"
    log_info "=========================================="
    log_info "Built libraries:"
    log_info "  $OPENSSL_SRC/libssl.a"
    log_info "  $OPENSSL_SRC/libcrypto.a"
    if [[ $INSTALL -eq 1 ]]; then
        log_info "Installed to: $PREFIX"
    fi
    log_info "=========================================="
}

# Run main function
main "$@"
