#!/bin/bash
#
# DSSSL System Installer
# Replaces system OpenSSL with DSSSL (DSMIL-Grade OpenSSL)
#
# WARNING: This script modifies system libraries. Use with caution.
# Always test in a non-production environment first.
#
# Classification: UNCLASSIFIED // FOR OFFICIAL USE ONLY

set -euo pipefail

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_PREFIX="${INSTALL_PREFIX:-/usr/local}"
BACKUP_DIR="${BACKUP_DIR:-/opt/dsssl-backup-$(date +%Y%m%d-%H%M%S)}"
LOG_FILE="${LOG_FILE:-/var/log/dsssl-install.log}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*" | tee -a "$LOG_FILE" >&2
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*" | tee -a "$LOG_FILE"
}

log_info() {
    echo -e "${GREEN}[INFO]${NC} $*" | tee -a "$LOG_FILE"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

# Detect system OpenSSL locations
detect_openssl() {
    log_info "Detecting system OpenSSL installation..."
    
    OPENSSL_BIN=$(command -v openssl || echo "")
    OPENSSL_LIB_DIRS=(
        "/usr/lib"
        "/usr/lib64"
        "/usr/local/lib"
        "/usr/local/lib64"
        "/lib"
        "/lib64"
    )
    
    OPENSSL_LIBS=(
        "libssl.so"
        "libcrypto.so"
        "libssl.so.3"
        "libcrypto.so.3"
        "libssl.so.1.1"
        "libcrypto.so.1.1"
    )
    
    if [[ -z "$OPENSSL_BIN" ]]; then
        log_error "OpenSSL binary not found in PATH"
        exit 1
    fi
    
    log_info "Found OpenSSL binary: $OPENSSL_BIN"
    OPENSSL_VERSION=$($OPENSSL_BIN version 2>/dev/null || echo "unknown")
    log_info "System OpenSSL version: $OPENSSL_VERSION"
}

# Create backup
create_backup() {
    log_info "Creating backup of system OpenSSL..."
    
    mkdir -p "$BACKUP_DIR"
    
    # Backup binary
    if [[ -f "$OPENSSL_BIN" ]]; then
        cp -v "$OPENSSL_BIN" "$BACKUP_DIR/openssl.bin" 2>&1 | tee -a "$LOG_FILE"
    fi
    
    # Backup libraries
    for lib_dir in "${OPENSSL_LIB_DIRS[@]}"; do
        if [[ -d "$lib_dir" ]]; then
            for lib in "${OPENSSL_LIBS[@]}"; do
                if [[ -f "$lib_dir/$lib" ]] || [[ -L "$lib_dir/$lib" ]]; then
                    mkdir -p "$BACKUP_DIR/lib"
                    cp -v "$lib_dir/$lib" "$BACKUP_DIR/lib/" 2>&1 | tee -a "$LOG_FILE" || true
                fi
            done
        fi
    done
    
    # Backup include files
    OPENSSL_INCLUDE_DIRS=(
        "/usr/include/openssl"
        "/usr/local/include/openssl"
    )
    
    for inc_dir in "${OPENSSL_INCLUDE_DIRS[@]}"; do
        if [[ -d "$inc_dir" ]]; then
            mkdir -p "$BACKUP_DIR/include"
            cp -rv "$inc_dir" "$BACKUP_DIR/include/" 2>&1 | tee -a "$LOG_FILE" || true
        fi
    done
    
    # Save system information
    {
        echo "Backup created: $(date)"
        echo "System: $(uname -a)"
        echo "OpenSSL binary: $OPENSSL_BIN"
        echo "OpenSSL version: $OPENSSL_VERSION"
        echo "Backup directory: $BACKUP_DIR"
    } > "$BACKUP_DIR/backup-info.txt"
    
    log_info "Backup created in: $BACKUP_DIR"
}

# Build DSSSL if needed
build_dsssl() {
    log_info "Checking DSSSL build status..."
    
    if [[ ! -f "$SCRIPT_DIR/.openssl/libssl.so" ]] && [[ ! -f "$SCRIPT_DIR/.openssl/libssl.so.3" ]]; then
        log_warn "DSSSL not built. Building now..."
        
        if [[ ! -f "$SCRIPT_DIR/util/build-dsllvm-world.sh" ]]; then
            log_error "Build script not found. Please build DSSSL first."
            exit 1
        fi
        
        cd "$SCRIPT_DIR"
        ./util/build-dsllvm-world.sh --clean
        
        if [[ $? -ne 0 ]]; then
            log_error "DSSSL build failed"
            exit 1
        fi
    else
        log_info "DSSSL already built"
    fi
}

# Install DSSSL
install_dsssl() {
    log_info "Installing DSSSL..."
    
    cd "$SCRIPT_DIR"
    
    # Determine build directory
    BUILD_DIR=".openssl"
    if [[ ! -d "$BUILD_DIR" ]]; then
        BUILD_DIR="build"
    fi
    
    if [[ ! -d "$BUILD_DIR" ]]; then
        log_error "Build directory not found"
        exit 1
    fi
    
    # Install binaries
    log_info "Installing binaries..."
    install -m 755 "$BUILD_DIR/apps/openssl" "$INSTALL_PREFIX/bin/openssl"
    
    # Create symlink if /usr/bin/openssl exists
    if [[ -f "/usr/bin/openssl" ]] && [[ "$INSTALL_PREFIX" != "/usr" ]]; then
        mv "/usr/bin/openssl" "/usr/bin/openssl.system" 2>/dev/null || true
        ln -sf "$INSTALL_PREFIX/bin/openssl" "/usr/bin/openssl"
    fi
    
    # Install libraries
    log_info "Installing libraries..."
    
    # Find library directory
    LIB_DIR="$BUILD_DIR"
    if [[ -d "$BUILD_DIR/lib" ]]; then
        LIB_DIR="$BUILD_DIR/lib"
    elif [[ -d "$BUILD_DIR/.libs" ]]; then
        LIB_DIR="$BUILD_DIR/.libs"
    fi
    
    # Determine system library directory
    SYSTEM_LIB_DIR="/usr/lib"
    if [[ -d "/usr/lib64" ]] && [[ $(uname -m) == "x86_64" ]]; then
        SYSTEM_LIB_DIR="/usr/lib64"
    fi
    
    # Install libssl
    for lib in libssl.so libssl.so.3 libcrypto.so libcrypto.so.3; do
        if [[ -f "$LIB_DIR/$lib" ]]; then
            install -m 755 "$LIB_DIR/$lib" "$SYSTEM_LIB_DIR/$lib"
            
            # Update library links
            if [[ "$lib" == "libssl.so.3" ]]; then
                ln -sf "$SYSTEM_LIB_DIR/libssl.so.3" "$SYSTEM_LIB_DIR/libssl.so" 2>/dev/null || true
            fi
            if [[ "$lib" == "libcrypto.so.3" ]]; then
                ln -sf "$SYSTEM_LIB_DIR/libcrypto.so.3" "$SYSTEM_LIB_DIR/libcrypto.so" 2>/dev/null || true
            fi
        fi
    done
    
    # Update library cache
    log_info "Updating library cache..."
    if command -v ldconfig >/dev/null 2>&1; then
        ldconfig
    fi
    
    # Install include files
    log_info "Installing include files..."
    if [[ -d "$BUILD_DIR/include/openssl" ]]; then
        mkdir -p "$INSTALL_PREFIX/include"
        cp -r "$BUILD_DIR/include/openssl" "$INSTALL_PREFIX/include/"
    elif [[ -d "include/openssl" ]]; then
        mkdir -p "$INSTALL_PREFIX/include"
        cp -r "include/openssl" "$INSTALL_PREFIX/include/"
    fi
    
    log_info "DSSSL installation complete"
}

# Verify installation
verify_installation() {
    log_info "Verifying installation..."
    
    # Check binary
    NEW_OPENSSL=$(command -v openssl || echo "")
    if [[ -z "$NEW_OPENSSL" ]]; then
        log_error "OpenSSL binary not found after installation"
        return 1
    fi
    
    # Check version
    NEW_VERSION=$($NEW_OPENSSL version 2>/dev/null || echo "unknown")
    log_info "Installed OpenSSL version: $NEW_VERSION"
    
    # Check if it's DSSSL
    if $NEW_OPENSSL version 2>&1 | grep -qi "dsssl\|dsmil"; then
        log_info "DSSSL detected in version string"
    else
        log_warn "DSSSL identifier not found in version string"
    fi
    
    # Test basic functionality
    log_info "Testing basic functionality..."
    if $NEW_OPENSSL version -a >/dev/null 2>&1; then
        log_info "Basic functionality test passed"
    else
        log_error "Basic functionality test failed"
        return 1
    fi
    
    # Test library loading
    log_info "Testing library loading..."
    if ldconfig -p | grep -q "libssl.so"; then
        log_info "Library loading test passed"
    else
        log_warn "Library loading test inconclusive"
    fi
    
    log_info "Installation verification complete"
    return 0
}

# Create rollback script
create_rollback_script() {
    log_info "Creating rollback script..."
    
    ROLLBACK_SCRIPT="$BACKUP_DIR/rollback.sh"
    
    cat > "$ROLLBACK_SCRIPT" <<EOF
#!/bin/bash
#
# DSSSL Rollback Script
# Restores system OpenSSL from backup
#
# Backup created: $(date)
# Backup directory: $BACKUP_DIR

set -euo pipefail

echo "Rolling back DSSSL installation..."

# Restore binary
if [[ -f "$BACKUP_DIR/openssl.bin" ]]; then
    install -m 755 "$BACKUP_DIR/openssl.bin" "$OPENSSL_BIN"
fi

# Restore libraries
if [[ -d "$BACKUP_DIR/lib" ]]; then
    for lib in "$BACKUP_DIR/lib"/*; do
        if [[ -f "\$lib" ]]; then
            libname=\$(basename "\$lib")
            for lib_dir in /usr/lib /usr/lib64 /usr/local/lib /usr/local/lib64; do
                if [[ -d "\$lib_dir" ]]; then
                    install -m 755 "\$lib" "\$lib_dir/\$libname" 2>/dev/null || true
                fi
            done
        fi
    done
    ldconfig
fi

# Restore include files
if [[ -d "$BACKUP_DIR/include/openssl" ]]; then
    for inc_dir in /usr/include /usr/local/include; do
        if [[ -d "\$inc_dir" ]]; then
            rm -rf "\$inc_dir/openssl"
            cp -r "$BACKUP_DIR/include/openssl" "\$inc_dir/"
        fi
    done
fi

# Restore /usr/bin/openssl if it was moved
if [[ -f "/usr/bin/openssl.system" ]]; then
    mv "/usr/bin/openssl.system" "/usr/bin/openssl"
fi

echo "Rollback complete"
EOF
    
    chmod +x "$ROLLBACK_SCRIPT"
    log_info "Rollback script created: $ROLLBACK_SCRIPT"
}

# Main installation function
main() {
    log_info "=========================================="
    log_info "DSSSL System Installer"
    log_info "=========================================="
    log_info "This will replace system OpenSSL with DSSSL"
    log_info "Backup will be created in: $BACKUP_DIR"
    log_info ""
    
    # Safety check
    if [[ "${FORCE_INSTALL:-}" != "1" ]]; then
        echo -n "Are you sure you want to continue? (yes/no): "
        read -r response
        if [[ "$response" != "yes" ]]; then
            log_info "Installation cancelled"
            exit 0
        fi
    fi
    
    # Run installation steps
    check_root
    detect_openssl
    create_backup
    build_dsssl
    install_dsssl
    
    if verify_installation; then
        create_rollback_script
        log_info "=========================================="
        log_info "Installation completed successfully!"
        log_info "Backup location: $BACKUP_DIR"
        log_info "Rollback script: $BACKUP_DIR/rollback.sh"
        log_info "=========================================="
    else
        log_error "Installation verification failed"
        log_info "You can rollback using: $BACKUP_DIR/rollback.sh"
        exit 1
    fi
}

# Run main function
main "$@"
