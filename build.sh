#!/bin/bash
#
# DSSSL Enhanced Build System
# Comprehensive build, dependency management, and installation orchestrator
# Features: Automatic dependency detection, thermal throttling, build resume, METEOR optimization
#
# Usage:
#   ./build.sh [options]
#
# Options:
#   --deps-only          Install dependencies only
#   --build-only         Build only (assume dependencies installed)
#   --install-only       Install only (assume build completed)
#   --all                Full pipeline: deps + build + install (default)
#   --resume             Resume from previous interrupted build
#   --clean              Clean build directory before starting
#   --dry-run            Show what would be done without executing
#   --verbose            Enable verbose output
#   --thermal-max TEMP   Maximum CPU temperature before throttling (°C, default: 105)
#   --thermal-critical TEMP Critical temperature threshold (°C, default: 110)
#   --thermal-sensor PATH Custom temperature sensor path
#   --gpu-throttle       Enable GPU temperature monitoring/throttling (default: enabled)
#   --no-gpu-throttle    Disable GPU temperature monitoring/throttling
#   --with-oqs-provider  Build and stage oqs-provider (liboqs + provider)
#   --liboqs-branch BR   liboqs branch/tag to build (default: 0.11.0)
#   --prefix PATH        Installation prefix (default: /usr/local)
#   --replace-system     Replace system OpenSSL (requires root)
#   --test               Run test suite after build
#   --help               Show this help message
#

set -euo pipefail

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_SCRIPT="${SCRIPT_DIR}/util/build-dsllvm-world.sh"
INSTALL_SCRIPT="${SCRIPT_DIR}/install-dsssl.sh"

# Default options (optimized for performance and thermal safety)
MODE="all"
RESUME=false
CLEAN=false
DRY_RUN=false
VERBOSE=false
THERMAL_MAX=105
THERMAL_CRITICAL=110
THERMAL_SENSOR=""
GPU_THROTTLE=true  # Enable GPU thermal throttling by default
WITH_OQS=true
LIBOQS_BRANCH="0.11.0"
PREFIX="/usr/local"
REPLACE_SYSTEM=false
TEST=false

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging
LOG_FILE="${SCRIPT_DIR}/dsssl-build-$(date +%Y%m%d-%H%M%S).log"

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $*" | tee -a "$LOG_FILE"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*" | tee -a "$LOG_FILE"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $*" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*" | tee -a "$LOG_FILE" >&2
}

log_step() {
    echo -e "${BLUE}[STEP]${NC} $*" | tee -a "$LOG_FILE"
    echo -e "${BLUE}$(printf '%.0s=' {1..60})${NC}" | tee -a "$LOG_FILE"
}

# Show banner
show_banner() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════════════════╗"
    echo "║                                                                          ║"
    echo "║  ██████  ███████ ███████ ██      ██       ██████   ██████   ██████      ║"
    echo "║  ██   ██ ██      ██      ██      ██       ██   ██ ██    ██ ██    ██     ║"
    echo "║  ██   ██ ███████ ███████ ██      ██       ██████  ██    ██ ██    ██     ║"
    echo "║  ██   ██      ██      ██ ██      ██       ██   ██ ██    ██ ██    ██     ║"
    echo "║  ██████  ███████ ███████ ███████ ███████  ██████   ██████   ██████      ║"
    echo "║                                                                          ║"
    echo "║  DSMIL-Grade Secure OpenSSL Build System                               ║"
    echo "║  Enhanced with METEOR Optimization & Thermal Intelligence              ║"
    echo "║                                                                          ║"
    echo "╚══════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo "Build Log: $LOG_FILE"
    echo ""
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --deps-only)
                MODE="deps"
                shift
                ;;
            --build-only)
                MODE="build"
                shift
                ;;
            --install-only)
                MODE="install"
                shift
                ;;
            --all)
                MODE="all"
                shift
                ;;
            --resume)
                RESUME=true
                shift
                ;;
            --clean)
                CLEAN=true
                shift
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --verbose)
                VERBOSE=true
                shift
                ;;
            --thermal-max=*)
                THERMAL_MAX="${1#*=}"
                shift
                ;;
            --thermal-critical=*)
                THERMAL_CRITICAL="${1#*=}"
                shift
                ;;
            --thermal-sensor=*)
                THERMAL_SENSOR="${1#*=}"
                shift
                ;;
            --gpu-throttle)
                GPU_THROTTLE=true
                shift
                ;;
            --no-gpu-throttle)
                GPU_THROTTLE=false
                shift
                ;;
            --with-oqs-provider)
                WITH_OQS=true
                shift
                ;;
            --without-oqs-provider)
                WITH_OQS=false
                shift
                ;;
            --liboqs-branch=*)
                LIBOQS_BRANCH="${1#*=}"
                shift
                ;;
            --prefix=*)
                PREFIX="${1#*=}"
                shift
                ;;
            --replace-system)
                REPLACE_SYSTEM=true
                shift
                ;;
            --test)
                TEST=true
                shift
                ;;
            --help|-h)
                show_usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                echo "Use --help for usage information"
                exit 1
                ;;
        esac
    done
}

# Show usage information
show_usage() {
    cat << EOF
DSSSL Enhanced Build System

Usage: $0 [options]

Modes:
  --deps-only          Install dependencies only
  --build-only         Build only (assume dependencies installed)
  --install-only       Install only (assume build completed)
  --all                Full pipeline: deps + build + install (default)

Build Options:
  --resume             Resume from previous interrupted build
  --clean              Clean build directory before starting
  --dry-run            Show what would be done without executing
  --verbose            Enable verbose output
  --with-oqs-provider  Build and stage oqs-provider (liboqs + provider)
  --liboqs-branch BR   liboqs branch/tag to build (default: 0.11.0)
  --test               Run test suite after build

Thermal Management:
  --thermal-max TEMP   Maximum CPU temperature before throttling (°C, default: 105)
  --thermal-critical TEMP Critical temperature threshold (°C, default: 110)
  --thermal-sensor PATH Custom temperature sensor path
  --gpu-throttle       Enable GPU temperature monitoring/throttling

Installation:
  --prefix PATH        Installation prefix (default: /usr/local)
  --replace-system     Replace system OpenSSL (requires root)

Examples:
  $0                           # Full build with all enhancements
  $0 --resume                  # Resume interrupted build
  $0 --deps-only               # Install dependencies only
  $0 --thermal-max=100 --gpu-throttle  # Custom thermal settings
  $0 --replace-system          # Replace system OpenSSL

EOF
}

# Check if scripts exist
check_scripts() {
    if [[ ! -f "$BUILD_SCRIPT" ]]; then
        log_error "Build script not found: $BUILD_SCRIPT"
        exit 1
    fi

    if [[ "$MODE" == "install" ]] || [[ "$MODE" == "all" ]]; then
        if [[ ! -f "$INSTALL_SCRIPT" ]]; then
            log_error "Install script not found: $INSTALL_SCRIPT"
            exit 1
        fi
    fi
}

# Detect package manager
detect_package_manager() {
    if command -v apt-get &> /dev/null; then
        PACKAGE_MANAGER="apt"
        PACKAGE_UPDATE="apt-get update"
        PACKAGE_INSTALL="apt-get install -y"
    elif command -v dnf &> /dev/null; then
        PACKAGE_MANAGER="dnf"
        PACKAGE_UPDATE="dnf check-update || true"
        PACKAGE_INSTALL="dnf install -y"
    elif command -v yum &> /dev/null; then
        PACKAGE_MANAGER="yum"
        PACKAGE_UPDATE="yum check-update || true"
        PACKAGE_INSTALL="yum install -y"
    elif command -v zypper &> /dev/null; then
        PACKAGE_MANAGER="zypper"
        PACKAGE_UPDATE="zypper refresh"
        PACKAGE_INSTALL="zypper install -y"
    elif command -v pacman &> /dev/null; then
        PACKAGE_MANAGER="pacman"
        PACKAGE_UPDATE="pacman -Sy"
        PACKAGE_INSTALL="pacman -S --noconfirm"
    else
        log_warning "Unsupported package manager. Please install dependencies manually."
        return 1
    fi

    log_info "Detected package manager: $PACKAGE_MANAGER"
    return 0
}

# Install dependencies
install_dependencies() {
    log_step "Installing DSSSL Dependencies"

    if [[ "$DRY_RUN" == true ]]; then
        log_info "Would detect package manager and install dependencies"
        return 0
    fi

    # Detect package manager
    if ! detect_package_manager; then
        log_warning "Automatic dependency installation not supported on this system"
        log_warning "Please install the following manually:"
        echo "  - build-essential (or equivalent)"
        echo "  - cmake, ninja-build"
        echo "  - libssl-dev, zlib1g-dev"
        echo "  - python3, perl"
        echo "  - git, wget"
        return 1
    fi

    # Update package list
    log_info "Updating package list..."
    if [[ "$VERBOSE" == true ]]; then
        $PACKAGE_UPDATE
    else
        $PACKAGE_UPDATE >/dev/null 2>&1
    fi

    # Core build tools
    local core_deps=(
        "build-essential"
        "cmake"
        "ninja-build"
        "gcc"
        "g++"
        "python3"
        "python3-dev"
        "perl"
        "git"
        "wget"
        "curl"
    )

    # OpenSSL build dependencies
    local ssl_deps=(
        "libssl-dev"
        "zlib1g-dev"
        "libzstd-dev"
        "libbz2-dev"
        "liblzma-dev"
        "libkrb5-dev"
        "libidn2-dev"
        "libunistring-dev"
    )

    # Additional development tools
    local dev_deps=(
        "pkg-config"
        "autoconf"
        "automake"
        "libtool"
        "bison"
        "flex"
        "texinfo"
    )

    # Thermal monitoring dependencies
    local thermal_deps=(
        "lm-sensors"
        "sysfsutils"
    )

    # All dependencies
    local all_deps=("${core_deps[@]}" "${ssl_deps[@]}" "${dev_deps[@]}" "${thermal_deps[@]}")

    log_info "Installing dependencies..."
    if [[ "$VERBOSE" == true ]]; then
        $PACKAGE_INSTALL "${all_deps[@]}"
    else
        echo -n "Installing packages... "
        if $PACKAGE_INSTALL "${all_deps[@]}" >/dev/null 2>&1; then
            echo "✅ Done"
        else
            echo "❌ Failed"
            return 1
        fi
    fi

    # Verify critical tools
    local critical_tools=("gcc" "g++" "cmake" "ninja" "python3" "perl" "git")
    local missing_tools=()

    for tool in "${critical_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done

    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log_error "Critical tools still missing: ${missing_tools[*]}"
        return 1
    fi

    log_success "All dependencies installed successfully"
    return 0
}

# Build DSSSL
build_dsssl() {
    log_step "Building DSSSL"

    if [[ ! -f "$BUILD_SCRIPT" ]]; then
        log_error "Build script not found: $BUILD_SCRIPT"
        return 1
    fi

    # Build command arguments
    local build_args=()

    if [[ "$CLEAN" == true ]]; then
        build_args+=("--clean")
    fi

    if [[ "$RESUME" == true ]]; then
        build_args+=("--resume")
    fi

    if [[ "$DRY_RUN" == true ]]; then
        build_args+=("--dry-run")
    fi

    if [[ "$VERBOSE" == true ]]; then
        build_args+=("--verbose")
    fi

    if [[ "$THERMAL_MAX" != "105" ]]; then
        build_args+=("--thermal-max=$THERMAL_MAX")
    fi

    if [[ "$THERMAL_CRITICAL" != "110" ]]; then
        build_args+=("--thermal-critical=$THERMAL_CRITICAL")
    fi

    if [[ -n "$THERMAL_SENSOR" ]]; then
        build_args+=("--thermal-sensor=$THERMAL_SENSOR")
    fi

    if [[ "$GPU_THROTTLE" == true ]]; then
        build_args+=("--gpu-throttle")
    fi

    if [[ "$WITH_OQS" == true ]]; then
        build_args+=("--with-oqs-provider")
        build_args+=("--liboqs-branch=$LIBOQS_BRANCH")
    fi

    if [[ "$TEST" == true ]]; then
        build_args+=("--test")
    fi

    build_args+=("--prefix=$PREFIX")

    log_info "Running build script with args: ${build_args[*]}"

    if [[ "$DRY_RUN" == true ]]; then
        echo "Would execute: $BUILD_SCRIPT ${build_args[*]}"
        return 0
    fi

    # Execute build
    if cd "$SCRIPT_DIR" && "$BUILD_SCRIPT" "${build_args[@]}"; then
        log_success "DSSSL build completed successfully"
        return 0
    else
        log_error "DSSSL build failed"
        return 1
    fi
}

# Install DSSSL
install_dsssl() {
    log_step "Installing DSSSL"

    if [[ ! -f "$INSTALL_SCRIPT" ]]; then
        log_error "Install script not found: $INSTALL_SCRIPT"
        return 1
    fi

    # Install command arguments
    local install_args=()

    if [[ "$DRY_RUN" == true ]]; then
        log_info "Would install DSSSL to $PREFIX"
        return 0
    fi

    if [[ "$REPLACE_SYSTEM" == true ]]; then
        log_warning "Replacing system OpenSSL - this requires root privileges"
        if [[ $EUID -ne 0 ]]; then
            log_error "Must run as root to replace system OpenSSL"
            log_error "Use: sudo $0 --replace-system"
            return 1
        fi
        # The install script handles system replacement
    fi

    install_args+=("INSTALL_PREFIX=$PREFIX")

    log_info "Running install script..."

    # Execute install
    if cd "$SCRIPT_DIR" && "$INSTALL_SCRIPT" "${install_args[@]}"; then
        log_success "DSSSL installation completed successfully"

        if [[ "$REPLACE_SYSTEM" == true ]]; then
            log_success "System OpenSSL has been replaced with DSSSL"
            log_warning "Please restart services that depend on OpenSSL"
        fi

        return 0
    else
        log_error "DSSSL installation failed"
        return 1
    fi
}

# Verify installation
verify_installation() {
    log_step "Verifying Installation"

    if [[ "$DRY_RUN" == true ]]; then
        log_info "Would verify DSSSL installation"
        return 0
    fi

    # Check if DSSSL binaries exist
    local openssl_cmd="$PREFIX/bin/openssl"
    if [[ -x "$openssl_cmd" ]]; then
        log_success "DSSSL binary found: $openssl_cmd"

        # Test version
        local version
        version=$("$openssl_cmd" version 2>/dev/null || echo "unknown")
        log_info "DSSSL version: $version"

        # Test basic functionality
        if "$openssl_cmd" version -a >/dev/null 2>&1; then
            log_success "Basic functionality test passed"
        else
            log_warning "Basic functionality test failed"
        fi
    else
        log_error "DSSSL binary not found: $openssl_cmd"
        return 1
    fi

    # Check libraries
    local libssl="$PREFIX/lib64/libssl.so"
    local libcrypto="$PREFIX/lib64/libcrypto.so"

    if [[ -f "$libssl" ]] || [[ -f "$libcrypto" ]]; then
        log_success "DSSSL libraries found"
    else
        log_warning "DSSSL libraries not found in expected location"
    fi

    log_success "Installation verification completed"
    return 0
}

# Show post-installation instructions
show_post_install() {
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  DSSSL Installation Complete!                                           ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    if [[ "$REPLACE_SYSTEM" == true ]]; then
        echo -e "${GREEN}System OpenSSL has been replaced with DSSSL${NC}"
        echo ""
        echo -e "${YELLOW}⚠️  IMPORTANT: Please restart services that use OpenSSL:${NC}"
        echo "   - SSH daemon: sudo systemctl restart ssh"
        echo "   - Web servers: sudo systemctl restart apache2/nginx"
        echo "   - Other services: Check with 'sudo systemctl list-units --type=service'"
        echo ""
    fi

    echo -e "${GREEN}To use DSSSL:${NC}"
    echo "  export PATH=\"$PREFIX/bin:\$PATH\""
    echo "  export LD_LIBRARY_PATH=\"$PREFIX/lib64:\$LD_LIBRARY_PATH\""
    echo "  export OPENSSL_CONF=\"$PREFIX/ssl/openssl.cnf\""
    echo ""
    echo "  # Or add to your shell profile:"
    echo "  echo 'export PATH=\"$PREFIX/bin:\$PATH\"' >> ~/.bashrc"
    echo "  echo 'export LD_LIBRARY_PATH=\"$PREFIX/lib64:\$LD_LIBRARY_PATH\"' >> ~/.bashrc"
    echo "  echo 'export OPENSSL_CONF=\"$PREFIX/ssl/openssl.cnf\"' >> ~/.bashrc"
    echo ""

    if [[ "$WITH_OQS" == true ]]; then
        echo -e "${GREEN}Quantum-Safe Cryptography:${NC}"
        echo "  DSSSL includes post-quantum cryptographic algorithms via OQS provider"
        echo "  Use 'openssl list -providers' to see available providers"
        echo ""
    fi

    echo -e "${GREEN}Documentation:${NC}"
    echo "  Build log: $LOG_FILE"
    echo "  Security features: docs/DSSL_AUDIT_REPORT.md"
    echo "  Implementation: docs/DSSL_REMEDIATION_PLAN.md"
    echo ""

    echo -e "${GREEN}Next steps:${NC}"
    echo "  1. Test DSSSL: openssl version"
    echo "  2. Run applications with enhanced security"
    echo "  3. Consider enabling CNSA 2.0 compliance features"
}

# Main execution
main() {
    show_banner
    parse_args "$@"
    check_scripts

    local start_time=$(date +%s)

    case "$MODE" in
        "deps")
            log_info "Mode: Dependencies only"
            if ! install_dependencies; then
                log_error "Dependency installation failed"
                exit 1
            fi
            log_success "Dependencies installed successfully"
            ;;

        "build")
            log_info "Mode: Build only"
            if ! build_dsssl; then
                log_error "Build failed"
                exit 1
            fi
            ;;

        "install")
            log_info "Mode: Install only"
            if ! install_dsssl; then
                log_error "Installation failed"
                exit 1
            fi
            if ! verify_installation; then
                log_error "Installation verification failed"
                exit 1
            fi
            ;;

        "all")
            log_info "Mode: Full pipeline (deps + build + install)"

            # Dependencies
            if ! install_dependencies; then
                log_error "Dependency installation failed"
                exit 1
            fi

            # Build
            if ! build_dsssl; then
                log_error "Build failed"
                exit 1
            fi

            # Install
            if ! install_dsssl; then
                log_error "Installation failed"
                exit 1
            fi

            # Verify
            if ! verify_installation; then
                log_error "Installation verification failed"
                exit 1
            fi

            # Show completion
            show_post_install
            ;;

        *)
            log_error "Invalid mode: $MODE"
            exit 1
            ;;
    esac

    local end_time=$(date +%s)
    local duration=$((end_time - start_time))

    log_success "Operation completed in ${duration}s"
    log_info "Log saved to: $LOG_FILE"
}

# Run main function
main "$@"
