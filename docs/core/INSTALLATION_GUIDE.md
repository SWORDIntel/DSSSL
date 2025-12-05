# DSSSL Installation Guide

## System Installation (Replacing System OpenSSL)

This guide covers installing DSSSL as a replacement for system OpenSSL.

**⚠️ WARNING**: Replacing system OpenSSL can affect system stability. Always:
- Test in a non-production environment first
- Create backups before installation
- Have a rollback plan ready
- Understand the implications for your system

## Prerequisites

1. **Root access** - Installation requires root privileges
2. **Build tools** - Ensure build dependencies are installed
3. **Backup space** - Ensure sufficient disk space for backups
4. **Testing environment** - Test in VM or non-critical system first

## Quick Installation

```bash
# Clone DSSSL repository
git clone https://github.com/SWORDIntel/DSSSL.git
cd DSSSL

# Build DSSSL (if not already built)
./util/build-dsllvm-world.sh --clean

# Run installer (as root)
sudo ./install-dsssl.sh
```

## Installation Process

The installer performs the following steps:

1. **Detection** - Detects current OpenSSL installation
2. **Backup** - Creates backup of system OpenSSL
3. **Build** - Builds DSSSL if not already built
4. **Install** - Installs DSSSL binaries and libraries
5. **Verify** - Verifies installation success
6. **Rollback Script** - Creates rollback script for easy restoration

## Installation Options

### Environment Variables

```bash
# Custom installation prefix (default: /usr/local)
INSTALL_PREFIX=/opt/dsssl ./install-dsssl.sh

# Custom backup directory
BACKUP_DIR=/backup/openssl-$(date +%Y%m%d) ./install-dsssl.sh

# Custom log file
LOG_FILE=/var/log/dsssl-install.log ./install-dsssl.sh

# Force installation without confirmation
FORCE_INSTALL=1 ./install-dsssl.sh
```

### Example: Custom Installation

```bash
INSTALL_PREFIX=/opt/dsssl \
BACKUP_DIR=/backup/openssl-backup \
LOG_FILE=/var/log/dsssl-install.log \
./install-dsssl.sh
```

## What Gets Installed

### Binaries
- `/usr/local/bin/openssl` (or `$INSTALL_PREFIX/bin/openssl`)
- `/usr/bin/openssl` (symlink to DSSSL binary)

### Libraries
- `/usr/lib/libssl.so.3` (or `/usr/lib64/libssl.so.3`)
- `/usr/lib/libcrypto.so.3` (or `/usr/lib64/libcrypto.so.3`)
- Symlinks: `libssl.so`, `libcrypto.so`

### Headers
- `/usr/local/include/openssl/` (or `$INSTALL_PREFIX/include/openssl/`)

## Verification

After installation, verify DSSSL is working:

```bash
# Check version
openssl version

# Should show DSSSL or DSMIL in version string
openssl version -a

# Test basic functionality
openssl speed

# Test TLS 1.3
openssl s_client -connect google.com:443 -tls1_3

# Test hybrid KEM (if configured)
openssl s_client -groups X25519MLKEM768 -connect server:443
```

## Rollback

If you need to restore the original OpenSSL:

```bash
# Find backup directory
ls -la /opt/dsssl-backup-*

# Run rollback script
sudo /opt/dsssl-backup-YYYYMMDD-HHMMSS/rollback.sh
```

Or manually restore:

```bash
# Restore binary
sudo cp /opt/dsssl-backup-*/openssl.bin /usr/bin/openssl

# Restore libraries
sudo cp /opt/dsssl-backup-*/lib/* /usr/lib/
sudo ldconfig

# Restore /usr/bin/openssl if it was moved
if [ -f /usr/bin/openssl.system ]; then
    sudo mv /usr/bin/openssl.system /usr/bin/openssl
fi
```

## System Integration

### Update Alternatives (Debian/Ubuntu)

```bash
# Register DSSSL with alternatives system
sudo update-alternatives --install /usr/bin/openssl openssl /usr/local/bin/openssl 100 \
    --slave /usr/lib/libssl.so libssl.so /usr/lib/libssl.so.3 \
    --slave /usr/lib/libcrypto.so libcrypto.so /usr/lib/libcrypto.so.3

# Switch between OpenSSL versions
sudo update-alternatives --config openssl
```

### Systemd Services

If you have services that depend on OpenSSL, restart them:

```bash
# Restart services that use OpenSSL
sudo systemctl restart apache2
sudo systemctl restart nginx
sudo systemctl restart postgresql
# etc.
```

### Package Managers

**Note**: Installing DSSSL may conflict with package managers. Consider:

1. **Holding packages** (Debian/Ubuntu):
   ```bash
   sudo apt-mark hold openssl libssl-dev
   ```

2. **Excluding from updates** (RHEL/CentOS):
   ```bash
   sudo yum versionlock openssl
   ```

## Troubleshooting

### Library Loading Issues

```bash
# Check library paths
ldconfig -p | grep ssl

# Update library cache
sudo ldconfig

# Check library dependencies
ldd /usr/bin/openssl
```

### Version Conflicts

```bash
# Check which OpenSSL is being used
which openssl
openssl version

# Check library versions
ldd $(which openssl) | grep ssl
```

### Build Issues

If DSSSL isn't built:

```bash
# Build manually
cd /path/to/DSSSL
./util/build-dsllvm-world.sh --clean

# Verify build
ls -la .openssl/apps/openssl
ls -la .openssl/libssl.so*
```

### Permission Issues

```bash
# Ensure script is executable
chmod +x install-dsssl.sh

# Run as root
sudo ./install-dsssl.sh
```

## Safety Considerations

### Before Installation

1. **Backup system** - Full system backup recommended
2. **Test environment** - Test in VM or non-production system
3. **Documentation** - Document current OpenSSL version
4. **Dependencies** - List applications using OpenSSL
5. **Maintenance window** - Plan for potential downtime

### After Installation

1. **Test applications** - Test all critical applications
2. **Monitor logs** - Check system logs for errors
3. **Performance** - Monitor performance impact
4. **Security** - Verify security features work
5. **Rollback plan** - Keep rollback script accessible

## Uninstallation

To completely remove DSSSL:

```bash
# Restore original OpenSSL
sudo /opt/dsssl-backup-*/rollback.sh

# Remove DSSSL files
sudo rm -f /usr/local/bin/openssl
sudo rm -f /usr/lib/libssl.so.3
sudo rm -f /usr/lib/libcrypto.so.3
sudo rm -rf /usr/local/include/openssl

# Update library cache
sudo ldconfig
```

## Advanced Configuration

### Custom Build Configuration

```bash
# Build with custom options
cd DSSSL
./Configure dsllvm-world --prefix=/opt/dsssl
make -j$(nproc)
make install

# Then run installer with custom prefix
INSTALL_PREFIX=/opt/dsssl ./install-dsssl.sh
```

### Multiple OpenSSL Versions

To keep both system OpenSSL and DSSSL:

```bash
# Install DSSSL to custom location
INSTALL_PREFIX=/opt/dsssl ./install-dsssl.sh

# Use DSSSL via PATH
export PATH=/opt/dsssl/bin:$PATH
export LD_LIBRARY_PATH=/opt/dsssl/lib:$LD_LIBRARY_PATH

# Or use alternatives system (see above)
```

## Support

For installation issues:

1. Check installation log: `/var/log/dsssl-install.log`
2. Review backup information: `/opt/dsssl-backup-*/backup-info.txt`
3. Verify system compatibility
4. Contact support team

## Security Notes

- DSSSL installation modifies system libraries
- All changes are logged for audit purposes
- Backups are created automatically
- Rollback capability is provided
- Installation requires root privileges

**Classification**: UNCLASSIFIED // FOR OFFICIAL USE ONLY
