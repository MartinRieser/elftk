#!/bin/bash
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# Standalone .deb package builder for elftk
# Usage: ./scripts/build-deb.sh [version]
# Requirements: dpkg-dev, debhelper on Debian/Ubuntu systems

set -e

# Package information
PACKAGE_NAME="elftk"
VERSION="${1:-1.0.0}"
ARCH="$(dpkg --print-architecture)"
MAINTAINER="ELF Symbol Reader Team <noreply@example.com>"
DESCRIPTION="ELF file analysis toolkit for embedded software development"
HOMEPAGE="https://github.com/your-repo/ELFSymbolReader"

echo "Building .deb package for elftk v${VERSION}..."

# Check if we're on a Debian-based system
if ! command -v dpkg-deb >/dev/null 2>&1; then
    echo "Error: dpkg-deb not found. This script requires a Debian-based system."
    echo "Use 'make deb' with Docker for cross-platform building."
    exit 1
fi

# Build the binary first
echo "Building elftk binary..."
make clean
make

# Create package directory structure
PKG_DIR="build/deb/${PACKAGE_NAME}_${VERSION}_${ARCH}"
rm -rf "build/deb"
mkdir -p "${PKG_DIR}/usr/bin"
mkdir -p "${PKG_DIR}/usr/share/doc/${PACKAGE_NAME}"
mkdir -p "${PKG_DIR}/DEBIAN"

# Copy binary
cp build/bin/elftk "${PKG_DIR}/usr/bin/"
chmod 755 "${PKG_DIR}/usr/bin/elftk"

# Copy documentation
cp README.md "${PKG_DIR}/usr/share/doc/${PACKAGE_NAME}/"
cp LICENSE "${PKG_DIR}/usr/share/doc/${PACKAGE_NAME}/"

# Create control file
cat > "${PKG_DIR}/DEBIAN/control" << EOF
Package: ${PACKAGE_NAME}
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: ${ARCH}
Depends: libdwarf1 (>= 0.4.0), libelf1, zlib1g
Maintainer: ${MAINTAINER}
Description: ${DESCRIPTION}
 elftk is a comprehensive ELF file analysis toolkit designed for embedded
 software development. It extracts symbols, functions, variables, and memory
 layouts from ELF binaries using DWARF debug information.
 .
 Key features:
  - ARM, ARM64, RISC-V, and Xtensa architecture support
  - CSV and JSON output formats
  - Symbol and function extraction
  - Memory layout analysis
  - Cross-platform compatibility
Homepage: ${HOMEPAGE}
EOF

# Create postinst script
cat > "${PKG_DIR}/DEBIAN/postinst" << 'EOF'
#!/bin/bash
set -e

# Ensure the binary is executable
chmod 755 /usr/bin/elftk

# Update man database if it exists
if command -v mandb >/dev/null 2>&1; then
    mandb -q || true
fi

exit 0
EOF
chmod 755 "${PKG_DIR}/DEBIAN/postinst"

# Create prerm script
cat > "${PKG_DIR}/DEBIAN/prerm" << 'EOF'
#!/bin/bash
set -e

# Nothing special needed for removal
exit 0
EOF
chmod 755 "${PKG_DIR}/DEBIAN/prerm"

# Build the package
echo "Building .deb package..."
dpkg-deb --build "${PKG_DIR}"

# Move to output directory
mkdir -p build/dist
cp "${PKG_DIR}.deb" "build/dist/"

# Verify the package
echo "Verifying package..."
dpkg-deb --info "build/dist/${PACKAGE_NAME}_${VERSION}_${ARCH}.deb"
echo ""
echo "Package contents:"
dpkg-deb --contents "build/dist/${PACKAGE_NAME}_${VERSION}_${ARCH}.deb"

# Run lintian for package quality check if available
if command -v lintian >/dev/null 2>&1; then
    echo ""
    echo "Running lintian quality check..."
    lintian "build/dist/${PACKAGE_NAME}_${VERSION}_${ARCH}.deb" || true
fi

echo ""
echo "✅ Package built successfully: build/dist/${PACKAGE_NAME}_${VERSION}_${ARCH}.deb"
echo ""
echo "To install:"
echo "  sudo dpkg -i build/dist/${PACKAGE_NAME}_${VERSION}_${ARCH}.deb"
echo "  sudo apt-get install -f  # Install missing dependencies if any"
echo ""
echo "To uninstall:"
echo "  sudo apt-get remove ${PACKAGE_NAME}"