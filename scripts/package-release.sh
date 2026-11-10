#!/usr/bin/env bash
# ==============================================================================
# OpenAudit Standalone Release Packaging Script
#
# Builds self-contained production distributions for OpenAudit without requiring
# end users to have Rust, Cargo, Node.js, or development toolchains installed.
#
# Output artifacts in: artifacts/packages/
# - openaudit_<version>_<arch>.deb (Debian / Ubuntu native package)
# - openaudit-<version>-<os>-<arch>.tar.gz (Portable archive)
# - SHA256SUMS (Integrity verification manifest)
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DIST_DIR="${WORKSPACE_ROOT}/artifacts/packages"

VERSION="0.1.0-alpha.0"
RUST_TARGET="${1:-}"
if [ "${RUST_TARGET}" = "--target" ]; then
    RUST_TARGET="${2:-}"
fi

if [ -n "${RUST_TARGET}" ]; then
    case "${RUST_TARGET}" in
        *linux*) OS="linux" ;;
        *darwin*) OS="darwin" ;;
        *) OS="$(uname -s | tr '[:upper:]' '[:lower:]')" ;;
    esac
    ARCH="${RUST_TARGET%%-*}"
else
    OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
    ARCH="$(uname -m)"
fi

# Normalize architecture strings
case "${ARCH}" in
    x86_64|amd64)
        DEB_ARCH="amd64"
        PKG_ARCH="x86_64"
        ;;
    aarch64|arm64)
        DEB_ARCH="arm64"
        PKG_ARCH="aarch64"
        ;;
    *)
        DEB_ARCH="${ARCH}"
        PKG_ARCH="${ARCH}"
        ;;
esac

echo "================================================================================"
echo " Building OpenAudit Standalone Packages (v${VERSION} - ${OS}/${PKG_ARCH})"
echo "================================================================================"

mkdir -p "${DIST_DIR}"

# 1. Compile workspace binaries in release mode
echo "[*] Compiling release binaries..."
if [ -n "${RUST_TARGET}" ]; then
    cargo build --release --target "${RUST_TARGET}" -p openaudit-cli -p openaudit-agent -p openaudit-server --bins
    TARGET_DIR="${CARGO_TARGET_DIR:-${WORKSPACE_ROOT}/target}/${RUST_TARGET}/release"
else
    cargo build --release --bins
    TARGET_DIR="${CARGO_TARGET_DIR:-${WORKSPACE_ROOT}/target}/release"
fi

# Determine target directory
if [ ! -f "${TARGET_DIR}/openaudit-cli" ]; then
    if [ -n "${RUST_TARGET}" ] && [ -f "${WORKSPACE_ROOT}/target/${RUST_TARGET}/release/openaudit-cli" ]; then
        TARGET_DIR="${WORKSPACE_ROOT}/target/${RUST_TARGET}/release"
    elif [ -f "${WORKSPACE_ROOT}/target/release/openaudit-cli" ]; then
        TARGET_DIR="${WORKSPACE_ROOT}/target/release"
    else
        echo "[-] Error: Built binaries not found in ${TARGET_DIR}." >&2
        exit 1
    fi
fi

echo "[+] Release binaries located at: ${TARGET_DIR}"

# 2. Package Portable Archive (.tar.gz)
TARBALL_NAME="openaudit-${VERSION}-${OS}-${PKG_ARCH}.tar.gz"
STAGE_TAR="${DIST_DIR}/stage-tar"
rm -rf "${STAGE_TAR}"
mkdir -p "${STAGE_TAR}/bin" "${STAGE_TAR}/share/openaudit" "${STAGE_TAR}/docs"

cp "${TARGET_DIR}/openaudit-cli" "${STAGE_TAR}/bin/openaudit-cli"
ln -sf "openaudit-cli" "${STAGE_TAR}/bin/openaudit"

if [ -f "${TARGET_DIR}/openaudit-agent" ]; then
    cp "${TARGET_DIR}/openaudit-agent" "${STAGE_TAR}/bin/openaudit-agent"
fi
if [ -f "${TARGET_DIR}/openaudit-server" ]; then
    cp "${TARGET_DIR}/openaudit-server" "${STAGE_TAR}/bin/openaudit-server"
fi

# Bundle runtime resources, configs and docs
cp "${WORKSPACE_ROOT}/LICENSE" "${STAGE_TAR}/"
cp "${WORKSPACE_ROOT}/README.md" "${STAGE_TAR}/"
if [ -f "${WORKSPACE_ROOT}/docs/PACKAGING-AND-DISTRIBUTION.md" ]; then
    cp "${WORKSPACE_ROOT}/docs/PACKAGING-AND-DISTRIBUTION.md" "${STAGE_TAR}/docs/"
fi

if [ "${OS}" = "linux" ]; then
    mkdir -p "${STAGE_TAR}/lib/systemd/system" "${STAGE_TAR}/lib/udev/rules.d"
    cp "${WORKSPACE_ROOT}/packaging/systemd/"*.service "${STAGE_TAR}/lib/systemd/system/" 2>/dev/null || true
    cp "${WORKSPACE_ROOT}/packaging/udev/"*.rules "${STAGE_TAR}/lib/udev/rules.d/" 2>/dev/null || true
elif [ "${OS}" = "darwin" ]; then
    mkdir -p "${STAGE_TAR}/Library/LaunchDaemons"
    cp "${WORKSPACE_ROOT}/packaging/launchd/"*.plist "${STAGE_TAR}/Library/LaunchDaemons/" 2>/dev/null || true
fi

echo "[*] Creating portable distribution archive: ${TARBALL_NAME}..."
tar -czf "${DIST_DIR}/${TARBALL_NAME}" -C "${DIST_DIR}" "stage-tar"
rm -rf "${STAGE_TAR}"
echo "[+] Portable tarball generated: ${DIST_DIR}/${TARBALL_NAME}"

# 3. Package Debian .deb (Linux only, when dpkg-deb is available)
if [ "${OS}" = "linux" ] && command -v dpkg-deb >/dev/null 2>&1; then
    DEB_NAME="openaudit_${VERSION}_${DEB_ARCH}.deb"
    STAGE_DEB="${DIST_DIR}/stage-deb"
    rm -rf "${STAGE_DEB}"

    mkdir -p "${STAGE_DEB}/DEBIAN"
    mkdir -p "${STAGE_DEB}/usr/bin"
    mkdir -p "${STAGE_DEB}/lib/systemd/system"
    mkdir -p "${STAGE_DEB}/lib/udev/rules.d"
    mkdir -p "${STAGE_DEB}/usr/share/doc/openaudit"

    # Install binaries
    install -m 0755 "${TARGET_DIR}/openaudit-cli" "${STAGE_DEB}/usr/bin/openaudit-cli"
    ln -sf "openaudit-cli" "${STAGE_DEB}/usr/bin/openaudit"

    if [ -f "${TARGET_DIR}/openaudit-agent" ]; then
        install -m 0755 "${TARGET_DIR}/openaudit-agent" "${STAGE_DEB}/usr/bin/openaudit-agent"
    fi
    if [ -f "${TARGET_DIR}/openaudit-server" ]; then
        install -m 0755 "${TARGET_DIR}/openaudit-server" "${STAGE_DEB}/usr/bin/openaudit-server"
    fi

    # Install system services and udev rules
    if [ -d "${WORKSPACE_ROOT}/packaging/systemd" ]; then
        install -m 0644 "${WORKSPACE_ROOT}/packaging/systemd/"*.service "${STAGE_DEB}/lib/systemd/system/"
    fi
    if [ -d "${WORKSPACE_ROOT}/packaging/udev" ]; then
        install -m 0644 "${WORKSPACE_ROOT}/packaging/udev/"*.rules "${STAGE_DEB}/lib/udev/rules.d/"
    fi

    # Install documentation and licenses
    install -m 0644 "${WORKSPACE_ROOT}/LICENSE" "${STAGE_DEB}/usr/share/doc/openaudit/copyright"
    install -m 0644 "${WORKSPACE_ROOT}/README.md" "${STAGE_DEB}/usr/share/doc/openaudit/README.md"

    # Process control file
    sed -e "s/{{VERSION}}/${VERSION}/g" \
        -e "s/{{ARCH}}/${DEB_ARCH}/g" \
        "${WORKSPACE_ROOT}/packaging/deb/control.template" > "${STAGE_DEB}/DEBIAN/control"

    install -m 0755 "${WORKSPACE_ROOT}/packaging/deb/postinst" "${STAGE_DEB}/DEBIAN/postinst"
    install -m 0755 "${WORKSPACE_ROOT}/packaging/deb/prerm" "${STAGE_DEB}/DEBIAN/prerm"

    echo "[*] Building Debian package: ${DEB_NAME}..."
    dpkg-deb --build --root-owner-group "${STAGE_DEB}" "${DIST_DIR}/${DEB_NAME}"
    rm -rf "${STAGE_DEB}"
    echo "[+] Debian package generated: ${DIST_DIR}/${DEB_NAME}"
fi

# 4. Generate SHA256 checksums
echo "[*] Generating SHA-256 integrity manifest..."
cd "${DIST_DIR}"
shopt -s nullglob
PKG_FILES=(*.deb *.tar.gz *.zip)
if [ "${#PKG_FILES[@]}" -gt 0 ]; then
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "${PKG_FILES[@]}" > SHA256SUMS
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "${PKG_FILES[@]}" > SHA256SUMS
    fi
fi
shopt -u nullglob

echo "================================================================================"
echo " Packages Built Successfully:"
ls -lh "${DIST_DIR}"
echo "================================================================================"
cat "${DIST_DIR}/SHA256SUMS"
