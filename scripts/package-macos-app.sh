#!/usr/bin/env bash
# ==============================================================================
# OpenAudit macOS .app Bundle Packaging Script
#
# Builds a standalone macOS application bundle (.app) for Apple Silicon
# containing the native OpenAudit Desktop GUI with embedded rules, local engine,
# and AppIcon.icns.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DIST_DIR="${WORKSPACE_ROOT}/artifacts/packages"
APP_BUNDLE="${DIST_DIR}/OpenAudit.app"
VERSION="0.1.0-alpha.0"

echo "================================================================================"
echo " Packaging OpenAudit macOS Desktop Application (v${VERSION})"
echo "================================================================================"

mkdir -p "${DIST_DIR}"

# 1. Ensure icons exist
if [ ! -f "${WORKSPACE_ROOT}/packaging/macos/AppIcon.icns" ]; then
    echo "[*] Generating application icon..."
    python3 "${WORKSPACE_ROOT}/scripts/generate_app_icon.py"
fi

# 2. Build release binary for openaudit-desktop
echo "[*] Compiling openaudit-desktop in release mode..."
cargo build --release --bin openaudit-desktop

TARGET_BIN="${WORKSPACE_ROOT}/target/release/openaudit-desktop"
if [ ! -f "${TARGET_BIN}" ]; then
    echo "[-] Error: Release binary not found at ${TARGET_BIN}" >&2
    exit 1
fi

# 3. Create .app bundle directory structure
echo "[*] Constructing OpenAudit.app bundle layout..."
rm -rf "${APP_BUNDLE}"
mkdir -p "${APP_BUNDLE}/Contents/MacOS"
mkdir -p "${APP_BUNDLE}/Contents/Resources"

# 4. Copy binary and assets
cp "${TARGET_BIN}" "${APP_BUNDLE}/Contents/MacOS/openaudit-desktop"
chmod 0755 "${APP_BUNDLE}/Contents/MacOS/openaudit-desktop"

cp "${WORKSPACE_ROOT}/packaging/macos/Info.plist" "${APP_BUNDLE}/Contents/Info.plist"
cp "${WORKSPACE_ROOT}/packaging/macos/AppIcon.icns" "${APP_BUNDLE}/Contents/Resources/AppIcon.icns"

# 5. Code signing: Ad-hoc for local development vs Developer ID for external distribution
# NOTE: Ad-hoc signing (codesign --sign -) permits local Mach-O execution on Apple Silicon.
# It does NOT provide Gatekeeper compliance for external distribution, which requires
# an Apple Developer ID Application certificate and Apple Notarization (xcrun notarytool).
if [ -n "${MACOS_DEVELOPER_ID:-}" ]; then
    echo "[*] Signing with Developer ID Application: ${MACOS_DEVELOPER_ID}..."
    codesign --force --deep --options runtime --timestamp --sign "${MACOS_DEVELOPER_ID}" "${APP_BUNDLE}"
    echo "[+] Developer ID code signature applied."
    if [ "${MACOS_NOTARIZE:-false}" = "true" ]; then
        echo "[*] Notarization requested. Submitting to Apple Notary Service..."
        xcrun notarytool submit "${DIST_DIR}/${ZIP_NAME}" --keychain-profile "AC_PASSWORD" --wait
        xcrun stapler staple "${APP_BUNDLE}"
        echo "[+] Apple Notarization and ticket stapling complete."
    fi
elif command -v codesign >/dev/null 2>&1; then
    echo "[*] Applying ad-hoc code signature for local Apple Silicon development execution..."
    codesign --force --deep --sign - "${APP_BUNDLE}"
    echo "[+] Ad-hoc signature verified for local host execution (NOT notarized for external distribution)."
fi

# 6. Create distributable zip archive
ZIP_NAME="OpenAudit-${VERSION}-macos-aarch64.zip"
echo "[*] Creating distributable archive: ${ZIP_NAME}..."
rm -f "${DIST_DIR}/${ZIP_NAME}"
(cd "${DIST_DIR}" && zip -r -q "${ZIP_NAME}" "OpenAudit.app")

# 7. Update SHA256SUMS
(
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
)

echo "================================================================================"
echo "[+] macOS Application Bundle Created Successfully:"
echo "    App Bundle: ${APP_BUNDLE}"
echo "    Distribution Zip: ${DIST_DIR}/${ZIP_NAME} ($(du -h "${DIST_DIR}/${ZIP_NAME}" | cut -f1))"
echo "--------------------------------------------------------------------------------"
echo " Code-Signing & Gatekeeper Distribution Status:"
if [ -n "${MACOS_DEVELOPER_ID:-}" ]; then
    echo "    Mode: Developer ID Application (${MACOS_DEVELOPER_ID})"
    if [ "${MACOS_NOTARIZE:-false}" = "true" ]; then
        echo "    Notarization: Complete (Gatekeeper compliant for distribution)"
    else
        echo "    Notarization: Pending (Requires notarization before distribution)"
    fi
else
    echo "    Mode: Ad-Hoc Signature (codesign --sign -)"
    echo "    Status: Valid for LOCAL execution on Apple Silicon only."
    echo "    Notice: NOT valid for external distribution. Gatekeeper requires"
    echo "            Developer ID signing and Apple Notarization."
fi
echo "================================================================================"

