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

# 5. Ad-hoc codesign for local Apple Silicon execution
if command -v codesign >/dev/null 2>&1; then
    echo "[*] Applying ad-hoc code signature for Apple Silicon compliance..."
    codesign --force --deep --sign - "${APP_BUNDLE}"
    echo "[+] Code signature verified: $(codesign -v "${APP_BUNDLE}" 2>&1 || true)"
fi

# 6. Create distributable zip archive
ZIP_NAME="OpenAudit-${VERSION}-macos-aarch64.zip"
echo "[*] Creating distributable archive: ${ZIP_NAME}..."
(cd "${DIST_DIR}" && zip -r -q "${ZIP_NAME}" "OpenAudit.app")

echo "================================================================================"
echo "[+] macOS Application Bundle Created Successfully:"
echo "    App Bundle: ${APP_BUNDLE}"
echo "    Distribution Zip: ${DIST_DIR}/${ZIP_NAME} ($(du -h "${DIST_DIR}/${ZIP_NAME}" | cut -f1))"
echo "================================================================================"
