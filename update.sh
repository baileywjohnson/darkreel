#!/usr/bin/env bash
#
# Darkreel auto-updater — checks for new releases and applies them.
#
# Checks GitHub for the latest tagged release. If it's newer than
# what's installed, downloads the binary, verifies the checksum,
# and restarts the service.
#
# Usage:
#   sudo ./update.sh              # run once
#   sudo ./update.sh --install    # install as a daily cron job
#   sudo ./update.sh --uninstall  # remove the cron job
#
set -euo pipefail

REPO="baileywjohnson/darkreel"
INSTALL_DIR="/usr/local/bin"
BINARY="darkreel"
SERVICE="darkreel"
VERSION_FILE="/var/lib/darkreel/.version"
CRON_FILE="/etc/cron.d/darkreel-update"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[x]${NC} $1"; exit 1; }

# --- Install/uninstall cron ---
if [ "${1:-}" = "--install" ]; then
  if [ "$(id -u)" -ne 0 ]; then
    error "Must be root to install cron job"
  fi
  SCRIPT_PATH=$(readlink -f "$0")
  cat > "$CRON_FILE" <<EOF
# Check for Darkreel updates daily at 4 AM
0 4 * * * root $SCRIPT_PATH >> /var/log/darkreel-update.log 2>&1
EOF
  info "Auto-update cron job installed (daily at 4 AM)"
  info "Logs: /var/log/darkreel-update.log"
  exit 0
fi

if [ "${1:-}" = "--uninstall" ]; then
  rm -f "$CRON_FILE"
  info "Auto-update cron job removed"
  exit 0
fi

# --- Root check ---
if [ "$(id -u)" -ne 0 ]; then
  error "Must be root (use sudo ./update.sh)"
fi

# --- Detect architecture ---
ARCH=$(uname -m)
case "$ARCH" in
  x86_64)  ARCH="amd64" ;;
  aarch64) ARCH="arm64" ;;
  *) error "Unsupported architecture: $ARCH" ;;
esac

# --- Get latest release ---
LATEST=$(curl -sf "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | head -1 | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')

if [ -z "$LATEST" ]; then
  error "Could not fetch latest release from GitHub"
fi

# --- Check current version ---
CURRENT=""
if [ -f "$VERSION_FILE" ]; then
  CURRENT=$(cat "$VERSION_FILE")
fi

if [ "$CURRENT" = "$LATEST" ]; then
  info "Already on latest version ($LATEST)"
  exit 0
fi

info "Update available: ${CURRENT:-unknown} -> $LATEST"

# --- Download binary, checksums, and signature ---
ASSET="darkreel-linux-${ARCH}"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${LATEST}/${ASSET}"
CHECKSUM_URL="https://github.com/${REPO}/releases/download/${LATEST}/checksums.txt"
SIG_URL="https://github.com/${REPO}/releases/download/${LATEST}/${ASSET}.sig"
SIGNING_PUB="/etc/darkreel/signing.pub"

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

info "Downloading $ASSET..."
curl -fsSL -o "${TMP_DIR}/${ASSET}" "$DOWNLOAD_URL" || error "Download failed"
curl -fsSL -o "${TMP_DIR}/checksums.txt" "$CHECKSUM_URL" || error "Checksum download failed"
curl -fsSL -o "${TMP_DIR}/${ASSET}.sig" "$SIG_URL" || error "Signature download failed"

# --- Verify checksum ---
EXPECTED=$(grep "$ASSET" "${TMP_DIR}/checksums.txt" | awk '{print $1}')
ACTUAL=$(sha256sum "${TMP_DIR}/${ASSET}" | awk '{print $1}')

if [ -z "$EXPECTED" ]; then
  error "Could not find checksum for $ASSET in checksums.txt"
fi

if [ "$EXPECTED" != "$ACTUAL" ]; then
  error "Checksum mismatch! Expected: $EXPECTED Got: $ACTUAL"
fi

info "Checksum verified"

# --- Verify Ed25519 signature ---
if [ -f "$SIGNING_PUB" ]; then
  echo -n "$ACTUAL" > "${TMP_DIR}/${ASSET}.hash"
  if openssl pkeyutl -verify -pubin \
    -inkey "$SIGNING_PUB" \
    -rawin -in "${TMP_DIR}/${ASSET}.hash" -sigfile "${TMP_DIR}/${ASSET}.sig" 2>/dev/null; then
    info "Ed25519 signature verified"
  else
    error "Signature verification FAILED — binary may be tampered with"
  fi
else
  error "No signing public key at $SIGNING_PUB — refusing to install unsigned binary. Run setup.sh to configure signature verification."
fi

# --- Install (atomic: copy to temp location, then mv to avoid partial writes) ---
chmod +x "${TMP_DIR}/${ASSET}"
cp "${TMP_DIR}/${ASSET}" "${INSTALL_DIR}/${BINARY}.new"
systemctl stop "$SERVICE"
mv "${INSTALL_DIR}/${BINARY}.new" "${INSTALL_DIR}/${BINARY}"
systemctl start "$SERVICE"

# --- Record version ---
echo "$LATEST" > "$VERSION_FILE"

# --- Health check ---
sleep 2
if curl -sf http://127.0.0.1:8080/health >/dev/null 2>&1; then
  info "Updated to $LATEST successfully"
else
  warn "Service started but health check failed — check logs: journalctl -u $SERVICE"
fi
