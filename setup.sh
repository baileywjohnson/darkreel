#!/usr/bin/env bash
#
# Darkreel quickstart — sets up Darkreel on a fresh Linux VPS.
#
# What this script does:
#   1. Installs Go (if not present) and Caddy (for automatic TLS)
#   2. Builds Darkreel from source
#   3. Creates a systemd service
#   4. Configures Caddy as a reverse proxy with automatic HTTPS
#   5. Starts everything
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/baileywjohnson/darkreel/main/setup.sh | bash
#
# Or clone first and run locally:
#   git clone https://github.com/baileywjohnson/darkreel.git
#   cd darkreel
#   sudo ./setup.sh
#
set -euo pipefail

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[x]${NC} $1"; exit 1; }

# --- Root check ---
if [ "$(id -u)" -ne 0 ]; then
  error "This script must be run as root (use sudo ./setup.sh)"
fi

# --- Gather input ---
echo -e "${BOLD}Darkreel Setup${NC}"
echo ""

DOMAIN=""
ADMIN_USER="admin"
ADMIN_PASS=""
DATA_DIR="/var/lib/darkreel"
INSTALL_DIR="/usr/local/bin"

read -rp "Domain name (e.g., media.example.com): " DOMAIN
if [ -z "$DOMAIN" ]; then
  error "Domain is required for TLS. Point your DNS A record to this server first."
fi

# Check DNS before proceeding
SERVER_IP=$(curl -sf https://ifconfig.me || curl -sf https://api.ipify.org || echo "")
if [ -n "$SERVER_IP" ]; then
  DOMAIN_IP=$(dig +short "$DOMAIN" 2>/dev/null | tail -1)
  if [ -z "$DOMAIN_IP" ]; then
    warn "Could not resolve $DOMAIN. Make sure the DNS A record points to $SERVER_IP"
    read -rp "Continue anyway? [y/N]: " confirm
    [ "$confirm" != "y" ] && [ "$confirm" != "Y" ] && exit 1
  elif [ "$DOMAIN_IP" != "$SERVER_IP" ]; then
    warn "$DOMAIN resolves to $DOMAIN_IP but this server is $SERVER_IP"
    warn "Caddy will fail to get a TLS certificate unless DNS points here."
    read -rp "Continue anyway? [y/N]: " confirm
    [ "$confirm" != "y" ] && [ "$confirm" != "Y" ] && exit 1
  else
    info "DNS check passed: $DOMAIN -> $SERVER_IP"
  fi
fi

read -rp "Admin username [admin]: " input
ADMIN_USER="${input:-admin}"

while true; do
  read -rsp "Admin password (16+ chars, must include letter, number, symbol): " ADMIN_PASS
  echo ""
  if [ ${#ADMIN_PASS} -ge 16 ]; then
    break
  fi
  warn "Password must be at least 16 characters."
done

echo ""
info "Domain:     $DOMAIN"
info "Admin user: $ADMIN_USER"
info "Data dir:   $DATA_DIR"
echo ""

# --- Install Go ---
if ! command -v go &>/dev/null; then
  info "Installing Go..."
  GO_VERSION="1.23.4"
  ARCH=$(dpkg --print-architecture 2>/dev/null || echo "amd64")
  curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${ARCH}.tar.gz" | tar -C /usr/local -xzf -
  export PATH="/usr/local/go/bin:$PATH"
  echo 'export PATH="/usr/local/go/bin:$PATH"' >> /etc/profile.d/golang.sh
  info "Go $(go version | awk '{print $3}') installed"
else
  info "Go already installed: $(go version | awk '{print $3}')"
fi

# --- Clone or use existing repo ---
REPO_DIR="/opt/darkreel"
if [ -f "main.go" ] && [ -d "internal" ]; then
  info "Using current directory as source"
  REPO_DIR="$(pwd)"
elif [ -d "$REPO_DIR" ]; then
  info "Updating existing repo at $REPO_DIR"
  cd "$REPO_DIR" && git pull --quiet
else
  info "Cloning Darkreel..."
  git clone --quiet https://github.com/baileywjohnson/darkreel.git "$REPO_DIR"
fi
cd "$REPO_DIR"

# --- Build ---
info "Building Darkreel..."
if [ -f "build.sh" ]; then
  bash build.sh
else
  go build -o darkreel .
fi
cp darkreel "$INSTALL_DIR/darkreel"
info "Binary installed to $INSTALL_DIR/darkreel"

# --- Create user and data directory ---
if ! id -u darkreel &>/dev/null; then
  useradd --system --no-create-home --shell /usr/sbin/nologin darkreel
  info "Created system user 'darkreel'"
fi
mkdir -p "$DATA_DIR"
chown darkreel:darkreel "$DATA_DIR"

# --- Install Caddy ---
if ! command -v caddy &>/dev/null; then
  info "Installing Caddy..."
  apt-get update -qq
  apt-get install -y -qq debian-keyring debian-archive-keyring apt-transport-https curl >/dev/null
  curl -fsSL 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  echo "deb [signed-by=/usr/share/keyrings/caddy-stable-archive-keyring.gpg] https://dl.cloudsmith.io/public/caddy/stable/deb/debian any-version main" > /etc/apt/sources.list.d/caddy-stable.list
  apt-get update -qq
  apt-get install -y -qq caddy >/dev/null
  info "Caddy installed"
else
  info "Caddy already installed"
fi

# --- Configure Caddy ---
cat > /etc/caddy/Caddyfile <<EOF
${DOMAIN} {
    reverse_proxy localhost:8080
}
EOF
info "Caddy configured for $DOMAIN (automatic HTTPS via Let's Encrypt)"

# --- Create systemd service ---
cat > /etc/systemd/system/darkreel.service <<EOF
[Unit]
Description=Darkreel — E2E encrypted media server
After=network.target
Wants=caddy.service

[Service]
Type=simple
User=darkreel
Group=darkreel
ExecStart=${INSTALL_DIR}/darkreel -addr 127.0.0.1:8080 -data ${DATA_DIR}
Restart=always
RestartSec=5

# First-run bootstrap (ignored after admin account exists)
Environment=DARKREEL_ADMIN_USERNAME=${ADMIN_USER}
Environment=DARKREEL_ADMIN_PASSWORD=${ADMIN_PASS}

# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${DATA_DIR}
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

# --- Start services ---
systemctl daemon-reload
systemctl enable --now darkreel
systemctl restart caddy

info "Waiting for Darkreel to start..."
for i in $(seq 1 15); do
  if curl -sf http://127.0.0.1:8080/health >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

if curl -sf http://127.0.0.1:8080/health >/dev/null 2>&1; then
  echo ""
  echo -e "${GREEN}${BOLD}Darkreel is running!${NC}"
  echo ""
  echo -e "  ${BOLD}URL:${NC}       https://${DOMAIN}"
  echo -e "  ${BOLD}Username:${NC}  ${ADMIN_USER}"
  echo -e "  ${BOLD}Data dir:${NC}  ${DATA_DIR}"
  echo ""

  # Show recovery code from the file Darkreel writes on first run
  RC_FILE="${DATA_DIR}/RECOVERY_CODE"
  if [ -f "$RC_FILE" ]; then
    RC=$(cat "$RC_FILE")
    echo -e "  ${YELLOW}${BOLD}RECOVERY CODE:${NC}"
    echo -e "  ${BOLD}${RC}${NC}"
    echo ""
    echo -e "  ${YELLOW}Save this code somewhere safe — it is the only way to regain${NC}"
    echo -e "  ${YELLOW}access to your encrypted data if you forget your password.${NC}"
    echo ""
    echo -e "  The code is in ${RC_FILE}"
    echo -e "  ${BOLD}Delete that file after you've saved the code:${NC}"
    echo -e "  sudo rm ${RC_FILE}"
    echo ""
  else
    echo -e "  ${YELLOW}IMPORTANT:${NC} Check the logs for your recovery code:"
    echo -e "  ${BOLD}sudo journalctl -u darkreel --no-pager | grep -i recovery${NC}"
    echo ""
  fi

  echo "  Useful commands:"
  echo "    sudo systemctl status darkreel    # check status"
  echo "    sudo journalctl -fu darkreel      # follow logs"
  echo "    sudo systemctl restart darkreel   # restart"
  echo ""
else
  error "Darkreel failed to start. Check: sudo journalctl -u darkreel --no-pager"
fi
