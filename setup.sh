#!/usr/bin/env bash
#
# Darkreel quickstart — sets up Darkreel on a fresh Linux VPS.
#
# What this script does:
#   1. Applies system updates and installs security tooling
#   2. Creates a non-root admin user and a locked-down deploy user
#   3. Configures UFW firewall (SSH, HTTP, HTTPS only)
#   4. Disables root SSH login
#   5. Installs Go (if not present) and Caddy (for automatic TLS)
#   6. Builds Darkreel from source
#   7. Creates a hardened systemd service
#   8. Configures Caddy as a reverse proxy with automatic HTTPS
#   9. Sets up daily database backups via cron
#   10. Starts everything
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
SSH_USER=""
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

read -rp "Darkreel admin username [admin]: " input
ADMIN_USER="${input:-admin}"

while true; do
  read -rsp "Darkreel admin password (16+ chars, must include letter, number, symbol): " ADMIN_PASS
  echo ""
  if [ ${#ADMIN_PASS} -ge 16 ]; then
    break
  fi
  warn "Password must be at least 16 characters."
done

echo ""
read -rp "Create a personal SSH user? Enter username (or leave empty to skip): " SSH_USER

echo ""
info "Domain:     $DOMAIN"
info "Admin user: $ADMIN_USER"
info "Data dir:   $DATA_DIR"
[ -n "$SSH_USER" ] && info "SSH user:   $SSH_USER"
echo ""

# ============================================================
# SYSTEM HARDENING
# ============================================================

# --- System updates ---
info "Applying system updates..."
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq >/dev/null 2>&1
info "System updated"

# --- Install security packages ---
info "Installing security packages..."
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq fail2ban unattended-upgrades ufw >/dev/null
info "fail2ban, unattended-upgrades, and UFW installed"

# --- Enable unattended security updates ---
cat > /etc/apt/apt.conf.d/20auto-upgrades <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
info "Automatic security updates enabled"

# --- Configure fail2ban ---
systemctl enable --now fail2ban >/dev/null 2>&1
info "fail2ban enabled"

# --- Firewall ---
ufw --force reset >/dev/null 2>&1
ufw default deny incoming >/dev/null 2>&1
ufw default allow outgoing >/dev/null 2>&1
ufw allow OpenSSH >/dev/null 2>&1
ufw allow 80 >/dev/null 2>&1
ufw allow 443 >/dev/null 2>&1
ufw --force enable >/dev/null 2>&1
info "UFW firewall enabled (SSH, HTTP, HTTPS only)"

# --- Create personal SSH user ---
if [ -n "$SSH_USER" ]; then
  if ! id -u "$SSH_USER" &>/dev/null; then
    useradd -m -s /bin/bash "$SSH_USER"
    usermod -aG sudo "$SSH_USER"

    # Copy root's SSH keys to the new user
    if [ -f /root/.ssh/authorized_keys ]; then
      mkdir -p "/home/${SSH_USER}/.ssh"
      cp /root/.ssh/authorized_keys "/home/${SSH_USER}/.ssh/"
      chown -R "${SSH_USER}:${SSH_USER}" "/home/${SSH_USER}/.ssh"
      chmod 700 "/home/${SSH_USER}/.ssh"
      chmod 600 "/home/${SSH_USER}/.ssh/authorized_keys"
    fi

    info "Created SSH user '$SSH_USER' with sudo access"
    echo ""
    warn "Set a password for $SSH_USER (needed for sudo):"
    passwd "$SSH_USER"
    echo ""
  else
    info "SSH user '$SSH_USER' already exists"
  fi
fi

# --- Create deploy user (for CI/CD) ---
if ! id -u deploy &>/dev/null; then
  useradd -m -s /bin/bash deploy
  # Only allow copying to the exact binary path, and stop/start the service
  echo 'deploy ALL=(ALL) NOPASSWD: /usr/bin/cp /home/deploy/darkreel /usr/local/bin/darkreel, /usr/bin/systemctl stop darkreel, /usr/bin/systemctl start darkreel, /usr/bin/systemctl restart darkreel' > /etc/sudoers.d/deploy
  chmod 440 /etc/sudoers.d/deploy
  info "Created deploy user with limited sudo"
else
  info "Deploy user already exists"
fi

# --- Install signing public key (for CI/CD binary verification) ---
mkdir -p /etc/darkreel
if [ ! -f /etc/darkreel/signing.pub ]; then
  warn "No signing public key found at /etc/darkreel/signing.pub"
  warn "CI/CD binary verification will fail without it."
  warn "Copy your signing public key to the VPS:"
  warn "  scp ~/.ssh/darkreel_signing.pub youruser@server:/etc/darkreel/signing.pub"
  echo ""
fi

# --- Disable root SSH login ---
if grep -q "^PermitRootLogin yes" /etc/ssh/sshd_config 2>/dev/null || grep -q "^#PermitRootLogin" /etc/ssh/sshd_config 2>/dev/null; then
  if [ -n "$SSH_USER" ]; then
    sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    systemctl restart ssh
    info "Root SSH login disabled"
  else
    warn "Skipping root SSH disable — no personal SSH user was created"
    warn "Run this manually after setting up SSH access for another user:"
    warn "  sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && systemctl restart ssh"
  fi
fi

# ============================================================
# DARKREEL INSTALLATION
# ============================================================

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

# --- Create darkreel system user and data directory ---
if ! id -u darkreel &>/dev/null; then
  useradd --system --no-create-home --shell /usr/sbin/nologin darkreel
  info "Created system user 'darkreel'"
fi
mkdir -p "$DATA_DIR"
chown darkreel:darkreel "$DATA_DIR"

# --- Install Caddy ---
if ! command -v caddy &>/dev/null; then
  info "Installing Caddy..."
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

# --- Set up daily database backups ---
mkdir -p "${DATA_DIR}/backups"
chown darkreel:darkreel "${DATA_DIR}/backups"

cat > /etc/cron.d/darkreel-backup <<EOF
# Daily Darkreel database backup at 3 AM, keep 7 days
0 3 * * * darkreel sqlite3 ${DATA_DIR}/darkreel.db ".backup '${DATA_DIR}/backups/darkreel-\$(date +\\%Y\\%m\\%d).db'" && find ${DATA_DIR}/backups -name "darkreel-*.db" -mtime +7 -delete
EOF
info "Daily database backup configured (3 AM, 7-day retention)"

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

  echo -e "  ${BOLD}What was set up:${NC}"
  echo "    - System updates applied"
  echo "    - UFW firewall (SSH, HTTP, HTTPS only)"
  echo "    - fail2ban (auto-bans brute force SSH attempts)"
  echo "    - Automatic security updates"
  echo "    - Caddy reverse proxy with automatic TLS"
  echo "    - Hardened systemd service"
  echo "    - Daily database backups (${DATA_DIR}/backups/)"
  echo "    - Deploy user for CI/CD (limited sudo)"
  [ -n "$SSH_USER" ] && echo "    - SSH user '$SSH_USER' with sudo access"
  [ -n "$SSH_USER" ] && echo "    - Root SSH login disabled"
  echo ""
  echo "  Useful commands:"
  echo "    sudo systemctl status darkreel    # check status"
  echo "    sudo journalctl -fu darkreel      # follow logs"
  echo "    sudo systemctl restart darkreel   # restart"
  [ -n "$SSH_USER" ] && echo "    ssh ${SSH_USER}@${SERVER_IP:-your-server}       # SSH in"
  echo ""
else
  error "Darkreel failed to start. Check: sudo journalctl -u darkreel --no-pager"
fi
