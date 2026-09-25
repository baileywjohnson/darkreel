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
#   9. Sets up daily encrypted database backups via cron (age, offline key)
#   10. Starts everything
#
# Usage — download, read, then run (don't pipe it into a shell: you should
# see what you are about to run as root, and the interactive prompts need
# the terminal's stdin):
#   git clone https://github.com/baileywjohnson/darkreel.git
#   cd darkreel
#   less setup.sh
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
STORAGE_GB=""
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

while true; do
  echo ""
  read -rp "Per-user storage quota in GB (e.g., 50): " STORAGE_GB
  if [ -n "$STORAGE_GB" ] && echo "$STORAGE_GB" | grep -qE '^[0-9]*\.?[0-9]+$' && [ "$STORAGE_GB" != "0" ] && [ "$STORAGE_GB" != "0.0" ]; then
    break
  fi
  warn "Enter a number greater than 0 (e.g., 50, 0.5, 100)"
done

echo ""
read -rp "Create a personal SSH user? Enter username (or leave empty to skip): " SSH_USER

AUTO_UPDATE="n"
echo ""
read -rp "Enable auto-updates from tagged releases? (daily check, checksum verified) [y/N]: " AUTO_UPDATE

# Backups are encrypted with age to a public key; only the matching private
# key (identity) can decrypt them, and it must NOT live on this server.
BACKUP_RECIPIENT_FILE="/etc/darkreel/backup-recipient.txt"
BACKUP_RECIPIENT=""
if [ -f "$BACKUP_RECIPIENT_FILE" ]; then
  BACKUP_RECIPIENT=$(grep -m1 '^age1' "$BACKUP_RECIPIENT_FILE" || true)
fi
if [ -z "$BACKUP_RECIPIENT" ]; then
  echo ""
  echo "Database backups are encrypted to an age public key. Paste one you generated"
  echo "offline (age-keygen on another machine), or leave empty to generate a key"
  echo "pair now — the private key is then shown once and not kept on this server."
  read -rp "age recipient for backups (age1...) [generate]: " BACKUP_RECIPIENT
  if [ -n "$BACKUP_RECIPIENT" ] && ! echo "$BACKUP_RECIPIENT" | grep -qE '^age1[0-9a-z]{58}$'; then
    error "Not an age X25519 recipient (expected age1 followed by 58 characters)"
  fi
fi

DISABLE_ACCESS_LOGS="y"
echo ""
read -rp "Disable Caddy access logs for privacy? (recommended unless you need debugging) [Y/n]: " DISABLE_ACCESS_LOGS_INPUT
[ "$DISABLE_ACCESS_LOGS_INPUT" = "n" ] || [ "$DISABLE_ACCESS_LOGS_INPUT" = "N" ] && DISABLE_ACCESS_LOGS="n"

echo ""
info "Domain:     $DOMAIN"
info "Admin user: $ADMIN_USER"
info "Quota:      ${STORAGE_GB} GB per user"
info "Data dir:   $DATA_DIR"
[ -n "$SSH_USER" ] && info "SSH user:   $SSH_USER"
[ "$AUTO_UPDATE" = "y" ] || [ "$AUTO_UPDATE" = "Y" ] && info "Auto-update: enabled"
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

# sqlite3 + age for the nightly encrypted backup; jq to read Go's release index.
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq sqlite3 age jq >/dev/null
info "sqlite3, age, and jq installed"

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
chown -R deploy:deploy /home/deploy
chmod 755 /home/deploy

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
# GO_VERSION must match the `go` directive in go.mod. The tarball is verified
# against a SHA-256 before extraction: pinned here for amd64/arm64 (from
# https://go.dev/dl/?mode=json&include=all), looked up in that index for
# other architectures. Update both when bumping go.mod.
if ! command -v go &>/dev/null; then
  info "Installing Go..."
  GO_VERSION="1.26.7"
  ARCH=$(dpkg --print-architecture 2>/dev/null || echo "amd64")
  case "$ARCH" in
    armhf) ARCH="armv6l" ;;
    i386)  ARCH="386" ;;
  esac
  GO_TARBALL="go${GO_VERSION}.linux-${ARCH}.tar.gz"
  case "$GO_TARBALL" in
    go1.26.7.linux-amd64.tar.gz) GO_SHA256="ffb5f8de10c62550dfddab66b36b57030721e0a44a3218e9e1181d7b59f121ca" ;;
    go1.26.7.linux-arm64.tar.gz) GO_SHA256="5a4ec883379d51ee9ce1040d5e87f8d35e20387574dd8c947feb01eabc3c1b37" ;;
    *)
      GO_SHA256=$(curl -fsSL "https://go.dev/dl/?mode=json&include=all" \
        | jq -r --arg f "$GO_TARBALL" '[.[].files[] | select(.filename == $f) | .sha256][0] // empty')
      ;;
  esac
  if ! echo "$GO_SHA256" | grep -qE '^[0-9a-f]{64}$'; then
    error "No SHA-256 found for $GO_TARBALL — refusing to install an unverified Go toolchain"
  fi
  GO_TMP=$(mktemp -d)
  curl -fsSL -o "${GO_TMP}/${GO_TARBALL}" "https://go.dev/dl/${GO_TARBALL}"
  if ! echo "${GO_SHA256}  ${GO_TMP}/${GO_TARBALL}" | sha256sum -c --quiet -; then
    rm -rf "$GO_TMP"
    error "Checksum mismatch for $GO_TARBALL — not installing"
  fi
  rm -rf /usr/local/go
  tar -C /usr/local -xzf "${GO_TMP}/${GO_TARBALL}"
  rm -rf "$GO_TMP"
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
if [ "$DISABLE_ACCESS_LOGS" = "y" ]; then
cat > /etc/caddy/Caddyfile <<EOF
${DOMAIN} {
    reverse_proxy localhost:8080
    log {
        output discard
    }
}
EOF
info "Caddy configured for $DOMAIN (HTTPS, access logs disabled for privacy)"
else
cat > /etc/caddy/Caddyfile <<EOF
${DOMAIN} {
    reverse_proxy localhost:8080
}
EOF
info "Caddy configured for $DOMAIN (HTTPS, access logs enabled)"
fi

# --- Write environment file (restricted permissions) ---
# The admin password is written to a separate one-time bootstrap file
# that is deleted immediately after the first successful start.
# This avoids leaving the plaintext password in the long-lived env file
# and is resilient to interruptions — the bootstrap file persists until
# explicitly removed after a successful health check.
cat > /etc/darkreel/env <<EOF
DARKREEL_ADMIN_USERNAME=${ADMIN_USER}
MAX_STORAGE_GB=${STORAGE_GB}
ALLOW_REGISTRATION=false
# PERSIST_SESSION keeps the browser's keys (as non-extractable CryptoKeys in
# IndexedDB) so a page refresh doesn't require logging in again. Set to
# "false" to require the password after every refresh.
PERSIST_SESSION=true
# Darkreel sits behind the local Caddy configured above, so every request
# arrives from loopback. Without these, all clients share one rate-limit
# bucket and a single client can lock everyone out of login. Only the
# loopback proxy is trusted; the client address is taken from the
# X-Forwarded-For entry Caddy appends.
TRUST_PROXY=true
TRUST_PROXY_CIDR=127.0.0.1/32,::1/128
EOF
chmod 600 /etc/darkreel/env
chown darkreel:darkreel /etc/darkreel/env

# Write the admin password to a separate bootstrap file (deleted after first start)
BOOTSTRAP_FILE="/etc/darkreel/bootstrap.env"
echo "DARKREEL_ADMIN_PASSWORD=${ADMIN_PASS}" > "$BOOTSTRAP_FILE"
chmod 600 "$BOOTSTRAP_FILE"
chown darkreel:darkreel "$BOOTSTRAP_FILE"
info "Environment file written to /etc/darkreel/env (mode 600)"

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
EnvironmentFile=/etc/darkreel/env
EnvironmentFile=-/etc/darkreel/bootstrap.env
Restart=always
RestartSec=5

# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${DATA_DIR}
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
CapabilityBoundingSet=
SystemCallFilter=@system-service
SystemCallArchitectures=native
UMask=0077
LockPersonality=true
MemoryDenyWriteExecute=true

[Install]
WantedBy=multi-user.target
EOF

# --- Set up daily database backups (encrypted, 30-day retention) ---
# Backups live outside the data directory, owned by root: the service can't
# read or delete them, and nothing the server does to its data dir (orphan
# cleanup, a restore) touches them.
BACKUP_DIR="/var/backups/darkreel"
install -d -m 700 -o root -g root "$BACKUP_DIR"

if [ ! -f "$BACKUP_RECIPIENT_FILE" ] || ! grep -q '^age1' "$BACKUP_RECIPIENT_FILE"; then
  if [ -z "$BACKUP_RECIPIENT" ]; then
    # Generate a key pair in memory; only the public half is written to disk.
    BACKUP_IDENTITY=$(age-keygen 2>/dev/null)
    BACKUP_RECIPIENT=$(echo "$BACKUP_IDENTITY" | age-keygen -y)
    echo ""
    echo -e "${YELLOW}${BOLD}BACKUP DECRYPTION KEY — shown once, not stored on this server:${NC}"
    echo ""
    echo "$BACKUP_IDENTITY"
    echo ""
    echo -e "${YELLOW}Copy all three lines into a file on another machine or a password manager"
    echo -e "(e.g. darkreel-backup-key.txt). Without it the backups cannot be decrypted;"
    echo -e "anyone who has it (plus a backup) gets the database.${NC}"
    unset BACKUP_IDENTITY
    read -rp "Press Enter once the key is saved somewhere off this server... " _
    clear 2>/dev/null || true
  fi
  echo "$BACKUP_RECIPIENT" > "$BACKUP_RECIPIENT_FILE"
  chown root:root "$BACKUP_RECIPIENT_FILE"
  chmod 644 "$BACKUP_RECIPIENT_FILE"
  info "Backup recipient (public key) saved to $BACKUP_RECIPIENT_FILE"
fi

cat > /usr/local/sbin/darkreel-backup <<'BACKUPEOF'
#!/usr/bin/env bash
# Nightly Darkreel database backup: a consistent SQL dump, encrypted with age
# to the public key in /etc/darkreel/backup-recipient.txt. The plaintext never
# touches disk — sqlite3 streams the dump straight into age — and a failed
# run leaves no partial file behind.
set -euo pipefail
umask 077
DATA_DIR="DATADIR"
BACKUP_DIR="/var/backups/darkreel"
RECIPIENTS="/etc/darkreel/backup-recipient.txt"

out="${BACKUP_DIR}/darkreel-$(date +%Y%m%d).sql.age"
partial=$(mktemp "${BACKUP_DIR}/.darkreel-backup.XXXXXX")
trap 'rm -f "$partial"' EXIT

# Read the database as the service user so SQLite's -wal/-shm files are
# never created root-owned (that would lock the service out of its DB).
runuser -u darkreel -- sqlite3 "${DATA_DIR}/darkreel.db" .dump \
  | age --encrypt -R "$RECIPIENTS" -o "$partial"
mv "$partial" "$out"
find "$BACKUP_DIR" -name 'darkreel-*.age' -mtime +30 -delete
BACKUPEOF
sed -i "s|DATADIR|${DATA_DIR}|g" /usr/local/sbin/darkreel-backup
chown root:root /usr/local/sbin/darkreel-backup
chmod 755 /usr/local/sbin/darkreel-backup

cat > /etc/cron.d/darkreel-backup <<'CRONEOF'
# Daily Darkreel database backup at 3 AM (age-encrypted, 30-day retention).
# Output and failures go to the journal: journalctl -t darkreel-backup
0 3 * * * root /usr/local/sbin/darkreel-backup 2>&1 | logger -t darkreel-backup
CRONEOF
info "Daily encrypted database backup configured (3 AM, ${BACKUP_DIR}, 30-day retention)"

# Earlier versions kept openssl-encrypted backups inside the data directory
# with the key next to them. Leave them for the operator to move or delete.
if [ -d "${DATA_DIR}/backups" ] || [ -f /etc/darkreel/backup.key ]; then
  warn "Old-format backups found (${DATA_DIR}/backups, key /etc/darkreel/backup.key)."
  warn "They use AES-CBC with the key on this host. Once the new backups are verified,"
  warn "move them off the server or delete them:"
  warn "  sudo rm -rf ${DATA_DIR}/backups && sudo shred -u /etc/darkreel/backup.key"
fi

# --- Auto-updates ---
if [ "$AUTO_UPDATE" = "y" ] || [ "$AUTO_UPDATE" = "Y" ]; then
  # Copy update script to a stable location
  if [ -f "${REPO_DIR}/update.sh" ]; then
    cp "${REPO_DIR}/update.sh" "${INSTALL_DIR}/darkreel-update"
    chmod +x "${INSTALL_DIR}/darkreel-update"
    "${INSTALL_DIR}/darkreel-update" --install
  else
    warn "update.sh not found in repo — skipping auto-update setup"
  fi
fi

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
  # Bootstrap succeeded — delete the one-time bootstrap file containing
  # the plaintext admin password. The password is now stored only as an
  # Argon2id hash in the database.
  rm -f /etc/darkreel/bootstrap.env
  info "Bootstrap credentials removed (password stored as hash in DB)"

  echo ""
  echo -e "${GREEN}${BOLD}Darkreel is running!${NC}"
  echo ""
  echo -e "  ${BOLD}URL:${NC}       https://${DOMAIN}"
  echo -e "  ${BOLD}Username:${NC}  ${ADMIN_USER}"
  echo -e "  ${BOLD}Data dir:${NC}  ${DATA_DIR}"
  echo ""

  # Read recovery code from the temp file written by the server.
  RC_FILE="${DATA_DIR}/.recovery-code"
  if [ -f "$RC_FILE" ]; then
    RC=$(cat "$RC_FILE")
    echo -e "  ${YELLOW}${BOLD}RECOVERY CODE:${NC}"
    echo -e "  ${BOLD}${RC}${NC}"
    echo ""
    echo -e "  ${YELLOW}Save this code somewhere safe — it is the only way to regain${NC}"
    echo -e "  ${YELLOW}access to your encrypted data if you forget your password.${NC}"
    echo ""

    # Securely delete the temp file
    shred -u "$RC_FILE" 2>/dev/null || rm -f "$RC_FILE"
    info "Recovery code file deleted"
    echo ""
  else
    echo -e "  ${YELLOW}IMPORTANT:${NC} Check the logs for your recovery code:"
    echo -e "  ${BOLD}sudo journalctl -u darkreel --no-pager | grep 'recovery code'${NC}"
    echo ""
  fi

  echo -e "  ${BOLD}What was set up:${NC}"
  echo "    - System updates applied"
  echo "    - UFW firewall (SSH, HTTP, HTTPS only)"
  echo "    - fail2ban (auto-bans brute force SSH attempts)"
  echo "    - Automatic security updates"
  echo "    - Caddy reverse proxy with automatic TLS"
  echo "    - Hardened systemd service"
  echo "    - Daily age-encrypted database backups (/var/backups/darkreel/)"
  echo "    - Deploy user for CI/CD (limited sudo)"
  [ "$AUTO_UPDATE" = "y" ] || [ "$AUTO_UPDATE" = "Y" ] && echo "    - Auto-updates from tagged releases (daily at 4 AM)"
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
