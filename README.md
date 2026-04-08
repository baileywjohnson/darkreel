<p align="center">
  <img src="https://em-content.zobj.net/source/apple/391/popcorn_1f37f.png" width="120" />
</p>

<h1 align="center">Darkreel</h1>

<p align="center">
  <strong>Encrypted media storage & streaming.</strong><br>
  Your server stores opaque blobs. Your browser holds the keys.
</p>

<p align="center">
  <a href="https://github.com/baileywjohnson/darkreel/stargazers"><img src="https://img.shields.io/github/stars/baileywjohnson/darkreel?style=flat&color=yellow" alt="Stars"></a>
  <a href="https://github.com/baileywjohnson/darkreel/commits/main"><img src="https://img.shields.io/github/last-commit/baileywjohnson/darkreel?style=flat" alt="Last Commit"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/baileywjohnson/darkreel?style=flat" alt="License"></a>
</p>

<p align="center">
  <a href="https://darkreel.io">Website</a> •
  <a href="#threat-model">Threat Model</a> •
  <a href="#features">Features</a> •
  <a href="#cryptography">Cryptography</a> •
  <a href="#deploy">Deploy</a> •
  <a href="#hardening">Hardening</a> •
  <a href="#api">API</a>
</p>

---

## Threat model

### What the server sees

```
data/
  darkreel.db                      # rows of ciphertext
  f47ac10b-58cc/
    a3d9c8e2-7b14/
      000000.enc   [4.00 MB]       # could be anything
      000001.enc   [2.00 MB]       # padded to bucket size
      000002.enc   [1.00 MB]       # random fill hides real size
      thumb.enc    [256 KB]        # encrypted thumbnail
```

Every file timestamp on disk reads `2024-01-01T00:00:00Z`. Every chunk is padded to 1, 2, 4, 8, or 16 MB with random data. Upload dates are coarsened to year + week number. An attacker with root on your server sees uniform blobs with no meaningful metadata.

| Data | Visible to server? |
|------|--------------------|
| File content | **no** -- AES-256-GCM, per-file key |
| File names, types, MIME | **no** -- encrypted metadata blob |
| File sizes, dimensions, duration | **no** -- chunk padding + encrypted metadata |
| Thumbnails | **no** -- separate encrypted key |
| Folder structure | **no** -- encrypted blob |
| Passwords | **never** -- Argon2id hash only |
| Master key | **never** -- encrypted, browser-only |
| Usernames | yes |
| File count per user | yes (database row count) |
| Approximate total storage | yes (disk usage, though padding obscures per-file) |
| Upload timestamps | year + week only (coarsened) |

## Features

- **End-to-end encrypted** -- AES-256-GCM chunk encryption, keys derived from your password via Argon2id. The server stores only opaque blobs.
- **Zero-knowledge metadata** -- File names, types, sizes, dimensions, and durations are encrypted into a single blob. The server cannot read any of it.
- **Encrypted streaming** -- Videos stream via MSE with chunk-level decryption in a Web Worker. No server-side decryption. Playback starts after the first chunk.
- **Size fingerprinting resistance** -- Every encrypted chunk is padded to a bucketed size (1, 2, 4, 8, or 16 MB) with random data. Original file sizes are unrecoverable from disk.
- **Secure deletion** -- Deleted files are overwritten 3 times with random data, fsynced, then unlinked. Best-effort on SSDs due to wear leveling.
- **Multi-user** -- Each user has an isolated, encrypted library with their own master key. Admin panel for user management.
- **Encrypted folders** -- Organize your media into folders. The folder structure is encrypted -- only you can see it.
- **Recovery codes** -- 256-bit recovery code generated at account creation. If you lose your password, this is the only way back in. Lose both and your data is gone.
- **Single binary** -- One Go binary with an embedded web UI and SQLite. No external dependencies, no containers, no runtime requirements.
- **Self-hosted** -- Runs on your hardware. A $6/month VPS is enough. Your data never touches a third-party service.

### Supported formats

- **Video:** MP4, MOV, WEBM, MKV, M4V
- **Image:** JPG, PNG, GIF, WEBP

> **Note:** Only MP4 and MOV videos support streaming playback when uploaded in the browser. CLI uploads via ffmpeg support all video formats with full streaming.

## Cryptography

### Key hierarchy

```
Password
 ├─ Argon2id(password, authSalt)  →  password hash  (login verification)
 └─ Argon2id(password, kdfSalt)   →  KDF key
     └─ AES-256-GCM decrypt (AAD: userID)  →  master key  (browser memory only)
         ├─ wraps per-file encryption keys    (AAD: mediaID)
         ├─ wraps per-file thumbnail keys     (AAD: mediaID)
         ├─ encrypts metadata blobs           (AAD: mediaID)
         └─ encrypts folder structure         (AAD: userID)
```

The master key never leaves the browser. It's also encrypted with a 256-bit recovery code (AAD: userID) generated at account creation -- shown once, never stored in plaintext.

### Algorithms

| Component | Algorithm | Details |
|-----------|-----------|---------|
| Password hashing | Argon2id | 3 iterations, 64 MB memory, 4 threads |
| Master key derivation | Argon2id | Separate salt from auth hash |
| File encryption | AES-256-GCM | Chunk index as AAD (prevents reordering) |
| Key wrapping | AES-256-GCM | Random nonce, context-bound AAD (user ID or media ID) |
| Metadata encryption | AES-256-GCM | Media ID as AAD (prevents ciphertext substitution) |
| Session key | PBKDF2-SHA256 | 600,000 iterations |
| Chunk padding | Random fill | Bucketed to 1/2/4/8/16 MB per chunk |
| Secure deletion | 3-pass shred | Random overwrite, fsync, then unlink |

### AAD binding

All block-level encryption uses Additional Authenticated Data (AAD) to cryptographically bind ciphertext to its context:

- **Master key wrapping** (KDF key, session key, recovery code) uses the **user ID** as AAD
- **File key and thumbnail key wrapping** uses the **media ID** as AAD
- **Metadata encryption** uses the **media ID** as AAD
- **Folder tree encryption** uses the **user ID** as AAD

This prevents ciphertext substitution attacks -- an attacker with database access cannot swap encrypted keys or metadata between users or media items. Decryption will fail if the AAD doesn't match.

### On-disk format

```
// encrypted chunk
[nonce: 12 bytes] [ciphertext] [GCM tag: 16 bytes]
// chunk index bound as AAD — reorder and decryption fails

// padded chunk on disk
[real length: 4B big-endian] [encrypted data] [random padding → bucket]
```

## Streaming

Videos are remuxed to fragmented MP4 on upload -- no re-encoding. The CLI uses ffmpeg (supports all formats including WEBM/MKV). The browser uses mp4box.js (144 KB, no WASM, supports MP4/MOV).

```
upload:
  container → extract samples → fMP4 segments (~2s)
    → merge into ~1 MB chunks → AES-256-GCM encrypt
    → pad to bucket size → upload

playback:
  fetch chunk (prefetch-ahead) → Web Worker decrypt
    → MediaSource Extensions → <video>
    → playback starts after first chunk

download:
  fetch all chunks → decrypt → fMP4 → standard MP4
```

iOS Safari 17.1+ uses ManagedMediaSource. Non-remuxable formats uploaded via browser are stored as-is and played via blob URL.

## Trade-offs

These are deliberate:

- **Chunk padding wastes disk space.** A 3 MB file becomes 4 MB on disk. A 5 MB file becomes 8 MB. This is the cost of preventing size fingerprinting. If an observer can correlate chunk sizes to known files, encryption is weakened.

- **Timestamps are coarsened.** Upload dates are stored as year + week only. Precise timestamps reveal usage patterns. That precision is deliberately discarded.

- **No server-side thumbnails.** The server can't see your files, so it can't generate thumbnails. The browser encrypts them before upload with a separate per-file key.

- **No recovery without codes.** Lose your password and your recovery code? Your data is cryptographically gone. No backdoor, no admin recovery, no "forgot password" email. This is correct behavior for a zero-knowledge system.

- **SSD deletion is best-effort.** The 3-pass overwrite works on HDDs. On SSDs, wear leveling may retain old data. See [Disk encryption (LUKS)](#disk-encryption-luks) for the recommended mitigation.

## Deploy

### One command on a fresh VPS

```bash
git clone https://github.com/baileywjohnson/darkreel.git && cd darkreel
sudo ./setup.sh
# firewall, fail2ban, SSH hardening, TLS via Caddy,
# systemd service, daily backups — all handled
```

Designed for a fresh Ubuntu 22.04+ or Debian 12+ VPS (e.g., a $6/month DigitalOcean droplet, Hetzner VPS, or similar). The script asks for your domain (verified against server IP), an admin password, and optionally a personal SSH user. Safe to re-run.

| Step | What | Why |
|------|------|-----|
| System updates | `apt upgrade`, installs `unattended-upgrades` | Patches known vulnerabilities, keeps them patched automatically |
| Firewall | UFW configured for SSH, HTTP, HTTPS only | Blocks all other inbound traffic |
| fail2ban | Installed and enabled | Auto-bans IPs after failed SSH attempts |
| SSH hardening | Creates personal user, disables root login | Limits attack surface if an SSH key is compromised |
| Deploy user | `deploy` user with limited sudo | For CI/CD -- can only copy the binary and restart the service |
| Go | Installs Go if not present | Required to build from source |
| Caddy | Installed and configured | Automatic HTTPS via Let's Encrypt, reverse proxies to Darkreel |
| Darkreel | Built, installed to `/usr/local/bin/` | The application itself |
| systemd service | Hardened service (NoNewPrivileges, ProtectSystem, PrivateTmp) | Runs as dedicated `darkreel` user, restricted filesystem access |
| Database backups | Daily cron job at 3 AM, 7-day retention | SQLite `.backup` for consistent snapshots while the server runs |

### When it's done

1. Open `https://your-domain.com` and log in
2. The setup script will display your **recovery code** -- save it somewhere safe
3. The script will offer to delete the recovery code file from disk automatically. If you skip this, delete it manually: `sudo rm /var/lib/darkreel/RECOVERY_CODE`
4. SSH in as your personal user going forward: `ssh yourname@your-server-ip`

The recovery code is the only way to regain access to your encrypted data if you forget your password. No one -- including the server admin -- can recover it without this code.

### Manual

```bash
git clone https://github.com/baileywjohnson/darkreel.git && cd darkreel
bash build.sh
DARKREEL_ADMIN_PASSWORD='YourStr0ng!Password' ./darkreel
# listening on :8080 — put Caddy or nginx in front for TLS
```

~14 MB RAM. One binary. Zero dependencies. No Docker, no PostgreSQL, no Redis, no S3.

### Configuration

```
./darkreel [flags]

  -addr string   Listen address (default ":8080")
  -data string   Data directory for database and encrypted files (default "./data")
```

| Variable | Default | Description |
|----------|---------|-------------|
| `DARKREEL_ADMIN_USERNAME` | `admin` | Admin username (first-run bootstrap only) |
| `DARKREEL_ADMIN_PASSWORD` | **(required on first run)** | Admin password (first-run bootstrap only) |
| `PERSIST_SESSION` | `true` | Cache master key in sessionStorage (survives page refresh). Set to `false` for higher security -- see [Session persistence](#session-persistence) |
| `ALLOW_REGISTRATION` | `false` | Allow new user registration via the web UI |

Password: 16-128 characters, at least one letter, number, and symbol. Username: 3-64 alphanumeric characters.

### Run with systemd

```ini
[Unit]
Description=Darkreel
After=network.target

[Service]
Type=simple
User=darkreel
Group=darkreel
ExecStart=/usr/local/bin/darkreel -addr 127.0.0.1:8080 -data /var/lib/darkreel
Environment=DARKREEL_ADMIN_PASSWORD=YourStr0ng!Password
Restart=always
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/darkreel

[Install]
WantedBy=multi-user.target
```

### Reverse proxy with Caddy

```
media.example.com {
    reverse_proxy localhost:8080
}
```

Caddy handles TLS automatically via Let's Encrypt. For nginx, see the [nginx example](#reverse-proxy-nginx) below.

## API

All endpoints except `/health` and `/api/config` require a JWT. JWTs contain user ID, session ID, and admin flag -- nothing else.

### Auth

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/auth/register` | Register (returns recovery code) |
| POST | `/api/auth/login` | Login (returns JWT + encrypted master key) |
| POST | `/api/auth/logout` | Logout (immediate session invalidation) |
| POST | `/api/auth/recover` | Reset password with recovery code |
| POST | `/api/auth/change-password` | Change password (re-encrypts master key, invalidates all other sessions) |
| DELETE | `/api/auth/account` | Delete account and all media |
| GET | `/api/config` | Server config (registration, session persistence) |

### Media

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/media` | List media (paginated) |
| GET | `/api/media/:id` | Get media metadata |
| POST | `/api/media/upload` | Upload (multipart: metadata + thumbnail + chunks). Media ID is client-generated (UUID) for AAD binding. |
| PATCH | `/api/media/:id` | Update metadata (e.g., folder assignment) |
| DELETE | `/api/media/:id` | Secure delete (3-pass shred) |
| GET | `/api/media/:id/chunk/:index` | Download encrypted chunk |
| GET | `/api/media/:id/thumbnail` | Download encrypted thumbnail |
| GET | `/api/media/:id/download` | Download all chunks concatenated |

### Folders

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/folders` | Get encrypted folder tree |
| PUT | `/api/folders` | Save encrypted folder tree |

### Admin

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/admin/users` | List users |
| POST | `/api/admin/users` | Create user |
| DELETE | `/api/admin/users/:id` | Delete user and all their media |
| POST | `/api/admin/registration` | Toggle registration on/off |

### Health

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check (no auth) -- returns `{"status":"ok"}` |

## Operations

### Backups

**The database is load-bearing.** Every encrypted file key lives in `darkreel.db`. Lose the database and every file on disk becomes permanently undecryptable -- even with the correct password.

```bash
# Hot backup (server stays running, WAL-safe)
sqlite3 /var/lib/darkreel/darkreel.db ".backup /path/to/backup.db"

# Full backup (stop for consistency)
sudo systemctl stop darkreel
tar czf darkreel-backup-$(date +%Y%m%d).tar.gz /var/lib/darkreel/
sudo systemctl start darkreel
```

Both database and media are required for a full restore. The database without the media means you have keys but no files. The media without the database means you have encrypted blobs with no way to decrypt them.

Backups are safe to store off-site -- media is encrypted on disk, keys are encrypted in the database. An attacker with a backup can't decrypt anything without a user's password.

#### SQLite backup with cron

```bash
# /etc/cron.d/darkreel-backup
# Daily backup at 3 AM, keep 7 days
0 3 * * * root sqlite3 /var/lib/darkreel/darkreel.db ".backup '/var/lib/darkreel/backups/darkreel-$(date +\%Y\%m\%d).db'" && find /var/lib/darkreel/backups -name "darkreel-*.db" -mtime +7 -delete
```

### Upgrading

Migrations run automatically on startup.

```bash
cd /opt/darkreel && git pull && bash build.sh
sudo cp darkreel /usr/local/bin/darkreel
sudo systemctl restart darkreel
```

Or use the auto-updater -- checks GitHub for tagged releases, verifies SHA-256, restarts the service:

```bash
sudo ./update.sh              # check once
sudo ./update.sh --install    # daily cron at 4 AM
sudo ./update.sh --uninstall  # remove cron
```

### System requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 1 vCPU | 2+ vCPU |
| RAM | 512 MB | 1+ GB |
| Disk | 10 GB | Depends on media library |
| OS | Linux (amd64 or arm64) | Ubuntu 22.04+ / Debian 12+ |

### Security hardening

The setup script handles all of this. If deploying manually:

- TLS termination -- Caddy or nginx (Darkreel does not handle TLS)
- UFW firewall -- SSH, HTTP, HTTPS only
- fail2ban -- auto-ban after failed SSH attempts
- SSH hardened -- root login disabled, key-only auth
- systemd sandboxing -- `NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`
- Dedicated `darkreel` user -- minimal permissions
- SRI hashes -- frontend JS/CSS integrity verified by browser (including dynamically loaded mp4box.js)
- Rate limiting -- 5 auth attempts/min/IP (uses `X-Real-IP` behind reverse proxy)
- Security headers -- `nosniff`, `DENY` framing, `no-referrer`, strict CSP, HSTS, `Permissions-Policy`
- COOP/COEP -- defense-in-depth for SharedArrayBuffer
- Cache-Control -- `no-store` on all API responses to prevent caching of sensitive data
- Graceful shutdown -- in-flight requests drain before the database closes
- Session expiration -- sessions expire after 24 hours, with periodic cleanup
- Password change -- all existing sessions are invalidated immediately
- Admin re-verification -- admin status is checked from the database on every admin request
- Timing side-channel mitigation -- recovery endpoint performs dummy work for non-existent users

### Session persistence

`PERSIST_SESSION` (default: `true`) controls whether the master encryption key is cached in the browser's `sessionStorage` between page refreshes. This is a convenience vs. security trade-off:

| Setting | Behavior | Security |
|---------|----------|----------|
| `true` (default) | Master key survives page refresh. Users stay logged in until they close the tab or their session expires. | If an attacker achieves XSS or has a malicious browser extension, they could read the key from `sessionStorage`. The tight CSP (`script-src 'self'` + SRI on all scripts) makes XSS difficult, but not impossible. |
| `false` | Master key is cleared on every page refresh. Users must re-enter their password to decrypt their library. | The key only exists in JavaScript memory during the active session. No persistent storage. More secure, but less convenient. |

To disable:

```bash
# In /etc/darkreel/env (or your environment config)
PERSIST_SESSION=false
```

Then restart: `sudo systemctl restart darkreel`

### Disk encryption (LUKS)

The 3-pass secure deletion works on traditional HDDs but is unreliable on SSDs due to wear leveling -- the SSD controller may retain old data in spare sectors even after overwriting. If your threat model includes physical disk seizure or forensic recovery:

```bash
# Set up LUKS on the data partition (do this BEFORE installing Darkreel)
sudo cryptsetup luksFormat /dev/sdX
sudo cryptsetup open /dev/sdX darkreel-data
sudo mkfs.ext4 /dev/mapper/darkreel-data
sudo mount /dev/mapper/darkreel-data /var/lib/darkreel
```

With LUKS, all data at rest is encrypted at the block level. Shredding becomes irrelevant because the underlying blocks are already encrypted -- destroying the LUKS key makes all data unrecoverable regardless of SSD wear leveling.

This is the recommended setup for production deployments on VPS providers where you don't control the physical hardware.

### Recovery codes

On account creation, a 256-bit recovery code is generated and shown once. Save it offline.

If you forget your password:

```bash
curl -X POST https://media.example.com/api/auth/recover \
  -H 'Content-Type: application/json' \
  -d '{"username": "you", "recovery_code": "your-code", "new_password": "NewStr0ng!Password"}'
```

This resets your password, re-encrypts the master key, and returns a new recovery code. Your data remains accessible.

If you lose both your password and recovery code, your data is permanently inaccessible. No one -- including the server admin -- can recover your encryption keys. This is by design.

### Upload limits

| Limit | Value |
|-------|-------|
| Max thumbnail | 256 KB |
| Max chunk | 20 MB |
| Max chunks per file | 50,000 |
| Max total upload | 100 GB |

### Data directory

```
data/
  darkreel.db              # SQLite database
  {userID}/
    {mediaID}/
      000000.enc           # Padded encrypted chunk
      000001.enc
      ...
      thumb.enc            # Encrypted thumbnail
```

All files are created with `0600` permissions, directories with `0700`.

### Reverse proxy (nginx)

```nginx
server {
    listen 443 ssl http2;
    server_name media.example.com;

    ssl_certificate     /etc/letsencrypt/live/media.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/media.example.com/privkey.pem;

    client_max_body_size 0;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Related

- [darkreel-cli](https://github.com/baileywjohnson/darkreel-cli) -- Command-line upload tool. ffmpeg-based remuxing for all video formats.
- [PPVDA](https://github.com/baileywjohnson/ppvda) -- Privacy-focused video downloader with Darkreel integration.

## License

MIT
