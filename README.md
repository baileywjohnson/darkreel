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
  <a href="#scalability">Scalability</a> •
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

Every file timestamp on disk reads `2024-01-01T00:00:00Z`. Every chunk is padded to 1, 2, 4, 8, or 16 MB with random data. Upload dates are coarsened to year only. An attacker with root on your server sees uniform blobs with no meaningful metadata.

| Data | Visible to server? |
|------|--------------------|
| File content | **no** - AES-256-GCM, per-file key |
| File names, types, MIME | **no** - encrypted metadata blob |
| File sizes, dimensions, duration | **no** - chunk padding + encrypted metadata |
| Thumbnails | **no** - separate encrypted key |
| Folder structure | **no** - encrypted blob |
| Passwords | **never** - Argon2id hash only |
| Master key | **never** - encrypted, browser-only. Cleared from server memory immediately after login. |
| Usernames | yes |
| File count per user | yes (database row count) |
| Approximate total storage | yes (quantized to 256 KB buckets, padding obscures per-file) |
| Upload timestamps | year only (coarsened) |

## Features

- **End-to-end encrypted** - AES-256-GCM chunk encryption, keys derived from your password via Argon2id. The server stores only opaque blobs.
- **Zero-knowledge metadata** - File names, types, sizes, dimensions, and durations are encrypted into a single blob. The server cannot read any of it.
- **Encrypted streaming** - Videos stream via MSE with chunk-level decryption in a Web Worker. No server-side decryption. Playback starts after the first chunk.
- **Size fingerprinting resistance** - Every encrypted chunk is padded to a bucketed size (1, 2, 4, 8, or 16 MB) with random data, both on disk and over the network. Original file sizes are unrecoverable. Storage quotas are quantized to 256 KB buckets to prevent exact-size fingerprinting in the database.
- **Secure deletion** - Deleted files are overwritten with random data, fsynced, then unlinked. The data is already AES-256-GCM encrypted and the encryption keys are deleted first, making the ciphertext computationally unrecoverable. The overwrite is defense-in-depth. Best-effort on SSDs due to wear leveling.
- **Multi-user** - Each user has an isolated, encrypted library with their own master key. Admin panel for user management.
- **Hash modification** - Random nonces injected into file headers (JPEG COM, PNG tEXt, MP4 free box appended at end, WebM Void) before encryption. Files with identical content produce different ciphertexts, defeating duplicate detection.
- **Chunk integrity verification** - Chunk counts are stored inside the encrypted metadata blob. On download/playback, the client verifies the count matches, detecting truncation attacks where an attacker deletes chunks from the server.
- **Generic file storage** - Not just media. Upload any file type — PDFs, documents, archives, code. Everything is encrypted with the same zero-knowledge scheme.
- **Encrypted folders** - Organize your files into folders. The folder structure is encrypted - only you can see it. Drag-and-drop to reorganize (desktop and mobile touch).
- **Folder download** - Download an entire folder (including subfolders) as a ZIP file, decrypted client-side.
- **Upload progress tracking** - Real-time progress bar on gallery tiles during upload. Encryption progress (0-50%) and network transfer progress (50-100%) via XHR upload events.
- **Image rotation** - Rotate images at the pixel level. The original is securely deleted and replaced with a freshly encrypted copy using new keys.
- **6 color themes** - Classic, cool, forest, neon, ocean, and warm. Stored in localStorage.
- **Recovery codes** - 256-bit recovery code generated at account creation and rotated on every password change. If you lose your password, this is the only way back in. Lose both and your data is gone.
- **Single binary** - One Go binary with an embedded web UI and SQLite. No external dependencies, no containers, no runtime requirements.
- **Self-hosted** - Runs on your hardware. A $6/month VPS is enough. Your data never touches a third-party service.

### Supported formats

- **Video:** MP4, MOV, WEBM, MKV, M4V — with thumbnail generation, streaming playback (MP4/MOV), and in-browser preview
- **Image:** JPG, PNG, GIF, WEBP — with thumbnail generation and in-browser preview
- **Any file:** PDFs, documents, archives, and any other file type can be uploaded and stored with full encryption. Non-media files are displayed with a file icon in the gallery and a download button in the viewer (no preview).

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

The master key never leaves the browser. During login, the server briefly decrypts it to re-encrypt with a session key for the client, then immediately clears it from memory. The master key is also encrypted with a 256-bit recovery code (AAD: userID) generated at account creation and rotated on every password change - shown once, never stored in plaintext.

### Algorithms

| Component | Algorithm | Details |
|-----------|-----------|---------|
| Password hashing | Argon2id | 3 iterations, 64 MB memory, 4 threads |
| Master key derivation | Argon2id | Separate salt from auth hash |
| File encryption | AES-256-GCM | Media ID + chunk index as AAD (prevents reordering and cross-file substitution) |
| Key wrapping | AES-256-GCM | Random nonce, context-bound AAD (user ID or media ID) |
| Metadata encryption | AES-256-GCM | Media ID as AAD (prevents ciphertext substitution) |
| Session key | PBKDF2-SHA256 | 600,000 iterations |
| Chunk padding | Random fill | Bucketed to 1/2/4/8/16 MB per chunk (on disk and over the network) |
| Hash modification | Nonce injection | JPEG COM, PNG tEXt, MP4 free box (appended at end), WebM Void element |
| Secure deletion | 1-pass shred | Random overwrite, fsync, then unlink. Keys deleted first — ciphertext is unrecoverable regardless. |

### AAD binding

All block-level encryption uses Additional Authenticated Data (AAD) to cryptographically bind ciphertext to its context:

- **Master key wrapping** (KDF key, session key, recovery code) uses the **user ID** as AAD
- **File key and thumbnail key wrapping** uses the **media ID** as AAD
- **Metadata encryption** uses the **media ID** as AAD
- **Folder tree encryption** uses the **user ID** as AAD

This prevents ciphertext substitution attacks - an attacker with database access cannot swap encrypted keys or metadata between users or media items. Decryption will fail if the AAD doesn't match.

### On-disk format

```
// encrypted chunk
[nonce: 12 bytes] [ciphertext] [GCM tag: 16 bytes]
// chunk index bound as AAD - reorder and decryption fails

// padded chunk on disk
[real length: 4B big-endian] [encrypted data] [random padding → bucket]
```

## Streaming

Videos are remuxed to fragmented MP4 on upload - no re-encoding. The CLI uses ffmpeg (supports all formats including WEBM/MKV). The browser uses mp4box.js (144 KB, no WASM, supports MP4/MOV).

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

- **Chunk padding wastes disk space and bandwidth.** A 3 MB file becomes 4 MB on disk and over the wire. A 5 MB file becomes 8 MB. Thumbnails are always 256 KB regardless of actual size. This is the cost of preventing size fingerprinting — if an observer can correlate chunk sizes to known files, encryption is weakened.

- **Timestamps are coarsened.** Upload dates are stored as year only. Precise timestamps reveal usage patterns. That precision is deliberately discarded.

- **No server-side thumbnails.** The server can't see your files, so it can't generate thumbnails. The browser encrypts them before upload with a separate per-file key.

- **No recovery without codes.** Lose your password and your recovery code? Your data is cryptographically gone. No backdoor, no admin recovery, no "forgot password" email. This is correct behavior for a zero-knowledge system.

- **SSD deletion is best-effort.** The overwrite pass works on HDDs. On SSDs, wear leveling may retain old data. Since the encryption keys are deleted before shredding, the on-disk ciphertext is computationally unrecoverable regardless. See [Disk encryption (LUKS)](#disk-encryption-luks) for additional mitigation.

- **Quotas are quantized and track logical size, not disk size.** Storage quotas are enforced against the encrypted byte count, quantized to 256 KB buckets to prevent exact-size content fingerprinting. Actual disk usage is higher than the quota suggests because every chunk is padded to a bucket boundary (1/2/4/8/16 MB). This is intentional — exposing exact or padded sizes would leak information that weakens size-fingerprinting resistance.

## Scalability

Darkreel is designed to run well on a single machine, from a $6/month VPS to a dedicated server.

| Metric | Tested | Notes |
|--------|--------|-------|
| Users | 100+ | Each user has isolated encrypted storage |
| Media items | 100,000+ | SQLite with covering indexes, WAL mode |
| Total storage | Limited by disk | Quotas enforced per-user |
| Concurrent uploads | 3 per user | Per-user semaphore prevents disk exhaustion |
| Concurrent downloads | Limited by bandwidth | Chunks streamed directly from disk (zero-copy when possible) |
| Startup time | Seconds at 100K items | Parallelized integrity checks |

### What scales well

- **Storage** — flat file layout with UUID directories, no deep nesting. Filesystem performance stays constant regardless of total items.
- **Reads** — chunk serving uses `sendfile(2)` zero-copy transfer (when compression is bypassed for encrypted data). No buffering in Go memory.
- **Writes** — upload chunks stream directly to disk. Peak memory is ~64 KB per concurrent chunk write regardless of chunk size.
- **Database** — SQLite WAL mode with covering indexes. Read queries don't block writes. Connection pool sized to avoid churn.

### Known limitations

- **Concurrent logins** — each login performs two Argon2id derivations (3 iterations, 64 MB RAM, 4 threads each), totaling ~600ms and pinning 8 OS threads. On a machine with 8 cores, only 2 logins can run at full speed concurrently. This is a deliberate security trade-off — weaker KDF parameters would make passwords easier to brute-force.
- **SQLite write contention** — SQLite allows only one writer at a time. With many concurrent uploads from different users, write operations (quota checks, media record inserts) may briefly queue. This is rarely a bottleneck in practice since the I/O-heavy chunk writes don't hold the database lock.
- **Single-machine architecture** — Darkreel does not support horizontal scaling or clustering. For most self-hosted use cases (personal, family, small team), a single machine with adequate disk is more than sufficient.
- **Chunk count sent in plaintext** — The number of chunks per file is sent unencrypted during upload so the server can validate upload completeness. Since chunks are ~1 MB each (or fMP4 segment boundaries), this reveals approximate file size to the server. Exact sizes remain hidden by chunk padding and encrypted metadata.

## Deploy

### One command on a fresh VPS

```bash
git clone https://github.com/baileywjohnson/darkreel.git && cd darkreel
sudo ./setup.sh
# firewall, fail2ban, SSH hardening, TLS via Caddy,
# systemd service, daily backups - all handled
```

Designed for a fresh Ubuntu 22.04+ or Debian 12+ VPS (e.g., a $6/month DigitalOcean droplet, Hetzner VPS, or similar). The script asks for your domain (verified against server IP), an admin password, a per-user storage quota in GB, and optionally a personal SSH user. Safe to re-run.

| Step | What | Why |
|------|------|-----|
| System updates | `apt upgrade`, installs `unattended-upgrades` | Patches known vulnerabilities, keeps them patched automatically |
| Firewall | UFW configured for SSH, HTTP, HTTPS only | Blocks all other inbound traffic |
| fail2ban | Installed and enabled | Auto-bans IPs after failed SSH attempts |
| SSH hardening | Creates personal user, disables root login | Limits attack surface if an SSH key is compromised |
| Deploy user | `deploy` user with limited sudo | For CI/CD - can only copy the binary and restart the service |
| Go | Installs Go if not present | Required to build from source |
| Caddy | Installed and configured | Automatic HTTPS via Let's Encrypt, reverse proxies to Darkreel |
| Darkreel | Built, installed to `/usr/local/bin/` | The application itself |
| systemd service | Hardened service with 15+ security directives | Runs as dedicated `darkreel` user with capability bounding, syscall filtering, namespace restrictions, and more |
| Database backups | Daily cron job at 3 AM, encrypted, 30-day retention | SQLite `.backup` → AES-256-CBC encrypted with a dedicated key |

### When it's done

1. Open `https://your-domain.com` and log in
2. The setup script will display your **recovery code** - save it somewhere safe
3. SSH in as your personal user going forward: `ssh yourname@your-server-ip`

The recovery code is written to a temporary file in the data directory (`{data}/.recovery-code`, chmod 0600), read by the setup script, then securely deleted. It is never logged to stderr or journald. Save it immediately - it's the only way to regain access to your encrypted data if you forget your password. No one - including the server admin - can recover it without this code.

### Manual

```bash
git clone https://github.com/baileywjohnson/darkreel.git && cd darkreel
bash build.sh
DARKREEL_ADMIN_PASSWORD='YourStr0ng!Password' ./darkreel
# listening on :8080 - put Caddy or nginx in front for TLS
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
| `PERSIST_SESSION` | `true` | Cache master key in sessionStorage (survives page refresh). Set to `false` for higher security - see [Session persistence](#session-persistence) |
| `ALLOW_REGISTRATION` | `false` | Initial registration state on first run. Once an admin toggles registration via the admin panel, that setting is persisted to the database and takes precedence over this variable on subsequent restarts. |
| `TRUST_PROXY` | `false` | Trust `X-Forwarded-For` / `X-Real-IP` headers for rate limiting. **Only enable when running behind a trusted reverse proxy** (Caddy, nginx). Without a proxy, clients can spoof these headers to bypass rate limits. |
| `MAX_STORAGE_GB` | **(none)** | Default per-user storage quota in GB (env var fallback). Set to `50` for 50 GB per user. Supports decimals (e.g. `0.5`). Quotas are required — uploads are blocked until a default quota is configured via the admin panel or this variable. The setup script prompts for this automatically. |

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
EnvironmentFile=/etc/darkreel/env
Restart=always
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/darkreel
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
```

### Reverse proxy with Caddy

```
media.example.com {
    reverse_proxy localhost:8080
    log {
        output discard
    }
}
```

Caddy handles TLS automatically via Let's Encrypt. The setup script offers to disable Caddy access logs for privacy (recommended — access logs record client IPs and request paths including media UUIDs). When running behind any reverse proxy, set `TRUST_PROXY=true` so rate limiting uses the real client IP from `X-Forwarded-For` instead of the proxy's address. For nginx, see the [nginx example](#reverse-proxy-nginx) below.

## API

All endpoints except `/health` and `/api/config` require a JWT. JWTs contain user ID, session ID, and admin flag - nothing else.

### Auth

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/auth/register` | Register (returns recovery code) |
| POST | `/api/auth/login` | Login (returns JWT + encrypted master key) |
| POST | `/api/auth/logout` | Logout (immediate session invalidation) |
| POST | `/api/auth/recover` | Reset password with recovery code |
| POST | `/api/auth/change-password` | Change password (re-encrypts master key, rotates recovery code, invalidates all other sessions) |
| DELETE | `/api/auth/account` | Delete account and all media |
| GET | `/api/config` | Server config (registration, session persistence) |

### Media

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/media` | List media (paginated) |
| GET | `/api/media/quota` | Check quota (returns effective quota and current usage) |
| GET | `/api/media/:id` | Get media metadata |
| POST | `/api/media/upload` | Upload (multipart: metadata + thumbnail + chunks). Media ID is client-generated (UUID) for AAD binding. |
| PATCH | `/api/media/:id` | Update metadata (e.g., folder assignment) |
| DELETE | `/api/media/:id` | Secure delete (1-pass shred) |
| GET | `/api/media/:id/chunk/:index` | Download encrypted chunk |
| GET | `/api/media/:id/thumbnail` | Download encrypted thumbnail |

### Folders

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/folders` | Get encrypted folder tree |
| PUT | `/api/folders` | Save encrypted folder tree |

### Admin

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/admin/users` | List users with storage usage |
| POST | `/api/admin/users` | Create user (returns recovery code) |
| DELETE | `/api/admin/users/:id` | Delete user and all their media |
| PATCH | `/api/admin/users/:id/quota` | Raise per-user storage quota (can only be increased) |
| GET | `/api/admin/storage` | Get storage stats (used bytes, allocated quota, disk usage) |
| PUT | `/api/admin/storage/quota` | Set default storage quota for new users |
| POST | `/api/admin/registration` | Toggle registration on/off |

### Health

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check (no auth) - returns `{"status":"ok"}` |

## Operations

### Backups

**The database is load-bearing.** Every encrypted file key lives in `darkreel.db`. Lose the database and every file on disk becomes permanently undecryptable - even with the correct password.

```bash
# Hot backup (server stays running, WAL-safe)
sqlite3 /var/lib/darkreel/darkreel.db ".backup /path/to/backup.db"

# Full backup (stop for consistency)
sudo systemctl stop darkreel
tar czf darkreel-backup-$(date +%Y%m%d).tar.gz /var/lib/darkreel/
sudo systemctl start darkreel
```

Both database and media are required for a full restore. The database without the media means you have keys but no files. The media without the database means you have encrypted blobs with no way to decrypt them.

Backups are safe to store off-site - media is encrypted on disk, keys are encrypted in the database. An attacker with a backup can't decrypt anything without a user's password.

#### SQLite backup with cron

The setup script configures encrypted backups automatically. For manual setups:

```bash
# Generate a backup encryption key (store this separately!)
openssl rand -hex 32 > /etc/darkreel/backup.key
chmod 600 /etc/darkreel/backup.key

# /etc/cron.d/darkreel-backup
# Daily encrypted backup at 3 AM, keep 30 days
0 3 * * * darkreel /bin/bash -c 'BACKUP_TMP=$(mktemp) && sqlite3 /var/lib/darkreel/darkreel.db ".backup $BACKUP_TMP" && openssl enc -aes-256-cbc -salt -pbkdf2 -in "$BACKUP_TMP" -out "/var/lib/darkreel/backups/darkreel-$(date +\%Y\%m\%d).db.enc" -pass file:/etc/darkreel/backup.key && rm -f "$BACKUP_TMP" && find /var/lib/darkreel/backups -name "darkreel-*.db.enc" -mtime +30 -delete'
```

### Upgrading

Migrations run automatically on startup.

```bash
cd /opt/darkreel && git pull && bash build.sh
sudo cp darkreel /usr/local/bin/darkreel
sudo systemctl restart darkreel
```

Or use the auto-updater - checks GitHub for tagged releases, verifies SHA-256 checksum and Ed25519 signature (required — updates are refused if the signing public key is missing), restarts the service:

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

- TLS termination - Caddy or nginx (Darkreel does not handle TLS)
- UFW firewall - SSH, HTTP, HTTPS only
- fail2ban - auto-ban after failed SSH attempts
- SSH hardened - root login disabled, key-only auth
- systemd sandboxing - `NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`, `PrivateDevices`, `CapabilityBoundingSet=`, `SystemCallFilter`, and more
- Dedicated `darkreel` user - minimal permissions
- SRI hashes - frontend JS/CSS integrity verified by browser (including dynamically loaded mp4box.js)
- Rate limiting - 5 auth attempts/min/IP + 10 attempts/15min/username (per-username limits defend against distributed brute-force even when per-IP limits are bypassed)
- Security headers - `nosniff`, `DENY` framing, `no-referrer`, strict CSP, HSTS, `Permissions-Policy`
- COOP/COEP - defense-in-depth for SharedArrayBuffer
- Cache-Control - `no-store` on all API responses to prevent caching of sensitive data
- Graceful shutdown - in-flight requests drain before the database closes
- Session expiration - sessions expire after 24 hours, with periodic cleanup
- Password change - all existing sessions are invalidated immediately
- Admin re-verification - admin status is checked from the database on every admin request
- Timing side-channel mitigation - login and recovery endpoints perform dummy work for non-existent users
- BREACH mitigation - HTTP compression disabled on auth endpoints that return secrets
- Last-admin protection - the system prevents deletion of the last admin account (atomic transaction prevents TOCTOU race)
- Mandatory storage quotas - quotas are required for all users, tracked in bytes for accuracy across all file types. Per-user quotas can only be raised, never lowered. Total allocated quotas are validated against available disk capacity (with a 2 GB reserve). Uploads are blocked until a quota is configured
- Startup integrity checks - orphan cleanup, incomplete upload detection, and size backfill run concurrently with parallelized filesystem checks for fast startup even with large media libraries.
- Proxy-aware rate limiting - `X-Forwarded-For` trust is off by default; must be explicitly enabled via `TRUST_PROXY=true` to prevent header spoofing
- Encrypted backups - database backups encrypted with AES-256-CBC using a dedicated key
- Per-user upload concurrency limit - max 3 concurrent uploads per user, prevents disk exhaustion via parallel uploads
- Network-level padding - chunks and thumbnails sent padded over the wire (not just on disk), so Content-Length reveals only bucket tier
- Master key cleared immediately - server clears the plaintext master key from memory immediately after the login response, not after 24h session expiry
- Recovery code rotation - recovery code is rotated on every password change; old codes are immediately invalidated
- Signed auto-updates - auto-updater refuses to install binaries without a valid Ed25519 signature (hard failure on missing signing key)
- Caddy access log control - setup script offers to disable Caddy access logs for privacy (client IPs and request paths are not logged)
- SQLite secure deletion - `PRAGMA secure_delete=FAST` zeroes deleted database pages when it can do so without extra I/O, balancing privacy with write performance. All data in the database is encrypted, so forensic recovery of raw pages yields only ciphertext.
- Async secure deletion - file shredding runs in a background worker pool so delete operations return immediately. The file key is already removed from the database, making the encrypted data unrecoverable. Pending shreds drain on graceful shutdown
- LRU rate-limiter eviction - IP and account rate limiters evict the oldest entry when at capacity, preventing a botnet from filling the map and blocking all legitimate users
- Batched upload durability - chunk writes are fsynced once after all chunks are written (not per-chunk), maintaining durability guarantees while minimizing I/O overhead
- Static asset caching - JS, CSS, and font files are served with long-lived immutable cache headers. Cache-busting is handled via content-hash query parameters that change on every build. index.html is always revalidated to pick up new asset versions.
- Metadata blob size limits - uploaded encrypted metadata fields are validated against strict size limits (128 bytes for encrypted keys, 64 bytes for nonces, 64 KB for metadata blobs) to prevent database bloat attacks.
- Password-change and account-deletion rate limiting - these endpoints are rate-limited (5/min/IP) in addition to requiring the current password, preventing brute-force attacks via authenticated sessions.
- Streaming chunk uploads - upload chunks are streamed directly to disk without buffering the entire chunk in memory, reducing peak memory usage from ~36 MB to ~64 KB per concurrent chunk write.
- Hashed rate-limiter identifiers - IP addresses and usernames are FNV-64a hashed before storage in rate limiters, so a process memory dump cannot reveal plaintext identifiers
- Privacy-safe logging - server logs contain no usernames, user IDs, media IDs, IP addresses, or file paths. Only generic operational messages are logged
- Storage-layer path validation - media directory paths are validated as UUIDs at the storage layer (defense-in-depth against path traversal, in addition to handler-level validation)
- Upload chunk count enforcement - the server rejects excess chunks immediately during the upload loop, preventing disk exhaustion from clients sending more chunks than declared
- Oversized thumbnail rejection - thumbnails exceeding the 256 KB limit are rejected with a clear error instead of silently truncated, preventing corrupted encrypted data from being stored
- Folder tree random padding - encrypted folder tree blobs are padded with random bytes (not zeros), preventing a database-level attacker from determining exact folder structure size
- Thread-safe PRNG - chunk padding and file shredding use per-goroutine PRNG instances (ChaCha8-seeded from crypto/rand) to avoid data races under concurrent uploads and deletions. No shared mutable state between goroutines.
- Graceful shredder shutdown - the background shredder rejects new work after shutdown begins, preventing panics from sends on a closed channel during graceful server shutdown
- Metadata update size limits - the PATCH metadata endpoint enforces the same blob size limits as upload (64 KB metadata, 64-byte nonces), preventing database bloat via repeated metadata updates
- Dynamic asset cache-busting - dynamically loaded scripts (mp4box.js) include content-hash query parameters derived from their SRI hash, preventing stale browser cache from breaking integrity checks after upgrades
- Generic registration errors - public registration endpoint returns a generic error on failure, preventing username enumeration
- Admin storage coarsening - per-user storage usage shown to admins is coarsened to the nearest GB, reducing per-upload activity monitoring precision while keeping exact values for internal quota enforcement

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

The secure deletion overwrite is defense-in-depth — encryption keys are deleted first, making the ciphertext computationally unrecoverable. The overwrite pass works on traditional HDDs but is unreliable on SSDs due to wear leveling. If your threat model includes physical disk seizure or forensic recovery:

```bash
# Set up LUKS on the data partition (do this BEFORE installing Darkreel)
sudo cryptsetup luksFormat /dev/sdX
sudo cryptsetup open /dev/sdX darkreel-data
sudo mkfs.ext4 /dev/mapper/darkreel-data
sudo mount /dev/mapper/darkreel-data /var/lib/darkreel
```

With LUKS, all data at rest is encrypted at the block level. The combination of Darkreel's application-layer encryption (keys deleted before shredding) and LUKS block-layer encryption provides two independent layers of protection against physical recovery.

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

If you lose both your password and recovery code, your data is permanently inaccessible. No one - including the server admin - can recover your encryption keys. This is by design.

### Upload limits

| Limit | Value |
|-------|-------|
| Max thumbnail | 256 KB |
| Max chunk | 20 MB |
| Max chunks per file | 50,000 |
| Max total upload | 100 GB |
| Per-user storage | Configurable via admin panel or `MAX_STORAGE_GB` (required) |

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

- [darkreel-cli](https://github.com/baileywjohnson/darkreel-cli) - Command-line client. Upload, list, and download encrypted media. ffmpeg-based remuxing for all video formats.
- [PPVDA](https://github.com/baileywjohnson/ppvda) - Privacy-focused video downloader with Darkreel integration.

## License

MIT
