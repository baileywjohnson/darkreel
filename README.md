# 🍿 Darkreel

End-to-end encrypted video and photo storage with streaming playback. The server never sees your content -- all encryption and decryption happens in your browser.

## Features

- **End-to-end encrypted** -- AES-256-GCM chunk encryption, keys derived from your password via Argon2id. The server stores only opaque blobs.
- **Streaming playback** -- Videos are remuxed to fragmented MP4 on upload. Encrypted chunks are fetched in parallel, decrypted in a Web Worker, and streamed to `<video>` via MediaSource Extensions. Playback starts in seconds, not after the full download.
- **Zero-knowledge metadata** -- File names, types, sizes, dimensions, and durations are encrypted into a single blob. The server cannot read any of it.
- **Chunk padding** -- Every encrypted chunk is padded to a fixed size with random data, preventing file size fingerprinting.
- **Secure deletion** -- Deleted files are overwritten 3 times with random data before unlinking.
- **Multi-user** -- Each user has an isolated, encrypted library with their own master key.
- **Folders** -- Organize your media into folders. The folder structure is encrypted -- only you can see it.
- **Recovery codes** -- 256-bit recovery code generated at account creation. If you forget your password, the recovery code is the only way back in.
- **Single binary** -- One Go binary with an embedded web UI. No external dependencies, no runtime requirements.
- **Self-hosted** -- Your data stays on your hardware.

## Why Darkreel

Most encrypted storage tools encrypt your files but stop there. Darkreel goes further:

- **Size fingerprinting resistance** -- Every encrypted chunk is padded to exactly 1,048,604 bytes with random fill. An observer with full disk access sees uniform blobs — they can't determine original file sizes, distinguish a 500 KB photo from a 900 KB one, or correlate files across backups by size.

- **Secure deletion, not just unlinking** -- When you delete a file, the data is overwritten 3 times with random bytes, fsynced to disk, then unlinked. On spinning disks, deleted data is actually destroyed. Most tools just call `delete()` and trust the filesystem to eventually reclaim the space.

- **Timestamp coarsening** -- Upload timestamps are stored as year + week number only (e.g., "2026-W14"). Most tools store full-precision timestamps, which can reveal usage patterns, time zones, and activity windows. Darkreel deliberately discards this information.

- **14 MB of RAM** -- Darkreel is a single Go binary with an embedded web UI and SQLite. No Docker, no PostgreSQL, no Redis, no S3, no external services. It runs comfortably on a $6/month VPS. Most self-hosted media tools need 1-6 GB of RAM across multiple containers.

- **Hardened deployment in one command** -- The setup script doesn't just install Darkreel. It configures the firewall, fail2ban, SSH hardening, automatic TLS, automatic OS security updates, and daily database backups. Most tools ship a `docker-compose.yml` and leave server hardening as an exercise for the reader.

- **Encrypted video streaming** -- Videos are remuxed to fragmented MP4 on upload — via ffmpeg in the CLI, or ffmpeg WASM in the browser (loaded once in the background, reused across uploads). Each encrypted chunk contains complete MP4 fragments that the browser can decode independently. On playback, 4 chunks are fetched in parallel, decrypted in a Web Worker, and appended to a MediaSource SourceBuffer. Playback starts after the first chunk — no waiting for the full file. No server-side decryption.

## Quick start (VPS)

The setup script is designed for a **fresh Ubuntu/Debian VPS** (e.g., a $6/month DigitalOcean droplet, Hetzner VPS, or similar). It handles everything from system hardening to TLS certificates in a single command.

### Prerequisites

1. A fresh Ubuntu 22.04+ or Debian 12+ VPS with root SSH access
2. A domain or subdomain with a DNS A record pointing to the server's IP address

### Run the setup

```bash
git clone https://github.com/baileywjohnson/darkreel.git
cd darkreel
sudo ./setup.sh
```

The script will prompt you for:

- **Domain name** -- verified against the server's IP before proceeding
- **Darkreel admin username and password** -- for the web UI
- **Personal SSH username** -- creates a non-root user for you to SSH in as (optional but recommended)

### What the script does

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
3. Delete the recovery code file: `sudo rm /var/lib/darkreel/RECOVERY_CODE`
4. SSH in as your personal user going forward: `ssh yourname@your-server-ip`

The recovery code is the only way to regain access to your encrypted data if you forget your password. No one -- including the server admin -- can recover it without this code.

### Running it again

The script is safe to re-run. It will skip steps that are already done (existing users, installed packages, etc.), pull the latest code, rebuild, and restart the service.

## Quick start (manual)

### Prerequisites

- Go 1.22+ (to build from source)
- A TLS reverse proxy (Caddy, nginx, etc.) -- Darkreel does not handle TLS

### Build and run

```bash
git clone https://github.com/baileywjohnson/darkreel.git
cd darkreel
bash build.sh

DARKREEL_ADMIN_PASSWORD='YourStr0ng!Password' ./darkreel
```

The server starts at `http://localhost:8080`. On first run it creates an admin account, prints a recovery code to stderr, and writes it to `data/RECOVERY_CODE`. Save the recovery code somewhere safe and delete the file.

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

## Configuration

### CLI flags

```
./darkreel [flags]

  -addr string   Listen address (default ":8080")
  -data string   Data directory for database and encrypted files (default "./data")
```

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DARKREEL_ADMIN_USERNAME` | `admin` | Admin username (first-run bootstrap only) |
| `DARKREEL_ADMIN_PASSWORD` | **(required on first run)** | Admin password (first-run bootstrap only) |
| `PERSIST_SESSION` | `false` | Cache master key in sessionStorage (survives page refresh, less secure) |
| `ALLOW_REGISTRATION` | `false` | Allow new user registration via the web UI |

### Account constraints

- Username: 3-64 alphanumeric characters
- Password: 16-128 characters, must contain at least one letter, one number, and one symbol

## How it works

1. Your password derives a **master key** via Argon2id that never leaves your browser
2. Each file gets a random **file key**, encrypted (wrapped) with your master key and stored on the server
3. Videos are remuxed to **fragmented MP4** (no re-encoding) so each chunk is independently decodable
4. Files are split into **1 MB chunks**, each encrypted with AES-256-GCM using the chunk index as additional authenticated data (prevents reordering)
5. All file metadata (name, type, MIME, size, dimensions, duration, codec info) is encrypted into a single blob -- the server stores it opaquely
6. Every chunk is padded to a fixed size on disk with random fill so the server cannot determine original file sizes
7. Your browser fetches chunks in parallel, decrypts them in a Web Worker, and streams to `<video>` via MediaSource Extensions — playback starts after the first chunk

### Key hierarchy

```
Password
  |
  +--> Argon2id(password, authSalt)  --> password hash (for login verification)
  |
  +--> Argon2id(password, kdfSalt)   --> KDF key
         |
         +--> AES-256-GCM decrypt --> master key (lives in browser memory only)
                |
                +--> wraps per-file encryption keys
                +--> wraps per-file thumbnail keys
                +--> encrypts metadata blobs
                +--> encrypts folder structure
```

The master key is also encrypted with a 256-bit recovery code at account creation. The recovery code is shown once and never stored in plaintext.

### Encryption details

| Component | Algorithm | Details |
|-----------|-----------|---------|
| Password hashing | Argon2id | 3 iterations, 64 MB memory, 4 threads |
| Master key derivation | Argon2id | Separate salt from auth hash |
| File encryption | AES-256-GCM | 1 MB chunks, chunk index as AAD |
| Key wrapping | AES-256-GCM | Random nonce per operation |
| Session key (login) | PBKDF2-SHA256 | 600,000 iterations |
| Chunk storage | Padded | Fixed 1,048,604 bytes per chunk |
| Secure deletion | 3-pass shred | Random overwrite, fsync, then unlink |

## Privacy and security

### What the server knows

| Data | Visible to server? |
|------|--------------------|
| File content | No -- encrypted with per-file key |
| File name, type, MIME | No -- encrypted in metadata blob |
| File size, dimensions, duration | No -- encrypted in metadata blob |
| Thumbnails | No -- encrypted with separate per-file key |
| Number of files per user | Yes (database row count) |
| Approximate total storage | Yes (disk usage, though padding obscures individual file sizes) |
| Upload timestamps | Coarsened to year + week number only |
| Usernames | Yes (for authentication) |
| Passwords | Never -- hashed with Argon2id |
| Master key | Never -- encrypted with password-derived key |

### Security measures

- **TLS required** -- Darkreel does not handle TLS. Deploy behind a TLS-terminating reverse proxy. Without TLS, everything is plaintext on the wire.
- **Rate limiting** -- 5 auth attempts per minute per IP, 600 requests per minute globally.
- **Session validation** -- JWTs are validated against an in-memory session store. Logout takes effect immediately.
- **Security headers** -- `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, strict `Content-Security-Policy`, and HSTS.
- **SRI hashes** -- Frontend JavaScript and CSS include Subresource Integrity hashes to prevent tampering.
- **Coarsened timestamps** -- Upload dates are stored as year + week only, minimizing metadata leakage.

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

## Upload limits

| Limit | Value |
|-------|-------|
| Max thumbnail | 2 MB |
| Max chunk | 2 MB |
| Max chunks per file | 50,000 (~50 GB) |
| Max total upload | 100 GB |

## API

All endpoints except `/health` and `/api/config` require a JWT (obtained via login). JWTs contain only user ID, session ID, and admin flag.

### Auth

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/auth/register` | Register (returns recovery code) |
| POST | `/api/auth/login` | Login (returns JWT + encrypted master key) |
| POST | `/api/auth/logout` | Logout (invalidates session immediately) |
| POST | `/api/auth/recover` | Reset password with recovery code |
| POST | `/api/auth/change-password` | Change password (re-encrypts master key) |
| DELETE | `/api/auth/account` | Delete account and all media |
| GET | `/api/config` | Server config (registration, session persistence) |

### Media

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/media` | List media (paginated) |
| GET | `/api/media/:id` | Get media metadata |
| POST | `/api/media/upload` | Upload (multipart: metadata + thumbnail + chunks) |
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

### Other

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check (no auth) -- returns `{"status":"ok"}` |

## Data directory

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

## System requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 1 vCPU | 2+ vCPU |
| RAM | 512 MB | 1+ GB |
| Disk | 10 GB | Depends on media library |
| OS | Linux (amd64 or arm64) | Ubuntu 22.04+ / Debian 12+ |

Darkreel is lightweight -- single Go binary, SQLite database, no external services. The main resource requirement is disk space.

## Reverse proxy (nginx)

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

## Backups

**The database is critical.** Every encrypted file key lives in `darkreel.db`. If you lose the database, every file on disk becomes permanently undecryptable -- even with the correct password.

### What to back up

| What | Path | Why |
|------|------|-----|
| Database | `data/darkreel.db` | Contains encrypted file keys, user accounts, metadata |
| Encrypted media | `data/{userID}/` | The actual encrypted chunks (useless without the DB) |

Both are required for a full restore. The database without the media means you have keys but no files. The media without the database means you have encrypted blobs with no way to decrypt them.

### SQLite backup with cron

SQLite's `.backup` command creates a consistent snapshot even while the server is running (WAL mode handles this safely). Do not simply `cp` the database file while the server is running -- it may be in an inconsistent state.

```bash
# /etc/cron.d/darkreel-backup
# Daily backup at 3 AM, keep 7 days
0 3 * * * root sqlite3 /var/lib/darkreel/darkreel.db ".backup '/var/lib/darkreel/backups/darkreel-$(date +\%Y\%m\%d).db'" && find /var/lib/darkreel/backups -name "darkreel-*.db" -mtime +7 -delete
```

Set up the backup directory:

```bash
sudo mkdir -p /var/lib/darkreel/backups
sudo chown darkreel:darkreel /var/lib/darkreel/backups
```

### Full backup (database + media)

For a complete backup including all encrypted media:

```bash
# Stop the server for a fully consistent snapshot
sudo systemctl stop darkreel
tar czf darkreel-backup-$(date +%Y%m%d).tar.gz /var/lib/darkreel/
sudo systemctl start darkreel
```

Or for zero-downtime, back up the database via SQLite's `.backup` command and rsync the media directory:

```bash
sqlite3 /var/lib/darkreel/darkreel.db ".backup /tmp/darkreel-backup.db"
rsync -a /var/lib/darkreel/ /path/to/backup/ --exclude='backups'
cp /tmp/darkreel-backup.db /path/to/backup/darkreel.db
rm /tmp/darkreel-backup.db
```

### Restoring from backup

```bash
sudo systemctl stop darkreel
# Replace the data directory with the backup
sudo cp /path/to/backup/darkreel.db /var/lib/darkreel/darkreel.db
sudo rsync -a /path/to/backup/ /var/lib/darkreel/ --exclude='backups'
sudo chown -R darkreel:darkreel /var/lib/darkreel
sudo systemctl start darkreel
```

### Off-site backup

The backup files are encrypted at rest (file keys are encrypted in the database, media is encrypted on disk) so they are safe to store on remote services. An attacker with access to a backup cannot decrypt your media without a user's password.

## Upgrading

Database migrations run automatically on startup -- no manual migration steps required.

### Manual upgrade

```bash
cd /opt/darkreel  # or wherever you cloned it
git pull
bash build.sh
sudo systemctl stop darkreel
sudo cp darkreel /usr/local/bin/darkreel
sudo systemctl start darkreel
```

### Auto-update from releases

An update script is included that checks GitHub for new tagged releases, downloads the binary, verifies the SHA-256 checksum, and restarts the service. Updates only happen on tagged releases (e.g., `v1.0.0`) -- not every commit to main.

```bash
# Run once to check for updates
sudo ./update.sh

# Install as a daily cron job (checks at 4 AM)
sudo ./update.sh --install

# Remove the cron job
sudo ./update.sh --uninstall
```

Logs go to `/var/log/darkreel-update.log`. The update is atomic: if the checksum doesn't match, nothing is installed.

### Creating a release (for maintainers)

Push a version tag to trigger the release workflow:

```bash
git tag v1.0.0
git push origin v1.0.0
```

GitHub Actions builds binaries for Linux amd64 and arm64, generates SHA-256 checksums, and creates a GitHub release. Self-hosters with auto-update enabled will pick it up within 24 hours.

Check that it's healthy after upgrading:

```bash
curl -sf http://localhost:8080/health
# {"status":"ok"}
```

## Related projects

- [darkreel-cli](https://github.com/baileywjohnson/darkreel-cli) -- Command-line upload tool
- [PPVDA](https://github.com/baileywjohnson/ppvda) -- Privacy-focused video downloader with Darkreel integration

## License

MIT
