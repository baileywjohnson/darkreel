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
  <a href="#security-hardening">Hardening</a> •
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

Every media file and directory in the data directory has its modification/access time set to `2024-01-01T00:00:00Z` (directory mtimes are reset after each upload and deletion; `darkreel.db` itself is not). The inode change time (ctime) and, on filesystems that record one, the birth time cannot be set from userspace, so they still show roughly when each item was uploaded — see [Disk encryption](#disk-encryption-luks) for why an encrypted volume is recommended. Every chunk is padded to 1, 2, 4, 8 or 16 MB (then whole MB), every thumbnail to 256 KB. Upload dates are coarsened to year only (delegation records use date granularity — see below). An attacker with root on your server sees uniform blobs with no meaningful metadata beyond chunk counts, bucket sizes and those inode times.

| Data | Visible to server? |
|------|--------------------|
| File content | **no** - AES-256-GCM, per-file key |
| File names, types, MIME | **no** - encrypted metadata blob |
| File sizes, dimensions, duration | **no** exact values (encrypted metadata); approximate size only, from chunk count × bucket size |
| Thumbnails | **no** - separate encrypted key |
| Folder structure | **no** - encrypted blob |
| Passwords | **not stored** - Argon2id hash only. Sent to the server at login, registration, password change and recovery, where the KDF runs (see note) |
| Master key / private key | **not stored** in usable form - wrapped at rest. Held in plaintext only for the duration of a login, password-change or recovery request, then cleared (see note) |
| Usernames, public keys | yes |
| File count per user | yes (database row count) |
| Storage used per user | yes - sum of padded on-disk sizes, which the disk shows anyway |
| Upload timestamps | year only (coarsened) |
| Connected apps | yes - the name and URL the app supplied; authorize / last-used dates at day granularity (see "Timestamps are coarsened") |

> **What "zero-knowledge" means here — and where it stops.** Everything above describes what the server holds **at rest**: a stolen `darkreel.db`, a disk image, or a backup yields only Argon2id hashes and ciphertext, with no way to derive a key. That property is real and is the threat model Darkreel is built for.
>
> It is not the same as the server never seeing the material. Web Crypto has no Argon2id, so the browser cannot run the KDF; the password is sent over TLS and **the server performs the derivation** (see "Concurrent logins" under [Known limitations](#known-limitations)). During a login the server necessarily holds your password and, briefly, your decrypted master key — it is cleared as soon as it has been re-wrapped for the client. Registration and admin-created accounts likewise generate the master key and X25519 keypair server-side. A password change or recovery goes further: the server unwraps the old private key, opens every item's sealed keys to re-seal them, and generates the new keys, all within that one request.
>
> So: a passive operator, a database thief, or anyone with the disk after the fact learns nothing. An operator running **modified server code** can capture the password of anyone who logs in (and the keys of anyone who changes their password), and — because the server also serves the web app — can ship JavaScript that exfiltrates keys from the browser. If that is in your threat model, the mitigation is to run the binary you built from source yourself — which is the intended deployment anyway.


## Features

- **End-to-end encrypted** - AES-256-GCM chunk encryption under random per-file keys; your account keys are wrapped under your password (Argon2id) and a recovery code. The server stores only opaque blobs.
- **Zero-knowledge metadata** - File names, types, exact sizes, dimensions, and durations are encrypted into a single blob. The server cannot read any of it.
- **Encrypted streaming** - Videos stream via MSE with chunk-level decryption in a Web Worker. No server-side decryption. Playback starts after the first chunk.
- **Size fingerprinting resistance** - Clients pad every chunk *inside* the encryption (chunk format 2), so each chunk's ciphertext is exactly 1, 2, 4, 8 or 16 MB (then whole MB) and every thumbnail exactly 256 KB — the server and the network only ever see bucket sizes, never exact lengths (which would fingerprint known videos). Metadata and the folder tree are padded before encryption too. Quota usage is recorded as the padded on-disk size, so the database holds nothing more precise than what the disk already shows.
- **Secure deletion** - Deleted files are overwritten with random data, fsynced, then unlinked. The data is already AES-256-GCM encrypted and the encryption keys are deleted first, making the ciphertext computationally unrecoverable. The overwrite is defense-in-depth. Best-effort on SSDs due to wear leveling.
- **Multi-user** - Each user has an isolated, encrypted library with their own master key. Admin panel for user management; accounts an admin creates must choose their own password at first login.
- **Hash modification** - A random nonce is injected into JPEG (COM segment) and PNG (tEXt chunk) images before encryption, and by the CLI also into MP4s it doesn't remux (a `free` box appended at the end), so the file you get back doesn't hash-match the original. Other formats and remuxed videos are stored unmodified. The nonce is never sent to or stored by the server — a stored copy would let anyone with database access link a leaked image back to the account that uploaded it.
- **Chunk integrity verification** - The chunk count lives in the encrypted metadata, and each chunk carries an encrypted "last chunk" flag. Clients check the flag against the count, so dropping chunks from the end of an item is detected rather than yielding a silently short file. Every chunk is bound to its item and position by AAD.
- **Owner verification** - Anyone who holds your public key — a connected app, or someone with write access to the server's database — can create items that decrypt correctly. Uploads from your own browser or CLI carry an owner tag (an HMAC under a key derived from your master key, covering the item ID and its sealed keys) that nobody else can produce. Items without a valid tag are marked **APP** in the gallery and `[not your upload]` in `darkreel-cli list`; renaming or moving one marks it as yours.
- **Generic file storage** - Not just media. Upload any file type — PDFs, documents, archives, code. Everything is encrypted with the same zero-knowledge scheme.
- **Encrypted folders** - Organize your files into folders. The folder structure is encrypted - only you can see it. Drag-and-drop to reorganize (desktop and mobile touch).
- **Folder download** - Download an entire folder (including subfolders) as a ZIP file, decrypted client-side.
- **Upload progress tracking** - Real-time progress bar on gallery tiles during upload. Encryption progress (0-50%) and network transfer progress (50-100%) via XHR upload events.
- **Image rotation** - Rotate images at the pixel level. The original is securely deleted and replaced with a freshly encrypted copy using new keys.
- **Text editor** - Plain-text files (`.txt`, `.md`, `.log`, `.csv`/`.tsv`, `.json`, `.yaml`/`.yml`, `.xml`, `.ini`/`.conf`/`.cfg`) open directly in the viewer. Click Edit to modify; Save writes a freshly-encrypted copy and deletes the old one in a single action. A "New Text Document" button inside the Upload modal creates blank documents from scratch. 5 MB editor cap; larger text files fall back to Download.
- **6 color themes** - Classic, cool, forest, neon, ocean, and warm. Stored in localStorage.
- **Recovery codes** - 256-bit recovery code generated at account creation and replaced on every password change or recovery. If you lose your password, this is the only way back in. Lose both and your data is gone.
- **Key rotation on password change** - changing your password (or recovering with your recovery code) generates a new master key, X25519 keypair and recovery code, re-seals every item's keys to the new public key, and re-encrypts your folder tree. See [Password change and key rotation](#password-change-and-key-rotation) for what this does and does not protect.
- **Idle lock** - after 30 minutes without interaction (a playing video counts as activity) the web app logs out and drops its keys.
- **Delegated uploads** - Other apps (e.g., [PPVDA](https://github.com/baileywjohnson/ppvda)) can upload to your account without holding your password. Authorize once via a copy-paste consent flow; connected apps get a refresh token that mints short-lived upload-only JWTs. Apps hold your X25519 public key only — they can seal uploads to you but cannot read, list, or delete any existing media, and their uploads show as **APP** (see above). Settings → Connected Apps lists each app with its authorize / last-used / expiry dates and shows your upload-key fingerprint (SHA-256 of your public key) to compare with the one the app displays. Revoke anytime there; a connection also expires after 60 days unused or a year after authorization, whichever comes first, and a password change or recovery revokes them all.
- **Single binary** - One Go binary with an embedded web UI and SQLite. No external dependencies, no containers, no runtime requirements.
- **Self-hosted** - Runs on your hardware. A $6/month VPS is enough. Your data never touches a third-party service.

### Supported formats

- **Video:** MP4, MOV, WEBM, MKV, M4V — with thumbnail generation, streaming playback (MP4/MOV), and in-browser preview
- **Image:** JPG, PNG, GIF, WEBP — with thumbnail generation and in-browser preview
- **Text:** TXT, MD, LOG, CSV/TSV, JSON, YAML/YML, XML, INI/CONF/CFG — opens in an in-browser editor with view, edit, and save. Also supports creating new text documents from within the UI.
- **Any file:** PDFs, documents, archives, and any other file type can be uploaded and stored with full encryption. Non-media files are displayed with a file icon in the gallery and a download button in the viewer (no preview).

> **Note:** Only MP4 and MOV videos support streaming playback when uploaded in the browser.

## Cryptography

### Key hierarchy

```
Password  (sent to the server over TLS; never stored)
 ├─ Argon2id(password, authSalt)             →  password hash  (server: login verification)
 ├─ Argon2id(password, kdfSalt)              →  KDF key        (server: unwraps the stored master key)
 └─ PBKDF2-SHA256(password, kdfSalt, 600k)   →  session key    (browser: unwraps the copy of the
                                                                master key returned at login)
Master key (random 256-bit, per user; replaced on password change / recovery)
 ├─ stored wrapped twice: under the KDF key and under the recovery code (AAD: userID)
 ├─ AES-256-GCM wraps the X25519 private key                         (AAD: userID)
 ├─ AES-256-GCM encrypts the folder tree                              (AAD: userID)
 └─ HKDF-SHA256(info="darkreel-owner-v1")  →  owner-tag HMAC key

X25519 keypair (per user; replaced on password change / recovery)
 ├─ public key       (stored plaintext, handed to browsers and delegated clients)
 └─ private key      (wrapped twice: once by master key, once by recovery code)

Per-file symmetric keys (one trio generated per upload)
 ├─ file key         → AES-256-GCM encrypts chunks     (AAD: mediaID || chunkIndex)
 ├─ thumb key        → AES-256-GCM encrypts thumbnail  (AAD: mediaID || 0)
 └─ metadata key     → AES-256-GCM encrypts metadata   (AAD: mediaID)
    All three keys are sealed to the user's public key → server stores
    the 92-byte sealed blobs alongside the encrypted content.
```

Once login completes, the server has cleared its copy and the master key and private key live only in the browser, as non-extractable `CryptoKey`s: the master key is unwrapped directly into one (its raw bytes are never held in JavaScript), and the private key is imported as one right after it is decrypted. Script running in the page — an XSS, a malicious extension — can use the keys while the page is open, but cannot copy them out to use later.

All uploads (browser, CLI, or delegated third-party) produce the same sealed-box wire format. Delegated clients receive only the public key and never hold the master key or private key, so they can seal uploads to the user but cannot open anything.

### Algorithms

| Component | Algorithm | Details |
|-----------|-----------|---------|
| Password hashing | Argon2id | 3 iterations, 64 MB memory, 4 threads, 32-byte random salt |
| Master-key wrapping key | Argon2id | Same parameters, separate salt from the auth hash. The master key itself is random, not derived |
| File / thumb / metadata encryption | AES-256-GCM | Media ID + chunk index as AAD (prevents reordering and cross-file substitution) |
| Per-file key wrapping | X25519 + HKDF-SHA256 + AES-256-GCM | Sealed-box format: ephemeral X25519 ECDH, HKDF with `info="darkreel-seal-v1"`, AES-256-GCM over the derived key. 92-byte output per 32-byte key. Produces the same wire format whether sealed by browser (Web Crypto), CLI (golang.org/x/crypto), or a delegated client. |
| User keypair | X25519 | Generated at registration and replaced on every password change / recovery, private key dual-wrapped (master key + recovery code), both with user ID as AAD |
| Session key | PBKDF2-SHA256 | 600,000 iterations over the password and KDF salt; wraps the master key in the login / change-password response so the browser can unwrap it without Argon2id |
| Chunk padding | Inside the AEAD | Plaintext frame `version \| last-chunk flag \| length \| data \| zeros` sized so the ciphertext is exactly 1/2/4/8/16 MB (then whole MB); thumbnails exactly 256 KB |
| Metadata padding | Space fill | Bucketed to power-of-2 from 512 B before encryption so blob size doesn't leak filename length (folder tree too) |
| Owner tag | HMAC-SHA256 | Key = HKDF-SHA256(master key, "darkreel-owner-v1"); covers item ID + the three sealed keys; stored in the encrypted metadata |
| Delegation tokens | HS256 JWT (scoped) | 1-hour TTL, `scope=upload`, carries the delegation ID and is refused as soon as that delegation is revoked or expires; rejected on all non-upload endpoints |
| Refresh tokens | 32-byte URL-safe random | Stored server-side as `sha256("darkreel:delegation-refresh-v1\|"‖token)` — DB leak cannot be replayed. Expire after 60 days unused or 1 year after authorization |
| Hash modification | Nonce injection | JPEG COM, PNG tEXt; MP4 free box appended at end (CLI, non-remuxed files only) |
| Secure deletion | 1-pass shred | Random overwrite, fsync, then unlink. Keys deleted first — ciphertext is unrecoverable regardless. |

### AAD binding

All block-level encryption uses Additional Authenticated Data (AAD) to cryptographically bind ciphertext to its context:

- **Master key wrapping** (KDF key, session key, recovery code) uses the **user ID** as AAD
- **Private key wrapping** (under master key and under recovery code) uses the **user ID** as AAD
- **File / thumb / metadata key sealing** uses X25519-ECDH + HKDF; the derived AES-GCM key is per-upload by construction (fresh ephemeral keypair per seal), so there is no separate AAD on the sealed blob — substitution attacks are prevented by the ephemeral key being bound into the ciphertext itself
- **File chunk encryption** uses `UTF-8(mediaID) || BigEndian(uint64(chunkIndex))` as AAD
- **Thumbnail encryption** uses `UTF-8(mediaID) || BigEndian(uint64(0))` as AAD
- **Metadata encryption** uses the **media ID** as AAD
- **Folder tree encryption** uses the **user ID** as AAD

This prevents ciphertext substitution attacks - an attacker with database access cannot swap encrypted keys or metadata between users or media items. Decryption will fail if the AAD doesn't match.

### On-disk format

```
// chunk plaintext (chunk_format 2), padded before encryption
[version=2: 1B] [flags: 1B, bit0 = last chunk] [data length: 4B big-endian] [data] [zeros → bucket]

// encrypted chunk — exactly 1/2/4/8/16 MB (then whole MB); thumbnails 256 KB
[nonce: 12 bytes] [ciphertext] [GCM tag: 16 bytes]
// media ID + chunk index bound as AAD - reorder and decryption fails

// chunk on disk (the length prefix only ever shows a bucket size)
[ciphertext length: 4B big-endian] [encrypted chunk] [random padding → server bucket]
```

Items uploaded before chunk format 2 (no `chunk_format` in their metadata) use unpadded chunk plaintext and are still readable.

## Streaming

Videos are remuxed to fragmented MP4 on upload - no re-encoding. The CLI uses ffmpeg (supports all formats including WEBM/MKV, 1 s fragments). The browser uses mp4box.js (144 KB, no WASM, supports MP4/MOV, ~2 s segments).

```
upload:
  container → extract samples → fMP4 segments
    → merge into chunks that fit the 1 MB bucket
    → frame + pad to bucket size → AES-256-GCM encrypt → upload

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

- **Chunk padding wastes disk space and bandwidth.** Every chunk is padded up to its bucket, so a file costs up to one extra megabyte on disk and over the wire (more when a video segment lands in a larger bucket), and every item carries a 256 KB thumbnail regardless of actual size — a 100-byte text file occupies about 1.25 MB. This is the cost of preventing size fingerprinting — if an observer can correlate chunk sizes to known files, encryption is weakened.

- **Timestamps are coarsened.** Upload dates are stored as year only. Precise timestamps reveal usage patterns. That precision is deliberately discarded.

  Delegation records (`created_at`, `last_used_at` in the Connected Apps panel) are the one exception: they keep **date** granularity rather than year. `last_used_at` is rewritten on every token refresh, so at second precision it would have been a per-second log of when a connected client last uploaded — recoverable by anyone who seizes the database. A date defeats correlation with an observed network event while still letting you spot an app that is active when it shouldn't be, which is the entire point of the panel.

- **No server-side thumbnails.** The server can't see your files, so it can't generate thumbnails. The browser encrypts them before upload with a separate per-file key.

- **No recovery without codes.** Lose your password and your recovery code? Your data is cryptographically gone. No backdoor, no admin recovery, no "forgot password" email. This is correct behavior for a zero-knowledge system.

- **SSD deletion is best-effort.** The overwrite pass works on HDDs. On SSDs, wear leveling may retain old data. Since the encryption keys are deleted before shredding, the on-disk ciphertext is computationally unrecoverable regardless. See [Disk encryption (LUKS)](#disk-encryption-luks) for additional mitigation.

- **Quotas track disk size, including padding.** Every chunk is padded to a bucket boundary (1/2/4/8/16 MB) and every thumbnail to 256 KB, and quota is charged on that on-disk size, enforced as each chunk is written. Small files therefore use more quota than their content size. Charging only the ciphertext bytes let an uploader write ~1 MB of disk per 1-byte chunk for free.

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

- **Concurrent logins** — each login performs two Argon2id derivations (3 iterations, 64 MB RAM, 4 threads each) plus the 600,000-iteration PBKDF2 session key, taking roughly 600 ms. Registration, recovery, password change, account deletion and admin user creation run Argon2id too. All of these share one server-wide gate of 2–4 concurrent requests (by CPU count, so at most 256 MB of KDF memory); a request that can't get a slot within 10 seconds gets HTTP 503. This is a deliberate security trade-off — weaker KDF parameters would make passwords easier to brute-force.
- **SQLite write contention** — SQLite allows only one writer at a time. With many concurrent uploads from different users, write operations (quota checks, media record inserts) may briefly queue. This is rarely a bottleneck in practice since the I/O-heavy chunk writes don't hold the database lock.
- **Single-machine architecture** — Darkreel does not support horizontal scaling or clustering. For most self-hosted use cases (personal, family, small team), a single machine with adequate disk is more than sufficient.
- **Chunk count sent in plaintext** — The number of chunks per file is sent unencrypted during upload so the server can validate upload completeness. Together with the chunk bucket sizes this reveals approximate file size to the server (to within the bucket granularity). Exact sizes remain hidden by padding inside the encryption and by encrypted metadata.

## Deploy

### Setup script on a fresh VPS

```bash
git clone https://github.com/baileywjohnson/darkreel.git && cd darkreel
git log -1                # note the commit you are about to run
less setup.sh             # read what it will do as root
sudo ./setup.sh
# firewall, fail2ban, SSH hardening, TLS via Caddy,
# systemd service, daily encrypted backups - all handled
```

Don't pipe the script from the network into a shell (`curl … | bash`): you can't review what runs as root, the branch it comes from can change between your review and the download, and the script's interactive prompts need the terminal's stdin. Download, inspect, then run.

Designed for a fresh Ubuntu 22.04+ or Debian 12+ VPS (e.g., a $6/month DigitalOcean droplet, Hetzner VPS, or similar). The script asks for your domain (checked against the server's IP), an admin username and password, a per-user storage quota in GB, optionally a personal SSH user, whether to enable auto-updates, an age public key for backups (or generates one), and whether to disable Caddy access logs. Safe to re-run.

| Step | What | Why |
|------|------|-----|
| System updates | `apt upgrade`, installs `unattended-upgrades` | Patches known vulnerabilities, keeps them patched automatically |
| Firewall | UFW configured for SSH, HTTP, HTTPS only | Blocks all other inbound traffic |
| fail2ban | Installed and enabled | Auto-bans IPs after failed SSH attempts |
| SSH hardening | Optionally creates a personal sudo user (copying root's `authorized_keys`); if it does, disables root SSH login | Limits attack surface if an SSH key is compromised. Password authentication is left as it was |
| Deploy user | `deploy` user with limited sudo | For CI/CD - can only copy the binary into place and stop/start/restart the service |
| Go | Installs Go 1.26.7 (the `go.mod` version) if not present, verifying the tarball's SHA-256 before extracting | Required to build from source |
| Caddy | Installed from Caddy's signed apt repository and configured | Automatic HTTPS via Let's Encrypt, reverse proxies to Darkreel |
| Darkreel | Built with `build.sh`, installed to `/usr/local/bin/`; settings in `/etc/darkreel/env` (mode 0600), including `TRUST_PROXY=true` and `TRUST_PROXY_CIDR=127.0.0.1/32,::1/128` for the local Caddy | The application itself |
| systemd service | Hardened service with 15+ security directives | Runs as dedicated `darkreel` user with capability bounding, syscall filtering, namespace restrictions, and more |
| Database backups | Daily cron job at 3 AM, 30-day retention, in root-only `/var/backups/darkreel` | SQLite dump streamed into [age](https://age-encryption.org), encrypted to a public key whose private half is kept off the server |
| Auto-updates (optional) | `update.sh` installed as `/usr/local/bin/darkreel-update`, daily cron at 4 AM | Installs signed release binaries — needs the release signing public key at `/etc/darkreel/signing.pub` (see [Upgrading](#upgrading)) |

### When it's done

1. Open `https://your-domain.com` and log in
2. The setup script will display your **recovery code** - save it somewhere safe
3. If you let the script generate the backup key, it was displayed once (`AGE-SECRET-KEY-1…`) - it must be stored off the server, it is not kept anywhere on it
4. SSH in as your personal user going forward: `ssh yourname@your-server-ip`

On first run the server prints the admin recovery code to stderr with a prominent banner and also writes it to `{data}/.recovery-code` (chmod 0600) so a setup script or automation can pick it up; `setup.sh` shreds that file as soon as it has displayed the code, and the server deletes it after 5 minutes (or on the next start) in any case. Save the code somewhere durable during that window. No one — including the server admin — can recover it afterward. Under systemd the stderr copy also lands in the journal; see [SECURITY.md](SECURITY.md) for how to purge it.

### Manual

```bash
git clone https://github.com/baileywjohnson/darkreel.git && cd darkreel
bash build.sh
DARKREEL_ADMIN_PASSWORD='YourStr0ng!Password' ./darkreel
# listening on 127.0.0.1:8080 - put Caddy or nginx in front for TLS
# (pass `-addr 0.0.0.0:8080` only if you genuinely need a public bind)
```

~14 MB RAM. One binary. Zero dependencies. No Docker, no PostgreSQL, no Redis, no S3.

### Configuration

```
./darkreel [flags]

  -addr string   Listen address (default "127.0.0.1:8080" — loopback only)
  -data string   Data directory for database and encrypted files (default "./data")
```

| Variable | Default | Description |
|----------|---------|-------------|
| `DARKREEL_ADMIN_USERNAME` | `admin` | Admin username (first-run bootstrap only) |
| `DARKREEL_ADMIN_PASSWORD` | **(required on first run)** | Admin password (first-run bootstrap only) |
| `PERSIST_SESSION` | `true` | Keep the (non-extractable) keys in IndexedDB so a page refresh doesn't require logging in again. Set to `false` to require a login after every refresh - see [Session persistence](#session-persistence) |
| `ALLOW_REGISTRATION` | `false` | Initial registration state on first run. Once an admin toggles registration via the admin panel, that setting is persisted to the database and takes precedence over this variable on subsequent restarts. |
| `TRUST_PROXY` | `false` | Take the client address for rate limiting from `X-Forwarded-For` — the rightmost entry that isn't itself a trusted proxy, i.e. the address your proxy appended. `X-Real-IP` and `True-Client-IP` are ignored. **Only enable when running behind a trusted reverse proxy** (Caddy, nginx); `setup.sh` enables it for the Caddy it installs. Behind a proxy with this unset, every client shares the proxy's address and one rate-limit bucket. |
| `TRUST_PROXY_CIDR` | *(unset)* | Comma-separated CIDRs of trusted proxy peers (e.g. `127.0.0.1/32,10.0.0.0/8`). When set along with `TRUST_PROXY=true`, proxy headers are honored *only* from peers inside these networks — necessary if the bind address is reachable beyond the proxy (shared Docker network, cluster mesh). When unset (or if no entry parses — invalid entries are skipped with a warning), all upstreams are trusted, which is safe only if you firewall the bind address to the proxy yourself. |
| `MAX_STORAGE_GB` | **1** | Default per-user storage quota in GB. Set to `50` for 50 GB per user. Supports decimals (e.g. `0.5`). Can also be configured via the admin panel (which takes precedence). The setup script prompts for this automatically. |

Password: 16-128 characters, at least one letter, number, and symbol, no whitespace. Username: 3-64 alphanumeric characters.

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

Caddy handles TLS automatically via Let's Encrypt. The setup script offers to disable Caddy access logs for privacy (recommended — access logs record client IPs and request paths including media UUIDs). When running behind any reverse proxy, set `TRUST_PROXY=true` (and `TRUST_PROXY_CIDR`) so rate limiting uses the real client IP from `X-Forwarded-For` instead of the proxy's address — `setup.sh` does this for you. For nginx, see the [nginx example](#reverse-proxy-nginx) below.

## API

All endpoints except `/health`, `/api/config`, `/api/auth/{register,login,recover}` and `/api/delegation/{exchange,refresh}` require a JWT in the `Authorization: Bearer` header. JWTs contain user ID, session ID, admin flag, and optional scope; session JWTs last 24 hours and are also checked against the server's in-memory session list on every request (logout, password change and server restart end them). Delegation-minted JWTs carry `scope: "upload"` plus the delegation ID; they are rejected by every endpoint except the upload endpoint itself, and by that one too once the delegation is revoked or expired (checked on every request).

Until an admin-created account has changed its password, its session may call only `/api/auth/change-password` and `/api/auth/logout`; everything else returns 403 `password change required`.

A password change or recovery ends every session and delegation (401 afterwards); an upload, metadata edit or folder save already in flight when the keys rotate is refused with 409. Register, login, recover, change-password, account deletion and the two unauthenticated delegation endpoints share a limit of 5 requests/min per IP (see [Security hardening](#security-hardening)).

### Auth

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/auth/register` | Register (only while registration is enabled; returns recovery code; also generates the user's X25519 keypair) |
| POST | `/api/auth/login` | Login (returns JWT, `kdf_salt`, the master key wrapped under the PBKDF2 session key, public key, encrypted private key, `is_admin`, and `must_change_password` for admin-created accounts) |
| POST | `/api/auth/logout` | Logout (immediate session invalidation) |
| POST | `/api/auth/recover` | Reset password with recovery code. Rotates the master key and keypair (re-seals every item, re-encrypts the folder tree), issues a new recovery code, invalidates all sessions, revokes all delegations and pending delegation codes |
| POST | `/api/auth/change-password` | Change password. Same rotation as recover; returns a new session token plus the new `kdf_salt`, `encrypted_master_key`, `public_key`, `encrypted_priv_key` and `recovery_code` — the client must replace its master key **and** keypair |
| DELETE | `/api/auth/account` | Delete account and all media (requires the current password in the body; the last admin can't delete itself) |
| GET | `/api/config` | Server config (registration, session persistence) |

### Media

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/media` | List media (paginated). Each item includes `file_key_sealed`, `thumb_key_sealed`, `metadata_key_sealed` (each 92 bytes). Accepts full-scope JWT only. |
| GET | `/api/media/quota` | Check quota (returns effective quota and current usage). Full scope. |
| GET | `/api/media/:id` | Get media metadata. Full scope. |
| POST | `/api/media/upload` | Upload (multipart: metadata JSON + thumbnail + chunks). Metadata JSON carries the three sealed keys (exactly 92 bytes each), `metadata_enc`/`metadata_nonce`, and `chunk_count` (a `hash_nonce` sent by older clients is accepted and discarded). Media ID is client-generated (UUID) and bound into every AAD. Quota is charged per chunk as it streams in (403 when exceeded); an oversized chunk gets 413. Accepts either full-scope JWT (browser) or `upload`-scoped JWT (delegated client). |
| PATCH | `/api/media/:id` | Update metadata (e.g., folder assignment, rename). Full scope. |
| DELETE | `/api/media/:id` | Secure delete (1-pass shred). Full scope. |
| GET | `/api/media/:id/chunk/:index` | Download encrypted chunk, padded to its bucket (the client strips the 4-byte length prefix and padding). Full scope. |
| GET | `/api/media/:id/thumbnail` | Download encrypted thumbnail (always 256 KB + 4 bytes). Full scope. |

### Delegation (connected apps)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/delegation/authorize` | Mint a one-shot authorization code (120 s TTL) tied to the calling user. Called by the Darkreel SPA when a user approves a client in the "Authorize an App" dialog. Full-scope JWT required. |
| POST | `/api/delegation/exchange` | Consume an authorization code. Returns `{ user_id, public_key, refresh_token, delegation_id, scope }`. No auth (the code is the auth). Atomic via `DELETE ... RETURNING` — a single code cannot be exchanged twice. |
| POST | `/api/delegation/refresh` | Trade a refresh token for a 1 h upload-scoped JWT. No auth (the refresh token is the auth). Refused (and the delegation deleted) after 60 days unused or a year after authorization. Server lookup is via `sha256("darkreel:delegation-refresh-v1"‖token)` so a DB leak cannot be replayed. |
| GET | `/api/account/delegations` | List the caller's active delegations (client name, URL, created_at, last_used_at, expires_on). Full-scope JWT. |
| DELETE | `/api/account/delegations/:id` | Revoke a delegation. Its access tokens stop working immediately and the refresh token can no longer mint new ones. Full-scope JWT. |

### Folders

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/folders` | Get encrypted folder tree. Full scope. |
| PUT | `/api/folders` | Save encrypted folder tree (1 MB request limit). Full scope. |

### Admin

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/admin/users` | List users with storage usage |
| POST | `/api/admin/users` | Create user (returns recovery code). The account must change its password at first login, which replaces that recovery code |
| DELETE | `/api/admin/users/:id` | Delete user and all their media |
| PATCH | `/api/admin/users/:id/quota` | Raise per-user storage quota (can only be increased; total allocation must fit on disk) |
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
# Hot backup (server stays running, WAL-safe). Run as the service user so
# SQLite's -wal/-shm files are never created root-owned.
sudo -u darkreel sqlite3 /var/lib/darkreel/darkreel.db ".backup /path/to/backup.db"

# Full backup (stop for consistency)
sudo systemctl stop darkreel
tar czf darkreel-backup-$(date +%Y%m%d).tar.gz /var/lib/darkreel/
sudo systemctl start darkreel
```

Both database and media are required for a full restore. The database without the media means you have keys but no files. The media without the database means you have encrypted blobs with no way to decrypt them.

Keep backups outside the data directory. Startup cleanup only ever touches UUID-named directories there, but a restore or a mistaken `rm` of the data directory would take anything inside it along.

A backup holds no plaintext media or keys, but it does hold every account's password hash and password- and recovery-code-wrapped keys. Whoever has a backup plus someone's *then-current* password or recovery code can decrypt that account's items as of the backup — a later password change does not undo that for items that already existed (see [Password change and key rotation](#password-change-and-key-rotation)). Encrypt backups, keep the key off the server, and don't keep them longer than you need.

#### Nightly encrypted backups (setup.sh)

`setup.sh` installs `/usr/local/sbin/darkreel-backup`, run by root from `/etc/cron.d/darkreel-backup` at 3 AM:

- `sqlite3 .dump` of the live database (run as the `darkreel` user) is streamed straight into [`age`](https://age-encryption.org), so the plaintext database never touches disk and a failed run leaves no partial file.
- It is encrypted to the age **public key** in `/etc/darkreel/backup-recipient.txt`. The matching private key (identity) is **not** on the server: either you pasted a recipient you generated elsewhere, or setup generated a key pair, printed the identity once, and kept only the public half.
- Output goes to `/var/backups/darkreel/darkreel-YYYYMMDD.sql.age` (root-owned, mode 0700), outside the data directory. Files older than 30 days are deleted.
- Output and errors go to the journal: `journalctl -t darkreel-backup`.

The backups are only on the server until you copy them elsewhere. Because they are encrypted to a key the server doesn't hold, they are safe to ship off-host as-is, e.g. a daily `rsync -a /var/backups/darkreel/ backup-host:darkreel/` or `rclone copy`. Check the first few nights that files are appearing.

To use your own key instead: `age-keygen -o darkreel-backup-key.txt` on another machine, then put the `age1…` public key it prints into `/etc/darkreel/backup-recipient.txt`.

Installs from before this scheme kept AES-CBC (`openssl enc`) backups in `/var/lib/darkreel/backups` with the key in `/etc/darkreel/backup.key` on the same host. Once the new backups are verified, move the old ones off the server or delete them together with that key.

#### Restoring a backup

On a machine that has the age identity:

```bash
age --decrypt -i darkreel-backup-key.txt darkreel-20260101.sql.age > darkreel.sql
```

On the server (with the media directories from the same point in time or later still in place):

```bash
sudo systemctl stop darkreel
sudo mv /var/lib/darkreel/darkreel.db /var/lib/darkreel/darkreel.db.old   # also move any -wal/-shm files
sudo -u darkreel sqlite3 /var/lib/darkreel/darkreel.db < darkreel.sql
sudo systemctl start darkreel
shred -u darkreel.sql
```

Items uploaded after the backup was taken have no database row and are shredded as orphans at startup; items deleted after it come back as "incomplete" rows and are dropped. Password changes made after the backup are lost — users log in with the password (and recovery code) they had at that time.

#### Manual setups

```bash
sudo apt install sqlite3 age
age-keygen -o darkreel-backup-key.txt   # on ANOTHER machine; keep this file safe
# on the server, the public key only:
echo 'age1...' | sudo tee /etc/darkreel/backup-recipient.txt
sudo install -d -m 700 /var/backups/darkreel
```

then install a script like the one `setup.sh` writes to `/usr/local/sbin/darkreel-backup` and a root cron entry for it.

### Upgrading

Migrations run automatically on startup.

```bash
cd /path/to/darkreel      # the clone setup.sh ran from (/opt/darkreel if it cloned one)
git pull && bash build.sh
sudo cp darkreel /usr/local/bin/darkreel
sudo systemctl restart darkreel
```

> **Schema v2 (delegation + sealed-box uploads) is a clean-break migration.** Upgrading from a pre-delegation v1 database is not supported in-place because the server cannot regenerate per-user keypairs without the master key (which is never at rest on the server). If the server refuses to start with `refusing to start: on-disk schema version is ""`, back up or delete `data/darkreel.db` and let the server re-bootstrap the admin user from `DARKREEL_ADMIN_PASSWORD`. Existing users re-register; the old encrypted blobs are orphan-cleaned on first boot.

Or use the auto-updater. It fetches the latest GitHub release (tags must be `vMAJOR.MINOR.PATCH`), checks the binary's SHA-256 against `checksums.txt`, and verifies an Ed25519 signature over the manifest `darkreel-release-v1\n<tag>\n<asset>\n<sha256>` with the public key in `/etc/darkreel/signing.pub` — so an older signed binary can't be re-published under a newer tag, nor one architecture's binary stand in for another's. There is no fallback: without that key, or with a bad signature, nothing is installed. It refuses to install a release older than the one it last installed (`sort -V`), keeps that record in root-only `/var/lib/darkreel-updater`, then swaps the binary and restarts the service. The first run has no record, so it installs whatever the latest release is.

`setup.sh` does not install the signing key — copy the release signing public key to `/etc/darkreel/signing.pub` yourself before enabling updates.

```bash
sudo ./update.sh              # check once
sudo ./update.sh --install    # daily cron at 4 AM (log: /var/log/darkreel-update.log)
sudo ./update.sh --uninstall  # remove cron
```

Releases are built by `.github/workflows/release.yml`. The job that holds the signing key runs no third-party actions (only shell, openssl and `gh`), and the actions the build job uses are pinned to commit SHAs.

### System requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 1 vCPU | 2+ vCPU |
| RAM | 512 MB | 1+ GB |
| Disk | 10 GB | Depends on media library |
| OS | Linux (amd64 or arm64) | Ubuntu 22.04+ / Debian 12+ |

### Security hardening

The setup script handles the host side of this. If deploying manually:

- TLS termination - Caddy or nginx (Darkreel does not handle TLS, and binds `127.0.0.1:8080` by default)
- UFW firewall - SSH, HTTP, HTTPS only
- fail2ban - auto-ban after failed SSH attempts
- SSH - root login disabled once a personal sudo user exists. `setup.sh` does not change password authentication; switch SSH to key-only yourself
- systemd sandboxing - `NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`, `PrivateDevices`, `CapabilityBoundingSet=`, `SystemCallFilter`, and more, running as a dedicated `darkreel` user
- Caddy access log control - setup script offers to disable Caddy access logs for privacy (client IPs and request paths are not logged)

Built into the server and web app:

- SRI and asset versioning - `index.html` loads `app.css`, `crypto.js` and `app.js` with SRI hashes; `app.js` imports that same integrity-checked `crypto.js` URL and loads mp4box.js with its own SRI hash; the Web Worker is loaded from a content-versioned URL. `build.sh` regenerates the hashes and `?v=<hash>` versions. Only versioned JS/CSS URLs (and fonts) are cached as immutable; `index.html`, the service worker and unversioned URLs are always revalidated. SRI protects against stale or tampered caches, not against the server that serves `index.html` (see the [threat model](#threat-model) note)
- Security headers - `nosniff`, `DENY` framing, `no-referrer`, strict CSP, HSTS, `Permissions-Policy`; COOP/COEP as defense-in-depth for SharedArrayBuffer
- Cache-Control - `no-store` on API responses; encrypted chunks and thumbnails are immutable ciphertext and marked `private` cacheable
- BREACH mitigation - HTTP compression disabled on `/api/auth/*`, whose responses carry secrets
- Rate limiting - 6,000 requests/min/IP overall; 5/min/IP shared across register, login, recover, change-password, account deletion and the delegation exchange/refresh endpoints; and 10 failed attempts/15 min per username (login and password change share one budget, recovery has its own), which holds even when per-IP limits are bypassed. Only failures count against a username; a tripped limit returns HTTP 429 "Too many attempts for this account — try again later", identically for existing and nonexistent usernames. Anyone who knows a username can still spend its budget with wrong guesses, locking that account's password login for up to 15 minutes at a time
- Proxy-aware rate limiting - `X-Forwarded-For` trust is off by default and must be enabled via `TRUST_PROXY=true`; only the rightmost untrusted hop is used, so client-supplied entries can't choose the rate-limit bucket, and `X-Real-IP` / `True-Client-IP` are ignored. IPv6 clients are bucketed per /64
- Argon2id concurrency cap - every route that runs Argon2id goes through one global gate (2–4 at a time), so parallel logins can't exhaust memory; excess requests wait up to 10 s, then get 503
- Rate-limiter hardening - IP addresses and usernames are keyed-hashed (SipHash via `hash/maphash`, per-process random seed) before storage, so a memory dump reveals no plaintext identifiers and collisions can't be precomputed to spend another user's budget. Each limiter holds at most 10,000 entries and evicts the oldest when full, so a botnet can't fill it and block legitimate users
- Timing side-channel mitigation - login performs a dummy Argon2id for non-existent users; recovery does the same single AES-GCM check whether the username exists or not
- Generic registration errors - public registration returns a generic error on failure, preventing username enumeration
- Sessions - session JWTs expire after 24 hours and must also match an in-memory session entry (expired entries are swept every minute; all end on restart). The server clears the plaintext master key from that entry before the login response is sent
- Password change and recovery - rotate the master key, keypair and recovery code (old codes only unwrap the retired keys), invalidate all sessions, and revoke all delegations, their access tokens and pending delegation codes immediately. Both require the old password or recovery code; password change is also covered by the per-username limiter, defending against guessing the old password with a stolen JWT
- Forced password change for admin-created accounts - the admin chose the initial password and saw the recovery code, so at first login the account can do nothing but change its password (enforced by the server, not just the UI). The change rotates the master key, keypair and recovery code, leaving the admin with nothing that opens the account
- Delegation limits - access tokens are upload-only and checked against their delegation on every request; delegations expire after 60 days unused or a year after authorization and are pruned periodically
- Admin re-verification - admin status is checked from the database on every admin request
- Last-admin protection - the last admin account can't be deleted (atomic transaction prevents TOCTOU race)
- Mandatory storage quotas - all users have a storage quota (defaults to 1 GB), tracked in on-disk bytes (padding included) and enforced while chunks are written. Per-user quotas can only be raised, never lowered. Total allocated quotas are validated against available disk capacity (with a 2 GB reserve), and quota changes are refused if disk capacity can't be determined
- Upload validation - max 3 concurrent uploads per user; sealed keys must be exactly 92 bytes, nonces at most 64 bytes, encrypted metadata at most 64 KB (on upload and on PATCH); thumbnails over 256 KB and chunks over 20 MB are rejected rather than truncated; chunks beyond the declared count are rejected as they arrive
- Storage-layer path validation - media directory paths are validated as UUIDs at the storage layer (defense-in-depth against path traversal, in addition to handler-level validation); startup cleanup never follows symlinks and only touches UUID-named directories
- SQLite secure deletion - `PRAGMA secure_delete=ON` overwrites deleted content in the database file (the server refuses to start if it isn't in effect; databases from before it was enforced are vacuumed once), and the WAL is truncated periodically, after account deletion and after key rotation so old page images don't linger there. Deleting a media item or account therefore removes its sealed keys from disk rather than leaving them in free pages
- Async secure deletion - file shredding runs in a background worker pool so delete operations return immediately; the item's keys are already gone from the database. Shredding and chunk padding use per-goroutine ChaCha8 PRNGs seeded from `crypto/rand`
- Folder tree padding - on top of the client's padding before encryption, the server pads the stored folder-tree ciphertext to a power-of-2 size with random bytes
- Streaming, batched uploads - chunks stream to disk through a 64 KB buffer instead of being held in memory, and the media directory is fsynced once after all chunks are written
- Startup integrity checks - orphan cleanup, incomplete upload detection, and size backfill run concurrently with parallelized filesystem checks for fast startup even with large media libraries
- Graceful shutdown - on SIGTERM/SIGINT in-flight requests drain and queued secure-deletes finish before the database closes; the shredder refuses new work once shutdown begins
- Privacy-safe logging - request handling logs no usernames, user IDs, media IDs, IP addresses or media paths; only generic operational messages
- Admin storage coarsening - per-user storage usage shown to admins is coarsened to whole GB; exact values stay internal for quota enforcement
- Signed auto-updates and encrypted backups - see [Upgrading](#upgrading) and [Backups](#backups)

### Session persistence

`PERSIST_SESSION` (default: `true`) controls whether the session keys survive a page refresh:

| Setting | Behavior | Security |
|---------|----------|----------|
| `true` (default) | The master key, owner-tag key and private key are kept in IndexedDB as the non-extractable `CryptoKey` objects themselves, under a random per-tab session id (the session JWT is in `sessionStorage`). Users stay logged in across refreshes until they log out, go idle for 30 minutes, their session expires (24 h), or the server restarts; logging out deletes the stored keys. | Raw key bytes are never stored — earlier versions kept the master key base64-encoded in `sessionStorage`, readable by any script in the page. Script in the page can still *use* the stored keys, and the browser's IndexedDB files on disk hold them until logout, so on a shared or untrusted device prefer `false`. |
| `false` | Keys exist only in memory; every refresh requires the password. | Nothing is persisted. More secure, but less convenient. |

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
sudo mount -o noatime /dev/mapper/darkreel-data /var/lib/darkreel
```

`noatime` stops reads from updating file access times; without it, viewing an item records when it was (last) viewed.

With LUKS, all data at rest is encrypted at the block level. The combination of Darkreel's application-layer encryption (keys deleted before shredding) and LUKS block-layer encryption provides two independent layers of protection against physical recovery.

This is the recommended setup for production deployments on VPS providers where you don't control the physical hardware.

It is also the only way to hide *when* things happened on disk. Darkreel resets file and directory access/modification times to a fixed epoch, but every filesystem also keeps an inode change time (ctime), and ext4/btrfs/xfs keep a birth time; neither can be set by a userspace program. Someone who images an unencrypted disk can read upload times (and the last change to each user directory) to the second from them. On an encrypted volume they see nothing without the volume key.

### Recovery codes

On account creation, a 256-bit recovery code is generated and shown once. Save it offline.

If you forget your password:

```bash
curl -X POST https://media.example.com/api/auth/recover \
  -H 'Content-Type: application/json' \
  -d '{"username": "you", "recovery_code": "your-code", "new_password": "NewStr0ng!Password"}'
```

This resets your password, rotates your master key and keypair (see below), and returns a new recovery code. Your data remains accessible. Log in again afterwards; connected apps must be re-authorized.

If you lose both your password and recovery code, your data is permanently inaccessible. The server admin cannot recover your current keys either. This is by design.

### Password change and key rotation

Changing your password or recovering your account generates a **new master key and a new X25519 keypair**. In the same database transaction the server re-seals every item's three 92-byte key envelopes to the new public key, re-encrypts your folder tree under the new master key, stores the new password hash and key wraps, issues a new recovery code, and deletes all sessions, connected-app delegations, and pending delegation codes. The old password and old recovery code unwrap only the retired keys.

Items that carry a valid owner tag are re-tagged under the new master key in the same transaction; items without one keep showing **APP**.

What this protects: someone who knew your old password or recovery code and who copies the database *after* the change gets nothing. Everything uploaded after the change is sealed to a key they never had. This is also why an account an admin creates (the admin chose its initial password and saw its recovery code) can do nothing but change its password at first login: nothing is ever stored under keys the admin could unwrap.

What it cannot protect: the per-item file, thumbnail and metadata keys are **not** changed (that would mean re-encrypting every file). Items uploaded *before* the rotation are still encrypted with their original file keys, so someone holding an older database copy (a backup, a snapshot) plus the password or recovery code valid at that time can still decrypt those older items. If that matters, delete old backups and treat the old password as compromised for the older items. The rotation itself also runs on the server, which briefly holds the old and new keys (see the [threat model](#threat-model) note).

The rotation runs the X25519 re-seal for every item (a few hundred microseconds each), so a password change on an account with tens of thousands of items takes several seconds. The web app switches to the keys returned by change-password; every other session (other browsers, the CLI) is logged out and connected apps must be re-authorized. An upload, metadata edit or folder save that was already in flight against the old keys is refused with HTTP 409 rather than stored sealed to a retired key.

### Upload limits

| Limit | Value |
|-------|-------|
| Max thumbnail | 256 KB |
| Max chunk | 20 MB |
| Max chunks per file | 50,000 |
| Max total upload | 100 GB |
| Max encrypted metadata | 64 KB |
| Concurrent uploads per user | 3 |
| Per-user storage | Configurable via admin panel or `MAX_STORAGE_GB` (default: 1 GB) |

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
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Set `TRUST_PROXY=true` and `TRUST_PROXY_CIDR=127.0.0.1/32,::1/128` so rate limiting uses the address nginx appends to `X-Forwarded-For` (Darkreel ignores `X-Real-IP`).

## Related

- [darkreel-cli](https://github.com/baileywjohnson/darkreel-cli) - Command-line client. Upload, list, and download encrypted media. ffmpeg-based remuxing for all video formats.
- [PPVDA](https://github.com/baileywjohnson/ppvda) - Privacy-focused video downloader with Darkreel integration.

## License

MIT
