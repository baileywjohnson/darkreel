# Security

## Threat model

Darkreel is designed for **zero-knowledge** self-hosted media storage **at rest**: nothing the server stores — database, media files, backups — lets its operator, including the legitimate admin, recover plaintext content or metadata without a user's password or recovery code. It does not keep a *live* malicious server from learning secrets: the password is sent to the server, and the server briefly holds account keys, as described under "Out of scope".

### In scope

- Content confidentiality against a stolen or leaked database, disk image, or backup, and against a server compromised after the fact.
- Metadata confidentiality (filenames, types, exact sizes, dimensions, folder structure) against the same.
- Authentication and authorization boundaries: users cannot read, delete, or modify other users' media; non-admins cannot promote themselves; revoked admins cannot re-entrench; delegated apps can only upload; the password and recovery code an admin chose for an account they created stop working once the user takes over, because the account can do nothing until its password is changed, and that change rotates its keys.
- Integrity of a user's library against anyone who holds only their public key (a connected app, a database writer): such items decrypt, but lack the owner tag only the master-key holder can compute and are flagged **APP** in the web UI and `[not your upload]` in the CLI. Truncating an item's chunks is detected by the encrypted last-chunk flag.
- Resilience against: distributed brute force, per-IP and per-account rate-limit evasion, KDF memory exhaustion, TOCTOU on quota/admin checks, path traversal via media IDs / chunk indices, symlink attacks on the data directory, duplicate-detection side channels, and chunk-size fingerprinting.

### Out of scope

- **A live malicious or compromised server.** Web Crypto has no Argon2id, so the password is sent to the server over TLS at login, registration, password change and recovery, and the server runs the KDF.
  - At login the server decrypts the master key, re-wraps it for the client, and clears it from `SessionStore` immediately (`Sessions.ClearKey`) — so the window is the login request, not the 24 h session.
  - A password change or recovery holds the old and new master keys and private keys for the whole request, and opens every item's sealed keys (and its metadata, to recompute the owner tag) to re-seal them.
  - Registration and admin user creation generate the master key and keypair server-side.

  An attacker who can read process memory, or who runs modified server code, therefore recovers the password of anyone who logs in and the keys of anyone who logs in or changes their password. Because the same server serves the web app, it can also ship JavaScript that exfiltrates keys from the browser; SRI doesn't help against the origin itself. Run a binary you built from source on a host you control.
- **Captured login responses.** The master-key copy in a login or change-password response is wrapped under a PBKDF2-SHA256 key (600,000 iterations) derived from the password, which is cheaper to brute-force than the Argon2id protecting the database. TLS keeps it off the wire; anything that logs response bodies (a debugging proxy, a misconfigured TLS terminator) should be treated as holding a password verifier.
- **The admin recovery code reaches the system journal.** On first run it is printed to stderr, which under systemd means journald retains it indefinitely (root-readable, and captured by journal backups). The `data/.recovery-code` file is deleted after five minutes (`setup.sh` shreds it as soon as it has displayed it), but the journal copy is not, and `setup.sh` points to `journalctl` as a fallback for retrieving it. This is a durable, root-readable primitive for unwrapping the admin master key — the one exception to "no backdoor, no admin recovery." After you have saved the code, purge it:

  ```bash
  sudo journalctl --rotate
  sudo journalctl --vacuum-time=1s --unit=darkreel
  ```
- **Old database copies plus old credentials.** A password change or recovery replaces the account's master key and X25519 keypair and re-seals every item's key envelopes to the new public key, but the per-item file/thumbnail/metadata keys are unchanged. Anyone holding a database copy from *before* the change (a backup, a snapshot) plus the password or recovery code valid at that time can still decrypt the items that existed then. Everything uploaded after the change is out of their reach. This is why an account an admin creates must change its password at first login: until it does, the server refuses every request except the password change and logout, so nothing is ever encrypted under keys the admin could unlock.
- **Attackers who compromise a user's device.** The browser (or CLI) sees plaintext; client-side compromise is client-side compromise.
- **Traffic analysis.** Chunks and thumbnails are padded to fixed buckets (1/2/4/8/16 MB, then whole MB; 256 KB) inside the encryption, so no exact length is ever visible, but the chunk count and bucket sizes still reveal each item's approximate size, and per-user activity timing is visible to any on-path observer and to the server.
- **Side channels in the underlying OS, browser, or Go runtime** (e.g., Spectre, GC-driven plaintext-residue, swap to disk).

## Deployment requirements

### TLS is mandatory

Darkreel's HTTP server binds plain `http`, on `127.0.0.1:8080` by default. **It MUST be deployed behind a TLS-terminating reverse proxy** (Caddy, nginx, Traefik, Cloudflare Tunnel). Binding `-addr 0.0.0.0:8080` directly to the internet exposes passwords and JWT bearer tokens in cleartext.

If you run Darkreel behind a reverse proxy, set `TRUST_PROXY=true` so per-IP rate limiting uses the client address from `X-Forwarded-For` — the rightmost entry that isn't itself a trusted proxy (`X-Real-IP` and `True-Client-IP` are ignored). Otherwise leave it unset — enabling it without a trusted proxy lets any client spoof their IP. Also set `TRUST_PROXY_CIDR` to a comma-separated list of trusted proxy networks (`setup.sh` uses `127.0.0.1/32,::1/128`). Proxy headers are then honored only from peers inside those CIDRs; unset (or with no parseable entry) keeps the legacy "trust any upstream" behavior, which is safe only if you firewall the bind address to the proxy yourself.

### First-run admin bootstrap

`DARKREEL_ADMIN_PASSWORD` is required on first launch. The server emits the one-time recovery code to stderr (prominent banner) and also writes it to `<data-dir>/.recovery-code` (chmod 0600) so an automated setup script can pick it up. **The file is deleted after 5 minutes** — save the code somewhere durable during that window. A stale `.recovery-code` file left behind by a previous bootstrap is removed on the next startup. Losing the recovery code means losing the ability to recover the admin account if the password is lost. `setup.sh` passes the admin password through a separate `/etc/darkreel/bootstrap.env` that it deletes once the server is up.

### Data-directory permissions

The data directory holds the SQLite database (chmod 0600) and all encrypted media blobs (files 0600, directories 0700). The server process needs read/write there. No other local user should — a local attacker with filesystem access can delete or corrupt media, and can read the encrypted blobs (though not decrypt them without a user's key material).

### JWT secret behavior

The JWT signing secret is regenerated every process start. **All sessions are invalidated on restart.** This is intentional: no persistent secret means no persistent secret to steal from disk. Delegation refresh tokens survive restarts (they're stored hashed in the DB, independent of the JWT secret), so connected clients like PPVDA keep working across Darkreel restarts until the delegation is revoked or expires (60 days unused, or one year after authorization).

JWT verification pins the accepted algorithm to exact `HS256` — not just "any HMAC variant" — so a malformed token claiming `HS384`/`HS512` can't slip through even though we never issue those. A token must also name a live credential: session tokens a session in the server's memory, delegation tokens a delegation row that still exists. If you need persistent sessions across restarts, the `SetSecret` hook in `internal/auth/jwt.go` accepts a caller-supplied secret; it returns `ErrSecretAlreadyInitialized` if a secret was already generated, so misordered callers find out.

### Hardware / host

Run Darkreel on a host you control. The server process must never be accessible to other UIDs on the box. Containerize if sharing infrastructure. Back up the data directory with the same rigor as the server itself — the encrypted blobs are useless without the per-user keys (which live only in wrapped form), but the database contains every user's password hash and password- and recovery-code-wrapped keys. `setup.sh` encrypts nightly database dumps with age to a public key whose private half is kept off the server, and stores them root-only in `/var/backups/darkreel`; ship them off-host and keep retention short (see README, "Backups").

File and directory access/modification times in the data directory are normalized to a fixed epoch, but inode change times (ctime) and birth times cannot be set from userspace and reveal upload times to anyone who images an unencrypted disk. Put the data directory on an encrypted volume, mounted `noatime`.

## Cryptographic details

- Password hashing: Argon2id (t=3, m=64 MiB, p=4, 32-byte output), 32-byte random salt per user. A second Argon2id with a separate salt derives the key that wraps the (random) master key.
- Session key: PBKDF2-HMAC-SHA256, 600,000 iterations, 32-byte output, over the password and KDF salt. Used only to wrap the master key in login / change-password responses for the browser.
- Content encryption: AES-256-GCM with 12-byte random nonce, AAD = `UTF8(mediaID) || BigEndian(uint64(chunkIndex))` for chunks (index 0 for thumbnails), `UTF8(mediaID)` for metadata blobs, `UTF8(userID)` for master-key and private-key wrapping and the folder tree. AAD binding prevents cross-file and cross-user confused-deputy attacks.
- Chunk format 2: each chunk's plaintext is framed as `version | last-chunk flag | u32 length | data | zero padding`, sized so the ciphertext is exactly 1, 2, 4, 8 or 16 MiB (then whole MiB; the server accepts at most 20 MiB); thumbnails are exactly 256 KiB. The server's 4-byte on-disk length prefix therefore only reveals the bucket. Metadata JSON and the folder tree are space-padded to a power of two (from 512 B) before encryption. Items without `chunk_format: 2` in their metadata use the older unpadded format and remain readable.
- Per-file key sealing: each media upload generates three random 32-byte symmetric keys (file, thumbnail, metadata) and seals each to the account's X25519 public key using X25519-ECDH + HKDF-SHA256 + AES-256-GCM (HKDF info = `"darkreel-seal-v1"`; 92 bytes per sealed key). The server stores no plaintext file/thumb/metadata keys; outside a password change or recovery it could open them only with the user's master key, which it clears right after login. Delegated clients (e.g. PPVDA) hold only the public key, so a delegated-client compromise grants upload-only capability — not read/list/delete.
- Owner tags: HMAC-SHA256 under HKDF-SHA256(master key, info `"darkreel-owner-v1"`) over the label, media ID and the three sealed keys, stored inside the encrypted metadata. Browser and CLI uploads carry one; delegated uploads cannot. Re-saving an item's metadata from the browser (rename, move) tags it.
- Recovery: 32-byte random code, AES-256-GCM wrap of master key with AAD = `UTF8(userID)`. The user's X25519 private key is also wrapped twice — once under the master key, once under the recovery code — so recovery restores full access, not just auth.
- Key rotation: password change and recovery generate a new master key, X25519 keypair and recovery code. In one transaction the server opens each item's three sealed keys with the old private key and re-seals them to the new public key, re-encrypts the folder tree under the new master key (same AAD), recomputes valid owner tags, and deletes all sessions, delegations and pending delegation codes. Old and new key material is zeroed after use, and the WAL is checkpointed so the old wraps don't linger in it. Writes that clients encrypt to the account's keys (uploads, metadata edits, folder saves) are conditional on the public key they were authorized against, so a request racing the rotation fails with 409 instead of storing data sealed to a retired key.
- Delegations: authorization codes are single-use and expire after 2 minutes; refresh tokens are 32 random bytes stored as a domain-separated SHA-256 hash and expire after 60 days unused or one year after authorization. Access tokens (1 hour) carry the delegation ID; the auth middleware checks the delegation still exists on every request, so revocation, expiry, password change, recovery and account deletion cut them off immediately.
- Browser key handling: the master key is unwrapped directly into non-extractable `CryptoKey`s and the private key imported as one, so page script can use but not export them. With `PERSIST_SESSION=true` the `CryptoKey` objects themselves (never raw bytes) are kept in IndexedDB until logout; the web app logs out after 30 minutes idle.
- Nonce policy: every `EncryptBlock` / `EncryptChunk` call generates a fresh random nonce. There is no deterministic-nonce mode.
- Deletion: an item's keys are deleted from the database first (SQLite `secure_delete` is on and verified at startup), then its files are overwritten with random data, fsynced and unlinked in the background.

## Reporting a vulnerability

Email **baileywjohnson@gmail.com** with details. Please do not open a public issue for unfixed vulnerabilities. I'll acknowledge receipt within 7 days and aim to ship a fix within 30 days for high/critical severity.

When reporting, include:
- A clear description of the issue and impact.
- Steps to reproduce (PoC preferred, but not required).
- The Darkreel version and Go version used.
- Your threat-model assumptions (what attacker capability is required).

## Supported versions

Only the latest tagged release on `main` receives security updates. Older binaries are unsupported — keep your deployment current.

## Release integrity

Release binaries are built by `.github/workflows/release.yml`. Each `.sig` is an Ed25519 signature over the manifest `darkreel-release-v1\n<tag>\n<asset>\n<sha256>`, so a signature can't be moved to another release or architecture. The job holding the signing key runs no third-party actions (shell, openssl and `gh` only), and the actions in the other jobs are pinned to commit SHAs. `update.sh` rebuilds the manifest for what it is installing, refuses to install without `/etc/darkreel/signing.pub` or with a bad signature, never installs a release older than the one it last installed, and keeps that record in root-only `/var/lib/darkreel-updater`. `checksums.txt` itself is not signed; the signature is what's trusted.

## Dependency hygiene

`govulncheck` runs on pushes and pull requests to `main`, and weekly, in CI (see `.github/workflows/security.yml`), using the same Go toolchain as the release build (`go.mod`). A failing job on an unchanged branch usually means a new CVE was disclosed against one of our pinned deps or the toolchain — upgrade promptly. Dependabot opens weekly update PRs for Go modules and GitHub Actions.
