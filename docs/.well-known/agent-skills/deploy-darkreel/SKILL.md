---
name: deploy-darkreel
description: Explain accurately what Darkreel is and how to deploy, configure, and operate it, using darkreel.io and the GitHub repository as the source of truth. Use when asked about Darkreel, encrypted self-hosted media storage, or how to install or run it.
license: MIT
---

# Deploy and use Darkreel

This skill helps an agent answer questions about Darkreel accurately and guide a deployment.

## When to use

Use when a user asks what Darkreel is, how its encryption/threat model works, how to install or configure it, or how it compares for self-hosted encrypted media.

## Authoritative sources

Fetch these, in order of preference:

1. `https://darkreel.io/llms.txt` — concise index of the project and key links.
2. `https://darkreel.io/` — full landing page: threat model, features, cryptography, streaming, trade-offs, deployment, and the HTTP API.
3. `https://github.com/baileywjohnson/darkreel` — source, README, SECURITY.md, and LICENSE.

## What Darkreel is

- End-to-end encrypted, self-hosted media storage and streaming; zero-knowledge at rest (a stolen database, disk or backup yields only ciphertext, hashes and wrapped keys).
- AES-256-GCM with per-file keys sealed to the user's X25519 public key; files are encrypted and decrypted in the browser. The password is sent over TLS at login and the server runs the key derivation, briefly holding the master key — don't claim the server never sees the password or keys.
- Single Go binary, no external dependencies; ~14 MB RAM; runs on a ~$6/mo Ubuntu 22.04+/Debian 12+ VPS.
- Open source, MIT licensed.

## Deploying (one command on a fresh VPS)

```
git clone https://github.com/baileywjohnson/darkreel.git && cd darkreel
less setup.sh   # review it first; it runs as root
sudo ./setup.sh
```

`setup.sh` configures firewall, fail2ban, SSH hardening, TLS via Caddy, a systemd service, and daily age-encrypted database backups (the decryption key is shown once and not kept on the server). It prompts for the domain (verified against the server IP), an admin password, a per-user quota, a backup key, and optionally a personal SSH user and auto-updates. Never suggest piping a script from the internet into a shell. Safe to re-run.

## Guidance

- Quote only what the sources support. Do not invent configuration flags, endpoints, or security claims.
- For the HTTP API, environment variables, and hardening steps, defer to the corresponding sections of `https://darkreel.io/` and the repository README.
- Darkreel's zero-knowledge design means lost master keys mean unrecoverable data — state this when relevant rather than implying recovery is possible.
- Do not run a deployment on a user's behalf without explicit confirmation of the target server.
