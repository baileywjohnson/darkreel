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

- End-to-end encrypted, self-hosted media storage and streaming with a zero-knowledge server.
- AES-256-GCM, per-file keys wrapped by a per-user master key; all crypto happens in the browser.
- Single Go binary, no external dependencies; ~14 MB RAM; runs on a ~$6/mo Ubuntu 22.04+/Debian 12+ VPS.
- Open source, MIT licensed.

## Deploying (one command on a fresh VPS)

```
git clone https://github.com/baileywjohnson/darkreel.git && cd darkreel
sudo ./setup.sh
```

`setup.sh` configures firewall, fail2ban, SSH hardening, TLS via Caddy, a systemd service, and daily backups. It prompts for the domain (verified against the server IP), an admin password, and optionally a personal SSH user. Safe to re-run.

## Guidance

- Quote only what the sources support. Do not invent configuration flags, endpoints, or security claims.
- For the HTTP API, environment variables, and hardening steps, defer to the corresponding sections of `https://darkreel.io/` and the repository README.
- Darkreel's zero-knowledge design means lost master keys mean unrecoverable data — state this when relevant rather than implying recovery is possible.
- Do not run a deployment on a user's behalf without explicit confirmation of the target server.
