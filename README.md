# Rotex

**Local-first, zero-knowledge CLI to map GitHub Actions secret blast radius and safely rotate credentials in-place.**

[![CI](https://github.com/JOsee321/Rotex/actions/workflows/ci.yml/badge.svg)](https://github.com/JOsee321/Rotex/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/JOsee321/Rotex)](LICENSE)

---

## Why Rotex?

Modern engineering teams store long-lived credentials (`AWS_ACCESS_KEY_ID`, `NPM_TOKEN`, `CLOUDFLARE_API_TOKEN`, deploy keys) directly in GitHub Actions Secrets across dozens of repositories. When a supply-chain compromise hits or an audit requires 90-day key rotation, teams run into two major blind spots:

1. **Blast Radius Blindness:** GitHub does not provide a unified map showing which workflows, jobs, triggers (`pull_request_target`, `workflow_run`), unpinned actions, or `secrets: inherit` calls can access a given secret across an organization.
2. **Shared-Key Downtime Fear:** Rotating a shared production key manually across 5–15 repositories risks breaking deployments if a consumer is missed or a mid-flight update fails.

**Rotex solves both without forcing you to migrate to a third-party secret vault.** Everything runs locally on your workstation or self-hosted runner—raw secret values never leave your machine and are never written to stdout, stderr, logs, or state files.

---

## Core Security Guarantees

- **Zero-Knowledge & Local-First:** Direct HTTPS calls from your local machine to GitHub and cloud provider APIs. No Rotex backend server exists.
- **Read-Only by Default:** `rotex scan` and `rotex blast` only require read-only metadata scopes. Write operations require explicit `--apply` on `rotex rotate`.
- **Safe Dual-Key State Machine:** New credentials are minted, verified (e.g., via `sts:GetCallerIdentity`), encrypted locally with **Libsodium Sealed Box (`crypto_box_seal`)**, and injected into GitHub Actions Secrets *before* the old key is deactivated.
- **Automatic Rollback & Memory Hygiene:** Pre-injection verification/setup failures automatically delete newly minted uninjected keys, while partial-injection failures preserve both active keys to prevent downtime. Secret buffers are wrapped in redacted types (`[REDACTED]`) and zeroed in memory immediately after encryption.

---

## Architecture

```text
+-------------------------------------------------------------------+
|               USER MACHINE / SELF-HOSTED CI RUNNER                |
|                                                                   |
|  +-------------------------------------------------------------+  |
|  |                     rotex CLI (Go Binary)                   |  |
|  |                                                             |  |
|  |  [1. scan]           [2. blast]          [3. rotate]        |  |
|  |  - GH Metadata API   - Lockfile Parsers  - Preflight Guard  |  |
|  |  - YAML AST Parser   - Run History Diff  - Dual-Key Mint    |  |
|  |  - AWS IAM/Trail     - Priority Ranking  - SealedBox Inject |  |
|  |                                          - Verify & Rollback|  |
|  +---------------+-----------------------------+---------------+  |
|                  |                                                |
|        .rotex/state/<run-id>.json (Metadata & IDs only, ZERO secrets)
+------------------+-----------------------------+------------------+
                   | Direct HTTPS                | Direct HTTPS
                   v                             v
         +-------------------+         +-------------------+
         |    GitHub API     |         |     AWS APIs      |
         | - Actions Secrets |         | - IAM             |
         | - Workflows/Runs  |         | - STS             |
         | - Repo Trees      |         | - CloudTrail      |
         +-------------------+         +-------------------+
```

---

## Installation

### From Source (Go 1.23+)

```bash
go install github.com/JOsee321/Rotex/cmd/rotex@latest
```

### Build Locally

```bash
git clone https://github.com/JOsee321/Rotex.git
cd Rotex
go build -o rotex ./cmd/rotex
```

Prebuilt cross-platform binaries (Linux, macOS, Windows) and SHA-256 checksums are published on [GitHub Releases](https://github.com/JOsee321/Rotex/releases).

---

## Quickstart

Set a read-only GitHub token first:

```bash
export GITHUB_TOKEN="github_pat_..."
```

### 1. Map Secret Exposure (`rotex scan`)

Scan an entire organization (skips archived repositories by default, degrades gracefully on HTTP 403 org/environment permission boundaries):

```bash
rotex scan --org my-org
```

Scan a single repository without org-level permissions:

```bash
rotex scan --repo owner/repo --format markdown
```

Correlate GitHub secrets with read-only AWS IAM key age, unused zombie keys, overprivileged policies, and CloudTrail runner usage:

```bash
rotex scan --org my-org --with-aws --format table
```

Example output:

```text
Rotex Exposure Scan (org:my-org)
Repos scanned: 12 | Skipped: 2 | Workflows parsed: 28 | Unique secrets: 4 | Risky: 3 | Warnings: 0

SECRET NAME            SCOPES    REPOS                     WORKFLOWS  AGE (DAYS)  RISK FLAGS
AWS_ACCESS_KEY_ID      repo      my-org/api, my-org/web    4          142         aws_overprivileged,aws_stale_key,pull_request_target,stale_secret,unpinned_action
AWS_SECRET_ACCESS_KEY  repo      my-org/api, my-org/web    4          142         aws_overprivileged,aws_stale_key,pull_request_target,stale_secret,unpinned_action
NPM_TOKEN              org       my-org/sdk                2          45          secrets_inherit
```

### 2. Incident Blast Radius Mode (`rotex blast`)

When a package is compromised (e.g., an npm worm or OSV advisory), find every affected repository across lockfiles (`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `go.sum`, `requirements.txt`, `poetry.lock`), inspect workflow runs in the incident window, and prioritize which secrets to rotate first:

```bash
rotex blast --org my-org --pkg "compromised-pkg@1.2.3" --since 72h
```

Or pass an OSV/JSON advisory file:

```bash
rotex blast --org my-org --advisory ./advisory.json --format json
```

### 3. Safe In-Place Rotation (`rotex rotate`)

Preview a deterministic dry-run execution plan first (default behavior when `--apply` is omitted):

```bash
rotex rotate \
  --iam-user ci-deployer \
  --repo my-org/api \
  --repo my-org/web \
  --env my-org/web:production \
  --dry-run
```

Apply rotation across all targets (enforces AWS IAM's 2-key quota preflight check, encrypts secrets locally via `golang.org/x/crypto/nacl/box`, verifies via `sts:GetCallerIdentity`, and deactivates the old key while keeping a grace window):

```bash
rotex rotate \
  --iam-user ci-deployer \
  --repo my-org/api \
  --repo my-org/web \
  --env my-org/web:production \
  --apply
```

Roll back a rotation run if needed, or permanently delete the deactivated old key after your grace window:

```bash
rotex rollback --run-id rot-20261125-120000-ab12cd34
rotex cleanup  --run-id rot-20261125-120000-ab12cd34
```

---

## Development & Testing

```bash
go vet ./...
go test -race -count=1 ./...
```

---

## License

Licensed under the [Apache License 2.0](LICENSE).
