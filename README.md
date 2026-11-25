# Rotex

**Local-first, zero-knowledge CLI to map GitHub Actions secret blast radius and safely rotate credentials in-place.**

[![CI](https://github.com/JOsee321/Rotex/actions/workflows/ci.yml/badge.svg)](https://github.com/JOsee321/Rotex/actions/workflows/ci.yml)
[![Release](https://img.shields.io/badge/status-v0.1.0--beta-orange)](#security-model--known-limitations)
[![License](https://img.shields.io/github/license/JOsee321/Rotex)](LICENSE)

```text
$ rotex scan --repo cli/cli --format table --no-color
Rotex Exposure Scan (repo:cli/cli)
Repos scanned: 1 | Skipped: 0 | Workflows parsed: 15 | Unique secrets: 21 | Risky: 0 | Warnings: 2

SECRET NAME                                           SCOPES  REPOS    WORKFLOWS  AGE (DAYS)  RISK FLAGS
CLI_TRIAGE_APP_CLIENT_ID                              -       cli/cli  2          -           none
CLI_TRIAGE_APP_PRIVATE_KEY                            -       cli/cli  2          -           none
GATEWATCHER_APP_STORE_CONNECT_API_BASE64_PRIVATE_KEY  -       cli/cli  1          -           none
... (21 secrets mapped across 15 workflows) ...

Warnings:
- [unauthenticated] github (auth): GITHUB_TOKEN not set; running unauthenticated (60 req/hr limit, secret metadata inaccessible)
- [unauthorized] cli/cli (repo): unable to read repository secrets: github API /repos/cli/cli/actions/secrets?per_page=100 returned HTTP 401: Requires authentication
```

---

## Try in 10 Seconds (No Token Required)

You can audit public GitHub repositories immediately without configuring any token (60 req/hr unauthenticated GitHub rate limit; secret metadata endpoints degrade gracefully with clear warnings):

```bash
go install github.com/JOsee321/Rotex/cmd/rotex@latest

# Map workflow secret references & risky triggers on any public repo
rotex scan --repo cli/cli --no-color

# Check whether a compromised dependency affects lockfiles & recent workflow runs
rotex blast --repo spf13/cobra --pkg github.com/spf13/pflag --since 72h --no-color
```

---

## Why Rotex?

Modern engineering teams store long-lived credentials (`AWS_ACCESS_KEY_ID`, `NPM_TOKEN`, `CLOUDFLARE_API_TOKEN`, deploy keys) directly in GitHub Actions Secrets across dozens of repositories. When a supply-chain compromise hits or an audit requires 90-day key rotation, teams run into two major blind spots:

1. **Blast Radius Blindness:** GitHub does not provide a unified map showing which workflows, jobs, triggers (`pull_request_target`, `workflow_run`), unpinned actions, or `secrets: inherit` calls can access a given secret across an organization.
2. **Shared-Key Downtime Fear:** Rotating a shared production key manually across 5–15 repositories risks breaking deployments if a consumer is missed or a mid-flight update fails.

**Rotex solves both without forcing you to migrate to a third-party secret vault.** Everything runs locally on your workstation or self-hosted runner—raw secret values never leave your machine and are never written to stdout, stderr, logs, or state files.

---

## Core Capabilities

1. **Exposure Mapping (`rotex scan`):** Discovers Org/Repo/Environment secret metadata, parses `.github/workflows/*.yml` and `.yaml` ASTs, flags `pull_request_target`, `workflow_run`, unpinned third-party actions, `secrets: inherit`, stale secrets (>90 days), and correlates read-only AWS IAM + CloudTrail usage (`--with-aws`).
2. **Incident Mode (`rotex blast`):** Scans lockfiles (`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `go.sum`, `requirements.txt`, `poetry.lock`) against `--pkg` or OSV/JSON advisories (`--advisory`), checks workflow runs in the incident window (`--since 72h`), and ranks exposed secrets by blast radius priority.
3. **Safe In-Place Rotation (`rotex rotate`):** Runs a 6-stage dual-key state machine (`PREFLIGHT` -> `MINT` -> `INJECT` -> `VERIFY` -> `DEACTIVATE` -> optional `REVOKE`) using **Libsodium Sealed Box (`crypto_box_seal`)** client-side encryption, AWS IAM 2-key quota preflight guards, `sts:GetCallerIdentity` verification with exponential backoff, and automatic rollback on failure.

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

## Usage Examples

Set a GitHub token for private repositories, secret metadata (`updated_at`), and rotation:

```bash
export GITHUB_TOKEN="github_pat_..."
```

### 1. Organization & AWS Exposure Scan

```bash
# Scan an entire org (skips archived repos by default; degrades gracefully on HTTP 403)
rotex scan --org my-org

# Include AWS IAM credential age, zombie keys, overprivileged policies, and CloudTrail runner usage
rotex scan --org my-org --with-aws --format table

# Export machine-readable JSON or Markdown for audit reports
rotex scan --org my-org --format json > exposure-report.json
rotex scan --repo owner/repo --format markdown
```

### 2. Incident Blast Radius

```bash
rotex blast --org my-org --pkg "compromised-pkg@1.2.3" --since 72h
rotex blast --org my-org --advisory ./osv-advisory.json --format json
```

### 3. Safe In-Place AWS -> GitHub Rotation

```bash
# Always preview the deterministic dry-run plan first (also the default when --apply is omitted)
rotex rotate \
  --iam-user ci-deployer \
  --repo my-org/api \
  --repo my-org/web \
  --env my-org/web:production \
  --dry-run

# Apply dual-key rotation with STS verification and 24h deactivation grace window
rotex rotate \
  --iam-user ci-deployer \
  --repo my-org/api \
  --repo my-org/web \
  --env my-org/web:production \
  --apply

# Roll back or permanently delete the old key after the grace window
rotex rollback --run-id rot-20261125-120000-ab12cd34
rotex cleanup  --run-id rot-20261125-120000-ab12cd34
```

---

## Installation

- **Go Install (Go 1.23+):**
  ```bash
  go install github.com/JOsee321/Rotex/cmd/rotex@latest
  ```
- **Prebuilt Binaries:** Download archives and `checksums.txt` for Linux, macOS, and Windows from [GitHub Releases](https://github.com/JOsee321/Rotex/releases).
- **Build from Source:**
  ```bash
  git clone https://github.com/JOsee321/Rotex.git
  cd Rotex
  go build -o rotex ./cmd/rotex
  ```

---

## Security Model & Known Limitations

Rotex is currently in **Public Beta (`v0.1.0-beta`)**. Please review the following security boundaries before running write operations against production environments:

1. **Always Run `--dry-run` First:** `rotex scan` and `rotex blast` are strictly read-only, whereas `rotex rotate --apply` mutates AWS IAM access keys and GitHub Actions Secrets. Always review `rotex rotate --dry-run` before running `--apply`.
2. **Go Immutable `string` Memory Limitation:** Rotex wraps credential buffers in `SensitiveBytes` and explicitly clears byte slices (`WipeBytes` / `clear`) immediately after encryption. However, third-party HTTP/SDK layers (`net/http`, `aws-sdk-go-v2`) allocate standard Go `string` values (for example, AWS XML/SigV4 payloads) that are immutable in the Go runtime and cannot be deterministically zeroed before garbage collection.
3. **External TOCTOU on AWS 2-Key Quota:** `PREFLIGHT` verifies that the target IAM user has fewer than 2 access keys before minting. If an external operator or automation creates a second access key in the AWS Console between `PREFLIGHT` and `MINT`, AWS IAM rejects `CreateAccessKey` with `LimitExceeded` and `rotex` aborts safely without modifying any GitHub Secrets.
4. **Local State Journal:** `.rotex/state/<run-id>.json` stores metadata and key IDs only (`AKIA...`), never raw secret values, and is written with `0600` permissions.

For vulnerability reporting, see [SECURITY.md](SECURITY.md).

---

## Development & Testing

```bash
go vet ./...
go test -race -count=1 ./...
```

---

## License

Licensed under the [Apache License 2.0](LICENSE).
