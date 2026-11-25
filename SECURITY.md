# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in **Rotex** (such as credential leakage, cryptographic flaws in sealed-box encryption, or unintended write behavior in read-only commands), please **do not open a public GitHub Issue**.

Instead, report it privately via **GitHub Security Advisories** on the [Rotex repository Security tab](https://github.com/JOsee321/Rotex/security/advisories/new).

Please include:
- A clear description of the vulnerability and potential impact.
- Minimal steps or a proof-of-concept to reproduce the issue.
- The version or commit hash tested.

We will acknowledge reports within 48 hours and work to verify, patch, and coordinate disclosure responsibly.

## Security Design Principles

- **Local-First & Zero-Knowledge:** Rotex never phones home or transmits secrets to any third-party service.
- **Read-Only by Default:** `rotex scan` and `rotex blast` only require read-only metadata scopes.
- **No Secret Persistence:** Local state files under `.rotex/state/` store key IDs and stage metadata only, never secret material.
