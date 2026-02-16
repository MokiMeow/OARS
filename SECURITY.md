# Security Policy

## Reporting a Vulnerability

Please report security issues privately.

- Do **not** open a public GitHub issue for vulnerabilities.
- Preferred: use your host's private security advisory workflow (e.g., GitHub Security Advisories).
- Alternative: email `smohith.sm@gmail.com`.

Include:

- A clear description of the issue and impact
- Steps to reproduce (or a PoC if available)
- Affected version/commit and environment details

## Supported Versions

This repository currently publishes a single active development line. Security fixes are provided on a best-effort basis.

## Hardening Notes

- In production (`NODE_ENV=production`), OARS requires non-development values for:
  - `OARS_JWT_SECRET`
  - `OARS_VAULT_KEY`
  - `OARS_APPROVAL_STEP_UP_SECRET`
- Dev tokens are disabled by default in production. If you explicitly want them (not recommended), set:
  - `OARS_ALLOW_DEV_TOKENS_IN_PRODUCTION=true`
