# Dependency audit follow-up

Audit date: 2026-11-07.

The security update raises the minimum supported versions of the MCP SDK,
Fastify, Zod, and Vitest, updates the Hono server override, and refreshes
compatible locked dependencies. The production dependency audit reports no
known vulnerabilities at this date.

The full audit still reports six moderate affected package entries caused by
two development-only advisories in the Testcontainers archive dependencies:

- [GHSA-3g3m-2fjr-6pw4](https://github.com/advisories/GHSA-3g3m-2fjr-6pw4): `glob` cancellation does not reliably stop filesystem traversal.
- [GHSA-g3hv-75wg-m249](https://github.com/advisories/GHSA-g3hv-75wg-m249): `minimatch` glob expansion can amplify resource consumption.

The affected chain is `testcontainers` → `archiver` / `zip-stream` →
`archiver-utils` → `glob` → `minimatch`. These packages are omitted from the
production image by `npm ci --omit=dev`. Development-only does not mean harmless:
avoid running container/archive tests against untrusted filesystem inputs.

Latest Testcontainers 12.2.1 still selects Glob 10 and Minimatch 9 through its
archive dependencies. Patches for these advisories require Glob 14.0.2 and
Minimatch 11.0.1. Do not silently force incompatible transitive major versions or
downgrade Testcontainers merely to clear an audit score. Prefer an upstream
compatible update, or separately validate a replacement archive dependency.

The existing CI audit threshold remains unchanged and continues to report these
findings. This document is not an exception or acceptance of the remaining risk.

Recheck with:

```bash
npm audit --omit=dev --audit-level=moderate
npm audit --audit-level=moderate
```
