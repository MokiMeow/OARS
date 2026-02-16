# Contributing

## Development Setup

Prereqs:
- Node.js `>=22`

Install:

```bash
npm ci
```

## Quality Gates (required)

Run locally before opening a PR:

```bash
npm run release:gate
```

That runs:
- Typecheck
- Tests
- Build
- Perf smoke
- Conformance suite

## Security Checks

```bash
npm run security:check
```

## Running Locally

```bash
npm run dev
```

API defaults to `http://localhost:8080`.

## Notes

- Avoid committing generated artifacts (`dist/`, `node_modules/`, `data/`).
- If adding new endpoints, prefer `zod` request validation and add/extend tests in `tests/`.

