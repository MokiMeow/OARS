# OARS Conformance Suite

## Command

```bash
npm run conformance
```

## Current Checks

1. Health endpoint availability (`GET /health`)
2. Auth enforcement on protected endpoint (`GET /v1/connectors` without token)
3. Action submission flow (`POST /v1/actions`)
4. Receipt verification success (`POST /v1/receipts/verify`)

## Pass Criteria

- All checks must pass.
- Any failed check returns non-zero process exit code.

## CI Integration

- Included in `npm run release:gate`
- Included in `.github/workflows/ci-cd-gates.yml`
