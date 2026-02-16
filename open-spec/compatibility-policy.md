# OARS Compatibility Policy

## Versioning

- Profile versions use semantic versioning (`MAJOR.MINOR.PATCH`).
- `MAJOR` changes may break endpoint or payload compatibility.
- `MINOR` changes are backward compatible additive changes.
- `PATCH` changes are backward compatible fixes and clarifications.

## API Compatibility Rules

- Existing endpoints and required fields cannot be removed within the same major version.
- New optional fields may be added without version bump beyond `MINOR`.
- Error envelope must continue returning `error.code` and `error.message`.
- Receipt verification semantics (`isSignatureValid`, `isChainValid`, `isSchemaValid`) remain stable for `1.x`.

## Security Compatibility Rules

- Receipt signing algorithm changes require a major version bump.
- Trust metadata endpoint must provide historical verification continuity for retired keys.
- mTLS workload identity enforcement controls may be tightened in minor versions but never relaxed by default.

## Conformance Requirements

- Implementations must pass `npm run conformance` with zero failed checks.
- Release gate must pass typecheck, tests, build, perf smoke, and conformance checks.

## Deprecation Policy

- Deprecations are announced with migration guidance before removal.
- Deprecated endpoints remain available for at least one minor release cycle.
