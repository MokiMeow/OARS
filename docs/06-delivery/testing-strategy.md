# Testing Strategy

## Test Principles

- Security and correctness before feature velocity.
- Deterministic verification for all cryptographic behavior.
- Production-like environments for reliability tests.

## Test Layers

1. Unit Tests
- Policy rule evaluation correctness
- Receipt canonicalization and signing logic
- Approval state transitions

2. Integration Tests
- End-to-end action mediation flow
- Connector execution paths and error handling
- Evidence pipeline transformation and mapping

3. Contract Tests
- API compatibility and versioning behavior
- Connector interface behavior
- Receipt schema backward compatibility
- Open profile conformance checks (`npm run conformance`)

### Optional Docker-Backed Tests

- Postgres-backed integration tests are available but skipped by default.
- Run them with `npm run test:docker` (requires Docker Engine running).

4. Security Tests
- Authentication and authorization bypass attempts
- Input validation fuzz tests
- Key handling and secret exposure tests
- mTLS workload identity enforcement tests for service-to-service calls

5. Performance Tests
- Policy decision latency under load
- Receipt write throughput and verification latency
- Burst traffic resilience
- Automated smoke benchmark via `npm run perf:smoke` with configurable p95 threshold

6. Reliability Tests
- Service restart and failover tests
- Queue backpressure handling
- Regional failover simulation
- Backup creation and restore validation tests
- Disaster recovery drill evidence report generation checks

7. Compliance Validation Tests
- Evidence completeness checks
- Control mapping consistency tests
- Bundle signature and integrity checks

## Environment Matrix

- Local developer environment
- CI ephemeral test environment
- Shared staging environment
- Pre-production environment mirroring production topology

## Quality Gates

- Unit/integration pass rate: `100%` required for merge
- Critical security findings: `0` open for release
- Performance regression threshold: less than `5%` on key paths
- Evidence integrity failures: `0` tolerated

## Local Verification Commands

- `npm run security:check` (audit + typecheck + unit/integration suite)
- `npm run release:gate` (full build/test/perf/conformance gate)

## Release Readiness Checklist

- Test coverage targets achieved
- Penetration test reviewed and remediated
- SLO burn-in complete
- Incident drills completed and documented
