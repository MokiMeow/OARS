# mTLS Deployment (PC-011)

OARS supports "real" mutual TLS (mTLS) for service-to-service authentication by running the API with TLS client
certificates enabled (`OARS_MTLS_MODE=tls`). In this mode:

- The API verifies the client's certificate chain using `OARS_MTLS_CA_PATH`.
- OARS derives `x-oars-mtls-subject` and `x-oars-mtls-fingerprint` from the TLS peer certificate.
- Any presented `x-oars-mtls-*` headers are ignored/overwritten (prevents spoofing).
- `service`-role tokens require a valid workload identity (enforced by `ServiceIdentityService`).

## Local Reference Stack (Docker)

This repo includes `docker-compose.mtls.yml`, which generates a dev CA + server cert + client cert into
`data/mtls-certs/` (ignored by git) and runs the API on `https://localhost:8443`.

1. Generate certificates:

```bash
docker compose -f docker-compose.mtls.yml run --rm certgen
```

2. Start OARS:

```bash
docker compose -f docker-compose.mtls.yml up --build
```

## Client Example

Health check (no auth, TLS required):

```bash
curl --cacert data/mtls-certs/ca.crt https://localhost:8443/health
```

Authenticated call (example uses dev admin token):

```bash
curl --cacert data/mtls-certs/ca.crt \
  --cert data/mtls-certs/client.crt \
  --key data/mtls-certs/client.key \
  -H "Authorization: Bearer dev_admin_token" \
  https://localhost:8443/v1/connectors
```

## Configuration

- `OARS_MTLS_ENABLED=true` enables workload identity checks for `service`-role tokens.
- `OARS_MTLS_MODE=tls` enables TLS client-certificate-derived identity.
- `OARS_MTLS_CA_PATH` CA bundle used to validate client certificates (PEM).
- `OARS_TLS_CERT_PATH` / `OARS_TLS_KEY_PATH` server TLS certificate/private key (PEM).
- `OARS_MTLS_TRUSTED_IDENTITIES_FILE` points to a JSON file with trusted identities.
  `docker-compose.mtls.yml` writes a dev file at `data/mtls-certs/trusted-identities.json`.

