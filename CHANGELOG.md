# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project does not yet follow semantic versioning (no tagged releases).

## [Unreleased]

### Added

- Extracted the authorization server out of `fikua-lab-issuer` into its own
  service: HAIP authorization_code flow (PAR, authorize, token) with
  mandatory PKCE S256, DPoP sender-constraining, and ATCA client attestation.
- RFC 9068 JWT access tokens, DPoP-bound, verified offline by the Credential
  Issuer against this service's JWK Set.
- Token revocation denylist (`GET /oid4vci/v1/revoked-tokens`), polled by the
  Credential Issuer.
- End-user identification UI (`/identify/`), ported from the standalone
  `fikua-lab-identify` Cloudflare Worker — manual-form path only.
- OID4VP Verifier (`/oid4vp/v1/*`), ported from the Java `fikua-verifier`
  module, signing Request Objects via the Fikua DSS (CSC v2.0). Passing OIDF
  HAIP conformance.
- Full OpenAPI 3.0 spec, served at `/openapi.yaml` and browsable at
  `/swagger`.
- CI/CD: build & test workflow, SonarCloud analysis, deployment compose file.
- Health check now reports `degraded` when the Credential Issuer is
  unreachable.
- Test coverage for `internal/oauth2`, `internal/authz`, and
  `internal/httpapi`.

### Fixed

- `docs/openapi.yaml` symlink pointed one directory too high and was broken;
  now resolves to `internal/httpapi/openapi.yaml`.
- CSC v2.1.0.1 `signHash` field names (`hashes`/`hashAlgorithmOID`).

### Known gaps

- X.509 client-certificate identification is not ported (needs an
  mTLS-terminating route in front of this service).
- Issuer trust validation against the EU's real LOTL/LoTE infrastructure is
  not built — see [docs/issuer-trust-validation.md](docs/issuer-trust-validation.md).
- No structured logging, metrics, rate limiting, server timeouts, graceful
  shutdown, or dependency scanning (Dependabot/govulncheck) — shared gap
  across `fikua-lab-issuer` and `fikua-lab-attestation-registry` as well.
