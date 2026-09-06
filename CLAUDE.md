# fikua-lab-idp — Project Guide

## Purpose

The OAuth2 authorization server for the Fikua Lab EUDI Wallet ecosystem.
Extracted from
[`fikua-lab-issuer`](https://github.com/fikua/fikua-lab-issuer), which
embedded its own AS alongside the OID4VCI credential issuance it actually
exists to do.

**Why the split:** an authorization server is not the credential issuer's
private business. The wider ecosystem needs one — an OID4VP Verifier is
planned to live in this same service — and the issuer having been the only
one that owned an AS was an accident of how conformance testing got done,
not a design.

Also absorbed here: `fikua-lab-identify` (the manual identification form,
now `web/static/`) and, eventually, `fikua-lab-cert` (mTLS certificate
reading — **not ported**, see Status). Those two repos still exist but are
no longer deployment targets; do not wire new work into them.

## Status

The HAIP authorization_code flow is complete and matches what
`fikua-lab-issuer` was conformance-tested with: PAR, /authorize, /token,
DPoP, ATCA client attestation, PKCE S256, plus the end-user identification
flow behind /authorize.

**Not done:**

- **X.509 identification.** `web/static/app.js`'s `method-cert` button is
  a deliberate stub (`TODO(x509)`). The old flow leaned on
  `fikua-lab-cert`: Traefik terminating mTLS with
  `clientAuthType=RequestClientCert` and its `passTLSClientCert`
  middleware injecting `X-Forwarded-Tls-Client-Cert-Info`, which nginx
  echoed back and the page parsed itself. Replicating it needs an
  mTLS-terminating route for *this* service first — IaC work, not Go work.
- **Deployment.** No `compose.yaml`, no `.github/workflows/` yet. Follow
  `fikua-lab-issuer`'s pipeline shape when adding them, sourcing the
  compose file from `fikua-platform-iac/projects/fikua-lab-idp/`.

## Architecture

```text
cmd/idp/               entrypoint: wiring only, no logic
internal/config/       env var loading
internal/crypto/       the local EC P-256 access-token signing key + Wallet Provider trust anchor
internal/oauth2/       DPoP, client attestation (ATCA), PKCE, error model, RFC 9068 token minting
internal/session/      in-memory state: PAR requests, auth codes, pending identifications, revoked jtis
internal/issuerclient/ HTTP client for the Credential Issuer (issuance records, claim metadata)
internal/authz/        the OAuth2 flow itself: PAR, authorize, identification, token
internal/httpapi/      JSON API — /oid4vci/v1/*, /identify/*, well-known metadata
internal/webui/        serves the embedded identification UI
web/static/            UI assets (HTML/CSS/JS), embedded into the binary
```

## The seam with fikua-lab-issuer

The two services share **no Go module and no code** — only JSON API
contracts, so they stay independently deployable. Three contracts exist:

1. **Access tokens.** This service mints RFC 9068 JWTs; the issuer
   verifies them offline against `/oid4vci/v1/jwks`. Every fact the issuer
   needs travels as a claim (see README's table) — there is no shared
   session store any more.
2. **Revocation.** `/oid4vci/v1/revoked-tokens` publishes the `jti`s of
   tokens revoked because their authorization code was reused (RFC 6749
   §4.1.2). The issuer polls it. This exists *because* tokens are
   stateless — do not remove it thinking it's redundant.
3. **Issuance records.** `internal/issuerclient` resolves an
   `issuer_state` to a record, and creates one when identification
   completes. The record store belongs to the issuer; this service never
   touches credential data beyond passing it through.

`internal/oauth2/dpop.go` is **deliberately duplicated** with the issuer's
copy of the same file — see its header comment. Fix bugs in both.

## Conventions

- `gofmt` and `go vet` clean before every commit.
- No framework — standard library only (`net/http`, `embed`), matching
  `fikua-lab-issuer`. Keep it that way.
- Signing key: one local EC PEM, no ephemeral fallback, and explicitly
  **not** via the Fikua DSS. DSS is for the issuer's eIDAS-relevant
  credential signing key; this one signs access tokens nobody outside this
  ecosystem validates. Don't "upgrade" it.

## Language

- Code, comments, commit messages: English.
- Communication with the user: Catalan, Spanish, or English as they prefer.
