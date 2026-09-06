# fikua-lab-idp

Fikua Identity Provider — the OAuth2 authorization server for the Fikua
Lab EUDI Wallet ecosystem.

Standalone Go service (single binary) that runs the HAIP
authorization_code flow on behalf of
[`fikua-lab-issuer`](https://github.com/fikua/fikua-lab-issuer), and
serves the end-user identification UI that flow redirects to.

This code was extracted from `fikua-lab-issuer`, which used to embed its
own authorization server alongside the credential issuance it actually
exists to do. Splitting them out lets the rest of the ecosystem — an
OID4VP Verifier is next — authenticate against one authorization server
instead of borrowing the issuer's.

**HAIP-only**: a single protocol profile — authorization_code via Pushed
Authorization Requests (RFC 9126), DPoP sender-constraining (RFC 9449),
ATCA draft-07 client attestation, and PKCE S256 are all mandatory on
every request. There is no pre-authorized_code/plain flow.

## Access tokens

Access tokens are **RFC 9068 JWTs** (`typ: at+jwt`), signed with a local
EC P-256 key and DPoP-bound via a `cnf.jkt` claim. The Credential Issuer
verifies them offline against the JWK Set published at
`/oid4vci/v1/jwks`, so no introspection call happens per credential
request.

Beyond the registered claims, a token carries what the Credential Issuer
needs to complete issuance:

| Claim | Meaning |
| --- | --- |
| `cnf.jkt` | RFC 7638 thumbprint of the DPoP key the token is bound to |
| `issuance_record_id` | the issuance record the credential is built from |
| `c_nonce` | accepted as the wallet's proof-JWT nonce, so its first proof needs no Nonce Endpoint round trip |
| `client_id` | the attested wallet client |

Tokens are short-lived (5 minutes). Because they are stateless, RFC 6749
§4.1.2's "revoke the tokens issued from a reused authorization code" is
honoured by publishing the token's `jti` at
`GET /oid4vci/v1/revoked-tokens`, which the Credential Issuer polls and
checks before honouring a token.

## Run

```sh
make run          # http://localhost:8080
```

Requires an EC P-256 private key at `$FIKUA_CERTS_DIR/idp-key.pem`
(default `./certs`) — the service refuses to start without one, rather
than signing with a throwaway key that would silently invalidate every
token in flight on each restart. Generate one with:

```sh
openssl ecparam -genkey -name prime256v1 -noout -out certs/idp-key.pem
```

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `ADDR` | `:8080` | listen address |
| `FIKUA_BASE_URL` | `https://idp.fikua.com` | this AS's own identifier (`iss`) |
| `FIKUA_CREDENTIAL_ISSUER_URL` | `https://issuer.fikua.com` | the Credential Issuer tokens are minted for (`aud`) |
| `FIKUA_CERTS_DIR` | `./certs` | holds `idp-key.pem`, and optionally `root-ca.crt` for Wallet Provider trust pinning |
| `FIKUA_ISSUABLE_SCHEMES` | `urn:eudi:pid:1,...` | schemes the identification form may collect claims for |

## API

Full OpenAPI 3.0 spec at [`docs/openapi.yaml`](docs/openapi.yaml), also
served live at `/openapi.yaml` and browsable at `/swagger` (Swagger
UI) — same convention as `fikua-lab-issuer` and
`fikua-lab-attestation-registry`.

- `GET /.well-known/oauth-authorization-server` — RFC 8414 metadata.
- `GET /oid4vci/v1/jwks` — the access-token signing key's public JWK Set.
- `POST /oid4vci/v1/par` — Pushed Authorization Request.
- `GET /oid4vci/v1/authorize` — resolves a PAR request_uri into an authorization code, or redirects to identification.
- `POST /oid4vci/v1/token` — authorization_code grant, DPoP-bound RFC 9068 JWT.
- `GET /oid4vci/v1/revoked-tokens` — revoked `jti` denylist, polled by the Credential Issuer.
- `GET /identify/claims`, `POST /identify/complete`, `POST /identify/reject` — the identification UI's own backend (same-origin, not wallet-facing).
- `GET /health` — health check.

## UI

`/identify/` serves the end-user identification flow — plain HTML/CSS/JS,
no build step, absorbed from the standalone `fikua-lab-identify`
Cloudflare Worker.

The manual-form path is complete. Identification by X.509 client
certificate is **not ported yet**: it needs its own mTLS-terminating
Traefik route for this service before any Go code is worth writing. See
the `TODO(x509)` in `web/static/app.js` for where it plugs in, and
`fikua-lab-cert`'s `nginx.conf` for the header-reading mechanism to
replicate.

## Build

```sh
make build        # bin/idp, static binary, no CGO
```

## Docs

- [Issuer trust validation: LOTL and LoTE](docs/issuer-trust-validation.md) —
  what's needed to validate a presented credential's issuer against the
  EU's real trust infrastructure, and why it isn't built yet.

## License

Apache-2.0. See [LICENSE](LICENSE).
