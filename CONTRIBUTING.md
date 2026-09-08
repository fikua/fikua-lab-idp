# Contributing

## Setup

Requires Go 1.26 and an EC P-256 private key at `./certs/idp-key.pem` — see
[README.md](README.md#run) for how to generate one.

```sh
make run          # http://localhost:8080
make build         # bin/idp
```

## Before opening a PR

```sh
go vet ./...
gofmt -l .         # must print nothing
go build ./...
go test ./...
```

CI (`.github/workflows/build.yml`) runs the same checks plus a SonarCloud
scan on every push to `main` and every pull request.

## Style

- No CGO, single static binary.
- Comments explain *why*, not *what* — skip a comment if the code already
  says it.
- No new third-party dependency without a reason it can't be done with the
  standard library or what's already in `go.mod`.
- `internal/oauth2/dpop.go`, `internal/oauth2/clientattestation.go` and
  `internal/cscclient/client.go` are intentionally duplicated from sibling
  repos (`fikua-lab-issuer`, `fikua-lab-attestation-registry`) rather than
  shared via a Go module — see the doc comment at the top of each file for
  why. Fix bugs in both copies.

## Commits

Short, descriptive, imperative-mood messages (`fix: ...`, `Add ...`),
matching the existing history (`git log`). No enforced conventional-commit
format beyond that.

## Tests

New behaviour in `internal/oauth2`, `internal/authz`, or `internal/httpapi`
should come with a test — plain stdlib `testing`, no assertion library.
`internal/httpapi` tests follow the `httptest.Server`-driven pattern used by
`fikua-lab-attestation-registry`'s `handlers_test.go`.
