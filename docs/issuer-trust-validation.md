# Issuer trust validation: LOTL and LoTE

The OID4VP Verifier currently validates a presented credential's issuer
signature only against the x5c certificate chain embedded in the
presentation itself (`internal/sdjwtverify`, `internal/mdocverify`) —
correct for conformance testing, not for a production trust decision.
This document records what a real implementation needs and why it
isn't built yet.

## Two separate mechanisms, not one

The EUDI Wallet ecosystem's Issuer-trust model (ARF §3.5, §6.3.2.4)
requires validating against **two** ETSI specifications, not the
single classic eIDAS list most people mean by "LOTL":

- **ETSI TS 119 612 — Trusted Lists (the classic LOTL/TL mechanism)**:
  the EU-level List Of Trusted Lists (LOTL), a signed XML pointing at
  each Member State's own Trusted List, in turn listing Trust Service
  Providers and their services/certificates. This is the Article 22
  eIDAS mechanism — mature, in production for years across the EU.
  Answers *"who may vouch for a certificate"* (CAs / qualified trust
  services).
- **ETSI TS 119 602 — Lists of Trusted Entities (LoTE)**: a new
  spec (published 2025-11), EUDI-Wallet-specific, generalizing the
  same technical shape to list PID/Attestation/Wallet Providers
  themselves — *not* the same list as the classic eIDAS TL, despite
  looking similar on the wire. Answers *"who is vouched for"* (the
  Issuer entities a wallet should trust).

An Issuer-trust implementation needs both: TS 119 612 to validate the
chain of authority down to a Trust Service Provider, and TS 119 602 to
confirm that provider is a recognized PID/Attestation Provider for the
credential type being presented.

## Maturity differs sharply between the two — this is the reason to split them

- **TS 119 612 / classic LOTL: mature.** [`esig/dss`](https://github.com/esig/dss)
  (the EU-funded "Digital Signature Services" project — unrelated to,
  and not to be confused with, this ecosystem's own internal
  `fikua-lab-...` DSS mock CSC signing service; the shared name is a
  coincidence) has implemented LOTL/TL parsing and validation
  (`dss-tsl-validation`) for over a decade, in production use across
  the EU. Building against this today is realistic.
- **TS 119 602 / LoTE: not yet.** Published only in November 2025. The
  EU's own reference implementation —
  [`eudi-lib-kmp-etsi-1196x2`](https://github.com/eu-digital-identity-wallet)
  (Kotlin Multiplatform) plus the
  [`eudi-srv-trust-validator`](https://github.com/eu-digital-identity-wallet)
  microservice built on it — explicitly self-describes as an "initial
  development release... not recommended for production." There is
  essentially no other implementation of TS 119 602 anywhere yet, in
  any language.

## Why not built now

- `esig/dss` and the EU's own LoTE tooling are **Java-only** — no
  non-JVM port exists for either, and nothing in Go implements LOTL/TL
  or LoTE trust-list semantics (only unrelated signature-verification
  primitives like `goxmldsig`/`goxades` exist in Go, which don't touch
  trust-list parsing at all).
- Reimplementing TS 119 612 in Go from scratch is not a small task —
  `esig/dss` itself is a decade-plus, EU-funded, dozens-of-modules
  project (XAdES/CAdES/PAdES/JAdES, XML-DSig, ASiC, LOTL parsing/
  caching/pivot handling). TS 119 602 has no reference to port from at
  all yet outside the pre-production Kotlin library above.
- eIDAS2 requires Member States to offer at least one wallet by
  December 2026, and the trust-list ecosystem is live for some roles
  (RP access certificates, an age-verification attestation-provider
  list as of mid-2026) — but TS 119 602/LoTE specifically is still
  stabilizing even in its own reference implementation. This is a
  near-term roadmap item, not a today-blocking gap.

## Planned shape, once pursued

Given the maturity split above, **TS 119 612 (classic LOTL) is the
one worth building first** — the tooling for it is genuinely
production-ready today, unlike LoTE. Likely integration: a separate
Java microservice built on `esig/dss`'s `dss-tsl-validation` (either a
thin hand-built wrapper, or a hosted/updated version of `esig/dss`'s
own demo REST tooling), exposing a narrow endpoint —
"validate this X.509 chain as of this timestamp" → a trust verdict —
called over HTTP from this Go Verifier's issuer-signature check. Not
a dependency embedded in the `fikua-lab-idp` binary itself, and not a
Go reimplementation.

TS 119 602/LoTE support would follow the same pattern once the
ecosystem's own reference implementation graduates past
"not recommended for production" — likely by extending the same Java
microservice (or wrapping `eudi-lib-kmp-etsi-1196x2` directly) rather
than a second, separate integration.
