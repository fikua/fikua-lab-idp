package mdocverify

import (
	"crypto/x509"
	"fmt"
	"time"
)

// validateCertChain checks an X.509 chain (leaf first) taken from an mdoc
// COSE x5chain: every certificate is inside its validity window, each is
// signed by the next, and every non-leaf asserts the CA basic constraint.
// The chain is anchored on trustAnchor when one is given, otherwise on the
// chain's own self-signed root if it ships one.
//
// The final branch — no pinned anchor and no self-signed root, e.g. a lone
// leaf whose issuing CA is out of band — accepts. That is deliberate and
// conformance-testing-only: the OIDF suite issues the credential under its
// own ephemeral CA and ships only what fits in x5chain, so there is nothing
// to anchor to and rejecting would fail every conformance run. It is *not*
// a trust decision: what it grants is "this presentation is internally
// consistent", not "this issuer is trusted".
//
// Deferred future work, in the order it will matter: pin the Fikua Issuer's
// own trust anchor for production presentations (the trustAnchor parameter
// is the seam — pass a root and the chain must terminate at it), and, once
// this Verifier registers as a real eIDAS Relying Party, replace the pin
// with WRPAC-based authorization so the wallet and the Verifier are
// checking each other against the same registry rather than a hardcoded
// certificate.
func validateCertChain(chain []*x509.Certificate, trustAnchor *x509.Certificate) error {
	if len(chain) == 0 {
		return fmt.Errorf("empty certificate chain")
	}

	now := time.Now()
	for _, cert := range chain {
		if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
			return fmt.Errorf("certificate not valid (expired or not yet valid): %s", cert.Subject)
		}
	}

	for i := 0; i < len(chain)-1; i++ {
		subject, issuer := chain[i], chain[i+1]
		if err := requireCA(issuer); err != nil {
			return err
		}
		if err := verifySignedBy(subject, issuer); err != nil {
			return err
		}
	}

	top := chain[len(chain)-1]
	switch {
	case trustAnchor != nil:
		if !top.Equal(trustAnchor) {
			if err := requireCA(trustAnchor); err != nil {
				return err
			}
			return verifySignedBy(top, trustAnchor)
		}
	case isSelfSigned(top):
		return verifySignedBy(top, top)
	}
	return nil
}

// isSelfSigned reports whether cert names itself as issuer and verifies
// under its own key.
func isSelfSigned(cert *x509.Certificate) bool {
	if cert.Subject.String() != cert.Issuer.String() {
		return false
	}
	return cert.CheckSignatureFrom(cert) == nil
}

func requireCA(cert *x509.Certificate) error {
	if !cert.IsCA {
		return fmt.Errorf("issuer certificate is not a CA: %s", cert.Subject)
	}
	return nil
}

func verifySignedBy(subject, issuer *x509.Certificate) error {
	if err := subject.CheckSignatureFrom(issuer); err != nil {
		return fmt.Errorf("certificate %s is not signed by %s: %w", subject.Subject, issuer.Subject, err)
	}
	return nil
}
