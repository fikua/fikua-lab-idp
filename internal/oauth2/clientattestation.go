package oauth2

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// Client attestation transport, per ATCA draft-07.
const (
	HeaderClientAttestation    = "OAuth-Client-Attestation"
	HeaderClientAttestationPoP = "OAuth-Client-Attestation-PoP"

	ClientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-client-attestation"
)

const clientAttestationIATWindow = 5 * time.Minute

// ClientAttestationValidator validates a Wallet Instance Attestation (WIA)
// JWT + its Proof-of-Possession (PoP) JWT, per ATCA draft-07, returning
// the attested client_id.
type ClientAttestationValidator struct {
	// walletProviderAnchor, if set, pins WIA signature verification to
	// this single trusted CA (single-hop leaf-signature check, not full
	// X.509 path validation) — matching the Java issuer's root-ca.crt
	// loading. If nil, any self-consistent WIA is accepted (its x5c leaf
	// or header jwk verifies its own signature), with no chain-of-trust
	// check — same "no root CA configured" fallback as the Java issuer.
	walletProviderAnchor *x509.Certificate
	// expectedAudience is this authorization server's own identifier
	// (baseURL). Per ATCA draft-07 §5.2, the PoP JWT's `aud` claim MUST
	// equal it — a PoP minted for a different server must be rejected.
	expectedAudience string
}

// NewClientAttestationValidator builds a validator, optionally pinned to
// anchor (pass nil for no pinning). expectedAudience is this
// authorization server's own identifier, checked against every PoP
// JWT's `aud` claim.
func NewClientAttestationValidator(anchor *x509.Certificate, expectedAudience string) *ClientAttestationValidator {
	return &ClientAttestationValidator{walletProviderAnchor: anchor, expectedAudience: expectedAudience}
}

// ValidateHeaders validates client attestation carried in the
// OAuth-Client-Attestation / OAuth-Client-Attestation-PoP headers.
// Returns ("", nil) if both are absent (not an error by itself — the
// caller decides whether attestation was required).
func (v *ClientAttestationValidator) ValidateHeaders(wiaJWT, popJWT string) (string, error) {
	if wiaJWT == "" && popJWT == "" {
		return "", nil
	}
	if wiaJWT == "" {
		return "", Unauthorized(InvalidClient, "Missing OAuth-Client-Attestation header")
	}
	if popJWT == "" {
		return "", Unauthorized(InvalidClient, "Missing OAuth-Client-Attestation-PoP header")
	}
	return v.validateWiaAndPop(wiaJWT, popJWT)
}

// ValidateForm validates client attestation carried in the
// client_assertion_type/client_assertion form parameters
// ("<WIA>~<PoP>"). Returns ("", nil) if both are absent.
func (v *ClientAttestationValidator) ValidateForm(assertionType, assertion string) (string, error) {
	if assertionType == "" && assertion == "" {
		return "", nil
	}
	if assertionType != ClientAssertionType {
		return "", Unauthorized(InvalidClient, "Unsupported client_assertion_type: "+assertionType)
	}
	if assertion == "" {
		return "", Unauthorized(InvalidClient, "Missing client_assertion")
	}
	parts := strings.Split(assertion, "~")
	if len(parts) != 2 {
		return "", Unauthorized(InvalidClient, "client_assertion must contain WIA~PoP (two JWTs separated by ~)")
	}
	return v.validateWiaAndPop(parts[0], parts[1])
}

// Resolve tries header-based attestation first, falling back to form
// params — matching the Java issuer's resolveClientAttestation
// precedence.
func (v *ClientAttestationValidator) Resolve(wiaHeader, popHeader, assertionType, assertion string) (string, error) {
	clientID, err := v.ValidateHeaders(wiaHeader, popHeader)
	if err != nil || clientID != "" {
		return clientID, err
	}
	return v.ValidateForm(assertionType, assertion)
}

func (v *ClientAttestationValidator) validateWiaAndPop(wiaJWTString, popJWTString string) (string, error) {
	wiaMsg, err := jws.Parse([]byte(wiaJWTString))
	if err != nil {
		return "", Unauthorized(InvalidClient, "Invalid client attestation: "+err.Error())
	}
	if len(wiaMsg.Signatures()) != 1 {
		return "", Unauthorized(InvalidClient, "Invalid client attestation: expected exactly one signature")
	}
	wiaHeaders := wiaMsg.Signatures()[0].ProtectedHeaders()

	wiaKey, err := v.resolveWiaKey(wiaHeaders)
	if err != nil {
		return "", err
	}

	wiaToken, err := jwt.Parse([]byte(wiaJWTString), jwt.WithKey(jwa.ES256(), wiaKey), jwt.WithValidate(false))
	if err != nil {
		return "", Unauthorized(InvalidClient, "Client Attestation JWT signature verification failed")
	}

	if exp, hasExp := wiaToken.Expiration(); hasExp && time.Now().After(exp) {
		return "", Unauthorized(InvalidClient, "Client Attestation JWT has expired")
	}

	clientID, hasSub := wiaToken.Subject()
	if !hasSub || clientID == "" {
		var claimedClientID string
		if err := wiaToken.Get("client_id", &claimedClientID); err == nil {
			clientID = claimedClientID
		}
	}

	cnfKey, err := v.resolveCnfKey(wiaToken, popJWTString)
	if err != nil {
		return "", err
	}

	popToken, err := jwt.Parse([]byte(popJWTString), jwt.WithKey(jwa.ES256(), cnfKey), jwt.WithValidate(false))
	if err != nil {
		return "", Unauthorized(InvalidClient, "PoP signature verification failed")
	}

	if v.expectedAudience != "" {
		aud, _ := popToken.Audience()
		if !slices.Contains(aud, v.expectedAudience) {
			return "", Unauthorized(InvalidClientAttestation, "PoP JWT aud does not match this authorization server")
		}
	}

	if iat, hasIAT := popToken.IssuedAt(); hasIAT {
		if skew := time.Since(iat); skew > clientAttestationIATWindow || skew < -clientAttestationIATWindow {
			return "", Unauthorized(InvalidClient, "PoP JWT expired (iat too old)")
		}
	}
	if exp, hasExp := popToken.Expiration(); hasExp && time.Now().After(exp) {
		return "", Unauthorized(InvalidClient, "PoP JWT has expired")
	}

	return clientID, nil
}

// resolveWiaKey extracts the WIA's signing key from its header (x5c
// leaf, pinned to walletProviderAnchor if configured; else header jwk),
// per ATCA draft-07.
func (v *ClientAttestationValidator) resolveWiaKey(headers jws.Headers) (jwk.Key, error) {
	if chain, hasX5C := headers.X509CertChain(); hasX5C && chain.Len() > 0 {
		leafB64, _ := chain.Get(0)
		leafDER, err := base64.StdEncoding.DecodeString(string(leafB64))
		if err != nil {
			return nil, Unauthorized(InvalidClient, "Invalid client attestation: malformed x5c leaf certificate")
		}
		leaf, err := x509.ParseCertificate(leafDER)
		if err != nil {
			return nil, Unauthorized(InvalidClient, "Invalid client attestation: malformed x5c leaf certificate")
		}
		if v.walletProviderAnchor != nil {
			if err := leaf.CheckSignatureFrom(v.walletProviderAnchor); err != nil {
				return nil, Unauthorized(InvalidClient, "WIA is not issued by a trusted Wallet Provider")
			}
		}
		leafECDSA, ok := leaf.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, Unauthorized(InvalidClient, "Cannot verify WIA signature: leaf certificate is not an EC key")
		}
		return jwk.Import(leafECDSA)
	}
	if headerJWK, hasJWK := headers.JWK(); hasJWK {
		return headerJWK, nil
	}
	return nil, Unauthorized(InvalidClient, "Cannot verify WIA signature: no x5c or jwk in header")
}

// resolveCnfKey resolves the PoP-binding public key declared in the WIA's
// cnf claim: either an embedded cnf.jwk, or a cnf.jkt (RFC 7638
// thumbprint) that the PoP JWT's own header jwk must match.
func (v *ClientAttestationValidator) resolveCnfKey(wiaToken jwt.Token, popJWTString string) (jwk.Key, error) {
	var cnf map[string]any
	if err := wiaToken.Get("cnf", &cnf); err != nil || cnf == nil {
		return nil, Unauthorized(InvalidClient, "WIA missing cnf key for PoP verification")
	}

	if rawJWK, ok := cnf["jwk"]; ok {
		jwkBytes, err := json.Marshal(rawJWK)
		if err != nil {
			return nil, Unauthorized(InvalidClient, "WIA missing cnf key for PoP verification")
		}
		key, err := jwk.ParseKey(jwkBytes)
		if err != nil {
			return nil, Unauthorized(InvalidClient, "WIA missing cnf key for PoP verification")
		}
		return key, nil
	}

	jkt, _ := cnf["jkt"].(string)
	if jkt == "" {
		return nil, Unauthorized(InvalidClient, "WIA missing cnf key for PoP verification")
	}

	popMsg, err := jws.Parse([]byte(popJWTString))
	if err != nil || len(popMsg.Signatures()) != 1 {
		return nil, Unauthorized(InvalidClient, "WIA missing cnf key for PoP verification")
	}
	popHeaderKey, hasJWK := popMsg.Signatures()[0].ProtectedHeaders().JWK()
	if !hasJWK {
		return nil, Unauthorized(InvalidClient, "PoP key thumbprint does not match WIA cnf.jkt")
	}
	thumbprint, err := DPoPThumbprint(popHeaderKey)
	if err != nil || thumbprint != jkt {
		return nil, Unauthorized(InvalidClient, "PoP key thumbprint does not match WIA cnf.jkt")
	}
	return popHeaderKey, nil
}
