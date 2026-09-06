package verifier

import (
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/fikua/fikua-lab-idp/internal/session"
)

// authorizationRequest is the OID4VP Authorization Request (§5) that
// becomes the payload of the signed Request Object. Field names are the
// wire names a wallet reads; they must match the Java verifier's
// AuthorizationRequest record byte-for-byte, since the wallets and the
// conformance suite were tested against that shape.
//
// Scope is deliberately absent where the Java record had it: this Verifier
// only ever queries with DCQL, and OID4VP §5.1 makes scope and dcql_query
// mutually exclusive, so the field could only ever have been null.
type authorizationRequest struct {
	ResponseType   string            `json:"response_type"`
	ClientID       string            `json:"client_id"`
	ResponseMode   string            `json:"response_mode"`
	ResponseURI    string            `json:"response_uri"`
	Nonce          string            `json:"nonce"`
	State          string            `json:"state"`
	DCQLQuery      session.DCQLQuery `json:"dcql_query"`
	ClientMetadata map[string]any    `json:"client_metadata"`
	Audience       string            `json:"aud"`
	Issuer         string            `json:"iss"`
}

// signRequestObject signs req as a JAR (RFC 9101): a JWS whose payload is
// the request parameters, with typ=oauth-authz-req+jwt, the kid, and the
// signing certificate chain in x5c.
//
// The x5c header is what makes the whole request authenticable: an
// `x509_san_dns:` client_id (see Service.clientID) tells the wallet to
// check this Verifier's identity against the leaf certificate's SAN, so a
// request signed without one is a request no wallet can trust. HAIP §6.1.1
// forbids the trust anchor's own certificate from appearing in x5c, which
// cscclient.Signer.LeafDER already handles upstream.
func (s *Service) signRequestObject(req authorizationRequest) (string, error) {
	now := time.Now()

	builder := jwt.NewBuilder().
		Claim("response_type", req.ResponseType).
		Claim("client_id", req.ClientID).
		Claim("response_mode", req.ResponseMode).
		Claim("response_uri", req.ResponseURI).
		Claim("nonce", req.Nonce).
		Claim("state", req.State).
		Claim("dcql_query", req.DCQLQuery).
		Claim("client_metadata", req.ClientMetadata).
		Audience([]string{req.Audience}).
		Issuer(req.Issuer).
		IssuedAt(now).
		Expiration(now.Add(requestObjectTTL))

	token, err := builder.Build()
	if err != nil {
		return "", err
	}

	headers, err := s.requestObjectHeaders()
	if err != nil {
		return "", err
	}
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.ES256(), s.signingKey.Signer(), jws.WithProtectedHeaders(headers)))
	if err != nil {
		return "", err
	}
	return string(signed), nil
}

// requestObjectHeaders builds the JWS protected headers a Request Object
// must carry: RFC 9101 §10.8's typ (which a wallet uses to refuse a JWT
// meant for some other purpose replayed as a request object), the kid, and
// the x5c chain the client_id is checked against.
func (s *Service) requestObjectHeaders() (jws.Headers, error) {
	headers := jws.NewHeaders()
	if err := headers.Set(jws.TypeKey, JARType); err != nil {
		return nil, err
	}
	if err := headers.Set(jws.KeyIDKey, s.signingKey.KID()); err != nil {
		return nil, err
	}
	chain, err := s.signingKey.JOSEX5CChain()
	if err != nil {
		return nil, err
	}
	if chain != nil {
		if err := headers.Set(jws.X509CertChainKey, chain); err != nil {
			return nil, err
		}
	}
	return headers, nil
}
