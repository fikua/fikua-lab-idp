// Package verifier implements this service's OID4VP 1.0 Final Verifier
// role: creating a verification session, serving its signed Authorization
// Request (JAR, RFC 9101), receiving and verifying the wallet's VP Token,
// and answering the frontend's result poll.
//
// Ported from the Java fikua-verifier module's VerificationService, with
// its profile machinery removed. That service could switch protocol
// profiles at runtime out of a Postgres-backed ProfileStore; this one is
// HAIP-fixed and configured from env vars only — DCQL as the only query
// language, direct_post or direct_post.jwt as the only response modes,
// ES256 everywhere, and vp_formats_supported always published in
// client_metadata. A profile abstraction with exactly one profile in it is
// a lookup that can only return one answer.
package verifier

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	fikuacrypto "github.com/fikua/fikua-lab-idp/internal/crypto"
	"github.com/fikua/fikua-lab-idp/internal/mdocverify"
	"github.com/fikua/fikua-lab-idp/internal/oauth2"
	"github.com/fikua/fikua-lab-idp/internal/sdjwtverify"
	"github.com/fikua/fikua-lab-idp/internal/session"
)

// APIPrefix is where this Verifier's wallet- and frontend-facing endpoints
// live, matching the Java verifier's paths exactly so an existing wallet
// deep link or frontend poll keeps working across the port.
const APIPrefix = "/oid4vp/v1"

// Credential format identifiers (OID4VP 1.0 Final Appendix B).
const (
	FormatSDJWTVC = "dc+sd-jwt"
	FormatMsoMdoc = "mso_mdoc"
)

// ResponseTypeVPToken is the only response_type OID4VP §5.2 defines.
const ResponseTypeVPToken = "vp_token"

// JARType is the JOSE `typ` of a signed Authorization Request Object (RFC
// 9101 §4), and the media type it must be served with — see
// httpapi's request handler, which had been serving application/json.
const JARType = "oauth-authz-req+jwt"

// Response modes (OID4VP §8.2). direct_post.jwt additionally encrypts the
// response to the Verifier's own key (HAIP §5).
const (
	ResponseModeDirectPost    = "direct_post"
	ResponseModeDirectPostJWT = "direct_post.jwt"
)

// requestObjectTTL is how long a Request Object's own `exp` allows it to be
// accepted by a wallet. Deliberately the same as the session TTL it is
// carried by (session.verificationSessionTTL, 5 minutes) — a Request Object
// outliving its session would only fail later and less clearly.
const requestObjectTTL = 5 * time.Minute

// Service implements the Verifier's four operations. Mirrors
// internal/authz.Service's shape: a struct of injected dependencies and one
// method per endpoint, with no HTTP types crossing the boundary.
type Service struct {
	baseURL       string
	signingKey    *fikuacrypto.RequestSigningKey
	encryptionKey *fikuacrypto.ResponseEncryptionKey
	sessions      *session.Store
	// responseMode is fixed per deployment rather than per session. HAIP
	// §5 mandates encrypted responses, so direct_post.jwt is the intended
	// value; plain direct_post stays reachable for interop debugging
	// against wallets that cannot encrypt yet.
	responseMode string
}

// NewService builds a Service. baseURL is this Verifier's own externally
// visible origin — its host becomes the client_id wallets check the
// Request Object's certificate against, and it prefixes the request_uri and
// response_uri wallets call back on. signingKey signs the Request Object
// (see crypto.RequestSigningKey on why it must be a DSS-held key);
// encryptionKey decrypts direct_post.jwt responses and is published in
// client_metadata.
func NewService(baseURL string, signingKey *fikuacrypto.RequestSigningKey, encryptionKey *fikuacrypto.ResponseEncryptionKey, sessions *session.Store, responseMode string) *Service {
	if responseMode == "" {
		responseMode = ResponseModeDirectPostJWT
	}
	return &Service{
		baseURL:       baseURL,
		signingKey:    signingKey,
		encryptionKey: encryptionKey,
		sessions:      sessions,
		responseMode:  responseMode,
	}
}

// CreateSessionRequest is what the frontend asks for: a credential type
// (the SD-JWT VC `vct` or the mdoc docType), the claims to request, and
// which format to request them in.
type CreateSessionRequest struct {
	CredentialType string
	Claims         []string
	Format         string
}

// CreateSessionResult is what the frontend gets back — everything it needs
// to render a QR code and start polling.
type CreateSessionResult struct {
	SessionID  string
	RequestURI string
	ClientID   string
	State      string
}

// CreateSession builds a verification session: a fresh state and nonce, a
// DCQL query for the requested claims, and the signed Authorization Request
// the wallet will fetch from RequestURI.
func (s *Service) CreateSession(req CreateSessionRequest) (CreateSessionResult, error) {
	mdoc := isMdocFormat(req.Format)

	sessionID := session.RandomToken(16)
	state := session.RandomToken(32)
	nonce := session.RandomToken(32)

	dcql := buildDCQLQuery(mdoc, req.CredentialType, req.Claims)
	clientID, err := s.clientID()
	if err != nil {
		return CreateSessionResult{}, err
	}
	clientMetadata, err := s.buildClientMetadata(mdoc)
	if err != nil {
		return CreateSessionResult{}, err
	}
	responseURI := s.baseURL + APIPrefix + "/response"

	requestJWT, err := s.signRequestObject(authorizationRequest{
		ResponseType:   ResponseTypeVPToken,
		ClientID:       clientID,
		ResponseMode:   s.responseMode,
		ResponseURI:    responseURI,
		Nonce:          nonce,
		State:          state,
		DCQLQuery:      dcql,
		ClientMetadata: clientMetadata,
		// OID4VP §5.10: a signed request addressed to a wallet that has no
		// pre-registered relationship with this Verifier uses the SIOPv2
		// audience value. `iss` is the client_id, as RFC 9101 §4 requires
		// of a request object the client itself signs.
		Audience: "https://self-issued.me/v2",
		Issuer:   clientID,
	})
	if err != nil {
		return CreateSessionResult{}, err
	}

	s.sessions.StoreVerification(session.VerificationSession{
		SessionID:    sessionID,
		State:        state,
		Nonce:        nonce,
		DCQLQuery:    dcql,
		ResponseMode: s.responseMode,
		ClientID:     clientID,
		ResponseURI:  responseURI,
		RequestJWT:   requestJWT,
		Status:       "pending",
	})

	return CreateSessionResult{
		SessionID:  sessionID,
		RequestURI: s.baseURL + APIPrefix + "/request/" + sessionID,
		ClientID:   clientID,
		State:      state,
	}, nil
}

// GetRequestObject returns the signed Request Object (JAR) for sessionID,
// marking the session as request_sent. The caller must serve it as
// application/oauth-authz-req+jwt (JARType) — RFC 9101 §10.8 and OID4VP
// §5.10 both require it, and a wallet that content-negotiates will reject
// application/json.
func (s *Service) GetRequestObject(sessionID string) (string, error) {
	v, ok := s.sessions.FindVerification(sessionID)
	if !ok {
		return "", oauth2.NotFound(oauth2.InvalidRequest, "Session not found or expired")
	}
	s.sessions.UpdateVerificationStatus(sessionID, "request_sent")
	return v.RequestJWT, nil
}

// ResponseRequest is a wallet's POST to /oid4vp/v1/response. Exactly one of
// two shapes arrives: Response set (direct_post.jwt — everything else is
// inside the JWE), or VPToken plus State (plain direct_post).
type ResponseRequest struct {
	VPToken  string
	State    string
	Response string
}

// Result is the outcome of a verification, shaped for the JSON the Java
// verifier's VerificationResult record produced — the frontend polling
// /result/{id} reads these exact field names.
type Result struct {
	Status           string         `json:"status"`
	Claims           map[string]any `json:"claims,omitempty"`
	Error            string         `json:"error,omitempty"`
	ErrorDescription string         `json:"error_description,omitempty"`
}

// Result status values.
const (
	StatusSuccess = "success"
	StatusError   = "error"
)

func successResult(claims map[string]any) Result {
	return Result{Status: StatusSuccess, Claims: claims}
}

func errorResult(code, description string) Result {
	return Result{Status: StatusError, Error: code, ErrorDescription: description}
}

// HandleResponse verifies a wallet's VP Token and records the outcome
// against its session. It returns the result, plus the session it belonged
// to (empty when the state could not be resolved at all) so the caller can
// build the same-device redirect_uri OID4VP §8.2 expects.
//
// Note the two-layer error model this keeps from the Java original: a
// failed *verification* is a recorded, polled-for outcome (the frontend
// must be able to show "that presentation was rejected, and why"), while a
// malformed *request* — no state, no vp_token — is a plain protocol error
// that never touches a session.
func (s *Service) HandleResponse(req ResponseRequest) (Result, session.VerificationSession, error) {
	vpToken, state := req.VPToken, req.State

	if req.Response != "" {
		// direct_post.jwt: state and vp_token are inside the JWE, so it has
		// to be decrypted before any session can be resolved.
		decrypted, err := s.decryptResponse(req.Response)
		if err != nil {
			return errorResult("invalid_request", err.Error()), session.VerificationSession{}, nil
		}
		vpToken, state = decrypted.vpToken, decrypted.state
		if state == "" || vpToken == "" {
			return errorResult("invalid_request", "Decrypted response is missing state or vp_token"), session.VerificationSession{}, nil
		}
	} else {
		if state == "" {
			return Result{}, session.VerificationSession{}, oauth2.BadRequest(oauth2.InvalidRequest, "Missing state parameter")
		}
		if vpToken == "" {
			return Result{}, session.VerificationSession{}, oauth2.BadRequest(oauth2.InvalidRequest, "Missing vp_token or response parameter")
		}
	}

	v, ok := s.sessions.FindVerificationByState(state)
	if !ok {
		return errorResult("invalid_request", "Unknown or expired state parameter"), session.VerificationSession{}, nil
	}

	claims, err := s.verifyPresentation(v, vpToken)
	if err != nil {
		s.sessions.UpdateVerificationResult(v.SessionID, "failed", vpToken, nil, err.Error())
		return errorResult("invalid_presentation", err.Error()), v, nil
	}

	s.sessions.UpdateVerificationResult(v.SessionID, "verified", vpToken, claims, "")
	return successResult(claims), v, nil
}

// verifyPresentation dispatches to the format-specific verifier. The format
// comes off the session's own stored DCQL query, never off the response: a
// wallet must answer the question that was asked, not pick the format whose
// verification it prefers.
func (s *Service) verifyPresentation(v session.VerificationSession, vpToken string) (map[string]any, error) {
	if sessionFormat(v) == FormatMsoMdoc {
		var thumbprint []byte
		if v.ResponseMode == ResponseModeDirectPostJWT {
			// OID4VP §B.2.6: the handover binds to the response-encryption
			// key only when the response was actually encrypted. Passing it
			// for an unencrypted response would fail every signature.
			var err error
			thumbprint, err = s.encryptionKey.ThumbprintSHA256()
			if err != nil {
				return nil, err
			}
		}
		return mdocverify.Verify(vpToken, sessionDocType(v), v.ClientID, v.Nonce, thumbprint, v.ResponseURI, nil)
	}
	return sdjwtverify.Verify(vpToken, v.ClientID, v.Nonce)
}

// decryptedResponse is the plaintext of a direct_post.jwt JWE.
type decryptedResponse struct {
	vpToken string
	state   string
}

func (s *Service) decryptResponse(jwe string) (decryptedResponse, error) {
	plaintext, err := s.encryptionKey.Decrypt(jwe)
	if err != nil {
		return decryptedResponse{}, fmt.Errorf("failed to decrypt response: %w", err)
	}
	var payload struct {
		VPToken any    `json:"vp_token"`
		State   string `json:"state"`
	}
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return decryptedResponse{}, fmt.Errorf("decrypted response is not JSON: %w", err)
	}
	return decryptedResponse{vpToken: firstVPToken(payload.VPToken), state: payload.State}, nil
}

// firstVPToken pulls a single presentation out of the several shapes
// vp_token takes. OID4VP §8.1 makes it an object keyed by DCQL credential
// id whose values are arrays; older wallets send a bare string. This
// Verifier only ever asks for one credential, so the first value found is
// the answer.
func firstVPToken(raw any) string {
	switch v := raw.(type) {
	case string:
		return v
	case []any:
		if len(v) > 0 {
			return firstVPToken(v[0])
		}
	case map[string]any:
		for _, value := range v {
			if token := firstVPToken(value); token != "" {
				return token
			}
		}
	}
	return ""
}

// GetResult answers the frontend's poll for a session's outcome. A session
// that exists but has not been presented to yet is reported as a "pending"
// error rather than a success with no claims — the frontend must be able to
// tell "not yet" from "done, and empty".
func (s *Service) GetResult(sessionID string) (Result, error) {
	v, ok := s.sessions.FindVerification(sessionID)
	if !ok {
		return Result{}, oauth2.NotFound("not_found", "Session not found")
	}
	switch v.Status {
	case "verified":
		claims := v.VerifiedClaims
		if claims == nil {
			claims = map[string]any{}
		}
		return successResult(claims), nil
	case "failed":
		return errorResult("verification_failed", v.Error), nil
	default:
		return errorResult("pending", "Verification not yet completed"), nil
	}
}

// ResultURI is where a same-device wallet is sent after a successful
// presentation (OID4VP §8.2's redirect_uri).
func (s *Service) ResultURI(sessionID string) string {
	return s.baseURL + APIPrefix + "/result/" + sessionID
}

// clientID is this Verifier's OID4VP Client Identifier. The `x509_san_dns:`
// prefix (OID4VP §5.10) tells the wallet to authenticate the request by
// checking the Request Object's x5c leaf has this DNS name in its SAN —
// which is the whole reason the signing key has to be a real DSS-issued
// certificate and not a local self-signed one.
func (s *Service) clientID() (string, error) {
	host, err := hostOf(s.baseURL)
	if err != nil {
		return "", err
	}
	return "x509_san_dns:" + host, nil
}

// certHash is base64url(SHA-256(leaf DER)), the value an `x509_hash:`
// client_id carries (OID4VP §5.10). Not used to build this Verifier's own
// client_id — x509_san_dns is the HAIP-profile choice — but kept because it
// is the one client-identifier value derivable from the signing key alone,
// and a wallet that only supports x509_hash needs it.
func (s *Service) certHash() (string, error) {
	der := s.signingKey.LeafDER()
	if len(der) == 0 {
		return "", fmt.Errorf("verifier: x509_hash client_id requires a certificate, but the signing key has no x5c chain")
	}
	sum := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

func hostOf(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("verifier: %q is not a usable base URL", rawURL)
	}
	return u.Hostname(), nil
}

// buildClientMetadata assembles the client_metadata carried in the Request
// Object. vp_formats_supported is always present (OID4VP §5.1 requires it),
// and an encrypted response mode adds the response-encryption key and the
// content-encryption methods HAIP §5 requires be advertised.
func (s *Service) buildClientMetadata(mdoc bool) (map[string]any, error) {
	vpFormats := map[string]any{}
	if mdoc {
		// mso_mdoc advertises COSE algorithm identifiers, where ES256 is -7
		// (RFC 9053 §2.1) — not the JOSE "ES256" string.
		vpFormats[FormatMsoMdoc] = map[string]any{"alg": []int{-7}}
	} else {
		vpFormats[FormatSDJWTVC] = map[string]any{
			"sd-jwt_alg_values": []string{"ES256"},
			"kb-jwt_alg_values": []string{"ES256"},
		}
	}

	metadata := map[string]any{"vp_formats_supported": vpFormats}

	if s.responseMode == ResponseModeDirectPostJWT {
		publicJWK, err := s.encryptionKey.PublicJWK()
		if err != nil {
			return nil, err
		}
		metadata["jwks"] = map[string]any{"keys": []any{publicJWK}}
		metadata["encrypted_response_enc_values_supported"] = fikuacrypto.ResponseEncryptionEncValues
	}
	return metadata, nil
}

// buildDCQLQuery builds the DCQL query for one credential. SD-JWT VC
// filters on vct_values with single-segment claim paths; mso_mdoc filters
// on a single doctype_value with two-segment [namespace, element] paths,
// where the PID mdoc's namespace is its docType.
func buildDCQLQuery(mdoc bool, credentialType string, requestedClaims []string) session.DCQLQuery {
	claims := make([]session.DCQLClaimQuery, 0, len(requestedClaims))
	query := session.DCQLCredentialQuery{ID: "requested_credential"}

	if mdoc {
		for _, name := range requestedClaims {
			claims = append(claims, session.DCQLClaimQuery{Path: []string{credentialType, name}})
		}
		query.Format = FormatMsoMdoc
		query.Meta = &session.DCQLMeta{DoctypeValue: credentialType}
	} else {
		for _, name := range requestedClaims {
			claims = append(claims, session.DCQLClaimQuery{Path: []string{name}})
		}
		query.Format = FormatSDJWTVC
		query.Meta = &session.DCQLMeta{VCTValues: []string{credentialType}}
	}
	query.Claims = claims

	return session.DCQLQuery{Credentials: []session.DCQLCredentialQuery{query}}
}

// isMdocFormat maps the frontend's requested format onto this Verifier's
// two. Aliases accepted for the same reason the Java version accepted them:
// existing callers say "mdoc" or "iso_mdl" as often as the spec's
// "mso_mdoc". Anything unrecognised (including empty) means SD-JWT VC,
// which is this ecosystem's primary format.
func isMdocFormat(format string) bool {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case FormatMsoMdoc, "mdoc", "iso_mdl":
		return true
	default:
		return false
	}
}

// sessionFormat reads the credential format back off the session's own
// stored DCQL query, which is where it was fixed at creation time.
func sessionFormat(v session.VerificationSession) string {
	if len(v.DCQLQuery.Credentials) == 0 {
		return FormatSDJWTVC
	}
	return v.DCQLQuery.Credentials[0].Format
}

// sessionDocType recovers the requested mdoc docType from the session's
// DCQL query, so the presented document can be checked against it.
func sessionDocType(v session.VerificationSession) string {
	if len(v.DCQLQuery.Credentials) == 0 || v.DCQLQuery.Credentials[0].Meta == nil {
		return ""
	}
	return v.DCQLQuery.Credentials[0].Meta.DoctypeValue
}
