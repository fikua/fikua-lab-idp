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
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"

	fikuacrypto "github.com/fikua/fikua-lab-idp/internal/crypto"
	"github.com/fikua/fikua-lab-idp/internal/mdocverify"
	"github.com/fikua/fikua-lab-idp/internal/oauth2"
	"github.com/fikua/fikua-lab-idp/internal/sdjwtverify"
	"github.com/fikua/fikua-lab-idp/internal/session"
	"github.com/fikua/fikua-lab-idp/internal/statuslistcheck"
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
	baseURL    string
	signingKey *fikuacrypto.RequestSigningKey
	sessions   *session.Store
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
// (see crypto.RequestSigningKey on why it must be a DSS-held key). A
// response-encryption key is no longer a Service-level dependency: OID4VP
// §8.3 / HAIP §5.5 require a fresh one per Authorization Request, so
// CreateSession generates one per session instead (see
// session.VerificationSession.EncryptionKey) — a single key reused across
// every session's client_metadata failed OIDF's
// VP1FinalCheckEncryptionKeyNotReused.
func NewService(baseURL string, signingKey *fikuacrypto.RequestSigningKey, sessions *session.Store, responseMode string) *Service {
	if responseMode == "" {
		responseMode = ResponseModeDirectPostJWT
	}
	return &Service{
		baseURL:      baseURL,
		signingKey:   signingKey,
		sessions:     sessions,
		responseMode: responseMode,
	}
}

// CredentialRequest is one credential the frontend wants requested: its own
// DCQL credential-query ID, a credential type (the SD-JWT VC `vct` or the
// mdoc docType), the claims to request, and which format to request them
// in.
type CredentialRequest struct {
	ID             string
	CredentialType string
	Claims         []string
	Format         string
}

// CreateSessionRequest is what the frontend asks for: one or more
// credentials to request together in a single presentation. A
// single-element Credentials is the common case (e.g. a bare PID request);
// more than one means every credential listed is required in the same
// presentation — this Verifier has no notion of alternative/optional
// credential choices, so there is exactly one DCQLCredentialSet option
// naming all of them (see buildDCQLQuery).
type CreateSessionRequest struct {
	Credentials []CredentialRequest
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
	if len(req.Credentials) == 0 {
		return CreateSessionResult{}, fmt.Errorf("verifier: CreateSession requires at least one credential")
	}

	sessionID := session.RandomToken(16)
	state := session.RandomToken(32)
	nonce := session.RandomToken(32)

	dcql := buildDCQLQuery(req.Credentials)
	clientID, err := s.clientID()
	if err != nil {
		return CreateSessionResult{}, err
	}

	var encryptionKey *fikuacrypto.ResponseEncryptionKey
	if s.responseMode == ResponseModeDirectPostJWT {
		// Fresh per session — see NewService's doc comment on why this
		// can no longer live on the Service itself.
		encryptionKey, err = fikuacrypto.GenerateResponseEncryptionKey()
		if err != nil {
			return CreateSessionResult{}, err
		}
	}
	clientMetadata, err := s.buildClientMetadata(dcql, encryptionKey)
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
		SessionID:     sessionID,
		State:         state,
		Nonce:         nonce,
		DCQLQuery:     dcql,
		ResponseMode:  s.responseMode,
		ClientID:      clientID,
		ResponseURI:   responseURI,
		RequestJWT:    requestJWT,
		EncryptionKey: encryptionKey,
		Status:        "pending",
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
func (s *Service) HandleResponse(ctx context.Context, req ResponseRequest) (Result, session.VerificationSession, error) {
	var rawVPToken any = req.VPToken
	state := req.State
	var v session.VerificationSession

	if req.Response != "" {
		// direct_post.jwt: state and vp_token are inside the JWE. The
		// session — and so its own response-encryption private key — has
		// to be found first, via the kid the JWE names, since a single
		// shared key would fail OID4VP §8.3/HAIP §5.5's "fresh key per
		// Authorization Request" (see session.VerificationSession.
		// EncryptionKey's doc comment).
		kid, err := fikuacrypto.PeekResponseEncryptionKID(req.Response)
		if err != nil {
			return errorResult("invalid_request", err.Error()), session.VerificationSession{}, nil
		}
		found, ok := s.sessions.FindVerificationByEncryptionKID(kid)
		if !ok {
			return errorResult("invalid_request", "Unknown or expired encryption key"), session.VerificationSession{}, nil
		}
		v = found

		decrypted, err := decryptResponse(v.EncryptionKey, req.Response)
		if err != nil {
			return errorResult("invalid_request", err.Error()), session.VerificationSession{}, nil
		}
		rawVPToken, state = decrypted.vpToken, decrypted.state
		if state == "" || allVPTokens(parseVPToken(rawVPToken), v.DCQLQuery) == nil {
			return errorResult("invalid_request", "Decrypted response is missing state or vp_token"), session.VerificationSession{}, nil
		}
		if state != v.State {
			return errorResult("invalid_request", "Decrypted state does not match this encryption key's session"), session.VerificationSession{}, nil
		}
	} else {
		if state == "" {
			return Result{}, session.VerificationSession{}, oauth2.BadRequest(oauth2.InvalidRequest, "Missing state parameter")
		}
		if req.VPToken == "" {
			return Result{}, session.VerificationSession{}, oauth2.BadRequest(oauth2.InvalidRequest, "Missing vp_token or response parameter")
		}
		found, ok := s.sessions.FindVerificationByState(state)
		if !ok {
			return errorResult("invalid_request", "Unknown or expired state parameter"), session.VerificationSession{}, nil
		}
		v = found
	}

	vpTokens := allVPTokens(parseVPToken(rawVPToken), v.DCQLQuery)
	claims, err := s.verifyPresentations(ctx, v, vpTokens)
	if err != nil {
		s.sessions.UpdateVerificationResult(v.SessionID, "failed", vpTokens, nil, err.Error())
		return errorResult("invalid_presentation", err.Error()), v, nil
	}

	s.sessions.UpdateVerificationResult(v.SessionID, "verified", vpTokens, claims, "")
	return successResult(mergeClaims(claims)), v, nil
}

// mergeClaims flattens per-credential claims into the single map GetResult
// and this response have always returned. A single-credential session's
// result is unchanged from before this package supported more than one;
// callers that care about *which* credential a claim came from should read
// VerificationSession.VerifiedClaims/GetResultDetailed instead once that
// distinction matters to them — nothing does yet.
func mergeClaims(perCredential map[string]map[string]any) map[string]any {
	merged := map[string]any{}
	for _, claims := range perCredential {
		for k, v := range claims {
			merged[k] = v
		}
	}
	return merged
}

// verifyPresentations verifies every credential in the session's DCQL
// query against its matching entry in vpTokens (keyed by
// DCQLCredentialQuery.ID — see allVPTokens), then, when more than one
// credential was requested, checks they were all presented by the same
// holder (verifyCrossCredentialBinding). A single failure — a missing
// token, a bad signature, or a holder-key mismatch — fails the whole
// presentation: this Verifier has no notion of a partially-successful
// multi-credential response.
func (s *Service) verifyPresentations(ctx context.Context, v session.VerificationSession, vpTokens map[string]string) (map[string]map[string]any, error) {
	claims := make(map[string]map[string]any, len(v.DCQLQuery.Credentials))
	holderKeys := make(map[string]jwk.Key, len(v.DCQLQuery.Credentials))

	for _, cred := range v.DCQLQuery.Credentials {
		vpToken, ok := vpTokens[cred.ID]
		if !ok || vpToken == "" {
			return nil, fmt.Errorf("no presentation received for requested credential %q", cred.ID)
		}
		credClaims, holderKey, err := s.verifyPresentation(ctx, v, cred, vpToken)
		if err != nil {
			return nil, fmt.Errorf("credential %q: %w", cred.ID, err)
		}
		claims[cred.ID] = credClaims
		if holderKey != nil {
			holderKeys[cred.ID] = holderKey
		}
	}

	if len(v.DCQLQuery.Credentials) > 1 {
		if err := verifyCrossCredentialBinding(holderKeys); err != nil {
			return nil, err
		}
	}
	return claims, nil
}

// verifyPresentation dispatches to the format-specific verifier for one
// credential, then — for a credential that carries one — checks the
// presented credential's own Token Status List reference. HAIP §7 point
// 2.2.2.2 requires this fetch actually happen, not just that the
// presentation's signatures check out; a revoked credential's signature is
// still valid, that's the whole reason a separate status check exists. The
// format and docType come off cred, the session's own stored DCQL query
// for this credential ID, never off the response: a wallet must answer the
// question that was asked, not pick the format whose verification it
// prefers. holderKey is nil for mdoc (this Verifier does not yet extract a
// comparable per-credential key from an mdoc DeviceResponse — cross-format
// binding is future work, see verifyCrossCredentialBinding's doc comment).
func (s *Service) verifyPresentation(ctx context.Context, v session.VerificationSession, cred session.DCQLCredentialQuery, vpToken string) (map[string]any, jwk.Key, error) {
	if cred.Format == FormatMsoMdoc {
		var thumbprint []byte
		if v.ResponseMode == ResponseModeDirectPostJWT {
			// OID4VP §B.2.6: the handover binds to the response-encryption
			// key only when the response was actually encrypted. Passing it
			// for an unencrypted response would fail every signature.
			var err error
			thumbprint, err = v.EncryptionKey.ThumbprintSHA256()
			if err != nil {
				return nil, nil, err
			}
		}
		docType := ""
		if cred.Meta != nil {
			docType = cred.Meta.DoctypeValue
		}
		// mdoc status-list checking is not yet wired up here — this
		// Verifier's OIDF coverage so far only exercises the SD-JWT VC
		// path (docs/issuer-trust-validation.md tracks the analogous
		// issuer-trust gap; this is the same kind of "ported the
		// crypto, not yet every HAIP consequence of it" gap for mdoc).
		claims, err := mdocverify.Verify(vpToken, docType, v.ClientID, v.Nonce, thumbprint, v.ResponseURI, nil)
		return claims, nil, err
	}

	result, verifyErr := sdjwtverify.VerifyWithStatus(vpToken, v.ClientID, v.Nonce)
	// The status list fetch runs even when verifyErr is set: HAIP §7 point
	// 2.2.2.2 requires the Verifier check revocation status regardless of
	// whether the presentation is otherwise accepted (confirmed against
	// OIDF's invalid-signature/-KB-JWT-signature/-sd_hash conformance
	// tests, which all still require the fetch). status itself is read
	// off the issuer JWT's payload without waiting on its signature — see
	// sdjwtverify.unverifiedStatusClaim's doc comment on why that's safe.
	if ref, ok := statuslistcheck.ParseRef(result.Status); ok {
		if err := statuslistcheck.CheckValid(ctx, ref); err != nil && verifyErr == nil {
			verifyErr = err
		}
	}
	if verifyErr != nil {
		return nil, nil, verifyErr
	}
	return result.Claims, result.HolderKey, nil
}

// verifyCrossCredentialBinding requires every credential in a
// multi-credential presentation to have been presented by the same holder
// — the check that gives meaning to a Rulebook's
// `cryptographically_bound_to` claim (e.g. the Barcelona padró attestation
// declaring it presupposes a verified PID): without it, a wallet could mix
// a genuine padró attestation with a different person's PID and this
// Verifier would accept both as individually valid. Compared by JWK
// thumbprint (RFC 7638) rather than raw key material, so any two
// equivalent encodings of the same key still match.
//
// Only covers SD-JWT VC credentials today — an mdoc presentation's
// holderKeys entry is absent (see verifyPresentation), so a
// multi-credential set mixing formats cannot have its binding checked yet.
// That gap is acceptable for now: the Barcelona padró attestation this was
// built for is dc+sd-jwt-only (see fikua-lab-attestation-registry's
// padro-barcelona.json), so every credential this function is actually
// called with today has a holder key. Revisit if a mixed-format
// combination is ever requested.
func verifyCrossCredentialBinding(holderKeys map[string]jwk.Key) error {
	var firstID, firstThumb string
	for id, key := range holderKeys {
		thumb, err := jwkThumbprint(key)
		if err != nil {
			return fmt.Errorf("credential %q: computing holder key thumbprint: %w", id, err)
		}
		if firstThumb == "" {
			firstID, firstThumb = id, thumb
			continue
		}
		if thumb != firstThumb {
			return fmt.Errorf("credential %q is not bound to the same holder key as credential %q", id, firstID)
		}
	}
	return nil
}

// jwkThumbprint returns a JWK's RFC 7638 thumbprint as a base64url string,
// suitable for comparing two keys for equality regardless of their exact
// JSON encoding.
func jwkThumbprint(key jwk.Key) (string, error) {
	thumb, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(thumb), nil
}

// decryptedResponse is the plaintext of a direct_post.jwt JWE. vpToken is
// left as decoded JSON (string, or object keyed by DCQL credential id per
// OID4VP §8.1) rather than flattened here — allVPTokens is the one place
// that shape gets resolved, shared with the plain direct_post path.
type decryptedResponse struct {
	vpToken any
	state   string
}

func decryptResponse(key *fikuacrypto.ResponseEncryptionKey, jwe string) (decryptedResponse, error) {
	plaintext, err := key.Decrypt(jwe)
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
	return decryptedResponse{vpToken: payload.VPToken, state: payload.State}, nil
}

// parseVPToken normalizes a vp_token into the shape allVPTokens expects.
// The plain direct_post path hands this a raw form-field string, which is
// either a single presentation on its own (single-credential, no object
// wrapper) or a JSON-encoded {credential_id: [...]} object (OID4VP §8.1,
// multi-credential) — form fields have no native JSON type, so a
// multi-credential wallet must serialize it. The direct_post.jwt path
// hands this an already-decoded any (string or map, see decryptResponse)
// and gets it back unchanged.
func parseVPToken(raw any) any {
	s, ok := raw.(string)
	if !ok {
		return raw
	}
	var decoded any
	if err := json.Unmarshal([]byte(s), &decoded); err == nil {
		if _, isObject := decoded.(map[string]any); isObject {
			return decoded
		}
	}
	return s
}

// allVPTokens resolves the several shapes vp_token takes into a map keyed
// by DCQL credential-query ID. OID4VP §8.1 makes it an object keyed by
// DCQL credential id whose values are arrays when more than one credential
// was requested (or, per some wallets, even for exactly one); a bare
// string is a single-credential response from a wallet that skips the
// object wrapper entirely. When raw is a bare string, it is attributed to
// query.Credentials[0].ID — correct only for a single-credential session,
// which is the only shape a bare-string wallet response can mean anyway
// (a wallet has no way to name a credential ID without the object form).
func allVPTokens(raw any, query session.DCQLQuery) map[string]string {
	switch v := raw.(type) {
	case string:
		if v == "" || len(query.Credentials) == 0 {
			return nil
		}
		return map[string]string{query.Credentials[0].ID: v}
	case map[string]any:
		tokens := make(map[string]string, len(v))
		for id, value := range v {
			if token := firstOf(value); token != "" {
				tokens[id] = token
			}
		}
		return tokens
	}
	return nil
}

// firstOf unwraps a vp_token entry's value — a bare string, or (per OID4VP
// §8.1) a one-or-more-element array of strings, of which only the first is
// used since this Verifier never requests more than one instance of the
// same credential.
func firstOf(raw any) string {
	switch v := raw.(type) {
	case string:
		return v
	case []any:
		if len(v) > 0 {
			return firstOf(v[0])
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
		return successResult(mergeClaims(v.VerifiedClaims)), nil
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

// clientID is this Verifier's OID4VP Client Identifier. HAIP §5 is
// explicit and leaves no alternative: "For signed requests, the Verifier
// MUST use, and the Wallet MUST accept the Client Identifier Prefix
// x509_hash as defined in Section 5.9.3 of [OID4VP]" — not x509_san_dns,
// which OID4VP §5.9.3 defines as a separate, valid-but-not-HAIP-mandated
// scheme. Confirmed against an OIDF conformance run: a client_id of
// x509_san_dns:<host> made ExtractAndValidateX509HashClientId fail even
// though the x5c chain and signature both validated correctly — the test
// expects the hash scheme specifically, matching the spec text above.
func (s *Service) clientID() (string, error) {
	return s.certHash()
}

// certHash is `x509_hash:` plus base64url(SHA-256(leaf DER)) — this
// Verifier's Client Identifier per HAIP §5 / OID4VP §5.9.3. Derived from
// the signing key alone, which is why that key has to be a real
// DSS-issued certificate: a self-signed one would make every session's
// client_id valid only to a wallet that already trusts this exact
// throwaway cert.
func (s *Service) certHash() (string, error) {
	der := s.signingKey.LeafDER()
	if len(der) == 0 {
		return "", fmt.Errorf("verifier: x509_hash client_id requires a certificate, but the signing key has no x5c chain")
	}
	sum := sha256.Sum256(der)
	return "x509_hash:" + base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// buildClientMetadata assembles the client_metadata carried in the Request
// Object. vp_formats_supported is always present (OID4VP §5.1 requires it),
// listing every format actually requested across dcql's credentials (a
// mixed SD-JWT VC + mso_mdoc session advertises both). An encrypted
// response mode adds encryptionKey's public JWK and the content-encryption
// methods HAIP §5 requires be advertised. encryptionKey is this session's
// own — see CreateSession — never nil when the Service's responseMode is
// direct_post.jwt.
func (s *Service) buildClientMetadata(dcql session.DCQLQuery, encryptionKey *fikuacrypto.ResponseEncryptionKey) (map[string]any, error) {
	vpFormats := map[string]any{}
	for _, cred := range dcql.Credentials {
		switch cred.Format {
		case FormatMsoMdoc:
			// mso_mdoc advertises COSE algorithm identifiers, where ES256 is
			// -7 (RFC 9053 §2.1) — not the JOSE "ES256" string.
			vpFormats[FormatMsoMdoc] = map[string]any{"alg": []int{-7}}
		case FormatSDJWTVC:
			vpFormats[FormatSDJWTVC] = map[string]any{
				"sd-jwt_alg_values": []string{"ES256"},
				"kb-jwt_alg_values": []string{"ES256"},
			}
		}
	}

	metadata := map[string]any{"vp_formats_supported": vpFormats}

	if s.responseMode == ResponseModeDirectPostJWT {
		publicJWK, err := encryptionKey.PublicJWK()
		if err != nil {
			return nil, err
		}
		metadata["jwks"] = map[string]any{"keys": []any{publicJWK}}
		metadata["encrypted_response_enc_values_supported"] = fikuacrypto.ResponseEncryptionEncValues
	}
	return metadata, nil
}

// buildDCQLQuery builds the DCQL query for one or more credentials, one
// session.DCQLCredentialQuery per CredentialRequest, keyed by its own ID.
// SD-JWT VC filters on vct_values with single-segment claim paths; mso_mdoc
// filters on a single doctype_value with two-segment [namespace, element]
// paths, where the PID mdoc's namespace is its docType.
//
// More than one credential adds a single CredentialSets entry naming every
// requested ID as the one option — this Verifier always requires every
// credential it asks for, it never offers a wallet a choice between
// alternatives, so one all-of option is the whole of what needs saying (see
// CreateSessionRequest's doc comment).
func buildDCQLQuery(requests []CredentialRequest) session.DCQLQuery {
	credentials := make([]session.DCQLCredentialQuery, 0, len(requests))
	ids := make([]string, 0, len(requests))

	for _, req := range requests {
		mdoc := isMdocFormat(req.Format)
		claims := make([]session.DCQLClaimQuery, 0, len(req.Claims))
		query := session.DCQLCredentialQuery{ID: req.ID}

		if mdoc {
			for _, name := range req.Claims {
				claims = append(claims, session.DCQLClaimQuery{Path: []string{req.CredentialType, name}})
			}
			query.Format = FormatMsoMdoc
			query.Meta = &session.DCQLMeta{DoctypeValue: req.CredentialType}
		} else {
			for _, name := range req.Claims {
				claims = append(claims, session.DCQLClaimQuery{Path: []string{name}})
			}
			query.Format = FormatSDJWTVC
			query.Meta = &session.DCQLMeta{VCTValues: []string{req.CredentialType}}
		}
		query.Claims = claims

		credentials = append(credentials, query)
		ids = append(ids, req.ID)
	}

	dcql := session.DCQLQuery{Credentials: credentials}
	if len(requests) > 1 {
		dcql.CredentialSets = []session.DCQLCredentialSet{{Options: [][]string{ids}}}
	}
	return dcql
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
