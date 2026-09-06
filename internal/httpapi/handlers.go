// Package httpapi exposes this authorization server's endpoints: RFC 8414
// metadata, the HAIP authorization_code flow (PAR, authorize, token), the
// end-user identification flow backing /authorize, and the JWK Set the
// Credential Issuer verifies access tokens against.
package httpapi

import (
	_ "embed"
	"encoding/json"
	"html/template"
	"net/http"

	"github.com/fikua/fikua-lab-idp/internal/authz"
	fikuacrypto "github.com/fikua/fikua-lab-idp/internal/crypto"
	"github.com/fikua/fikua-lab-idp/internal/issuerclient"
	"github.com/fikua/fikua-lab-idp/internal/oauth2"
)

//go:embed authorize_error.html
var authorizeErrorHTML string

// authorizeErrorTemplate renders authorize_error.html — a human-readable
// error page for GET /oid4vci/v1/authorize failures, since a browser (not
// a wallet backend) is the one rendering this response, unlike every
// other OAuth2 endpoint here which is called machine-to-machine and can
// stay plain JSON.
var authorizeErrorTemplate = template.Must(template.New("authorize_error").Parse(authorizeErrorHTML))

// Handler serves the authorization server's JSON API.
type Handler struct {
	baseURL    string
	signingKey *fikuacrypto.SigningKey
	authz      *authz.Service
	issuer     *issuerclient.Client
}

// NewHandler builds an httpapi Handler. signingKey signs access tokens
// and backs the JWK Set; authzService implements the OAuth2 flows; issuer
// supplies the claim metadata the identification form renders.
func NewHandler(baseURL string, signingKey *fikuacrypto.SigningKey, authzService *authz.Service, issuer *issuerclient.Client) *Handler {
	return &Handler{baseURL: baseURL, signingKey: signingKey, authz: authzService, issuer: issuer}
}

// Routes registers this handler's endpoints on mux.
func (h *Handler) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /health", h.health)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", h.authServerMetadata)
	mux.HandleFunc("GET /oid4vci/v1/jwks", h.jwks)
	mux.HandleFunc("POST /oid4vci/v1/par", h.par)
	mux.HandleFunc("GET /oid4vci/v1/authorize", h.authorize)
	mux.HandleFunc("POST /oid4vci/v1/token", h.token)
	mux.HandleFunc("GET /oid4vci/v1/revoked-tokens", h.revokedTokens)
	// The identification endpoints are same-origin with the UI that
	// calls them (internal/webui serves it at /identify/), so they sit at
	// /identify/* rather than under the /oid4vci/v1 prefix the wallet-
	// facing OAuth2 endpoints use. Nothing but this service's own pages
	// calls them.
	mux.HandleFunc("GET /identify/claims", h.identifyClaims)
	mux.HandleFunc("POST /identify/complete", h.identifyComplete)
	mux.HandleFunc("POST /identify/reject", h.identifyReject)
}

func (h *Handler) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) authServerMetadata(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, buildHAIPAuthServerMetadata(h.baseURL))
}

func (h *Handler) jwks(w http.ResponseWriter, r *http.Request) {
	body, err := h.signingKey.JWKSetJSON()
	if err != nil {
		writeOAuthError(w, oauth2.BadRequest(oauth2.InvalidRequest, "Failed to build JWK Set: "+err.Error()))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	// Cacheable, unlike every other endpoint here: the Credential Issuer
	// fetches this on a timer to verify access tokens offline, and the
	// key only changes when it is deliberately rotated.
	w.Header().Set("Cache-Control", "max-age=600")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// revokedTokens serves the jti denylist the Credential Issuer polls.
// Access tokens are stateless JWTs, so RFC 6749 §4.1.2's "revoke the
// tokens issued from a reused authorization code" cannot be honoured by
// deleting anything — the issuer has to be told. Entries are dropped
// once the tokens they name would have expired anyway.
func (h *Handler) revokedTokens(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"revoked_jti": h.authz.RevokedJTIs()})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
