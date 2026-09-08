package oidcserver

import (
	"context"
	"fmt"
	"html/template"
	"net/http"
	"time"

	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/fikua/fikua-lab-idp/internal/oidcclients"
	"github.com/fikua/fikua-lab-idp/internal/session"
	"github.com/fikua/fikua-lab-idp/internal/verifier"
)

// LoginHandler is this bridge's replacement for a classic username/
// password login page: op.Client.LoginURL (see client.go) points every
// Relying Party's browser here instead. It starts an OID4VP verification
// session scoped to that Relying Party's own configuration (which
// credential, which claims — see oidcclients.Client), renders the QR the
// Verifier's Request Object encodes to, and polls the verification
// session until it resolves — completing the AuthRequest and handing
// the browser back to op.AuthorizeCallback only once a real presentation
// has been verified. There is no other way to reach a "done" AuthRequest
// through this bridge: unlike a password form, a person cannot simply
// submit credentials here — the wallet has to actually answer.
type LoginHandler struct {
	storage      *Storage
	clients      *oidcclients.Registry
	verifier     *verifier.Service
	authCallback func(ctx context.Context, requestID string) string
	// issuer is this bridge's own issuer identifier (baseURL+BasePath).
	// authCallback (op.AuthCallbackURL) builds an absolute URL from
	// whatever issuer op.IssuerFromContext finds on the context it is
	// called with — which is normally set by op's own request
	// interceptor (see op.CreateRouter), but /oidc/v1/login and
	// /oidc/v1/login/poll are this bridge's OWN handlers, mounted
	// alongside the op.Provider rather than behind it, so a request's
	// context here never carries that value. Every call site below
	// injects it explicitly via op.ContextWithIssuer instead of passing
	// r.Context() as-is — omitting this produces a relative,
	// unfollowable redirect (caught by this package's own
	// TestFullLoginToTokenFlow).
	issuer string
}

// NewLoginHandler builds a LoginHandler. authCallbackURL is
// op.AuthCallbackURL(provider) — threaded in from cmd/idp/main.go, which
// is the one place both the op.Provider and this handler are
// constructed, rather than this package importing op.Provider itself and
// creating a circular build step with whatever wires Storage into it.
// issuer is that same provider's own issuer identifier — see the
// LoginHandler.issuer field's doc comment for why this handler cannot
// simply read it off an incoming request's context the way op's own
// handlers do.
func NewLoginHandler(storage *Storage, clients *oidcclients.Registry, verifierService *verifier.Service, authCallbackURL func(context.Context, string) string, issuer string) *LoginHandler {
	return &LoginHandler{storage: storage, clients: clients, verifier: verifierService, authCallback: authCallbackURL, issuer: issuer}
}

// callbackURL is authCallback with this bridge's own issuer injected
// into the context — see the issuer field's doc comment.
func (h *LoginHandler) callbackURL(ctx context.Context, requestID string) string {
	return h.authCallback(op.ContextWithIssuer(ctx, h.issuer), requestID)
}

// ServeHTTP handles GET /oidc/v1/login?id={authRequestID}. Renders the QR
// page on first load; the page's own JS polls
// GET /oidc/v1/login/poll?id=... (pollStatus below) and, once verified,
// navigates the browser to this same handler's completion redirect.
func (h *LoginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	authRequestID := r.URL.Query().Get("id")
	if authRequestID == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	ar, ok := h.storage.internalStore().getAuthRequest(authRequestID)
	if !ok {
		http.Error(w, "unknown or expired login request", http.StatusNotFound)
		return
	}
	if ar.Done() {
		// Re-visiting a completed login (e.g. a refreshed tab) — send the
		// browser straight to the callback rather than starting a second,
		// pointless verification session.
		http.Redirect(w, r, h.callbackURL(r.Context(), ar.id), http.StatusFound)
		return
	}

	if _, ok := h.clients.Lookup(ar.clientID); !ok {
		// Cannot happen through op's own flow (CreateAuthRequest already
		// validated the client), but this handler is reachable directly
		// by URL, so it re-checks rather than trusting the query string.
		http.Error(w, "unknown client", http.StatusBadRequest)
		return
	}

	// Per OpenID4VP 1.0 §5.5, the AuthRequest's own scope names which
	// credential this login presents — see oidcclients.Registry.
	// ResolveCredentialScope's doc comment for why this is resolved
	// against a bridge-published catalogue rather than fixed on the
	// client's own registration.
	credentialScope, ok := h.clients.ResolveCredentialScope(ar.scopes)
	if !ok {
		http.Error(w, "the requested scope names no known credential to present", http.StatusBadRequest)
		return
	}

	verificationSessionID, ok := h.verificationSessionFor(ar)
	if !ok {
		result, err := h.verifier.CreateSession(verifier.CreateSessionRequest{
			Credentials: []verifier.CredentialRequest{{
				ID:             "requested_credential",
				CredentialType: credentialScope.CredentialType,
				Claims:         credentialScope.Claims,
			}},
		})
		if err != nil {
			http.Error(w, "failed to start verification: "+err.Error(), http.StatusBadGateway)
			return
		}
		h.storage.internalStore().linkVerificationSession(ar.id, result.SessionID)
		verificationSessionID = result.SessionID
	}

	renderLoginPage(w, authRequestID, verificationSessionID)
}

// verificationSessionFor returns the OID4VP session already started for
// this AuthRequest, if a previous page load began one — a page refresh
// must not mint a second QR/session for the same login.
func (h *LoginHandler) verificationSessionFor(ar *authRequest) (string, bool) {
	return h.storage.internalStore().getVerificationSession(ar.id)
}

// PollHandler serves GET /oidc/v1/login/poll?id={authRequestID}, the
// login page's own JS poll target. Returns {"status": "pending"} until
// the Verifier resolves the presentation, at which point it completes
// the AuthRequest (sets its subject from the verified SubjectID) and
// returns {"status": "done", "redirect": "..."} for the page to navigate
// to — op.AuthorizeCallback, which mints the authorization code and
// redirects on to the Relying Party.
func (h *LoginHandler) PollHandler(w http.ResponseWriter, r *http.Request) {
	authRequestID := r.URL.Query().Get("id")
	ar, ok := h.storage.internalStore().getAuthRequest(authRequestID)
	if !ok {
		writeJSONStatus(w, http.StatusNotFound, map[string]string{"status": "not_found"})
		return
	}
	if ar.Done() {
		writeJSONStatus(w, http.StatusOK, map[string]string{
			"status":   "done",
			"redirect": h.callbackURL(r.Context(), ar.id),
		})
		return
	}

	verificationSessionID, ok := h.verificationSessionFor(ar)
	if !ok {
		writeJSONStatus(w, http.StatusOK, map[string]string{"status": "pending"})
		return
	}
	v, found := h.verifierSessionResult(verificationSessionID)
	if !found {
		writeJSONStatus(w, http.StatusOK, map[string]string{"status": "pending"})
		return
	}
	switch v.Status {
	case "verified":
		if v.SubjectID == "" {
			// Should not happen for a "verified" status (see
			// internal/verifier.subjectIDFromHolderKeys, called on every
			// successful verification) — fail the login rather than
			// complete an AuthRequest with an empty subject, which
			// op.CreateIDToken would happily mint an ID Token for.
			writeJSONStatus(w, http.StatusOK, map[string]string{"status": "error", "error": "verification succeeded but produced no subject identifier"})
			return
		}
		ar.subject = v.SubjectID
		ar.doneAt = time.Now()
		writeJSONStatus(w, http.StatusOK, map[string]string{
			"status":   "done",
			"redirect": h.callbackURL(r.Context(), ar.id),
		})
	case "failed":
		writeJSONStatus(w, http.StatusOK, map[string]string{"status": "error", "error": v.Error})
	default:
		writeJSONStatus(w, http.StatusOK, map[string]string{"status": "pending"})
	}
}

// verifierSessionResult reads the verification session's raw state
// directly off session.Store rather than through verifier.Service.
// GetResult: GetResult's JSON Result deliberately never carries
// SubjectID (see verifier.Result's doc comment — it is not meant for any
// external, wallet- or frontend-facing poll), so this in-process reader
// is this bridge's only path to it.
func (h *LoginHandler) verifierSessionResult(sessionID string) (session.VerificationSession, bool) {
	return h.verifier.Session(sessionID)
}

func writeJSONStatus(w http.ResponseWriter, status int, body map[string]string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprintf(w, `{`)
	first := true
	for k, v := range body {
		if !first {
			fmt.Fprint(w, `,`)
		}
		first = false
		fmt.Fprintf(w, `%q:%q`, k, v)
	}
	fmt.Fprint(w, `}`)
}

var loginPageTemplate = template.Must(template.New("login").Parse(`<!DOCTYPE html>
<html><head><title>Fikua Verifier Login</title></head>
<body>
<h1>Scan to sign in</h1>
<p>Present your credential to continue.</p>
<div id="qr" data-request-uri="{{.RequestURI}}"></div>
<script>
(function poll() {
  fetch("/oidc/v1/login/poll?id={{.AuthRequestID}}")
    .then(function(r) { return r.json(); })
    .then(function(data) {
      if (data.status === "done") {
        window.location = data.redirect;
      } else if (data.status === "error") {
        document.body.innerHTML = "<p>Verification failed: " + data.error + "</p>";
      } else {
        setTimeout(poll, 2000);
      }
    });
})();
</script>
</body></html>`))

func renderLoginPage(w http.ResponseWriter, authRequestID, verificationSessionID string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = loginPageTemplate.Execute(w, struct {
		AuthRequestID string
		RequestURI    string
	}{AuthRequestID: authRequestID, RequestURI: verificationSessionID})
}
