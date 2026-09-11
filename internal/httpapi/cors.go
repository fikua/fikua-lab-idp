package httpapi

import "net/http"

// WithCORS wraps next with permissive CORS headers — every route on this
// AS is protocol-secured independently of the calling origin (ATCA
// client attestation on /oid4vci/v1/*, signed sessions + nonce/HAIP
// checks on /oid4vp/v1/*, PKCE + a registered redirect_uri on
// /oidc/v1/*), so restricting the browser Origin adds no real security —
// CORS is not an access-control mechanism, it only gates whether a
// browser's own fetch()/XHR is allowed to read the response, and any
// non-browser caller bypasses it entirely. What it WOULD do if
// restrictive is block legitimate third-party EUDI wallets/RPs running
// as web apps from a different origin, which is the opposite of what an
// interoperable AS wants. See fikua-lab-issuer's identical cors.go — not
// shared as a module across these two young, independently-deployed
// repos (same rationale as internal/oauth2/dpop.go's duplication).
func WithCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, DPoP, OAuth-Client-Attestation, OAuth-Client-Attestation-PoP")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
