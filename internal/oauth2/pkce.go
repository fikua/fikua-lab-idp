package oauth2

import (
	"crypto/sha256"
	"encoding/base64"
)

// VerifyPKCES256 reports whether codeVerifier hashes (SHA-256, base64url
// no padding) to storedChallenge, per RFC 7636 §4.6. Only S256 is
// supported — this AS's HAIP profile requires code_challenge_method to be
// exactly "S256" (enforced at /par, see Service.HandlePar).
func VerifyPKCES256(codeVerifier, storedChallenge string) bool {
	return computeS256Challenge(codeVerifier) == storedChallenge
}

func computeS256Challenge(codeVerifier string) string {
	digest := sha256.Sum256([]byte(codeVerifier))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}
