// Package oauth2 implements this authorization server's OAuth2 mechanics:
// the error model, DPoP proof validation, ATCA client attestation, PKCE
// verification, and RFC 9068 JWT access token minting.
package oauth2

// Error codes, per OAuth2 core and OID4VCI 1.0 Final §8.3.1.
const (
	InvalidRequest = "invalid_request"
	InvalidGrant   = "invalid_grant"
	InvalidClient  = "invalid_client"
	// InvalidClientAttestation, per ATCA draft-07 §6.2, MAY be used
	// alongside the more general invalid_client when a client
	// attestation or its proof-of-possession fails verification.
	InvalidClientAttestation = "invalid_client_attestation"
	// UnsupportedResponseType, per RFC 6749 §4.1.2.1, is returned when
	// response_type isn't one this authorization server supports — it
	// only ever supports "code" (FAPI 2.0 Security Profile §5.3.2.2-1
	// forbids hybrid/implicit response types like "code id_token").
	UnsupportedResponseType = "unsupported_response_type"
	UnsupportedGrantType    = "unsupported_grant_type"
	InvalidToken            = "invalid_token"
)

// Error is the OAuth2/OID4VCI error response body: {"error": "...",
// "error_description": "..."}. Description is omitted from the JSON
// entirely when empty.
type Error struct {
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

// Exception pairs an Error with the HTTP status it should be served with.
// It's a plain error value, not a panic/recover mechanism — handlers
// return it and the caller writes the response.
type Exception struct {
	HTTPStatus int
	Err        Error
}

func (e *Exception) Error() string {
	return e.Err.Code + ": " + e.Err.Description
}

// BadRequest builds a 400 Exception.
func BadRequest(code, description string) *Exception {
	return &Exception{HTTPStatus: 400, Err: Error{Code: code, Description: description}}
}

// Unauthorized builds a 401 Exception.
func Unauthorized(code, description string) *Exception {
	return &Exception{HTTPStatus: 401, Err: Error{Code: code, Description: description}}
}

// ServiceUnavailable builds a 503 Exception.
func ServiceUnavailable(code, description string) *Exception {
	return &Exception{HTTPStatus: 503, Err: Error{Code: code, Description: description}}
}
