package httpapi

// authServerMetadata is the OAuth 2.0 Authorization Server Metadata
// document (RFC 8414), served at /.well-known/oauth-authorization-server,
// shaped for this AS's HAIP-only profile.
type authServerMetadata struct {
	Issuer                                        string   `json:"issuer"`
	TokenEndpoint                                 string   `json:"token_endpoint"`
	AuthorizationEndpoint                         string   `json:"authorization_endpoint"`
	PushedAuthorizationRequestEndpoint            string   `json:"pushed_authorization_request_endpoint"`
	JWKSURI                                       string   `json:"jwks_uri"`
	ResponseTypesSupported                        []string `json:"response_types_supported"`
	GrantTypesSupported                           []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported                 []string `json:"code_challenge_methods_supported"`
	TokenEndpointAuthMethodsSupported             []string `json:"token_endpoint_auth_methods_supported"`
	DPoPSigningAlgValuesSupported                 []string `json:"dpop_signing_alg_values_supported"`
	ClientAttestationSigningAlgValuesSupported    []string `json:"client_attestation_signing_alg_values_supported"`
	ClientAttestationPoPSigningAlgValuesSupported []string `json:"client_attestation_pop_signing_alg_values_supported"`
	RequirePushedAuthorizationRequests            bool     `json:"require_pushed_authorization_requests"`
	TokenEndpointAuthSigningAlgValuesSupported    []string `json:"token_endpoint_auth_signing_alg_values_supported"`
	AuthorizationResponseIssParameterSupported    bool     `json:"authorization_response_iss_parameter_supported"`
	SubjectTypesSupported                         []string `json:"subject_types_supported"`
}

// buildHAIPAuthServerMetadata assembles the HAIP-profile Authorization
// Server Metadata. jwks_uri is what makes the split from the Credential
// Issuer work: that service discovers this AS's access-token signing key
// here rather than sharing a process with it.
func buildHAIPAuthServerMetadata(baseURL string) authServerMetadata {
	return authServerMetadata{
		Issuer:                                        baseURL,
		TokenEndpoint:                                 baseURL + "/oid4vci/v1/token",
		AuthorizationEndpoint:                         baseURL + "/oid4vci/v1/authorize",
		PushedAuthorizationRequestEndpoint:            baseURL + "/oid4vci/v1/par",
		JWKSURI:                                       baseURL + "/oid4vci/v1/jwks",
		ResponseTypesSupported:                        []string{"code"},
		GrantTypesSupported:                           []string{"authorization_code"},
		CodeChallengeMethodsSupported:                 []string{"S256"},
		TokenEndpointAuthMethodsSupported:             []string{"attest_jwt_client_auth"},
		DPoPSigningAlgValuesSupported:                 []string{"ES256"},
		ClientAttestationSigningAlgValuesSupported:    []string{"ES256"},
		ClientAttestationPoPSigningAlgValuesSupported: []string{"ES256"},
		RequirePushedAuthorizationRequests:            true,
		TokenEndpointAuthSigningAlgValuesSupported:    []string{"ES256"},
		AuthorizationResponseIssParameterSupported:    true,
		SubjectTypesSupported:                         []string{"public"},
	}
}
