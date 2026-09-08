package oauth2

import "testing"

func TestVerifyPKCES256(t *testing.T) {
	// RFC 7636 Appendix B's worked example.
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	const challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	if !VerifyPKCES256(verifier, challenge) {
		t.Fatal("expected the matching verifier/challenge pair to verify")
	}
}

func TestVerifyPKCES256WrongVerifier(t *testing.T) {
	const challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	if VerifyPKCES256("some-other-verifier", challenge) {
		t.Fatal("expected a mismatched verifier to fail")
	}
}

func TestVerifyPKCES256EmptyInputs(t *testing.T) {
	if VerifyPKCES256("", "") {
		t.Fatal("an empty verifier must not satisfy an empty challenge")
	}
}
