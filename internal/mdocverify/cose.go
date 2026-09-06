package mdocverify

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"math/big"

	"github.com/fxamacker/cbor/v2"
)

const (
	coseAlgES256      = -7
	coseHeaderAlg     = 1
	coseHeaderX5Chain = 33
)

// coseSign1 is the COSE_Sign1 structure (RFC 9052 §4.2) as it appears
// untagged inside IssuerSigned.issuerAuth and DeviceAuth.deviceSignature.
// Payload is nil for a detached signature (deviceSignature), which is why
// it is cbor.RawMessage rather than []byte — a CBOR null and an empty byte
// string must stay distinguishable.
type coseSign1 struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected map[int]cbor.RawMessage
	Payload     cbor.RawMessage
	Signature   []byte
}

// verifyCoseSign1Attached verifies a COSE_Sign1 whose payload travels
// inside it (issuerAuth), returning the payload bytes on success.
func verifyCoseSign1Attached(sign1 coseSign1, key *ecdsa.PublicKey) ([]byte, error) {
	var payload []byte
	if err := cbor.Unmarshal(sign1.Payload, &payload); err != nil {
		return nil, fmt.Errorf("COSE_Sign1 payload is not a byte string: %w", err)
	}
	if err := verifyCoseSign1Detached(sign1, payload, key); err != nil {
		return nil, err
	}
	return payload, nil
}

// verifyCoseSign1Detached verifies a COSE_Sign1 against an externally
// supplied payload (deviceSignature over DeviceAuthenticationBytes, whose
// own Payload element is null).
//
// Sig_structure per RFC 9052 §4.4:
// ["Signature1", protected_bytes, empty external_aad, payload].
func verifyCoseSign1Detached(sign1 coseSign1, payload []byte, key *ecdsa.PublicKey) error {
	// The protected header must declare ES256 (-7). Checked before the
	// signature so an attacker cannot pick the algorithm.
	var protectedHeader map[int]any
	if err := cbor.Unmarshal(sign1.Protected, &protectedHeader); err != nil {
		return fmt.Errorf("COSE_Sign1 protected header is not a CBOR map: %w", err)
	}
	alg, ok := protectedHeader[coseHeaderAlg]
	if !ok {
		return fmt.Errorf("COSE_Sign1 protected header has no alg")
	}
	if algInt, ok := toInt64(alg); !ok || algInt != coseAlgES256 {
		return fmt.Errorf("COSE_Sign1 alg is %v, want ES256 (-7)", alg)
	}

	sigStructure := struct {
		_           struct{} `cbor:",toarray"`
		Context     string
		Protected   []byte
		ExternalAAD []byte
		Payload     []byte
	}{Context: "Signature1", Protected: sign1.Protected, ExternalAAD: []byte{}, Payload: payload}
	toBeSigned, err := cbor.Marshal(sigStructure)
	if err != nil {
		return err
	}

	// COSE carries the signature as fixed-width r||s (P1363), not the
	// ASN.1 DER that crypto/ecdsa.VerifyASN1 expects — 64 bytes for P-256.
	if len(sign1.Signature) != 64 {
		return fmt.Errorf("COSE_Sign1 signature is %d bytes, want 64 (P-256 r||s)", len(sign1.Signature))
	}
	r := new(big.Int).SetBytes(sign1.Signature[:32])
	s := new(big.Int).SetBytes(sign1.Signature[32:])

	digest := sha256.Sum256(toBeSigned)
	if !ecdsa.Verify(key, digest[:], r, s) {
		return fmt.Errorf("COSE_Sign1 signature is invalid")
	}
	return nil
}

// coseCertChain extracts the x5chain (unprotected header label 33) as
// parsed certificates, leaf first. A single certificate is encoded as a
// bstr, several as an array of bstr — both shapes appear in the wild, and
// fikua-lab-issuer's builder emits the first for its one-cert chain.
func coseCertChain(sign1 coseSign1) ([]*x509.Certificate, error) {
	raw, ok := sign1.Unprotected[coseHeaderX5Chain]
	if !ok {
		return nil, nil
	}

	var single []byte
	if err := cbor.Unmarshal(raw, &single); err == nil {
		cert, err := x509.ParseCertificate(single)
		if err != nil {
			return nil, fmt.Errorf("parsing x5chain certificate: %w", err)
		}
		return []*x509.Certificate{cert}, nil
	}

	var multiple [][]byte
	if err := cbor.Unmarshal(raw, &multiple); err != nil {
		return nil, fmt.Errorf("x5chain is neither a byte string nor an array of them: %w", err)
	}
	chain := make([]*x509.Certificate, 0, len(multiple))
	for _, der := range multiple {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("parsing x5chain certificate: %w", err)
		}
		chain = append(chain, cert)
	}
	return chain, nil
}

// toInt64 normalises the several integer types fxamacker/cbor may decode a
// CBOR integer into when the destination is `any`.
func toInt64(v any) (int64, bool) {
	switch n := v.(type) {
	case int64:
		return n, true
	case uint64:
		return int64(n), true
	case int:
		return int64(n), true
	default:
		return 0, false
	}
}
