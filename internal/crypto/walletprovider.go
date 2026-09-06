package crypto

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
)

// LoadWalletProviderAnchor loads <certsDir>/root-ca.crt, if present, for
// pinning client-attestation (WIA) signature verification to a trusted
// Wallet Provider CA. Returns (nil, nil) if the file doesn't exist — this
// AS then accepts any self-consistent WIA, with no chain-of-trust check.
//
// Client attestation is validated only here now, not on the Credential
// Issuer: the AS is the one endpoint a wallet authenticates to.
func LoadWalletProviderAnchor(certsDir string) (*x509.Certificate, error) {
	path := filepath.Join(certsDir, "root-ca.crt")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	der := data
	if block, _ := pem.Decode(data); block != nil {
		der = block.Bytes
	}
	return x509.ParseCertificate(der)
}
