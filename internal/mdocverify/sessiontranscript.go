package mdocverify

import (
	"crypto/sha256"

	"github.com/fxamacker/cbor/v2"
)

// tagEncodedCBOR is CBOR tag 24, "encoded CBOR data item" (RFC 8949 §3.4.5.1).
const tagEncodedCBOR = 24

// openID4VPHandover builds the OID4VP SessionTranscript for the
// direct_post / direct_post.jwt flow, per OID4VP 1.0 Final §B.2.6 and ISO
// 18013-5 §9.1.5:
//
//	SessionTranscript     = [null, null, OpenID4VPHandover]
//	OpenID4VPHandover     = ["OpenID4VPHandover", sha256(OpenID4VPHandoverInfoBytes)]
//	OpenID4VPHandoverInfo = [clientId, nonce, jwkThumbprint, responseUri]
//
// jwkThumbprint is the raw RFC 7638 SHA-256 thumbprint of the Verifier's
// response-encryption key when the response is encrypted, and CBOR null
// when it is not — that is what stops a captured response being re-encrypted
// to a third party's key. There is no mdocGeneratedNonce: that was an ISO
// 18013-7 draft concept, dropped in OID4VP 1.0 Final.
//
// Every input here comes from the Verifier's own stored session, never from
// the response — reconstructing it and finding the device signature still
// verifies is precisely the binding check (the conformance suite's
// invalid-session-transcript case).
func openID4VPHandover(clientID, nonce string, encJWKThumbprint []byte, responseURI string) ([]byte, error) {
	var thumbprint any
	if encJWKThumbprint != nil {
		thumbprint = encJWKThumbprint
	}
	handoverInfo, err := cbor.Marshal([]any{clientID, nonce, thumbprint, responseURI})
	if err != nil {
		return nil, err
	}
	handoverInfoHash := sha256.Sum256(handoverInfo)

	handover := []any{"OpenID4VPHandover", handoverInfoHash[:]}
	// [DeviceEngagementBytes, EReaderKeyBytes, Handover] — both null for
	// this flow, since there was no NFC/BLE device engagement.
	return cbor.Marshal([]any{nil, nil, handover})
}

// deviceAuthenticationBytes builds the detached payload the device
// signature covers:
//
//	DeviceAuthentication      = ["DeviceAuthentication", SessionTranscript, docType, DeviceNameSpacesBytes]
//	DeviceAuthenticationBytes = #6.24(bstr .cbor DeviceAuthentication)
//
// sessionTranscript and deviceNameSpacesBytes are spliced in as already-
// encoded CBOR (cbor.RawMessage) rather than re-encoded: deviceNameSpaces
// in particular must be the verbatim bytes the wallet signed over, since
// any re-encoding could change the byte string and break the signature.
func deviceAuthenticationBytes(sessionTranscript []byte, docType string, deviceNameSpacesBytes []byte) ([]byte, error) {
	deviceAuth, err := cbor.Marshal([]any{
		"DeviceAuthentication",
		cbor.RawMessage(sessionTranscript),
		docType,
		cbor.RawMessage(deviceNameSpacesBytes),
	})
	if err != nil {
		return nil, err
	}
	return cbor.Marshal(cbor.Tag{Number: tagEncodedCBOR, Content: deviceAuth})
}
