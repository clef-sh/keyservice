package proxy

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
)

// clefHsmARN matches the Clef HSM synthetic ARN contract (v1):
//
//	arn:aws:kms:us-east-1:000000000000:alias/clef-hsm/v1/<BASE64URL(pkcs11-uri)>
//
// Partition tolerance (aws, aws-us-gov, aws-cn) matches SOPS's own KMS ARN
// regex. Region and account are accepted as placeholders; they carry no
// semantic meaning since --enable-local-keyservice=false stops SOPS from
// attempting real AWS KMS calls.
//
// Capture groups: (1) version marker (v1, v2, ...), (2) base64url payload.
var clefHsmARN = regexp.MustCompile(
	`^arn:aws[\w-]*:kms:[^:]+:\d+:alias/clef-hsm/(v\d+)/([A-Za-z0-9_-]+)$`,
)

// errUnrecognizedARN signals that the caller should map to gRPC
// Unimplemented — the ARN is well-formed AWS but not a Clef HSM synthetic.
var errUnrecognizedARN = errors.New("not a clef-hsm synthetic ARN")

// decodeKeyURI extracts the pkcs11 URI from a Clef HSM synthetic ARN.
//
// Fall-through: if the input starts with "pkcs11:" it is returned verbatim
// as a testing/direct-gRPC convenience. SOPS itself never emits such a
// value (its --kms regex rejects it), so any hit on this path is either a
// direct gRPC caller or a bug — we emit a slog.Warn to make it visible.
//
// Anything else returns errUnrecognizedARN so the handler can map to
// gRPC Unimplemented (matching the policy for non-KmsKey types).
func decodeKeyURI(arn string, logger *slog.Logger) (string, error) {
	if strings.HasPrefix(arn, "pkcs11:") {
		logger.Warn("raw pkcs11 URI on wire — testing path only, not a production contract", "arn", arn)
		return arn, nil
	}

	m := clefHsmARN.FindStringSubmatch(arn)
	if m == nil {
		return "", errUnrecognizedARN
	}
	version, payload := m[1], m[2]

	if version != "v1" {
		return "", fmt.Errorf("clef-hsm ARN version %s not supported", version)
	}

	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return "", fmt.Errorf("clef-hsm payload not valid base64url: %w", err)
	}
	if len(raw) == 0 {
		return "", errors.New("clef-hsm payload is empty")
	}

	uri := string(raw)
	if !strings.HasPrefix(uri, "pkcs11:") {
		return "", errors.New("decoded clef-hsm payload is not a pkcs11 URI")
	}
	return uri, nil
}
