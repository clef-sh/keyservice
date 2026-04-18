package proxy

import (
	"bytes"
	"encoding/base64"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

func buildARN(uri string) string {
	return "arn:aws:kms:us-east-1:000000000000:alias/clef-hsm/v1/" +
		base64.RawURLEncoding.EncodeToString([]byte(uri))
}

func TestDecodeKeyURI_Vectors(t *testing.T) {
	// Canonical base64url of each pkcs11 URI (RFC 4648 §5, no padding).
	// Both sides of the contract must agree on these bytes. The CLI spec
	// sent with this change contained typo'd vectors (dropped a '1' from
	// 'pkcs11'); these are the values Go's encoding/base64 RawURLEncoding
	// actually produces and are the authoritative cross-validation set.
	cases := []struct {
		name string
		uri  string
		arn  string
	}{
		{
			name: "default hash",
			uri:  "pkcs11:slot=0;label=clef-dek-wrapper",
			arn:  "arn:aws:kms:us-east-1:000000000000:alias/clef-hsm/v1/cGtjczExOnNsb3Q9MDtsYWJlbD1jbGVmLWRlay13cmFwcGVy",
		},
		{
			name: "hash override",
			uri:  "pkcs11:slot=0;label=foo;hash=sha1",
			arn:  "arn:aws:kms:us-east-1:000000000000:alias/clef-hsm/v1/cGtjczExOnNsb3Q9MDtsYWJlbD1mb287aGFzaD1zaGEx",
		},
		{
			name: "object alias and multi-digit slot",
			uri:  "pkcs11:slot=12345;object=wrap-key",
			arn:  "arn:aws:kms:us-east-1:000000000000:alias/clef-hsm/v1/cGtjczExOnNsb3Q9MTIzNDU7b2JqZWN0PXdyYXAta2V5",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeKeyURI(tc.arn, discardLogger())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.uri {
				t.Errorf("got %q, want %q", got, tc.uri)
			}
		})
	}
}

func TestDecodeKeyURI_PartitionVariants(t *testing.T) {
	uri := "pkcs11:slot=0;label=k"
	payload := base64.RawURLEncoding.EncodeToString([]byte(uri))

	for _, partition := range []string{"aws", "aws-us-gov", "aws-cn"} {
		t.Run(partition, func(t *testing.T) {
			arn := "arn:" + partition + ":kms:us-east-1:000000000000:alias/clef-hsm/v1/" + payload
			got, err := decodeKeyURI(arn, discardLogger())
			if err != nil {
				t.Fatalf("partition %q: %v", partition, err)
			}
			if got != uri {
				t.Errorf("got %q, want %q", got, uri)
			}
		})
	}
}

func TestDecodeKeyURI_Errors(t *testing.T) {
	cases := []struct {
		name      string
		arn       string
		wantUnrec bool // expect errUnrecognizedARN (→ gRPC Unimplemented)
		wantSub   string
	}{
		{
			name:      "non-KMS ARN",
			arn:       "arn:aws:s3:::my-bucket",
			wantUnrec: true,
		},
		{
			name:      "real AWS KMS alias unrelated to clef-hsm",
			arn:       "arn:aws:kms:us-east-1:123456789012:alias/my-app-key",
			wantUnrec: true,
		},
		{
			name:      "clef-hsm substring but not anchored (regex rejects)",
			arn:       "arn:aws:kms:us-east-1:123:alias/clef-hsm-lookalike/v1/cGtjczE6",
			wantUnrec: true,
		},
		{
			name:    "unknown version",
			arn:     "arn:aws:kms:us-east-1:000000000000:alias/clef-hsm/v2/cGtjczE6c2xvdD0w",
			wantSub: "v2 not supported",
		},
		{
			name:      "malformed base64 (contains =)",
			arn:       "arn:aws:kms:us-east-1:000000000000:alias/clef-hsm/v1/cGtjczE6c2xvdD0=",
			wantUnrec: true, // regex rejects — '=' not in [A-Za-z0-9_-]
		},
		{
			name:    "decoded payload is not pkcs11",
			arn:     "arn:aws:kms:us-east-1:000000000000:alias/clef-hsm/v1/aGVsbG8",
			wantSub: "not a pkcs11 URI",
		},
		{
			name:      "empty payload (regex requires at least one char)",
			arn:       "arn:aws:kms:us-east-1:000000000000:alias/clef-hsm/v1/",
			wantUnrec: true,
		},
		{
			name:      "missing version segment",
			arn:       "arn:aws:kms:us-east-1:000000000000:alias/clef-hsm/cGtjczE6c2xvdD0w",
			wantUnrec: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			uri, err := decodeKeyURI(tc.arn, discardLogger())
			if err == nil {
				t.Fatalf("expected error, got uri=%q", uri)
			}
			if tc.wantUnrec {
				if !errors.Is(err, errUnrecognizedARN) {
					t.Errorf("expected errUnrecognizedARN, got %v", err)
				}
				return
			}
			if tc.wantSub != "" && !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("expected error to contain %q, got %v", tc.wantSub, err)
			}
		})
	}
}

func TestDecodeKeyURI_LegacyPkcs11Passthrough(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	const uri = "pkcs11:slot=0;label=clef-dek-wrapper"
	got, err := decodeKeyURI(uri, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != uri {
		t.Errorf("got %q, want passthrough %q", got, uri)
	}

	logOutput := buf.String()
	if !strings.Contains(logOutput, "level=WARN") {
		t.Errorf("expected WARN level log, got: %s", logOutput)
	}
	if !strings.Contains(logOutput, "raw pkcs11 URI") {
		t.Errorf("expected warning about raw pkcs11 URI, got: %s", logOutput)
	}
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(&discardWriter{}, &slog.HandlerOptions{Level: slog.LevelError + 1}))
}
