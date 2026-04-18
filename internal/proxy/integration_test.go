//go:build integration

package proxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"log/slog"
	"testing"

	"github.com/clef-sh/keyservice/internal/hsm"
	"github.com/clef-sh/keyservice/internal/hsmtestutil"
	pb "github.com/getsops/sops/v3/keyservice"
)

// TestIntegration_SyntheticARN_FullStack exercises the full proxy stack
// end-to-end: a clef-hsm synthetic ARN arrives at Server.Encrypt, gets
// decoded back to a pkcs11 URI, flows through a real hsm.Client, wraps the
// DEK on a SoftHSM2 token, comes back through Server.Decrypt, and
// round-trips identically.
//
// This is the same contract SOPS will drive end-to-end once the CLI lands.
func TestIntegration_SyntheticARN_FullStack(t *testing.T) {
	fx := hsmtestutil.SoftHSM2(t)

	backend, err := hsm.NewClient(hsm.Config{ModulePath: fx.ModulePath, PIN: fx.PIN})
	if err != nil {
		t.Fatalf("hsm.NewClient: %v", err)
	}
	defer backend.Close()

	logger := slog.New(slog.NewTextHandler(&discardWriter{}, &slog.HandlerOptions{Level: slog.LevelError}))
	srv := NewServer(backend, logger)

	arn := "arn:aws:kms:us-east-1:000000000000:alias/clef-hsm/v1/" +
		base64.RawURLEncoding.EncodeToString([]byte(fx.PKCS11URI()))

	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	encResp, err := srv.Encrypt(context.Background(), &pb.EncryptRequest{
		Key:       &pb.Key{KeyType: &pb.Key_KmsKey{KmsKey: &pb.KmsKey{Arn: arn}}},
		Plaintext: dek,
	})
	if err != nil {
		t.Fatalf("Server.Encrypt: %v", err)
	}
	if len(encResp.Ciphertext) != 256 {
		t.Errorf("expected 256-byte RSA-2048 ciphertext, got %d bytes", len(encResp.Ciphertext))
	}

	decResp, err := srv.Decrypt(context.Background(), &pb.DecryptRequest{
		Key:        &pb.Key{KeyType: &pb.Key_KmsKey{KmsKey: &pb.KmsKey{Arn: arn}}},
		Ciphertext: encResp.Ciphertext,
	})
	if err != nil {
		t.Fatalf("Server.Decrypt: %v", err)
	}
	if !bytes.Equal(dek, decResp.Plaintext) {
		t.Fatalf("round-trip mismatch:\n  want %x\n  got  %x", dek, decResp.Plaintext)
	}
}
