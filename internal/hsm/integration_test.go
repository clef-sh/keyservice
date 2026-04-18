//go:build integration

package hsm

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/clef-sh/keyservice/internal/hsmtestutil"
)

// TestIntegration_SoftHSM2_RoundTrip exercises hsm.Client directly against
// a provisioned SoftHSM2 token: Encrypt a 32-byte DEK with RSA-OAEP, then
// Decrypt it back. Run with: make test-integration.
func TestIntegration_SoftHSM2_RoundTrip(t *testing.T) {
	fx := hsmtestutil.SoftHSM2(t)

	client, err := NewClient(Config{ModulePath: fx.ModulePath, PIN: fx.PIN})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	uri := fx.PKCS11URI()

	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	wrapped, err := client.Encrypt(uri, dek)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if len(wrapped) != 256 {
		t.Errorf("expected 256-byte RSA-2048 ciphertext, got %d bytes", len(wrapped))
	}

	unwrapped, err := client.Decrypt(uri, wrapped)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(dek, unwrapped) {
		t.Fatalf("round-trip mismatch:\n  want %x\n  got  %x", dek, unwrapped)
	}
}
