package proxy

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	pb "github.com/getsops/sops/v3/keyservice"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type mockBackend struct {
	encrypt func(keyURI string, plaintext []byte) ([]byte, error)
	decrypt func(keyURI string, ciphertext []byte) ([]byte, error)
}

func (m *mockBackend) Encrypt(keyURI string, plaintext []byte) ([]byte, error) {
	return m.encrypt(keyURI, plaintext)
}

func (m *mockBackend) Decrypt(keyURI string, ciphertext []byte) ([]byte, error) {
	return m.decrypt(keyURI, ciphertext)
}

type discardWriter struct{}

func (*discardWriter) Write(p []byte) (int, error) { return len(p), nil }

func newServer(backend Backend) *Server {
	logger := slog.New(slog.NewTextHandler(&discardWriter{}, nil))
	return NewServer(backend, logger)
}

func kmsKey(arn string) *pb.Key {
	return &pb.Key{KeyType: &pb.Key_KmsKey{KmsKey: &pb.KmsKey{Arn: arn}}}
}

func TestEncrypt_SyntheticARN_DecodesAndCallsBackend(t *testing.T) {
	const uri = "pkcs11:slot=0;label=clef-dek-wrapper"
	arn := buildARN(uri)

	srv := newServer(&mockBackend{
		encrypt: func(gotURI string, plaintext []byte) ([]byte, error) {
			if gotURI != uri {
				t.Errorf("backend got key %q, want decoded URI %q", gotURI, uri)
			}
			return []byte("wrapped-dek"), nil
		},
	})

	resp, err := srv.Encrypt(context.Background(), &pb.EncryptRequest{
		Key:       kmsKey(arn),
		Plaintext: []byte("raw-dek-bytes"),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(resp.Ciphertext) != "wrapped-dek" {
		t.Errorf("got ciphertext %q, want %q", resp.Ciphertext, "wrapped-dek")
	}
}

func TestDecrypt_SyntheticARN_DecodesAndCallsBackend(t *testing.T) {
	const uri = "pkcs11:slot=0;label=clef-dek-wrapper"
	arn := buildARN(uri)

	srv := newServer(&mockBackend{
		decrypt: func(gotURI string, ciphertext []byte) ([]byte, error) {
			if gotURI != uri {
				t.Errorf("backend got key %q, want decoded URI %q", gotURI, uri)
			}
			return []byte("unwrapped-dek"), nil
		},
	})

	resp, err := srv.Decrypt(context.Background(), &pb.DecryptRequest{
		Key:        kmsKey(arn),
		Ciphertext: []byte("wrapped-dek-bytes"),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(resp.Plaintext) != "unwrapped-dek" {
		t.Errorf("got plaintext %q, want %q", resp.Plaintext, "unwrapped-dek")
	}
}

func TestEncrypt_LegacyRawPkcs11URI_PassesThrough(t *testing.T) {
	const uri = "pkcs11:slot=0;label=clef-dek-wrapper"
	srv := newServer(&mockBackend{
		encrypt: func(gotURI string, _ []byte) ([]byte, error) {
			if gotURI != uri {
				t.Errorf("backend got %q, want %q", gotURI, uri)
			}
			return []byte("ok"), nil
		},
	})

	_, err := srv.Encrypt(context.Background(), &pb.EncryptRequest{
		Key:       kmsKey(uri),
		Plaintext: []byte("x"),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEncrypt_NonClefHsmARN_ReturnsUnimplemented(t *testing.T) {
	srv := newServer(&mockBackend{})
	_, err := srv.Encrypt(context.Background(), &pb.EncryptRequest{
		Key:       kmsKey("arn:aws:kms:us-east-1:123456789012:alias/my-real-aws-key"),
		Plaintext: []byte("x"),
	})
	assertCode(t, err, codes.Unimplemented)
}

func TestEncrypt_MalformedSyntheticARN_ReturnsInvalidArgument(t *testing.T) {
	srv := newServer(&mockBackend{})
	badARN := "arn:aws:kms:us-east-1:000000000000:alias/clef-hsm/v1/aGVsbG8" // "hello" — not pkcs11
	_, err := srv.Encrypt(context.Background(), &pb.EncryptRequest{
		Key:       kmsKey(badARN),
		Plaintext: []byte("x"),
	})
	assertCode(t, err, codes.InvalidArgument)
}

func TestEncrypt_UnknownVersion_ReturnsInvalidArgument(t *testing.T) {
	srv := newServer(&mockBackend{})
	futureARN := "arn:aws:kms:us-east-1:000000000000:alias/clef-hsm/v2/cGtjczE6c2xvdD0w"
	_, err := srv.Encrypt(context.Background(), &pb.EncryptRequest{
		Key:       kmsKey(futureARN),
		Plaintext: []byte("x"),
	})
	assertCode(t, err, codes.InvalidArgument)
}

func TestEncrypt_NilKey_ReturnsInvalidArgument(t *testing.T) {
	srv := newServer(&mockBackend{})
	_, err := srv.Encrypt(context.Background(), &pb.EncryptRequest{Plaintext: []byte("x")})
	assertCode(t, err, codes.InvalidArgument)
}

func TestDecrypt_NilKey_ReturnsInvalidArgument(t *testing.T) {
	srv := newServer(&mockBackend{})
	_, err := srv.Decrypt(context.Background(), &pb.DecryptRequest{Ciphertext: []byte("x")})
	assertCode(t, err, codes.InvalidArgument)
}

func TestEncrypt_NonKmsKeys_ReturnUnimplemented(t *testing.T) {
	srv := newServer(&mockBackend{})
	cases := map[string]*pb.Key{
		"age":   {KeyType: &pb.Key_AgeKey{AgeKey: &pb.AgeKey{Recipient: "age1..."}}},
		"pgp":   {KeyType: &pb.Key_PgpKey{PgpKey: &pb.PgpKey{Fingerprint: "ABCD"}}},
		"gcp":   {KeyType: &pb.Key_GcpKmsKey{GcpKmsKey: &pb.GcpKmsKey{ResourceId: "projects/p/..."}}},
		"azure": {KeyType: &pb.Key_AzureKeyvaultKey{AzureKeyvaultKey: &pb.AzureKeyVaultKey{VaultUrl: "https://v.azure.net"}}},
		"vault": {KeyType: &pb.Key_VaultKey{VaultKey: &pb.VaultKey{VaultAddress: "https://vault", EnginePath: "transit", KeyName: "k"}}},
	}
	for name, key := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := srv.Encrypt(context.Background(), &pb.EncryptRequest{Key: key, Plaintext: []byte("x")})
			assertCode(t, err, codes.Unimplemented)
		})
	}
}

func TestDecrypt_NonKmsKeys_ReturnUnimplemented(t *testing.T) {
	srv := newServer(&mockBackend{})
	_, err := srv.Decrypt(context.Background(), &pb.DecryptRequest{
		Key:        &pb.Key{KeyType: &pb.Key_AgeKey{AgeKey: &pb.AgeKey{Recipient: "age1..."}}},
		Ciphertext: []byte("x"),
	})
	assertCode(t, err, codes.Unimplemented)
}

func TestEncrypt_BackendError_ReturnsInternal(t *testing.T) {
	srv := newServer(&mockBackend{
		encrypt: func(string, []byte) ([]byte, error) { return nil, errors.New("hsm unreachable") },
	})
	_, err := srv.Encrypt(context.Background(), &pb.EncryptRequest{
		Key:       kmsKey(buildARN("pkcs11:slot=0;label=k")),
		Plaintext: []byte("x"),
	})
	assertCode(t, err, codes.Internal)
}

func TestDecrypt_BackendError_ReturnsInternal(t *testing.T) {
	srv := newServer(&mockBackend{
		decrypt: func(string, []byte) ([]byte, error) { return nil, errors.New("invalid ciphertext") },
	})
	_, err := srv.Decrypt(context.Background(), &pb.DecryptRequest{
		Key:        kmsKey(buildARN("pkcs11:slot=0;label=k")),
		Ciphertext: []byte("x"),
	})
	assertCode(t, err, codes.Internal)
}

func assertCode(t *testing.T, err error, want codes.Code) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error with code %s, got nil", want)
	}
	s, ok := status.FromError(err)
	if !ok || s.Code() != want {
		t.Fatalf("expected code %s, got %v", want, err)
	}
}
