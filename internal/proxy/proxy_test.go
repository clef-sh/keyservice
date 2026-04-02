package proxy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/clef-sh/keyservice/internal/cloud"
	pb "github.com/getsops/sops/v3/keyservice"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func testServer(t *testing.T, handler http.HandlerFunc) *Server {
	t.Helper()
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	client := cloud.NewClient(ts.URL, "test-token")
	logger := slog.New(slog.NewTextHandler(&discardWriter{}, nil))
	return NewServer(client, logger)
}

type discardWriter struct{}

func (d *discardWriter) Write(p []byte) (int, error) { return len(p), nil }

func kmsEncryptHandler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		resp := cloud.EncryptResponse{
			Ciphertext: base64.StdEncoding.EncodeToString([]byte("wrapped-dek")),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

func kmsDecryptHandler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		resp := cloud.DecryptResponse{
			Plaintext: base64.StdEncoding.EncodeToString([]byte("unwrapped-dek")),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

func TestEncrypt_KmsKey_Success(t *testing.T) {
	srv := testServer(t, kmsEncryptHandler(t))

	resp, err := srv.Encrypt(context.Background(), &pb.EncryptRequest{
		Key: &pb.Key{
			KeyType: &pb.Key_KmsKey{
				KmsKey: &pb.KmsKey{Arn: "arn:aws:kms:us-east-1:123:key/abc"},
			},
		},
		Plaintext: []byte("raw-dek-bytes"),
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(resp.Ciphertext) != "wrapped-dek" {
		t.Errorf("expected %q, got %q", "wrapped-dek", resp.Ciphertext)
	}
}

func TestDecrypt_KmsKey_Success(t *testing.T) {
	srv := testServer(t, kmsDecryptHandler(t))

	resp, err := srv.Decrypt(context.Background(), &pb.DecryptRequest{
		Key: &pb.Key{
			KeyType: &pb.Key_KmsKey{
				KmsKey: &pb.KmsKey{Arn: "arn:aws:kms:us-east-1:123:key/abc"},
			},
		},
		Ciphertext: []byte("wrapped-dek-bytes"),
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(resp.Plaintext) != "unwrapped-dek" {
		t.Errorf("expected %q, got %q", "unwrapped-dek", resp.Plaintext)
	}
}

func TestEncrypt_NilKey_ReturnsError(t *testing.T) {
	srv := testServer(t, kmsEncryptHandler(t))

	_, err := srv.Encrypt(context.Background(), &pb.EncryptRequest{
		Key:       nil,
		Plaintext: []byte("data"),
	})

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if s, ok := status.FromError(err); !ok || s.Code() != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument, got %v", err)
	}
}

func TestDecrypt_NilKey_ReturnsError(t *testing.T) {
	srv := testServer(t, kmsDecryptHandler(t))

	_, err := srv.Decrypt(context.Background(), &pb.DecryptRequest{
		Key:        nil,
		Ciphertext: []byte("data"),
	})

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if s, ok := status.FromError(err); !ok || s.Code() != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument, got %v", err)
	}
}

func TestEncrypt_AgeKey_ReturnsUnimplemented(t *testing.T) {
	srv := testServer(t, kmsEncryptHandler(t))

	_, err := srv.Encrypt(context.Background(), &pb.EncryptRequest{
		Key: &pb.Key{
			KeyType: &pb.Key_AgeKey{
				AgeKey: &pb.AgeKey{Recipient: "age1..."},
			},
		},
		Plaintext: []byte("data"),
	})

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if s, ok := status.FromError(err); !ok || s.Code() != codes.Unimplemented {
		t.Errorf("expected Unimplemented, got %v", err)
	}
}

func TestDecrypt_AgeKey_ReturnsUnimplemented(t *testing.T) {
	srv := testServer(t, kmsDecryptHandler(t))

	_, err := srv.Decrypt(context.Background(), &pb.DecryptRequest{
		Key: &pb.Key{
			KeyType: &pb.Key_AgeKey{
				AgeKey: &pb.AgeKey{Recipient: "age1..."},
			},
		},
		Ciphertext: []byte("data"),
	})

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if s, ok := status.FromError(err); !ok || s.Code() != codes.Unimplemented {
		t.Errorf("expected Unimplemented, got %v", err)
	}
}

func TestEncrypt_PgpKey_ReturnsUnimplemented(t *testing.T) {
	srv := testServer(t, kmsEncryptHandler(t))

	_, err := srv.Encrypt(context.Background(), &pb.EncryptRequest{
		Key: &pb.Key{
			KeyType: &pb.Key_PgpKey{
				PgpKey: &pb.PgpKey{Fingerprint: "ABCD1234"},
			},
		},
		Plaintext: []byte("data"),
	})

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if s, ok := status.FromError(err); !ok || s.Code() != codes.Unimplemented {
		t.Errorf("expected Unimplemented, got %v", err)
	}
}

func TestEncrypt_GcpKmsKey_ReturnsUnimplemented(t *testing.T) {
	srv := testServer(t, kmsEncryptHandler(t))

	_, err := srv.Encrypt(context.Background(), &pb.EncryptRequest{
		Key: &pb.Key{
			KeyType: &pb.Key_GcpKmsKey{
				GcpKmsKey: &pb.GcpKmsKey{ResourceId: "projects/p/locations/l/keyRings/r/cryptoKeys/k"},
			},
		},
		Plaintext: []byte("data"),
	})

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if s, ok := status.FromError(err); !ok || s.Code() != codes.Unimplemented {
		t.Errorf("expected Unimplemented, got %v", err)
	}
}

func TestEncrypt_AzureKey_ReturnsUnimplemented(t *testing.T) {
	srv := testServer(t, kmsEncryptHandler(t))

	_, err := srv.Encrypt(context.Background(), &pb.EncryptRequest{
		Key: &pb.Key{
			KeyType: &pb.Key_AzureKeyvaultKey{
				AzureKeyvaultKey: &pb.AzureKeyVaultKey{VaultUrl: "https://vault.azure.net"},
			},
		},
		Plaintext: []byte("data"),
	})

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if s, ok := status.FromError(err); !ok || s.Code() != codes.Unimplemented {
		t.Errorf("expected Unimplemented, got %v", err)
	}
}

func TestEncrypt_CloudAPIError_ReturnsInternal(t *testing.T) {
	srv := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(cloud.ErrorResponse{Error: "Access denied"})
	})

	_, err := srv.Encrypt(context.Background(), &pb.EncryptRequest{
		Key: &pb.Key{
			KeyType: &pb.Key_KmsKey{
				KmsKey: &pb.KmsKey{Arn: "arn:aws:kms:us-east-1:123:key/abc"},
			},
		},
		Plaintext: []byte("data"),
	})

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if s, ok := status.FromError(err); !ok || s.Code() != codes.Internal {
		t.Errorf("expected Internal, got %v", err)
	}
}

func TestDecrypt_CloudAPIError_ReturnsInternal(t *testing.T) {
	srv := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal server error"))
	})

	_, err := srv.Decrypt(context.Background(), &pb.DecryptRequest{
		Key: &pb.Key{
			KeyType: &pb.Key_KmsKey{
				KmsKey: &pb.KmsKey{Arn: "arn:aws:kms:us-east-1:123:key/abc"},
			},
		},
		Ciphertext: []byte("data"),
	})

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if s, ok := status.FromError(err); !ok || s.Code() != codes.Internal {
		t.Errorf("expected Internal, got %v", err)
	}
}
