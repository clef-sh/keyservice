package cloud

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEncrypt_Success(t *testing.T) {
	expectedCiphertext := []byte("wrapped-dek-bytes")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/cloud/kms/encrypt" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("unexpected auth header: %s", r.Header.Get("Authorization"))
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("unexpected content type: %s", r.Header.Get("Content-Type"))
		}

		body, _ := io.ReadAll(r.Body)
		var req EncryptRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Fatalf("unmarshal request: %v", err)
		}
		if req.KeyARN != "arn:aws:kms:us-east-1:123:key/abc" {
			t.Errorf("unexpected key ARN: %s", req.KeyARN)
		}

		// Verify plaintext is base64-encoded
		decoded, err := base64.StdEncoding.DecodeString(req.Plaintext)
		if err != nil {
			t.Fatalf("plaintext not valid base64: %v", err)
		}
		if string(decoded) != "dek-plaintext" {
			t.Errorf("unexpected plaintext: %s", string(decoded))
		}

		resp := map[string]interface{}{
			"data": map[string]string{
				"ciphertext": base64.StdEncoding.EncodeToString(expectedCiphertext),
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	result, err := client.Encrypt("arn:aws:kms:us-east-1:123:key/abc", []byte("dek-plaintext"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(result) != string(expectedCiphertext) {
		t.Errorf("expected %q, got %q", expectedCiphertext, result)
	}
}

func TestDecrypt_Success(t *testing.T) {
	expectedPlaintext := []byte("dek-plaintext")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/cloud/kms/decrypt" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		body, _ := io.ReadAll(r.Body)
		var req DecryptRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Fatalf("unmarshal request: %v", err)
		}
		if req.KeyARN != "arn:aws:kms:us-east-1:123:key/abc" {
			t.Errorf("unexpected key ARN: %s", req.KeyARN)
		}

		resp := map[string]interface{}{
			"data": map[string]string{
				"plaintext": base64.StdEncoding.EncodeToString(expectedPlaintext),
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	result, err := client.Decrypt("arn:aws:kms:us-east-1:123:key/abc", []byte("wrapped-dek"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(result) != string(expectedPlaintext) {
		t.Errorf("expected %q, got %q", expectedPlaintext, result)
	}
}

func TestEncrypt_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Access denied", Message: "Key not found for project"})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	_, err := client.Encrypt("arn:aws:kms:us-east-1:123:key/abc", []byte("dek"))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if got := err.Error(); got != "cloud encrypt: Access denied (HTTP 403)" {
		t.Errorf("unexpected error message: %s", got)
	}
}

func TestDecrypt_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Invalid token"})
	}))
	defer server.Close()

	client := NewClient(server.URL, "bad-token")
	_, err := client.Decrypt("arn:aws:kms:us-east-1:123:key/abc", []byte("wrapped"))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestEncrypt_NonJSONError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte("bad gateway"))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	_, err := client.Encrypt("arn:aws:kms:us-east-1:123:key/abc", []byte("dek"))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if got := err.Error(); got != "cloud encrypt: HTTP 502: bad gateway" {
		t.Errorf("unexpected error message: %s", got)
	}
}

func TestEncrypt_InvalidBase64Response(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]string{"ciphertext": "not-valid-base64!!!"}})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	_, err := client.Encrypt("arn:aws:kms:us-east-1:123:key/abc", []byte("dek"))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestDecrypt_InvalidBase64Response(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]string{"plaintext": "not-valid-base64!!!"}})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	_, err := client.Decrypt("arn:aws:kms:us-east-1:123:key/abc", []byte("wrapped"))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestEncrypt_NetworkError(t *testing.T) {
	client := NewClient("http://localhost:1", "test-token")
	_, err := client.Encrypt("arn:aws:kms:us-east-1:123:key/abc", []byte("dek"))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
