// Package cloud provides an HTTPS client for the Clef Cloud KMS API.
package cloud

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client communicates with the Clef Cloud KMS proxy API.
type Client struct {
	endpoint   string
	token      string
	httpClient *http.Client
}

// NewClient creates a Cloud API client.
func NewClient(endpoint, token string) *Client {
	return &Client{
		endpoint: endpoint,
		token:    token,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// EncryptRequest is the payload sent to the Cloud KMS encrypt endpoint.
type EncryptRequest struct {
	KeyARN    string `json:"keyArn"`
	Plaintext string `json:"plaintext"` // base64-encoded
}

// EncryptResponse is returned by the Cloud KMS encrypt endpoint.
type EncryptResponse struct {
	Ciphertext string `json:"ciphertext"` // base64-encoded
}

// DecryptRequest is the payload sent to the Cloud KMS decrypt endpoint.
type DecryptRequest struct {
	KeyARN     string `json:"keyArn"`
	Ciphertext string `json:"ciphertext"` // base64-encoded
}

// DecryptResponse is returned by the Cloud KMS decrypt endpoint.
type DecryptResponse struct {
	Plaintext string `json:"plaintext"` // base64-encoded
}

// ErrorResponse is returned on failure.
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

// Encrypt wraps a DEK via the Cloud KMS API.
func (c *Client) Encrypt(keyARN string, plaintext []byte) ([]byte, error) {
	req := EncryptRequest{
		KeyARN:    keyARN,
		Plaintext: base64.StdEncoding.EncodeToString(plaintext),
	}

	var resp EncryptResponse
	if err := c.do("POST", "/api/v1/cloud/kms/encrypt", req, &resp); err != nil {
		return nil, fmt.Errorf("cloud encrypt: %w", err)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(resp.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("cloud encrypt: invalid base64 response: %w", err)
	}

	return ciphertext, nil
}

// Decrypt unwraps a DEK via the Cloud KMS API.
func (c *Client) Decrypt(keyARN string, ciphertext []byte) ([]byte, error) {
	req := DecryptRequest{
		KeyARN:     keyARN,
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}

	var resp DecryptResponse
	if err := c.do("POST", "/api/v1/cloud/kms/decrypt", req, &resp); err != nil {
		return nil, fmt.Errorf("cloud decrypt: %w", err)
	}

	plaintext, err := base64.StdEncoding.DecodeString(resp.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("cloud decrypt: invalid base64 response: %w", err)
	}

	return plaintext, nil
}

func (c *Client) do(method, path string, reqBody any, respBody any) error {
	body, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	url := c.endpoint + path
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp ErrorResponse
		if json.Unmarshal(respBytes, &errResp) == nil && errResp.Error != "" {
			return fmt.Errorf("%s (HTTP %d)", errResp.Error, resp.StatusCode)
		}
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBytes))
	}

	if err := json.Unmarshal(respBytes, respBody); err != nil {
		return fmt.Errorf("unmarshal response: %w", err)
	}

	return nil
}
