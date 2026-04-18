// Package proxy implements the SOPS KeyService gRPC interface,
// forwarding Encrypt/Decrypt requests to a pluggable key-wrapping Backend.
//
// Wire format (the "Clef HSM synthetic ARN" contract with the CLI):
//
//	arn:aws:kms:us-east-1:000000000000:alias/clef-hsm/v1/<BASE64URL(pkcs11-uri)>
//
// The pkcs11 URI is smuggled inside an AWS-shaped ARN because SOPS's
// --kms regex rejects anything else. See arn.go for the contract regex and
// decode logic.
//
// Only KmsKey is handled; all other SOPS key types return gRPC UNIMPLEMENTED
// so SOPS falls back to its own local handling for those.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	pb "github.com/getsops/sops/v3/keyservice"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Backend wraps and unwraps 32-byte DEKs against an underlying KMS/HSM,
// identified by a raw pkcs11 URI. All synthetic-ARN unwrapping happens in
// the proxy layer before the Backend is called.
type Backend interface {
	Encrypt(keyURI string, plaintext []byte) ([]byte, error)
	Decrypt(keyURI string, ciphertext []byte) ([]byte, error)
}

// Server implements the SOPS KeyService gRPC interface.
type Server struct {
	pb.UnimplementedKeyServiceServer
	backend Backend
	logger  *slog.Logger
}

// NewServer creates a key service server backed by the given Backend.
func NewServer(backend Backend, logger *slog.Logger) *Server {
	return &Server{backend: backend, logger: logger}
}

func (s *Server) Encrypt(_ context.Context, req *pb.EncryptRequest) (*pb.EncryptResponse, error) {
	key := req.GetKey()
	if key == nil {
		return nil, status.Error(codes.InvalidArgument, "missing key")
	}

	kmsKey := key.GetKmsKey()
	if kmsKey == nil {
		return nil, status.Error(codes.Unimplemented,
			"only KmsKey carrying a clef-hsm synthetic ARN is supported by this keyservice")
	}

	s.logger.Debug("encrypt request", "arn", kmsKey.Arn, "bytes", len(req.Plaintext))

	uri, err := decodeKeyURI(kmsKey.Arn, s.logger)
	if err != nil {
		return nil, decodeErrorToStatus(err, kmsKey.Arn)
	}

	ciphertext, err := s.backend.Encrypt(uri, req.Plaintext)
	if err != nil {
		s.logger.Error("encrypt failed", "arn", kmsKey.Arn, "error", err)
		return nil, status.Error(codes.Internal, fmt.Sprintf("encrypt failed: %v", err))
	}

	s.logger.Debug("encrypt success", "arn", kmsKey.Arn)
	return &pb.EncryptResponse{Ciphertext: ciphertext}, nil
}

func (s *Server) Decrypt(_ context.Context, req *pb.DecryptRequest) (*pb.DecryptResponse, error) {
	key := req.GetKey()
	if key == nil {
		return nil, status.Error(codes.InvalidArgument, "missing key")
	}

	kmsKey := key.GetKmsKey()
	if kmsKey == nil {
		return nil, status.Error(codes.Unimplemented,
			"only KmsKey carrying a clef-hsm synthetic ARN is supported by this keyservice")
	}

	s.logger.Debug("decrypt request", "arn", kmsKey.Arn, "bytes", len(req.Ciphertext))

	uri, err := decodeKeyURI(kmsKey.Arn, s.logger)
	if err != nil {
		return nil, decodeErrorToStatus(err, kmsKey.Arn)
	}

	plaintext, err := s.backend.Decrypt(uri, req.Ciphertext)
	if err != nil {
		s.logger.Error("decrypt failed", "arn", kmsKey.Arn, "error", err)
		return nil, status.Error(codes.Internal, fmt.Sprintf("decrypt failed: %v", err))
	}

	s.logger.Debug("decrypt success", "arn", kmsKey.Arn)
	return &pb.DecryptResponse{Plaintext: plaintext}, nil
}

// decodeErrorToStatus maps decodeKeyURI failures to gRPC status codes.
// Unrecognized ARN (well-formed AWS but not a clef-hsm synthetic) maps to
// Unimplemented, matching the policy for unsupported SOPS key types.
// Everything else is a contract violation → InvalidArgument.
func decodeErrorToStatus(err error, arn string) error {
	if errors.Is(err, errUnrecognizedARN) {
		return status.Errorf(codes.Unimplemented,
			"arn is not a clef-hsm synthetic: %s", arn)
	}
	return status.Errorf(codes.InvalidArgument, "clef-hsm arn decode: %v", err)
}
