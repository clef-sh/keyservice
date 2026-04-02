// Package proxy implements the SOPS KeyService gRPC interface,
// proxying KMS encrypt/decrypt operations through the Clef Cloud API.
package proxy

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/clef-sh/keyservice/internal/cloud"
	pb "github.com/getsops/sops/v3/keyservice"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Server implements the SOPS KeyService gRPC interface.
// Only KmsKey operations are proxied. All other key types return UNIMPLEMENTED.
type Server struct {
	pb.UnimplementedKeyServiceServer
	client *cloud.Client
	logger *slog.Logger
}

// NewServer creates a key service proxy backed by the Cloud API.
func NewServer(client *cloud.Client, logger *slog.Logger) *Server {
	return &Server{
		client: client,
		logger: logger,
	}
}

// Encrypt handles SOPS encrypt requests by proxying to the Cloud KMS API.
func (s *Server) Encrypt(_ context.Context, req *pb.EncryptRequest) (*pb.EncryptResponse, error) {
	key := req.GetKey()
	if key == nil {
		return nil, status.Error(codes.InvalidArgument, "missing key")
	}

	kmsKey := key.GetKmsKey()
	if kmsKey == nil {
		return nil, status.Error(codes.Unimplemented,
			"only AWS KMS keys are supported by the Clef Cloud key service")
	}

	s.logger.Debug("encrypt request", "arn", kmsKey.Arn, "bytes", len(req.Plaintext))

	ciphertext, err := s.client.Encrypt(kmsKey.Arn, req.Plaintext)
	if err != nil {
		s.logger.Error("encrypt failed", "arn", kmsKey.Arn, "error", err)
		return nil, status.Error(codes.Internal, fmt.Sprintf("encrypt failed: %v", err))
	}

	s.logger.Debug("encrypt success", "arn", kmsKey.Arn)
	return &pb.EncryptResponse{Ciphertext: ciphertext}, nil
}

// Decrypt handles SOPS decrypt requests by proxying to the Cloud KMS API.
func (s *Server) Decrypt(_ context.Context, req *pb.DecryptRequest) (*pb.DecryptResponse, error) {
	key := req.GetKey()
	if key == nil {
		return nil, status.Error(codes.InvalidArgument, "missing key")
	}

	kmsKey := key.GetKmsKey()
	if kmsKey == nil {
		return nil, status.Error(codes.Unimplemented,
			"only AWS KMS keys are supported by the Clef Cloud key service")
	}

	s.logger.Debug("decrypt request", "arn", kmsKey.Arn, "bytes", len(req.Ciphertext))

	plaintext, err := s.client.Decrypt(kmsKey.Arn, req.Ciphertext)
	if err != nil {
		s.logger.Error("decrypt failed", "arn", kmsKey.Arn, "error", err)
		return nil, status.Error(codes.Internal, fmt.Sprintf("decrypt failed: %v", err))
	}

	s.logger.Debug("decrypt success", "arn", kmsKey.Arn)
	return &pb.DecryptResponse{Plaintext: plaintext}, nil
}
