// clef-keyservice is a SOPS-compatible gRPC key service that proxies
// KMS encrypt/decrypt operations through the Clef Cloud API.
//
// Usage:
//
//	clef-keyservice --token <cloud-token> [--endpoint <url>] [--addr <host:port>] [--verbose]
//
// The binary starts a gRPC server implementing the SOPS KeyService interface.
// On startup it prints "PORT=<port>" to stdout so the calling process can
// discover the assigned port (when using :0 for random port assignment).
//
// Only AWS KMS key operations are proxied. All other key types (PGP, age,
// GCP KMS, Azure Key Vault) return gRPC UNIMPLEMENTED, causing SOPS to
// fall back to local key handling.
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/clef-sh/keyservice/internal/cloud"
	"github.com/clef-sh/keyservice/internal/proxy"
	pb "github.com/getsops/sops/v3/keyservice"
	"google.golang.org/grpc"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:0", "Listen address (host:port). Use :0 for random port.")
	token := flag.String("token", "", "Clef Cloud bearer token (required)")
	endpoint := flag.String("endpoint", "https://api.clef.sh", "Clef Cloud API base URL")
	verbose := flag.Bool("verbose", false, "Enable debug logging to stderr")
	flag.Parse()

	if *token == "" {
		fmt.Fprintln(os.Stderr, "error: --token is required")
		os.Exit(1)
	}

	// Configure logger
	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	// Create Cloud API client
	client := cloud.NewClient(*endpoint, *token)

	// Start gRPC server
	lis, err := net.Listen("tcp", *addr)
	if err != nil {
		logger.Error("failed to listen", "addr", *addr, "error", err)
		os.Exit(1)
	}

	srv := grpc.NewServer()
	pb.RegisterKeyServiceServer(srv, proxy.NewServer(client, logger))

	// Print assigned port for the calling process to discover
	port := lis.Addr().(*net.TCPAddr).Port
	fmt.Fprintf(os.Stdout, "PORT=%d\n", port)

	// Handle shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		logger.Info("shutting down")
		srv.GracefulStop()
	}()

	logger.Info("key service started", "addr", lis.Addr().String())

	if err := srv.Serve(lis); err != nil {
		logger.Error("server failed", "error", err)
		os.Exit(1)
	}
}
