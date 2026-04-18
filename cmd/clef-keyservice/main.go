// clef-keyservice is a SOPS-compatible gRPC key service that wraps and
// unwraps DEKs against a PKCS#11 HSM (SoftHSM2, YubiHSM2, Thales Luna,
// AWS CloudHSM, Nitrokey — any vendor that ships a Cryptoki module).
//
// Usage:
//
//	clef-keyservice --pkcs11-module <path> [--addr <host:port>] [--verbose]
//
// The vendor PKCS#11 library path may be given via --pkcs11-module or the
// CLEF_PKCS11_MODULE env var. The user PIN, when required, is read from
// CLEF_PKCS11_PIN or a file pointed at by CLEF_PKCS11_PIN_FILE — never from
// argv, to keep it out of /proc/<pid>/cmdline.
//
// SOPS carries the target key in KmsKey.arn as a simplified pkcs11: URI:
//
//	pkcs11:slot=0;label=clef-dek-wrapper
//
// Wrap/unwrap uses CKM_RSA_PKCS_OAEP with SHA-256 against an RSA keypair
// provisioned on the HSM. All non-KMS SOPS key types return UNIMPLEMENTED
// so SOPS falls back to local handling for them.
//
// On startup the binary prints "PORT=<port>" to stdout so a parent process
// can discover the port when --addr uses :0.
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/clef-sh/keyservice/internal/hsm"
	"github.com/clef-sh/keyservice/internal/proxy"
	pb "github.com/getsops/sops/v3/keyservice"
	"google.golang.org/grpc"
)

var version = "dev"

func main() {
	addr := flag.String("addr", "127.0.0.1:0", "Listen address (host:port). Use :0 for random port.")
	module := flag.String("pkcs11-module", "", "Path to PKCS#11 module (.so/.dylib/.dll). Falls back to CLEF_PKCS11_MODULE.")
	verbose := flag.Bool("verbose", false, "Enable debug logging to stderr")
	showVersion := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		os.Exit(0)
	}

	if *module == "" {
		*module = os.Getenv("CLEF_PKCS11_MODULE")
	}
	if *module == "" {
		fmt.Fprintln(os.Stderr, "error: --pkcs11-module or CLEF_PKCS11_MODULE is required")
		os.Exit(1)
	}

	pin, err := resolvePIN()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	backend, err := hsm.NewClient(hsm.Config{ModulePath: *module, PIN: pin})
	if err != nil {
		logger.Error("failed to initialize HSM client", "module", *module, "error", err)
		os.Exit(1)
	}
	defer backend.Close()

	lis, err := net.Listen("tcp", *addr)
	if err != nil {
		logger.Error("failed to listen", "addr", *addr, "error", err)
		os.Exit(1)
	}

	srv := grpc.NewServer()
	pb.RegisterKeyServiceServer(srv, proxy.NewServer(backend, logger))

	port := lis.Addr().(*net.TCPAddr).Port
	fmt.Fprintf(os.Stdout, "PORT=%d\n", port)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		logger.Info("shutting down")
		srv.GracefulStop()
	}()

	logger.Info("key service started", "addr", lis.Addr().String(), "module", *module)

	if err := srv.Serve(lis); err != nil {
		logger.Error("server failed", "error", err)
		os.Exit(1)
	}
}

// resolvePIN reads the HSM user PIN from CLEF_PKCS11_PIN, falling back to
// the file named by CLEF_PKCS11_PIN_FILE. Returns "" (no login) if neither
// is set.
func resolvePIN() (string, error) {
	if p := os.Getenv("CLEF_PKCS11_PIN"); p != "" {
		return p, nil
	}
	if path := os.Getenv("CLEF_PKCS11_PIN_FILE"); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read CLEF_PKCS11_PIN_FILE: %w", err)
		}
		return strings.TrimRight(string(data), "\r\n"), nil
	}
	return "", nil
}
