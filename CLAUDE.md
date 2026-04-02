# CLAUDE.md

## Project Overview

`clef-keyservice` is a standalone Go binary that implements the SOPS gRPC key service protocol. It proxies KMS encrypt/decrypt operations through the Clef Cloud HTTPS API, allowing developers to use Cloud-managed KMS keys without AWS credentials on their local machine.

## Architecture

```
SOPS → gRPC (localhost) → clef-keyservice → HTTPS → Cloud API → AWS KMS
```

- **Input:** SOPS sends Encrypt/Decrypt requests via gRPC with a KmsKey (ARN) and data
- **Proxy:** Binary authenticates with Cloud API using a bearer token, forwards KMS operations
- **Output:** Wrapped/unwrapped DEK returned to SOPS. Secret values never leave the user's machine.

Only AWS KMS keys (`KmsKey`) are handled. All other key types return gRPC UNIMPLEMENTED — SOPS falls back to local key handling for those.

## Commands

```bash
make proto      # Generate Go code from proto (requires protoc + plugins)
make build      # Build for current platform
make build-all  # Cross-compile for all platforms
make test       # Run tests
make clean      # Remove build artifacts
```

## Binary Usage

```bash
clef-keyservice --token <cloud-token> [--endpoint <url>] [--addr <host:port>] [--verbose]
```

Prints `PORT=<port>` to stdout on startup so the CLI can discover the assigned port.

## Code Style

- Go 1.24+
- Standard library preferred over third-party dependencies
- `log/slog` for structured logging
- gRPC status codes for errors
- No panics in library code

## Proto Generation

The proto file is vendored from SOPS (`keyservice/keyservice.proto`). To regenerate:

```bash
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
make proto
```

## Security Properties

- Binds to 127.0.0.1 only (localhost)
- Short-lived process (dies when SOPS command finishes)
- Only DEK (32-byte key) crosses the wire, never secret values
- Cloud API validates bearer token and key ownership per request
