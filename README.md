# clef-keyservice

A standalone gRPC key service that implements the [SOPS KeyService protocol](https://github.com/getsops/sops). It proxies AWS KMS encrypt/decrypt operations through the Clef Cloud HTTPS API, allowing developers to use Cloud-managed KMS keys without local AWS credentials.

```
SOPS ──gRPC──▶ clef-keyservice ──HTTPS──▶ Clef Cloud API ──▶ AWS KMS
```

Secret values (file contents) never leave the developer's machine. Only the 32-byte data encryption key (DEK) crosses the wire for wrapping/unwrapping.

## How it works

1. The Clef CLI spawns `clef-keyservice` as a child process with a Cloud bearer token
2. The binary starts a gRPC server on localhost and prints `PORT=<port>` to stdout
3. SOPS connects to the gRPC server and sends `Encrypt`/`Decrypt` requests
4. For AWS KMS keys, the proxy forwards the operation to the Cloud API over HTTPS
5. For all other key types (PGP, age, GCP KMS, Azure Key Vault, Vault), the server returns gRPC `UNIMPLEMENTED` — SOPS falls back to local key handling
6. When the SOPS command finishes, the process exits

## Usage

```bash
clef-keyservice --token <cloud-token> [--endpoint <url>] [--addr <host:port>] [--verbose]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--token` | *(required)* | Clef Cloud bearer token |
| `--endpoint` | `https://api.clef.sh` | Clef Cloud API base URL |
| `--addr` | `127.0.0.1:0` | Listen address. `:0` assigns a random port |
| `--verbose` | `false` | Enable debug logging to stderr |

On startup, the binary prints `PORT=<port>` to stdout so the parent process can discover the assigned port.

## gRPC Interface

The service implements the SOPS `KeyService` proto:

```proto
service KeyService {
    rpc Encrypt(EncryptRequest) returns (EncryptResponse);
    rpc Decrypt(DecryptRequest) returns (DecryptResponse);
}
```

### Encrypt

SOPS sends a `KmsKey` (ARN) and plaintext DEK. The proxy wraps the key via Cloud KMS and returns ciphertext.

**Supported key type:** `KmsKey` only. All others return `UNIMPLEMENTED`.

### Decrypt

SOPS sends a `KmsKey` (ARN) and ciphertext DEK. The proxy unwraps the key via Cloud KMS and returns plaintext.

**Supported key type:** `KmsKey` only. All others return `UNIMPLEMENTED`.

### Error codes

| Code | Condition |
|------|-----------|
| `INVALID_ARGUMENT` | Request is missing a key |
| `UNIMPLEMENTED` | Key type is not `KmsKey` (PGP, age, GCP, Azure, Vault) |
| `INTERNAL` | Cloud API returned an error |

## Cloud API

The proxy translates gRPC calls into HTTPS requests to the Clef Cloud API.

### POST `/api/v1/cloud/kms/encrypt`

Wraps a plaintext DEK with the specified KMS key.

**Request:**
```json
{
  "keyArn": "arn:aws:kms:us-east-1:123456789:key/abc-def",
  "plaintext": "<base64-encoded plaintext>"
}
```

**Response:**
```json
{
  "ciphertext": "<base64-encoded ciphertext>"
}
```

### POST `/api/v1/cloud/kms/decrypt`

Unwraps a ciphertext DEK with the specified KMS key.

**Request:**
```json
{
  "keyArn": "arn:aws:kms:us-east-1:123456789:key/abc-def",
  "ciphertext": "<base64-encoded ciphertext>"
}
```

**Response:**
```json
{
  "plaintext": "<base64-encoded plaintext>"
}
```

### Authentication

All requests include an `Authorization: Bearer <token>` header. The Cloud API validates the token and verifies the caller has access to the requested KMS key.

### Error responses

```json
{
  "error": "unauthorized",
  "message": "invalid or expired token"
}
```

Errors are surfaced to SOPS as gRPC `INTERNAL` status codes.

## Security properties

- **Localhost only** — binds to `127.0.0.1`, not accessible from the network
- **Short-lived** — process exits when the parent SOPS command finishes
- **Minimal data exposure** — only the DEK (32 bytes) is sent to the Cloud API, never the actual secret values
- **Per-request auth** — the Cloud API validates the bearer token and key ownership on every request

## Building

```bash
make build       # Build for current platform → bin/clef-keyservice
make build-all   # Cross-compile for all platforms
make test        # Run unit tests
make clean       # Remove build artifacts
```

### Cross-compilation targets

| Target | Output |
|--------|--------|
| macOS ARM64 (Apple Silicon) | `bin/clef-keyservice-darwin-arm64` |
| macOS x64 (Intel) | `bin/clef-keyservice-darwin-x64` |
| Linux x64 | `bin/clef-keyservice-linux-x64` |
| Linux ARM64 | `bin/clef-keyservice-linux-arm64` |
| Windows x64 | `bin/clef-keyservice-win32-x64.exe` |

## npm platform packages

Each platform binary is published as a scoped npm package for use as an `optionalDependency`:

| Package | Platform |
|---------|----------|
| `@clef-sh/keyservice-darwin-arm64` | macOS ARM64 |
| `@clef-sh/keyservice-darwin-x64` | macOS x64 |
| `@clef-sh/keyservice-linux-x64` | Linux x64 |
| `@clef-sh/keyservice-linux-arm64` | Linux ARM64 |
| `@clef-sh/keyservice-win32-x64` | Windows x64 |

npm resolves the correct platform package automatically via the `os` and `cpu` fields in each `package.json`.

## License

[Business Source License 1.1](LICENSE) — see LICENSE for details.
