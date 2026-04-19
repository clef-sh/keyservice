# clef-keyservice (multiple platforms)

A standalone gRPC key service that implements the [SOPS KeyService protocol](https://github.com/getsops/sops) and bridges DEK wrap/unwrap to a hardware security module via **PKCS#11**. Supports any vendor that ships a Cryptoki shared library: SoftHSM2, YubiHSM2, Thales Luna, AWS CloudHSM, Nitrokey / NetHSM.

```
SOPS ──gRPC──▶ clef-keyservice ──cgo dlopen──▶ vendor PKCS#11 .so ──▶ HSM
```

Zero cloud custody. Private key material never leaves the HSM — `C_Encrypt` / `C_Decrypt` execute inside the device. Only the 32-byte data encryption key crosses the gRPC boundary between SOPS and this binary.

## How it works

1. The Clef CLI spawns `clef-keyservice` as a child process with the HSM module path and PIN set in the environment
2. The binary dlopens the vendor PKCS#11 library, starts a gRPC server on localhost, and prints `PORT=<port>` to stdout
3. SOPS connects to the gRPC server and sends `Encrypt` / `Decrypt` requests
4. The `KmsKey.arn` field carries a `pkcs11:` URI identifying the RSA wrap keypair on the HSM; the service opens a session on that slot, logs in with the PIN, and performs `CKM_RSA_PKCS_OAEP` wrap/unwrap against the key
5. For all other SOPS key types (PGP, age, GCP KMS, Azure Key Vault, Vault), the server returns gRPC `UNIMPLEMENTED` — SOPS falls back to its own local handling
6. When the SOPS command finishes, the process exits

## Usage

```bash
clef-keyservice --pkcs11-module <path> [--addr <host:port>] [--verbose]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--pkcs11-module` | *(required)* | Path to vendor PKCS#11 library (`.so` / `.dylib` / `.dll`). Falls back to `CLEF_PKCS11_MODULE`. |
| `--addr` | `127.0.0.1:0` | Listen address. `:0` assigns a random port |
| `--verbose` | `false` | Enable debug logging to stderr |
| `--version` | — | Print version and exit |

### Environment variables

| Variable | Purpose |
|----------|---------|
| `CLEF_PKCS11_MODULE` | Module path (fallback for `--pkcs11-module`) |
| `CLEF_PKCS11_PIN` | User PIN for `C_Login`. Never accept on argv (would leak to `/proc/<pid>/cmdline`) |
| `CLEF_PKCS11_PIN_FILE` | Alternative: path to a 0600 file containing the PIN |

Some vendor modules also require a vendor-specific config env (`SOFTHSM2_CONF`, `YUBIHSM_PKCS11_CONF`, `ChrystokiConfigurationPath`). Set those in the calling environment alongside `CLEF_PKCS11_MODULE`.

### Wire format — the Clef HSM synthetic ARN

SOPS's `--kms` flag enforces an AWS ARN regex and stores that exact string in `sops.kms[].arn` in the encrypted file, forwarding it verbatim in `KmsKey.arn` on the gRPC wire. To ship a pkcs11 URI through that contract, the Clef CLI wraps every URI in this synthetic ARN shape before handing it to SOPS:

```
arn:aws:kms:us-east-1:000000000000:alias/clef-hsm/v1/<BASE64URL(pkcs11-uri)>
```

| Field | Value | Notes |
|-------|-------|-------|
| Partition | `aws` / `aws-us-gov` / `aws-cn` | Matches SOPS's own ARN regex |
| Region | `us-east-1` | Placeholder — keyservice never dials AWS |
| Account | `000000000000` | Placeholder — 12-zero convention signals "synthetic" |
| Resource | `alias/clef-hsm/v1/<payload>` | `alias/` avoids any future AWS key-id tightening |
| `v1` | literal version marker | v2+ = `Unimplemented` until we bump |
| `<payload>` | `base64url(utf8(pkcs11-uri))` | RFC 4648 §5, no padding |

Validated by this anchored regex on both sides (CLI and keyservice):

```go
^arn:aws[\w-]*:kms:[^:]+:\d+:alias/clef-hsm/(v\d+)/([A-Za-z0-9_-]+)$
```

**Test vectors** (canonical, computed with Go's `encoding/base64.RawURLEncoding`):

| pkcs11 URI | Payload |
|------------|---------|
| `pkcs11:slot=0;label=clef-dek-wrapper` | `cGtjczExOnNsb3Q9MDtsYWJlbD1jbGVmLWRlay13cmFwcGVy` |
| `pkcs11:slot=0;label=foo;hash=sha1` | `cGtjczExOnNsb3Q9MDtsYWJlbD1mb287aGFzaD1zaGEx` |
| `pkcs11:slot=12345;object=wrap-key` | `cGtjczExOnNsb3Q9MTIzNDU7b2JqZWN0PXdyYXAta2V5` |

### Inner pkcs11 URI format

The decoded payload identifies the RSA wrap keypair on the HSM:

```
pkcs11:slot=0;label=clef-dek-wrapper              # OAEP SHA-256 (default)
pkcs11:slot=0;label=clef-dek-wrapper;hash=sha256  # explicit
pkcs11:slot=0;label=clef-dek-wrapper;hash=sha1    # legacy / SoftHSM2 compat
```

| Attribute | Aliases | Required | Default |
|-----------|---------|----------|---------|
| `slot` | `slot-id` | yes | — |
| `label` | `object` | yes | — |
| `hash` | — | no | `sha256` (accepts `sha1`, `sha256`, `sha384`, `sha512`) |

The hash is pinned in the URI because encrypt and decrypt must use the same value for a given ciphertext.

### Direct gRPC / testing

If a raw `pkcs11:` URI arrives in `KmsKey.arn` (bypassing SOPS — e.g. via `grpcurl` or an integration test), the keyservice accepts it verbatim and emits a `WARN` log noting that this is a testing affordance, not the production contract. SOPS itself will never emit such a value: its own `--kms` regex rejects anything that isn't AWS-shaped.

## Vendor module paths

| Vendor | Module path (Linux) | Extra config env |
|---|---|---|
| SoftHSM2 | `/usr/lib/softhsm/libsofthsm2.so` | `SOFTHSM2_CONF` |
| YubiHSM2 | `/usr/local/lib/yubihsm_pkcs11.so` | `YUBIHSM_PKCS11_CONF` (plus `yubihsm-connector` daemon) |
| Thales Luna | `/usr/safenet/lunaclient/lib/libCryptoki2_64.so` | `ChrystokiConfigurationPath` |
| AWS CloudHSM | `/opt/cloudhsm/lib/libcloudhsm_pkcs11.so` | cluster certs under `/opt/cloudhsm/etc/` |
| Nitrokey / OpenSC | `/usr/lib/opensc-pkcs11.so` | PC/SC daemon running |

## Network HSMs and mTLS

Network-attached HSMs (Thales Luna SA, AWS CloudHSM, remote YubiHSM via HTTPS connector, Securosys, Utimaco) typically authenticate the client with TLS client certificates. **Cert handling is entirely the vendor PKCS#11 library's responsibility** — clef-keyservice `dlopen`s the library and calls `C_*`; the library opens its own TCP connection, reads its own config file, presents the client cert, and validates the server cert. There is no TLS code in this binary and none is needed.

The user supplies cert paths to the vendor library through its config file, selected by a vendor-specific env variable passed through to this process alongside `CLEF_PKCS11_MODULE`:

| Vendor | Config file | Cert fields (inside the config) |
|---|---|---|
| Thales Luna | `Chrystoki.conf` via `ChrystokiConfigurationPath` | `[LunaSA Client]` → `ClientCertFile`, `ClientPrivKeyFile`, `ServerCAFile` |
| AWS CloudHSM | `/opt/cloudhsm/etc/cloudhsm-pkcs11.cfg` | `customerCA.crt` under `/opt/cloudhsm/etc/`, configured once via `configure-pkcs11` |
| YubiHSM2 | `yubihsm_pkcs11.conf` via `YUBIHSM_PKCS11_CONF` | `connector = https://...`, `cacert`, optional `cert`/`key` for client auth |
| Securosys CloudsHSM | `sb_pkcs11.cfg` via `SB_PKCS11_CFG` | `TLS_CLIENT_CERT`, `TLS_CLIENT_KEY`, `TLS_CA_BUNDLE` |

If a vendor ships a library that does not read cert paths from its own config — file an issue. There is no provision on our side to inject them.

### Keyservice bind address

The keyservice gRPC server binds to `127.0.0.1` by default and is expected to stay there — it is a short-lived local IPC sidecar spawned by the Clef CLI, not a network-reachable daemon. The gRPC channel has no TLS and no authentication. If `--addr` is set to a non-loopback address, a warning is logged at startup; exposing the keyservice off-host is unsupported and insecure.

## Provisioning a wrap keypair (SoftHSM2 example)

```bash
softhsm2-util --init-token --free --label clef --pin 1234 --so-pin 1234

# Note the Slot ID printed above, then:
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
  --login --pin 1234 --slot <SLOT> \
  --keypairgen --key-type rsa:2048 \
  --label clef-dek-wrapper --id 01
```

Then use `pkcs11:slot=<SLOT>;label=clef-dek-wrapper` as the SOPS key identifier (with `hash=sha1` for SoftHSM2 2.7, which rejects SHA-256 OAEP).

## gRPC Interface

The service implements the SOPS `KeyService` proto (consumed directly from `github.com/getsops/sops/v3/keyservice` to stay in lockstep with the CLI's SOPS pin):

```proto
service KeyService {
    rpc Encrypt(EncryptRequest) returns (EncryptResponse);
    rpc Decrypt(DecryptRequest) returns (DecryptResponse);
}
```

### Encrypt

SOPS sends a `KmsKey` (pkcs11 URI) and plaintext DEK. The service wraps it with the RSA public key on the HSM and returns ciphertext.

### Decrypt

SOPS sends a `KmsKey` (pkcs11 URI) and ciphertext DEK. The service unwraps it with the RSA private key on the HSM (which never leaves the device) and returns plaintext.

**Supported key type:** `KmsKey` only. All others return `UNIMPLEMENTED`.

### Error codes

| Code | Condition |
|------|-----------|
| `INVALID_ARGUMENT` | Request is missing a key, or synthetic ARN is malformed (bad base64, unknown version, decoded payload not a pkcs11 URI) |
| `UNIMPLEMENTED` | Key type is not `KmsKey`, or ARN is a real AWS KMS ARN (not a clef-hsm synthetic) |
| `INTERNAL` | HSM returned an error (bad PIN, key not found, mechanism unsupported, etc.) |

## Security properties

- **Localhost only** — binds to `127.0.0.1`, not accessible from the network
- **Short-lived** — process exits when the parent SOPS command finishes
- **No key custody** — private key material stays inside the HSM; wrap/unwrap run in-device
- **PIN handling** — read from env or a 0600 file, never argv (stays out of `/proc/<pid>/cmdline`)
- **Mechanism** — RSA-OAEP with SHA-256 by default (FIPS-valid, universal across production HSM vendors, sized for a 32-byte DEK in one block). SHA-1/384/512 available via the URI for vendor compatibility

## Building

```bash
make build              # Build for current platform → bin/clef-keyservice
make build-all          # Cross-compile for all platforms
make test               # Run unit tests
make test-integration   # Provision a SoftHSM2 token + RSA keypair, round-trip through Client
make clean              # Remove build artifacts
```

cgo is required (miekg/pkcs11 is a Cryptoki wrapper). Cross-compilation needs a C toolchain per target; override with `CC_DARWIN_ARM64`, `CC_LINUX_AMD64`, etc. (e.g. `zig cc` works well):

```bash
make build-all CC_LINUX_AMD64="zig cc -target x86_64-linux-musl"
```

The integration test requires `softhsm2-util` and `pkcs11-tool` (OpenSC) on PATH. It skips cleanly if either is missing.

### Cross-compilation targets

| Target | Output | C toolchain required |
|--------|--------|----------------------|
| macOS ARM64 (Apple Silicon) | `bin/clef-keyservice-darwin-arm64` | clang (Xcode CLT) |
| macOS x64 (Intel) | `bin/clef-keyservice-darwin-x64` | clang (Xcode CLT) |
| Linux x64 | `bin/clef-keyservice-linux-x64` | gcc |
| Linux ARM64 | `bin/clef-keyservice-linux-arm64` | `aarch64-linux-gnu-gcc` |
| Windows x64 | `bin/clef-keyservice-win32-x64.exe` | `x86_64-w64-mingw32-gcc` (MinGW) |

Because cgo is required, local cross-compilation needs a C cross-compiler for each non-native target (e.g. `brew install mingw-w64` for Windows from macOS, `apt install gcc-aarch64-linux-gnu` for Linux ARM64 from Linux x64). The release pipeline avoids this by building each target natively on its own runner.

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
