# CLAUDE.md

## Project Overview

`clef-keyservice` is a standalone Go binary that implements the SOPS gRPC key
service protocol. It bridges SOPS Encrypt/Decrypt requests to a PKCS#11 HSM
(SoftHSM2, YubiHSM2, Thales Luna, AWS CloudHSM, Nitrokey — any vendor that
ships a Cryptoki module), letting developers wrap and unwrap DEKs against
hardware-held RSA keys with no cloud custody of key material.

## Architecture

```
SOPS → gRPC (localhost) → clef-keyservice → cgo dlopen → vendor PKCS#11 .so → HSM
```

- **Input:** SOPS sends Encrypt/Decrypt requests via gRPC with a KmsKey and data.
- **Bridge:** Binary loads the vendor PKCS#11 shared library in-process (via
  `github.com/miekg/pkcs11`), opens a session on the requested slot, and
  performs `CKM_RSA_PKCS_OAEP` (SHA-256) wrap/unwrap against the RSA key
  identified by label.
- **Output:** Wrapped/unwrapped DEK returned to SOPS. Secret values never
  leave the user's machine, and private key material never leaves the HSM.

`KmsKey.arn` is repurposed as an opaque pkcs11: URI:

```
pkcs11:slot=0;label=clef-dek-wrapper              # OAEP SHA-256 (default)
pkcs11:slot=0;label=clef-dek-wrapper;hash=sha1    # OAEP SHA-1 (legacy / SoftHSM2)
```

Supported `hash` values: `sha1`, `sha256` (default), `sha384`, `sha512`.
The hash is pinned in the URI because encrypt and decrypt must use the same
value for a given ciphertext.

All non-KMS SOPS key types return gRPC UNIMPLEMENTED so SOPS falls back to
its own local handling for those.

## Commands

```bash
make build              # Build for current platform (CGO_ENABLED=1)
make build-all          # Cross-compile for all platforms (each target needs a C toolchain)
make test               # Run unit tests
make test-integration   # Provision a SoftHSM2 token + keypair, round-trip through Client
make clean              # Remove build artifacts
```

## Binary Usage

```bash
clef-keyservice --pkcs11-module <path> [--addr <host:port>] [--verbose]
```

- `--pkcs11-module` — path to the vendor PKCS#11 library (`.so`/`.dylib`/`.dll`).
  Falls back to `CLEF_PKCS11_MODULE`.
- `CLEF_PKCS11_PIN` — user PIN for `C_Login`. Never accepted on argv
  (would leak into `/proc/<pid>/cmdline`). If unset, `CLEF_PKCS11_PIN_FILE`
  is read as a 0600 file. If neither is set, no login is performed.

Prints `PORT=<port>` to stdout on startup so the CLI can discover the
assigned port when `--addr` uses `:0`.

### Vendor module paths (reference)

| Vendor        | Module path (Linux)                                  | Extra config env                                  |
| ------------- | ---------------------------------------------------- | ------------------------------------------------- |
| SoftHSM2      | `/usr/lib/softhsm/libsofthsm2.so`                    | `SOFTHSM2_CONF`                                   |
| YubiHSM2      | `/usr/local/lib/yubihsm_pkcs11.so`                   | `YUBIHSM_PKCS11_CONF` (plus `yubihsm-connector`) |
| Thales Luna   | `/usr/safenet/lunaclient/lib/libCryptoki2_64.so`     | `ChrystokiConfigurationPath`                      |
| AWS CloudHSM  | `/opt/cloudhsm/lib/libcloudhsm_pkcs11.so`            | cluster certs under `/opt/cloudhsm/etc/`          |
| Nitrokey/OpenSC | `/usr/lib/opensc-pkcs11.so`                        | PC/SC daemon running                              |

### Provisioning a wrap keypair (SoftHSM2 example)

```bash
softhsm2-util --init-token --free --label clef --pin 1234 --so-pin 1234
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
  --login --pin 1234 --slot <N> \
  --keypairgen --key-type rsa:2048 --label clef-dek-wrapper --id 01
```

## Code Style

- Go 1.24+; standard library preferred over third-party dependencies.
- cgo is required (miekg/pkcs11 is a Cryptoki wrapper).
- `log/slog` for structured logging.
- gRPC status codes for errors.
- No panics in library code.

## Proto Contract

The SOPS keyservice proto is consumed directly from `github.com/getsops/sops/v3/keyservice` at a pinned version (kept in lockstep with the CLI's SOPS pin). No local `.proto` vendoring, no `protoc` toolchain required. Bumping the SOPS version is a `go get github.com/getsops/sops/v3@<version>` away.

## Security Properties

- Binds to 127.0.0.1 only (localhost).
- Short-lived process (dies when SOPS command finishes).
- Only the DEK (32-byte key) is wrapped/unwrapped at the boundary; secret
  values never transit this binary.
- Private key material never leaves the HSM — `C_Encrypt`/`C_Decrypt`
  execute inside the device.
- PIN is read from env or a 0600 file, never from argv.
- RSA-OAEP is the mechanism; hash defaults to SHA-256 (FIPS-valid,
  universal across production vendors, sized for a 32-byte DEK in one
  block). SHA-1/384/512 available for compat (e.g. SoftHSM2 2.7 rejects
  SHA-256 OAEP with CKR_ARGUMENTS_BAD and needs `hash=sha1`).
