.PHONY: build build-all test test-integration fmt clean

BINARY := clef-keyservice
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-s -w -X main.version=$(VERSION)"

# Build for current platform. cgo is required (miekg/pkcs11).
build:
	CGO_ENABLED=1 go build $(LDFLAGS) -o bin/$(BINARY) ./cmd/clef-keyservice

# Cross-compile. cgo means each target needs a matching C toolchain
# (e.g. zig cc, osxcross, musl-cross). Override CC_* per target on invocation:
#   make build-all CC_LINUX_AMD64="zig cc -target x86_64-linux-musl"
build-all:
	CGO_ENABLED=1 GOOS=darwin  GOARCH=arm64 CC=$(or $(CC_DARWIN_ARM64),cc) \
		go build $(LDFLAGS) -o bin/$(BINARY)-darwin-arm64 ./cmd/clef-keyservice
	CGO_ENABLED=1 GOOS=darwin  GOARCH=amd64 CC=$(or $(CC_DARWIN_AMD64),cc) \
		go build $(LDFLAGS) -o bin/$(BINARY)-darwin-x64 ./cmd/clef-keyservice
	CGO_ENABLED=1 GOOS=linux   GOARCH=arm64 CC=$(or $(CC_LINUX_ARM64),cc) \
		go build $(LDFLAGS) -o bin/$(BINARY)-linux-arm64 ./cmd/clef-keyservice
	CGO_ENABLED=1 GOOS=linux   GOARCH=amd64 CC=$(or $(CC_LINUX_AMD64),cc) \
		go build $(LDFLAGS) -o bin/$(BINARY)-linux-x64 ./cmd/clef-keyservice

# Unit tests (pure Go parts of the hsm package use the `nocgo` tag path-free,
# the rest still needs cgo because miekg/pkcs11 imports it unconditionally).
test:
	CGO_ENABLED=1 go test ./...

# Integration test: provisions a throwaway SoftHSM2 token + RSA keypair,
# then exercises Encrypt/Decrypt through the real PKCS#11 module — both
# directly against hsm.Client and end-to-end via proxy.Server with a
# synthetic clef-hsm ARN.
# Requires: softhsm2-util and pkcs11-tool (opensc) on PATH.
test-integration:
	CGO_ENABLED=1 go test -tags=integration -count=1 -v ./...

fmt:
	gofmt -w .

clean:
	rm -rf bin/
