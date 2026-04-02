.PHONY: proto build build-all test fmt clean

BINARY := clef-keyservice
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-s -w -X main.version=$(VERSION)"

# Generate Go code from proto
proto:
	protoc \
		--go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		proto/keyservice.proto

# Build for current platform
build:
	go build $(LDFLAGS) -o bin/$(BINARY) ./cmd/clef-keyservice

# Cross-compile for all supported platforms
build-all:
	GOOS=darwin  GOARCH=arm64 go build $(LDFLAGS) -o bin/$(BINARY)-darwin-arm64  ./cmd/clef-keyservice
	GOOS=darwin  GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY)-darwin-x64    ./cmd/clef-keyservice
	GOOS=linux   GOARCH=arm64 go build $(LDFLAGS) -o bin/$(BINARY)-linux-arm64   ./cmd/clef-keyservice
	GOOS=linux   GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY)-linux-x64     ./cmd/clef-keyservice
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY)-win32-x64.exe ./cmd/clef-keyservice

test:
	go test ./...

fmt:
	gofmt -w .

clean:
	rm -rf bin/
