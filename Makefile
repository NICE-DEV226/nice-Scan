.PHONY: build run test clean install release

BINARY = nice_scan
VERSION ?= $(shell git describe --tags 2>/dev/null || echo "dev")
LDFLAGS = -ldflags "-s -w -X main.version=$(VERSION)"

build:
	go build $(LDFLAGS) -o $(BINARY) ./cmd/nice_scan

build-windows:
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY).exe ./cmd/nice_scan

build-linux:
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY)-linux ./cmd/nice_scan

build-macos:
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY)-macos ./cmd/nice_scan

build-all: build-windows build-linux build-macos

run: build
	./$(BINARY) $(ARGS)

test:
	go test -race -v ./...

vet:
	go vet ./...

lint:
	golangci-lint run ./...

tidy:
	go mod tidy

clean:
	rm -f $(BINARY) $(BINARY).exe $(BINARY)-linux $(BINARY)-macos
	rm -rf dist/

release:
	goreleaser release --clean

snapshot:
	goreleaser release --snapshot --clean

# Quick: build + hack example.com
hack: build
	./$(BINARY) hack example.com --timeout 10s $(ARGS)
