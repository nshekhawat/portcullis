.PHONY: all build test test-short test-integration e2e bench lint fmt tidy proto docker ci clean install-tools help

# Variables
BINARY_NAME=portcullis
BUILD_DIR=bin
DOCKER_IMAGE=ghcr.io/nshekhawat/portcullis
VERSION?=$(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT?=$(shell git rev-parse --short HEAD 2>/dev/null || echo none)
PROTO_FILES=$(shell find api/proto -name '*.proto')

# Go build flags
LDFLAGS=-ldflags "-s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT)"

GOLANGCI_LINT_VERSION=v2.13.2

# Default target
all: lint test build

# Build the binary
build:
	@echo "Building $(BINARY_NAME) $(VERSION)..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/portcullis

# Build for Linux (cross-compilation)
build-linux:
	@echo "Building $(BINARY_NAME) for Linux..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/portcullis

# Run the service
run: build
	@echo "Running $(BINARY_NAME)..."
	./$(BUILD_DIR)/$(BINARY_NAME) serve

# Run with Redis
run-redis: build
	@echo "Running $(BINARY_NAME) with Redis..."
	PORTCULLIS_USE_REDIS=true ./$(BUILD_DIR)/$(BINARY_NAME) serve

# Run unit tests (integration tests are skipped)
test-short:
	@echo "Running short tests..."
	go test -race -short ./...

# Run all tests, including integration tests that need Docker
test:
	@echo "Running tests..."
	go test -race ./...

# Run integration tests only
test-integration:
	@echo "Running integration tests..."
	go test -race -run 'Integration|Redis' ./internal/storage/...

# Run end-to-end tests
e2e:
	@echo "Running e2e tests..."
	go test -race -tags e2e ./test/e2e/...

# Run benchmarks
bench:
	@echo "Running benchmarks..."
	go test -run '^$$' -bench . -benchtime 100x ./internal/...

# Run tests with coverage report
test-coverage:
	@echo "Running tests with coverage..."
	go test -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Run tests for specific package
test-pkg:
	@echo "Running tests for package $(PKG)..."
	go test -race -v -cover ./$(PKG)/...

# Run linter
lint:
	@echo "Running linter..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not installed, running go vet..."; \
		go vet ./...; \
	fi

# Everything CI runs locally.
ci: build
	@echo "Running CI checks..."
	go vet ./...
	$(MAKE) lint
	go test -race ./...

# Format code
fmt:
	@echo "Formatting code..."
	go fmt ./...

# Tidy dependencies
tidy:
	@echo "Tidying dependencies..."
	go mod tidy

# Download dependencies
deps:
	@echo "Downloading dependencies..."
	go mod download

# Generate protobuf code
proto:
	@echo "Generating protobuf code..."
	protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		$(PROTO_FILES)

# Build Docker image
docker:
	@echo "Building Docker image..."
	docker build --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) -t $(DOCKER_IMAGE):latest .

# Run with Docker
docker-run: docker
	@echo "Running with Docker..."
	docker run -p 8080:8080 -p 9090:9090 $(DOCKER_IMAGE):latest

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html

# Install development tools
install-tools:
	@echo "Installing development tools..."
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
	go install golang.org/x/vuln/cmd/govulncheck@v1.8.0

# Show help
help:
	@echo "Available targets:"
	@echo "  all              - Run lint, test, and build"
	@echo "  build            - Build the binary"
	@echo "  build-linux      - Build for Linux (cross-compilation)"
	@echo "  run              - Build and run the service"
	@echo "  run-redis        - Build and run with Redis"
	@echo "  test             - Run all tests"
	@echo "  test-short       - Run unit tests only"
	@echo "  test-integration - Run integration tests"
	@echo "  e2e              - Run end-to-end tests"
	@echo "  bench            - Run benchmarks"
	@echo "  test-coverage    - Run tests with coverage report"
	@echo "  test-pkg PKG=x   - Run tests for a specific package"
	@echo "  lint             - Run linter"
	@echo "  ci               - Run the CI check suite locally"
	@echo "  fmt              - Format code"
	@echo "  tidy             - Tidy dependencies"
	@echo "  deps             - Download dependencies"
	@echo "  proto            - Generate protobuf code"
	@echo "  docker           - Build Docker image"
	@echo "  docker-run       - Build and run the container"
	@echo "  clean            - Clean build artifacts"
	@echo "  install-tools    - Install development tools"
	@echo "  help             - Show this help"