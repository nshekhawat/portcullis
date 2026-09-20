.PHONY: all build test test-short test-integration e2e bench lint fmt tidy proto docker docker-demo ci demo demo-outage demo-down clean install-tools help

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

# --- Demo stack -------------------------------------------------------------

DEMO_DIR=deploy/demo
DEMO_COMPOSE=docker compose -f $(DEMO_DIR)/docker-compose.yaml
DEMO_ADMIN_URL=http://127.0.0.1:8001
DEMO_ADMIN_TOKEN=demo-admin-token
DEMO_TRAFFIC_SECONDS?=120
# Judge selection:
#   JUDGE=mockjev (default) runs the real TypeSafe client against the fake
#                           server in the stack, so no API key is needed.
#   JUDGE=typesafe          points the same client at api.typesafe.ai and
#                           requires TYPESAFE_API_KEY to be set.
JUDGE?=mockjev
ifeq ($(JUDGE),typesafe)
DEMO_TYPESAFE_BASE_URL=https://api.typesafe.ai
else
DEMO_TYPESAFE_BASE_URL=http://mockjev:8099
endif

# Bring the demo stack up, drive it, and print the live tier table.
#   make demo                  fake TypeSafe judge, no API key needed
#   make demo JUDGE=typesafe   real TypeSafe judge, needs TYPESAFE_API_KEY
demo: build
ifeq ($(JUDGE),typesafe)
	@if [ -z "$$TYPESAFE_API_KEY" ]; then \
		echo "JUDGE=typesafe needs TYPESAFE_API_KEY to be set" >&2; exit 1; \
	fi
endif
	@echo "Starting the demo stack (judge=$(JUDGE))..."
	TYPESAFE_BASE_URL=$(DEMO_TYPESAFE_BASE_URL) TYPESAFE_API_KEY=$${TYPESAFE_API_KEY} \
		$(DEMO_COMPOSE) up -d --build redis upstream mockjev gateway-a gateway-b nginx
	@echo "Waiting for the gateway to be ready..."
	@for i in $$(seq 1 60); do 		if curl -sf http://127.0.0.1:8001/ready >/dev/null 2>&1; then break; fi; 		sleep 1; 	done
	@echo "Generating $(DEMO_TRAFFIC_SECONDS)s of mixed traffic..."
	$(DEMO_COMPOSE) --profile tools run --rm -T trafficgen 		-scenario mixed -duration $(DEMO_TRAFFIC_SECONDS)s -target http://nginx:8000 &
	@sleep 2
	@echo "Live tier table (Ctrl-C to stop watching; traffic keeps flowing):"
	-./$(BUILD_DIR)/$(BINARY_NAME) admin tiers --watch --interval 2s 		--url $(DEMO_ADMIN_URL) --token $(DEMO_ADMIN_TOKEN)
	@echo "Waiting for the traffic run to finish..."
	@wait
	@echo
	@echo "=== verdict summary ==="
	-./$(BUILD_DIR)/$(BINARY_NAME) admin decisions --limit 25 		--url $(DEMO_ADMIN_URL) --token $(DEMO_ADMIN_TOKEN)
	@echo
	@echo "Flip to enforce with:"
	@echo "  ./$(BUILD_DIR)/$(BINARY_NAME) admin mode enforce --url $(DEMO_ADMIN_URL) --token $(DEMO_ADMIN_TOKEN)"

# Show the breaker opening while traffic keeps flowing.
demo-outage: 
	@echo "Failing the judge for 30s..."
	curl -sf -X POST -d '{"fail_rate":1}' http://127.0.0.1:8099/chaos >/dev/null
	sleep 30
	curl -sf -X POST -d '{"fail_rate":0}' http://127.0.0.1:8099/chaos >/dev/null
	@echo "Judge recovered. Breaker state and tiers:"
	-./$(BUILD_DIR)/$(BINARY_NAME) admin tiers --url $(DEMO_ADMIN_URL) --token $(DEMO_ADMIN_TOKEN)

# Tear the demo stack down, including volumes.
demo-down:
	$(DEMO_COMPOSE) --profile tools --profile observability down -v

# Bring up Prometheus and Grafana alongside the stack.
demo-observability:
	$(DEMO_COMPOSE) --profile observability up -d prometheus grafana

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
	@echo "  demo             - Run the demo stack (JUDGE=typesafe for the real model)"
	@echo "  demo-outage      - Fail the judge for 30s and show fail-static behavior"
	@echo "  demo-down        - Tear the demo stack down"
	@echo "  docker-run       - Build and run the container"
	@echo "  clean            - Clean build artifacts"
	@echo "  install-tools    - Install development tools"
	@echo "  help             - Show this help"