.PHONY: all build test lint clean docker proto run help

# Variables
BINARY_NAME=portcullis
BUILD_DIR=bin
DOCKER_IMAGE=portcullis
DOCKER_TAG=latest
GO_FILES=$(shell find . -name '*.go' -not -path './vendor/*')
PROTO_FILES=$(shell find api/proto -name '*.proto')

# Go build flags
LDFLAGS=-ldflags "-w -s"

# Default target
all: lint test build

# Build the binary
build:
	@echo "Building $(BINARY_NAME)..."
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
	./$(BUILD_DIR)/$(BINARY_NAME)

# Run with Redis
run-redis: build
	@echo "Running $(BINARY_NAME) with Redis..."
	PORTCULLIS_USE_REDIS=true ./$(BUILD_DIR)/$(BINARY_NAME)

# Run tests
test:
	@echo "Running tests..."
	go test -race -cover ./...

# Run tests with verbose output
test-verbose:
	@echo "Running tests (verbose)..."
	go test -race -v -cover ./...

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
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .

# Build and push Docker image
docker-push: docker
	@echo "Pushing Docker image..."
	docker push $(DOCKER_IMAGE):$(DOCKER_TAG)

# Run with Docker
docker-run: docker
	@echo "Running with Docker..."
	docker run -p 8080:8080 -p 9090:9090 $(DOCKER_IMAGE):$(DOCKER_TAG)

# Run with Docker Compose (including Redis)
docker-compose-up:
	@echo "Starting services with Docker Compose..."
	docker-compose up -d

docker-compose-down:
	@echo "Stopping services..."
	docker-compose down

# Deploy to Kubernetes
k8s-deploy:
	@echo "Deploying to Kubernetes..."
	kubectl apply -k k8s/

# Delete Kubernetes resources
k8s-delete:
	@echo "Deleting Kubernetes resources..."
	kubectl delete -k k8s/

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html

# Install development tools
install-tools:
	@echo "Installing development tools..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# Show help
help:
	@echo "Available targets:"
	@echo "  all            - Run lint, test, and build"
	@echo "  build          - Build the binary"
	@echo "  build-linux    - Build for Linux (cross-compilation)"
	@echo "  run            - Build and run the service"
	@echo "  run-redis      - Build and run with Redis"
	@echo "  test           - Run tests"
	@echo "  test-verbose   - Run tests with verbose output"
	@echo "  test-coverage  - Run tests with coverage report"
	@echo "  test-pkg PKG=x - Run tests for specific package"
	@echo "  lint           - Run linter"
	@echo "  fmt            - Format code"
	@echo "  tidy           - Tidy dependencies"
	@echo "  deps           - Download dependencies"
	@echo "  proto          - Generate protobuf code"
	@echo "  docker         - Build Docker image"
	@echo "  docker-push    - Build and push Docker image"
	@echo "  docker-run     - Run with Docker"
	@echo "  k8s-deploy     - Deploy to Kubernetes"
	@echo "  k8s-delete     - Delete Kubernetes resources"
	@echo "  clean          - Clean build artifacts"
	@echo "  install-tools  - Install development tools"
	@echo "  help           - Show this help"
