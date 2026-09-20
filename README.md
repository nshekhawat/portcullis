# Rate Limiter Service

A high-performance, distributed rate limiting service implementing the token bucket algorithm. Built with Go, it provides both HTTP REST and gRPC APIs for rate limit enforcement.

## Features

- **Token Bucket Algorithm**: Precise rate limiting with configurable burst support
- **Dual API Support**: HTTP REST and gRPC interfaces
- **Distributed Mode**: Redis backend for cluster-wide rate limiting
- **In-Memory Mode**: Fast local rate limiting without external dependencies
- **Flexible Key Extraction**: Rate limit by IP, API key, user ID, headers, or custom strategies
- **Prometheus Metrics**: Built-in observability and monitoring
- **Kubernetes Ready**: Includes manifests for deployment, HPA, and service discovery
- **Health Checks**: HTTP and gRPC health endpoints for container orchestration
- **Graceful Shutdown**: Clean resource cleanup on termination

## Quick Start

### Prerequisites

- Go 1.23 or later
- Redis (optional, for distributed mode)
- Docker (optional, for containerized deployment)

### Installation

```bash
# Clone the repository
git clone https://github.com/nshekhawat/portcullis.git
cd rate-limiter-go

# Download dependencies
go mod download

# Build the binary
go build -o bin/ratelimiter ./cmd/ratelimiter
```

### Running Locally

```bash
# Run with in-memory storage (default)
./bin/ratelimiter

# Run with Redis storage
RATE_LIMITER_USE_REDIS=true ./bin/ratelimiter
```

The service will start on:
- HTTP: `http://localhost:8080`
- gRPC: `localhost:9090`

## Configuration

Configuration can be provided via YAML file or environment variables.

### Configuration File

Copy `config.yaml.example` to `config.yaml` and modify as needed:

```yaml
server:
  http_port: 8080
  grpc_port: 9090
  read_timeout: 10s
  write_timeout: 10s

redis:
  address: "localhost:6379"
  password: ""
  db: 0
  pool_size: 10

ratelimit:
  key_prefix: "rl:"
  ttl: 1h
  default_rules:
    - name: default
      capacity: 100
      refill_rate: 10
      period: 1m

metrics:
  enabled: true
  path: "/metrics"

logging:
  level: "info"
  format: "json"
```

### Environment Variables

All configuration options can be set via environment variables with the prefix `RATE_LIMITER_`:

```bash
RATE_LIMITER_SERVER_HTTP_PORT=8080
RATE_LIMITER_SERVER_GRPC_PORT=9090
RATE_LIMITER_REDIS_ADDRESS=localhost:6379
RATE_LIMITER_USE_REDIS=true
```

## API Reference

### HTTP REST API

#### Check Rate Limit

```bash
POST /v1/check
Content-Type: application/json

{
  "identifier": "user-123",
  "resource": "api",
  "tokens": 1
}
```

Response:
```json
{
  "allowed": true,
  "limit": 100,
  "remaining": 99,
  "reset_at_unix": 1699999999,
  "retry_after_seconds": 0
}
```

#### Get Status

```bash
GET /v1/status/{identifier}?resource=api
```

#### Reset Limit

```bash
DELETE /v1/reset/{identifier}?resource=api
```

#### Health Check

```bash
GET /health    # Liveness check
GET /ready     # Readiness check
GET /metrics   # Prometheus metrics
```

### gRPC API

The gRPC service is defined in `api/proto/ratelimiter.proto`:

```protobuf
service RateLimiterService {
  rpc CheckRateLimit(CheckRequest) returns (CheckResponse);
  rpc GetLimitStatus(StatusRequest) returns (StatusResponse);
  rpc ResetLimit(ResetRequest) returns (ResetResponse);
}
```

Use `grpcurl` for testing:

```bash
# Check rate limit
grpcurl -plaintext -d '{"identifier":"user-123","resource":"api","tokens":1}' \
  localhost:9090 ratelimiter.RateLimiterService/CheckRateLimit

# Get status
grpcurl -plaintext -d '{"identifier":"user-123"}' \
  localhost:9090 ratelimiter.RateLimiterService/GetLimitStatus

# Health check
grpcurl -plaintext localhost:9090 grpc.health.v1.Health/Check
```

## Client Library

Use the built-in Go client library:

```go
package main

import (
    "context"
    "log"

    "github.com/nshekhawat/portcullis/pkg/client"
)

func main() {
    // HTTP Client
    httpClient, _ := client.NewHTTPClient(&client.HTTPConfig{
        BaseURL: "http://localhost:8080",
    })
    defer httpClient.Close()

    // gRPC Client
    grpcClient, _ := client.NewGRPCClient(&client.GRPCConfig{
        Address: "localhost:9090",
    })
    defer grpcClient.Close()

    ctx := context.Background()

    // Check rate limit
    decision, err := httpClient.Check(ctx, "user-123",
        client.WithResource("api"),
        client.WithTokens(1),
    )
    if err != nil {
        log.Fatal(err)
    }

    if decision.Allowed {
        log.Println("Request allowed")
    } else {
        log.Printf("Rate limited. Retry after: %v", decision.RetryAfter)
    }
}
```

## HTTP Middleware

Use as middleware in your Gin application:

```go
package main

import (
    "github.com/gin-gonic/gin"
    "github.com/nshekhawat/portcullis/internal/middleware"
    "github.com/nshekhawat/portcullis/internal/ratelimiter"
    "github.com/nshekhawat/portcullis/internal/storage"
)

func main() {
    store := storage.NewMemoryStorage(time.Hour)
    limiter := ratelimiter.NewRateLimiter(store, nil, nil)

    r := gin.Default()

    // IP-based rate limiting
    r.Use(middleware.IPBasedRateLimiter(limiter))

    // Or API key based
    r.Use(middleware.APIKeyRateLimiter(limiter, "X-API-Key"))

    r.GET("/api/resource", func(c *gin.Context) {
        c.JSON(200, gin.H{"status": "ok"})
    })

    r.Run(":8080")
}
```

## Docker

### Build Image

```bash
docker build -t rate-limiter:latest .
```

### Run Container

```bash
# With in-memory storage
docker run -p 8080:8080 -p 9090:9090 rate-limiter:latest

# With Redis
docker run -p 8080:8080 -p 9090:9090 \
  -e RATE_LIMITER_USE_REDIS=true \
  -e RATE_LIMITER_REDIS_ADDRESS=host.docker.internal:6379 \
  rate-limiter:latest
```

## Kubernetes Deployment

```bash
# Deploy to Kubernetes
kubectl apply -k k8s/

# Verify deployment
kubectl get pods -l app=rate-limiter

# Access the service
kubectl port-forward svc/rate-limiter 8080:8080 9090:9090
```

The Kubernetes manifests include:
- Deployment with 3 replicas
- Horizontal Pod Autoscaler (3-10 replicas)
- Pod Disruption Budget
- ConfigMap for configuration
- Service for load balancing
- ServiceAccount
- Redis deployment (for development)

## Metrics

Prometheus metrics are exposed at `/metrics`:

| Metric | Type | Description |
|--------|------|-------------|
| `ratelimiter_http_requests_total` | Counter | Total HTTP requests |
| `ratelimiter_http_request_duration_seconds` | Histogram | HTTP request duration |
| `ratelimiter_ratelimit_allowed_total` | Counter | Allowed rate limit requests |
| `ratelimiter_ratelimit_denied_total` | Counter | Denied rate limit requests |
| `ratelimiter_tokens_consumed_total` | Counter | Total tokens consumed |
| `ratelimiter_storage_operations_total` | Counter | Storage operations count |
| `ratelimiter_storage_operation_duration_seconds` | Histogram | Storage operation duration |
| `ratelimiter_grpc_requests_total` | Counter | Total gRPC requests |
| `ratelimiter_grpc_request_duration_seconds` | Histogram | gRPC request duration |

## Development

### Run Tests

```bash
# Run all tests
go test ./...

# Run with coverage
go test -cover ./...

# Run specific package tests
go test -v ./internal/ratelimiter/...
```

### Generate Proto Files

```bash
protoc --go_out=. --go_opt=paths=source_relative \
  --go-grpc_out=. --go-grpc_opt=paths=source_relative \
  api/proto/ratelimiter.proto
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Client Applications                      │
└─────────────┬───────────────────────────────────┬───────────┘
              │                                   │
              ▼                                   ▼
       ┌──────────────┐                   ┌──────────────┐
       │  HTTP API    │                   │  gRPC API    │
       │  (Gin)       │                   │              │
       └──────┬───────┘                   └──────┬───────┘
              │                                   │
              └─────────────┬─────────────────────┘
                            │
                            ▼
                   ┌────────────────┐
                   │  Rate Limiter  │
                   │    Service     │
                   └────────┬───────┘
                            │
                            ▼
                   ┌────────────────┐
                   │  Token Bucket  │
                   │   Algorithm    │
                   └────────┬───────┘
                            │
              ┌─────────────┴─────────────┐
              │                           │
              ▼                           ▼
       ┌──────────────┐           ┌──────────────┐
       │   Memory     │           │    Redis     │
       │   Storage    │           │   Storage    │
       └──────────────┘           └──────────────┘
```

## License

MIT License - Free to use.
